/*
 * Copyright 2025 Jeremy Heer
 * Licensed under the Apache License, Version 2.0
 */
package com.heer.sync;

import com.unboundid.directory.sdk.sync.api.SyncSource;
import com.unboundid.directory.sdk.sync.config.SyncSourceConfig;
import com.unboundid.directory.sdk.sync.types.ChangeRecord;
import com.unboundid.directory.sdk.sync.types.EndpointException;
import com.unboundid.directory.sdk.sync.types.PostStepResult;
import com.unboundid.directory.sdk.sync.types.SetStartpointOptions;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;

import com.unboundid.scim2.client.ScimService;
import com.unboundid.scim2.common.messages.ListResponse;
import com.unboundid.scim2.common.types.GroupResource;

import com.heer.sync.lib.ConfigFileLoader;
import com.heer.sync.lib.scim2.Scim2ClientFactory;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Custom SCIM2 source for detecting orphaned groups.
 * <p>
 * This source plugin queries the SCIM2 directory during resync operations
 * and streams all groups through the sync pipe. It's designed to work with
 * an LDAP destination plugin that checks for group existence in LDAP and
 * deletes orphaned groups from SCIM2 if they're not found.
 * </p>
 * 
 * <h2>Architecture:</h2>
 * <pre>
 * SCIM2 Source → Sync Pipe → LDAP Destination → Orphan Cleanup Plugin
 * (list all groups)          (lookup in LDAP)    (delete if not found)
 * </pre>
 * 
 * <h2>Usage:</h2>
 * <p>This source is intended for <b>manual resync operations only</b>:</p>
 * <pre>
 * realtime-sync resync --pipe-name SCIM2-Group-Orphan-Cleanup --dry-run
 * </pre>
 * 
 * <h2>Configuration:</h2>
 * <pre>
 * scim2.base.url=https://api.example.com/scim/v2
 * scim2.group.base=/Groups
 * scim2.auth.type=basic
 * scim2.username=sync-service
 * scim2.password=changeme
 * cleanup.page.size=100
 * </pre>
 * 
 * @author Jeremy Heer
 */
public class Scim2GroupOrphanCheckSource extends SyncSource
{
  private SyncServerContext serverContext;
  
  // SCIM2 client components
  private Scim2ClientFactory clientFactory;
  private ScimService scimService;
  
  // Configuration
  private ConfigFileLoader configLoader;
  private String baseUrl;
  private String groupBasePath = "/Groups";
  private String baseDN;
  private int pageSize = 100;
  
  @Override
  public String getExtensionName()
  {
    return "SCIM2 Group Orphan Check Source";
  }
  
  @Override
  public String[] getExtensionDescription()
  {
    return new String[] {
      "Custom SCIM2 source for orphan cleanup resync operations.",
      "",
      "This source queries SCIM2 and streams all groups through the sync pipe.",
      "Used with LDAP destination to detect and delete groups not found in LDAP.",
      "",
      "Features:",
      "- Paginated SCIM2 queries for scalability",
      "- Optimized queries (excludes large members array)",
      "- Preserves scim2GroupId attribute for cleanup",
      "- Converts SCIM2 GroupResource to LDAP Entry format",
      "- Designed for manual resync operations only",
      "",
      "Usage:",
      "  realtime-sync resync --pipe-name SCIM2-Group-Orphan-Cleanup --dry-run"
    };
  }
  
  @Override
  public void defineConfigArguments(final ArgumentParser parser) throws ArgumentException
  {
    // Shared config file
    parser.addArgument(new FileArgument(
        null, "config-file", true, 1,
        "{path}",
        "Path to shared configuration properties file containing SCIM2 connection settings.",
        true, true, true, false));
    
    // SCIM2 endpoint configuration
    parser.addArgument(new StringArgument(
        null, "scim2-base-url", false, 1,
        "{url}",
        "The base URL of the SCIM2 endpoint (e.g., https://example.com/scim/v2). " +
        "Can be provided via config file."));
    
    // Base DN for synthetic LDAP entries
    parser.addArgument(new StringArgument(
        null, "base-dn", false, 1,
        "{dn}",
        "Base DN for synthetic LDAP entries (e.g., ou=Groups,dc=example,dc=com). " +
        "Can be provided via config file as ldap.base.dn."));
    
    // Page size for SCIM2 queries
    parser.addArgument(new StringArgument(
        null, "page-size", false, 1,
        "{size}",
        "Number of groups to fetch per page from SCIM2 (default: 100). " +
        "Can be provided via config file as cleanup.page.size."));
  }
  
  @Override
  public void initializeSyncSource(
      final SyncServerContext context,
      final SyncSourceConfig config,
      final ArgumentParser parser)
  {
    serverContext = context;
    
    // Load configuration file
    FileArgument configFileArg = (FileArgument) parser.getNamedArgument("config-file");
    if (configFileArg != null && configFileArg.isPresent()) {
      try {
        configLoader = new ConfigFileLoader(configFileArg.getValue().getAbsolutePath(), serverContext);
        serverContext.debugInfo("Loaded shared configuration from: " + 
                                configFileArg.getValue().getAbsolutePath());
      } catch (java.io.IOException e) {
        throw new RuntimeException("Failed to load config file: " + e.getMessage(), e);
      }
    } else {
      throw new RuntimeException("config-file is required");
    }
    
    // Get base URL
    baseUrl = getConfigValue(parser, "scim2-base-url", "scim2.base.url", null);
    if (baseUrl == null || baseUrl.trim().isEmpty()) {
      throw new RuntimeException("scim2-base-url is required");
    }
    
    // Get paths
    groupBasePath = getConfigValue(parser, "scim2-group-base", "scim2.group.base", "/Groups");
    
    // Get base DN
    baseDN = getConfigValue(parser, "base-dn", "ldap.base.dn", "ou=Groups,dc=example,dc=com");
    
    // Get page size
    String pageSizeStr = getConfigValue(parser, "page-size", "cleanup.page.size", "100");
    pageSize = Integer.parseInt(pageSizeStr);
    
    // Build SCIM2 client factory
    clientFactory = buildClientFactory(parser);
    
    // Create SCIM2 service
    scimService = clientFactory.createScimService();
    
    serverContext.debugInfo("SCIM2 Group Orphan Check Source initialized successfully");
    serverContext.debugInfo("  Base URL: " + baseUrl);
    serverContext.debugInfo("  Group path: " + groupBasePath);
    serverContext.debugInfo("  Base DN: " + baseDN);
    serverContext.debugInfo("  Page size: " + pageSize);
  }
  
  @Override
  public void finalizeSyncSource()
  {
    serverContext.debugInfo("Finalizing SCIM2 Group Orphan Check Source");
    // Cleanup resources if needed
  }
  
  /**
   * This method is not used for resync-only sources.
   * Orphan cleanup is performed via manual resync, not continuous polling.
   */
  @Override
  public List<ChangeRecord> getNextBatchOfChanges(
      final int maxChanges,
      final AtomicLong numStillPending) throws EndpointException
  {
    // This source is designed for resync operations only
    // No continuous change detection
    serverContext.debugInfo("getNextBatchOfChanges called - no continuous sync supported");
    numStillPending.set(0);
    return new ArrayList<>();
  }
  
  /**
   * Lists all groups from SCIM2 during resync operations.
   * Groups are fetched in pages and converted to LDAP Entry format,
   * preserving the scim2GroupId attribute for later cleanup.
   * Uses optimized queries that exclude the large members array.
   */
  @Override
  public void listAllEntries(final BlockingQueue<ChangeRecord> outputQueue) throws EndpointException
  {
    serverContext.debugInfo("Starting SCIM2 group enumeration for orphan detection");
    
    int totalGroups = 0;
    int startIndex = 1;
    boolean hasMore = true;
    
    try
    {
      while (hasMore)
      {
        serverContext.debugInfo("Fetching SCIM2 groups page (startIndex=" + startIndex + 
                               ", pageSize=" + pageSize + ")");
        
        // Query SCIM2 for groups (exclude members for performance)
        ListResponse<GroupResource> response = scimService.searchRequest(groupBasePath)
            .attributes("id", "displayName", "externalId") // Exclude large members array
            .page(startIndex, pageSize)
            .invoke(GroupResource.class);
        
        List<GroupResource> groups = response.getResources();
        
        if (groups == null || groups.isEmpty())
        {
          hasMore = false;
          break;
        }
        
        // Convert each SCIM2 group to LDAP entry and queue for processing
        for (GroupResource group : groups)
        {
          Entry entry = convertGroupToLdapEntry(group);
          ChangeRecord changeRecord = new ChangeRecord.Builder(null, entry.getParsedDN())
              .fullEntry(entry)
              .build();
          
          // Block if queue is full (capacity: 1000)
          outputQueue.put(changeRecord);
          totalGroups++;
        }
        
        serverContext.debugInfo("Queued " + groups.size() + " groups (total so far: " + totalGroups + ")");
        
        // Check if there are more pages
        if (groups.size() < pageSize)
        {
          hasMore = false;
        }
        else
        {
          startIndex += pageSize;
        }
      }
      
      serverContext.debugInfo("Completed SCIM2 group enumeration: " + totalGroups + " groups queued");
    }
    catch (InterruptedException e)
    {
      Thread.currentThread().interrupt();
      throw new EndpointException(PostStepResult.ABORT_OPERATION,
                                  "Group enumeration interrupted", e);
    }
    catch (Exception e)
    {
      throw new EndpointException(PostStepResult.ABORT_OPERATION,
                                  "Failed to list SCIM2 groups: " + e.getMessage(), e);
    }
  }
  
  /**
   * Converts a SCIM2 GroupResource to an LDAP Entry format.
   * Preserves the SCIM2 group ID in the scim2GroupId attribute for later cleanup.
   */
  private Entry convertGroupToLdapEntry(final GroupResource group) throws Exception
  {
    String displayName = group.getDisplayName();
    String scim2GroupId = group.getId();
    
    // Build DN (simple string concatenation)
    String dn = "cn=" + displayName + "," + baseDN;
    
    // Create entry
    Entry entry = new Entry(dn);
    entry.addAttribute("objectClass", "groupOfNames");
    entry.addAttribute("cn", displayName);
    entry.addAttribute("scim2GroupId", scim2GroupId); // CRITICAL: Preserve for cleanup
    
    // Add externalId if available
    if (group.getExternalId() != null) {
      entry.addAttribute("externalId", group.getExternalId());
    }
    
    // Add placeholder member for groupOfNames objectClass requirement
    entry.addAttribute("member", "cn=placeholder");
    
    return entry;
  }
  
  @Override
  public Entry fetchEntry(final SyncOperation operation) throws EndpointException
  {
    ChangeRecord record = operation.getChangeRecord();
    throw new IllegalStateException(
      "fetchEntry() should not be called because the full entry is set " +
      "on the ChangeRecord: " + record.toString());
  }

  @Override
  public String getCurrentEndpointURL()
  {
    return baseUrl + groupBasePath;
  }
  
  @Override
  public void setStartpoint(final SetStartpointOptions options) throws EndpointException
  {
    // Not used for resync-only sources
    serverContext.debugInfo("setStartpoint called - resync-only source");
  }
  
  @Override
  public Serializable getStartpoint()
  {
    // Not used for resync-only sources
    return null;
  }
  
  @Override
  public void acknowledgeCompletedOps(final LinkedList<SyncOperation> completedOps)
         throws EndpointException
  {
    // Not used for resync-only sources
    // No startpoint tracking needed
  }
  
  /**
   * Helper to get config value from argument or properties file.
   */
  private String getConfigValue(
      final ArgumentParser parser,
      final String argName,
      final String propKey,
      final String defaultValue)
  {
    StringArgument arg = (StringArgument) parser.getNamedArgument(argName);
    if (arg != null && arg.isPresent()) {
      return arg.getValue();
    }
    return configLoader.getProperty(propKey, defaultValue);
  }
  
  /**
   * Builds a SCIM2 client factory from configuration.
   */
  private Scim2ClientFactory buildClientFactory(final ArgumentParser parser)
  {
    // Get authentication config
    String authType = configLoader.getProperty("scim2.auth.type", "basic");
    String username = configLoader.getProperty("scim2.username");
    String password = configLoader.getProperty("scim2.password");
    String bearerToken = configLoader.getProperty("scim2.bearer.token");
    
    // Get SSL config
    String trustStorePath = configLoader.getProperty("scim2.truststore.path");
    String trustStorePassword = configLoader.getProperty("scim2.truststore.password");
    String trustStoreType = configLoader.getProperty("scim2.truststore.type", "JKS");
    boolean allowUntrustedCerts = configLoader.getBooleanProperty("scim2.allow.untrusted.certs", false);
    
    // Get proxy config
    String proxyHost = configLoader.getProperty("scim2.proxy.host");
    String proxyPort = configLoader.getProperty("scim2.proxy.port");
    String proxyUsername = configLoader.getProperty("scim2.proxy.username");
    String proxyPassword = configLoader.getProperty("scim2.proxy.password");
    String proxyType = configLoader.getProperty("scim2.proxy.type", "http");
    
    // Get timeout config
    int connectTimeout = configLoader.getIntProperty("scim2.connect.timeout.ms", 30000);
    int readTimeout = configLoader.getIntProperty("scim2.read.timeout.ms", 60000);
    
    return new Scim2ClientFactory(
        serverContext, configLoader,
        baseUrl, "/Users", groupBasePath,
        authType, username, password, bearerToken,
        trustStorePath, trustStorePassword, trustStoreType, allowUntrustedCerts,
        proxyHost, proxyPort, proxyUsername, proxyPassword, proxyType,
        connectTimeout, readTimeout
    );
  }
}

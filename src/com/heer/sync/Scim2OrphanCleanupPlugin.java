/*
 * Copyright 2025 Jeremy Heer
 * Licensed under the Apache License, Version 2.0
 */
package com.heer.sync;

import com.unboundid.directory.sdk.sync.api.LDAPSyncDestinationPlugin;
import com.unboundid.directory.sdk.sync.config.LDAPSyncDestinationPluginConfig;
import com.unboundid.directory.sdk.sync.types.PostStepResult;
import com.unboundid.directory.sdk.sync.types.PreStepResult;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;

import com.unboundid.scim2.client.ScimService;

import com.heer.sync.lib.ConfigFileLoader;
import com.heer.sync.lib.scim2.Scim2ClientFactory;
import com.heer.sync.lib.scim2.Scim2OrphanCleanupHelper;

import java.util.List;

/**
 * LDAP destination plugin for detecting and cleaning up orphaned SCIM2 resources.
 * <p>
 * This plugin intercepts the postFetch operation of an LDAP destination to detect
 * when entries from SCIM2 (passed through as source) are NOT found in LDAP.
 * When an entry is missing from LDAP, it's considered an orphan and is deleted from SCIM2.
 * </p>
 * 
 * <h2>Architecture:</h2>
 * <pre>
 * SCIM2 Source → Sync Pipe → LDAP Destination → THIS PLUGIN
 * (list entries)             (lookup in LDAP)    (delete if not found)
 * </pre>
 * 
 * <h2>Operation Flow:</h2>
 * <ol>
 *   <li>SCIM2 source lists all users/groups during resync</li>
 *   <li>Each entry is converted to LDAP format with scim2UserId/scim2GroupId preserved</li>
 *   <li>LDAP destination searches for matching entry in LDAP</li>
 *   <li>postFetch() receives search results (empty if not found)</li>
 *   <li>If empty: Extract SCIM2 ID and delete from SCIM2</li>
 *   <li>If found: Entry exists in both systems, no action</li>
 * </ol>
 * 
 * <h2>Usage:</h2>
 * <pre>
 * # Dry run (uses resync's --dry-run flag, no deletions performed)
 * realtime-sync resync --pipe-name SCIM2-User-Orphan-Cleanup --dry-run
 * 
 * # Actual cleanup (deletions will be performed)
 * realtime-sync resync --pipe-name SCIM2-User-Orphan-Cleanup
 * </pre>
 * 
 * <h2>Configuration:</h2>
 * <pre>
 * scim2.base.url=https://api.example.com/scim/v2
 * scim2.user.base=/Users
 * scim2.group.base=/Groups
 * scim2.auth.type=basic
 * scim2.username=sync-service
 * scim2.password=changeme
 * cleanup.resource.type=user  # or 'group'
 * </pre>
 * 
 * @author Jeremy Heer
 */
public class Scim2OrphanCleanupPlugin extends LDAPSyncDestinationPlugin
{
  private SyncServerContext serverContext;
  
  // SCIM2 client components
  private Scim2ClientFactory clientFactory;
  private ScimService scimService;
  private Scim2OrphanCleanupHelper cleanupHelper;
  
  // Configuration
  private ConfigFileLoader configLoader;
  private String baseUrl;
  private String userBasePath = "/Users";
  private String groupBasePath = "/Groups";
  private String resourceType; // "user" or "group"
  private String ldapBaseDN; // LDAP base DN for subtree searches
  private String ldapUserIdAttribute = "uid"; // Attribute to search for users
  
  // Retry configuration
  private int maxRetries = 3;
  private int retryDelayMs = 1000;
  
  // Statistics
  private int orphansDetected = 0;
  private int orphansDeleted = 0;
  private int orphansAlreadyDeleted = 0;
  private int deletionFailures = 0;
  
  @Override
  public String getExtensionName()
  {
    return "SCIM2 Orphan Cleanup LDAP Plugin";
  }
  
  @Override
  public String[] getExtensionDescription()
  {
    return new String[] {
      "LDAP destination plugin for detecting and cleaning up orphaned SCIM2 resources.",
      "",
      "This plugin detects when SCIM2 entries are not found in LDAP during resync",
      "and deletes them from SCIM2. Works with SCIM2 orphan check source plugins.",
      "",
      "Features:",
      "- Detects missing entries via postFetch() interception",
      "- Deletes orphaned users or groups from SCIM2",
      "- Supports dry-run mode via resync --dry-run flag",
      "- Retry logic with exponential backoff",
      "- Operation statistics logging",
      "",
      "Usage:",
      "  realtime-sync resync --pipe-name SCIM2-User-Orphan-Cleanup --dry-run"
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
    
    // Resource type
    parser.addArgument(new StringArgument(
        null, "resource-type", false, 1,
        "{type}",
        "Type of resource to clean up: 'user' or 'group'. " +
        "Can be provided via config file as cleanup.resource.type."));
    
    // LDAP base DN for searches
    parser.addArgument(new StringArgument(
        null, "ldap-base-dn", false, 1,
        "{dn}",
        "LDAP base DN for subtree searches (e.g., ou=Users,dc=example,dc=com). " +
        "Can be provided via config file as ldap.base.dn."));
    
    // LDAP user ID attribute
    parser.addArgument(new StringArgument(
        null, "ldap-user-id-attr", false, 1,
        "{attr}",
        "LDAP attribute to use when searching for users (default: uid). " +
        "Can be provided via config file as ldap.user.id.attribute."));
  }
  
  @Override
  public void initializeLDAPSyncDestinationPlugin(
      final SyncServerContext context,
      final LDAPSyncDestinationPluginConfig config,
      final ArgumentParser parser) throws LDAPException
  {
    serverContext = context;
    
    try
    {
      // Load configuration file
      FileArgument configFileArg = (FileArgument) parser.getNamedArgument("config-file");
      if (configFileArg != null && configFileArg.isPresent()) {
        configLoader = new ConfigFileLoader(configFileArg.getValue().getAbsolutePath(), serverContext);
        serverContext.debugInfo("Loaded shared configuration from: " + 
                                configFileArg.getValue().getAbsolutePath());
      } else {
        throw new RuntimeException("config-file is required");
      }
      
      // Get base URL
      baseUrl = getConfigValue(parser, "scim2-base-url", "scim2.base.url", null);
      if (baseUrl == null || baseUrl.trim().isEmpty()) {
        throw new RuntimeException("scim2-base-url is required");
      }
      
      // Get paths
      userBasePath = getConfigValue(parser, "scim2-user-base", "scim2.user.base", "/Users");
      groupBasePath = getConfigValue(parser, "scim2-group-base", "scim2.group.base", "/Groups");
      
      // Get resource type
      resourceType = getConfigValue(parser, "resource-type", "cleanup.resource.type", null);
      if (resourceType == null || resourceType.trim().isEmpty()) {
        throw new RuntimeException("resource-type is required (user or group)");
      }
      if (!resourceType.equalsIgnoreCase("user") && !resourceType.equalsIgnoreCase("group")) {
        throw new RuntimeException("resource-type must be 'user' or 'group', got: " + resourceType);
      }
      
      // Get LDAP base DN for searches
      ldapBaseDN = getConfigValue(parser, "ldap-base-dn", "ldap.base.dn", null);
      if (ldapBaseDN == null || ldapBaseDN.trim().isEmpty()) {
        throw new RuntimeException("ldap-base-dn is required for subtree searches");
      }
      
      // Get LDAP user ID attribute
      ldapUserIdAttribute = getConfigValue(parser, "ldap-user-id-attr", "ldap.user.id.attribute", "uid");
      
      // Get retry configuration
      maxRetries = configLoader.getIntProperty("scim2.max.retries", 3);
      retryDelayMs = configLoader.getIntProperty("scim2.retry.delay.ms", 1000);
      
      // Build SCIM2 client factory
      clientFactory = buildClientFactory(parser);
      
      // Create SCIM2 service
      scimService = clientFactory.createScimService();
      
      // Create cleanup helper
      cleanupHelper = new Scim2OrphanCleanupHelper(
          scimService,
          baseUrl,
          userBasePath,
          groupBasePath,
          maxRetries,
          retryDelayMs
      );
      
      serverContext.debugInfo("SCIM2 Orphan Cleanup Plugin initialized successfully");
      serverContext.debugInfo("  Base URL: " + baseUrl);
      serverContext.debugInfo("  Resource type: " + resourceType);
      serverContext.debugInfo("  User path: " + userBasePath);
      serverContext.debugInfo("  Group path: " + groupBasePath);
      serverContext.debugInfo("  LDAP base DN: " + ldapBaseDN);
      serverContext.debugInfo("  LDAP user ID attribute: " + ldapUserIdAttribute);
      serverContext.debugInfo("  Max retries: " + maxRetries);
    }
    catch (Exception e)
    {
      throw new LDAPException(
          com.unboundid.ldap.sdk.ResultCode.LOCAL_ERROR,
          "Failed to initialize SCIM2 Orphan Cleanup Plugin: " + e.getMessage(),
          e);
    }
  }
  
  @Override
  public void finalizeLDAPSyncDestinationPlugin()
  {
    serverContext.debugInfo("Finalizing SCIM2 Orphan Cleanup Plugin");
    serverContext.debugInfo("Statistics:");
    serverContext.debugInfo("  Orphans detected: " + orphansDetected);
    serverContext.debugInfo("  Orphans deleted: " + orphansDeleted);
    serverContext.debugInfo("  Already deleted: " + orphansAlreadyDeleted);
    serverContext.debugInfo("  Deletion failures: " + deletionFailures);
  }
  
  /**
   * Called before LDAP destination fetches entry.
   * This intercepts the search request and modifies it to perform a proper subtree search
   * using the uid attribute instead of a base-level DN search.
   * 
   * The default behavior constructs a DN like "uid=empl117,dc=jeremy,dc=net" and does
   * a base search, but LDAP users may be named with different attributes (e.g., employeeNumber).
   * We need to search by uid to find the actual entry.
   */
  @Override
  public PreStepResult preFetch(
      final LDAPInterface destinationConnection,
      final SearchRequest searchRequest,
      final List<Entry> fetchedEntries,
      final SyncOperation operation) throws LDAPException
  {
    Entry sourceEntry = operation.getSourceEntry();
    if (sourceEntry == null) {
      operation.logInfo("CLEANUP: No source entry available for preFetch");
      return PreStepResult.CONTINUE;
    }
    
    // Extract the identifier based on resource type
    String identifier = null;
    String searchAttribute = null;
    
    if ("user".equalsIgnoreCase(resourceType)) {
      identifier = sourceEntry.getAttributeValue("uid");
      searchAttribute = ldapUserIdAttribute;
    } else if ("group".equalsIgnoreCase(resourceType)) {
      identifier = sourceEntry.getAttributeValue("cn");
      searchAttribute = "cn"; // Groups typically use cn
    }
    
    if (identifier == null || identifier.trim().isEmpty()) {
      operation.logInfo("CLEANUP WARNING: No identifier found in source entry for " + resourceType);
      return PreStepResult.CONTINUE;
    }
    
    // Construct a proper subtree search instead of base DN search
    Filter filter = Filter.createEqualityFilter(searchAttribute, identifier);
    
    operation.logInfo("CLEANUP: Modifying search from base DN '" + searchRequest.getBaseDN() + 
                     "' to subtree search - base: '" + ldapBaseDN + 
                     "', filter: " + filter.toString());
    
    // Modify the search request in-place
    searchRequest.setBaseDN(ldapBaseDN);
    searchRequest.setScope(SearchScope.SUB);
    searchRequest.setFilter(filter);
    
    // Don't return any attributes - we only care if the entry exists
    searchRequest.setAttributes("1.1");
    
    return PreStepResult.CONTINUE;
  }
  
  /**
   * Called after LDAP destination fetches entry.
   * This is where we detect orphans - if fetchedEntries is empty,
   * the entry exists in SCIM2 but not in LDAP.
   */
  @Override
  public PostStepResult postFetch(
      final LDAPInterface destinationConnection,
      final SearchRequest searchRequest,
      final List<Entry> fetchedEntries,
      final SyncOperation operation) throws LDAPException
  {
    // Check if entry was NOT found in LDAP (orphan detected)
    if (fetchedEntries == null || fetchedEntries.isEmpty())
    {
      orphansDetected++;
      
      // Get the source entry (from SCIM2)
      Entry sourceEntry = operation.getSourceEntry();
      if (sourceEntry == null) {
        operation.logInfo("CLEANUP: No source entry available for orphan detection");
        return PostStepResult.ABORT_OPERATION;
      }
      
      // Extract SCIM2 ID based on resource type
      String scim2Id = null;
      String identifier = null;
      
      if ("user".equalsIgnoreCase(resourceType)) {
        scim2Id = sourceEntry.getAttributeValue("scim2UserId");
        identifier = sourceEntry.getAttributeValue("uid");
      } else if ("group".equalsIgnoreCase(resourceType)) {
        scim2Id = sourceEntry.getAttributeValue("scim2GroupId");
        identifier = sourceEntry.getAttributeValue("cn");
      }
      
      if (scim2Id == null || scim2Id.trim().isEmpty()) {
        operation.logInfo("CLEANUP WARNING: No SCIM2 ID found in source entry - " +
                         "cannot delete orphan (identifier: " + identifier + ")");
        return PostStepResult.ABORT_OPERATION;
      }
      
      operation.logInfo("CLEANUP: ORPHAN DETECTED - " + resourceType + " '" + identifier + 
                       "' exists in SCIM2 but not in LDAP (SCIM2 ID: " + scim2Id + ")");
      
      // Delete the orphan from SCIM2
      // Note: Dry-run mode is controlled by the resync command's --dry-run flag
      // which affects the entire sync operation at a higher level
      try {
        boolean deleted = cleanupHelper.deleteResource(resourceType, scim2Id, operation);
        
        if (deleted) {
          orphansDeleted++;
          operation.logInfo("CLEANUP: Successfully deleted orphan " + resourceType + " '" + 
                           identifier + "' from SCIM2");
        } else {
          orphansAlreadyDeleted++;
          operation.logInfo("CLEANUP: Orphan " + resourceType + " '" + identifier + 
                           "' already deleted from SCIM2");
        }
      } catch (Exception e) {
        deletionFailures++;
        operation.logInfo("CLEANUP ERROR: Failed to delete orphan " + resourceType + " '" + 
                         identifier + "' from SCIM2: " + e.getMessage());
        // Continue with ABORT_OPERATION to skip further processing
      }
      
      // Abort the operation - no need to create/modify in LDAP
      return PostStepResult.ABORT_OPERATION;
    }
    
    // Entry found in LDAP - it's not an orphan, but abort to prevent modify attempts
    // This is a read-only orphan check operation
    return PostStepResult.ABORT_OPERATION;
  }
  
  /**
   * Appends a string representation of this LDAP sync destination plugin to
   * the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  @Override
  public void toString(final StringBuilder buffer)
  {
    buffer.append("Scim2OrphanCleanupPlugin(resourceType='");
    buffer.append(resourceType);
    buffer.append("', baseUrl='");
    buffer.append(baseUrl);
    buffer.append("', orphansDetected=");
    buffer.append(orphansDetected);
    buffer.append(", orphansDeleted=");
    buffer.append(orphansDeleted);
    buffer.append(")");
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
        baseUrl, userBasePath, groupBasePath,
        authType, username, password, bearerToken,
        trustStorePath, trustStorePassword, trustStoreType, allowUntrustedCerts,
        proxyHost, proxyPort, proxyUsername, proxyPassword, proxyType,
        connectTimeout, readTimeout
    );
  }
}

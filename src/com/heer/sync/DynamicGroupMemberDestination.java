/*
 * Copyright 2025 Corp Heer
 */

package com.heer.sync;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.unboundid.directory.sdk.sync.api.SyncDestination;
import com.unboundid.directory.sdk.sync.config.SyncDestinationConfig;
import com.unboundid.directory.sdk.sync.types.EndpointException;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;
import com.unboundid.scim2.client.ScimService;
import com.unboundid.scim2.common.types.GroupResource;
import com.unboundid.scim2.common.types.Member;
import com.unboundid.scim2.common.utils.JsonUtils;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;

import com.heer.sync.lib.ConfigFileLoader;
import com.heer.sync.lib.scim2.Scim2ClientFactory;
import com.heer.sync.lib.scim2.Scim2MemberHelper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SCIM2 Dynamic Group Destination plugin for synchronizing dynamic group memberships.
 * 
 * This plugin handles full group resync operations for dynamic groups (groups with memberURL
 * attributes). Since dynamic group membership is computed from LDAP queries, this plugin
 * only processes REPLACE operations (resync mode) and does not support incremental
 * ADD/DELETE operations.
 * 
 * Key Features:
 * - Full REPLACE operations using PUT (resync mode only)
 * - Integration with ConfigFileLoader for configuration management  
 * - Retry logic with exponential backoff
 * - Optimized group fetches excluding members array
 * 
 * Works with DynamicGroupSourcePlugin which provides the 'members' attribute
 * containing user IDs resolved from memberURL queries.
 */
public class DynamicGroupMemberDestination extends SyncDestination
{
  // Pre-configured ObjectMapper from SCIM2 SDK
  private static final ObjectMapper SCIM_OBJECT_MAPPER = JsonUtils.createObjectMapper();

  // Server context and configuration
  private SyncServerContext serverContext;
  private SyncDestinationConfig config;

  // SCIM2 clients
  private ScimService scimService;
  private Client jaxrsClient;

  // Configuration file loader
  private ConfigFileLoader configFileLoader;

  // Helper utilities
  private Scim2MemberHelper memberHelper;

  // Configuration parameters
  private String groupBasePath;
  private String userLookupAttribute;
  private int maxRetries;
  private int retryDelayMs;

  @Override
  public String getExtensionName()
  {
    return "SCIM2 Dynamic Group Sync Destination";
  }

  @Override
  public String[] getExtensionDescription()
  {
    return new String[]
    {
      "This SCIM2 destination synchronizes dynamic group membership changes to SCIM2 groups.",
      "It processes the 'members' attribute from DynamicGroupSourcePlugin, which contains " +
      "user IDs (uid values) resolved from memberURL queries, and updates the corresponding " +
      "SCIM2 group by replacing the entire member list.",
      "This plugin only supports REPLACE operations (resync mode) since dynamic group " +
      "membership is computed from LDAP queries rather than incremental changes."
    };
  }

  @Override
  public void defineConfigArguments(final ArgumentParser parser)
      throws ArgumentException
  {
    StringArgument configFileArg = new StringArgument(
        null, "config-file", false, 1, "{file-path}",
        "Path to configuration file containing SCIM2 connection settings. " +
        "If specified, settings from this file will be used as defaults, with " +
        "inline arguments taking precedence.");

    StringArgument groupBaseArg = new StringArgument(
        null, "group-base", false, 1, "{group-base}",
        "The base path for SCIM2 groups (e.g., /Groups). " +
        "Can be set via config file property: scim2.group.base");

    StringArgument userLookupAttrArg = new StringArgument(
        null, "user-lookup-attribute", false, 1, "{attribute}",
        "The LDAP attribute used to look up users (e.g., uid). " +
        "This should match the user ID values in the 'members' attribute. " +
        "Can be set via config file property: user.lookup.attribute (default: uid)");

    parser.addArgument(configFileArg);
    parser.addArgument(groupBaseArg);
    parser.addArgument(userLookupAttrArg);
  }

  @Override
  public Map<List<String>, String> getExamplesArgumentSets()
  {
    final LinkedHashMap<List<String>, String> exampleMap =
        new LinkedHashMap<List<String>, String>();

    exampleMap.put(
        Arrays.asList("config-file=/opt/sync/config/scim-sync.properties",
                     "group-base=/Groups"),
        "Synchronize dynamic group memberships using configuration file for " +
        "SCIM2 connection settings (base URL, authentication, etc.)");

    exampleMap.put(
        Arrays.asList("config-file=/opt/sync/config/scim-sync.properties",
                     "group-base=/Groups",
                     "user-lookup-attribute=uid"),
        "Synchronize with explicit user lookup attribute. This should match the " +
        "attribute configured in DynamicGroupSourcePlugin.");

    return exampleMap;
  }

  @Override
  public void initializeSyncDestination(
      final SyncServerContext serverContext,
      final SyncDestinationConfig config,
      final ArgumentParser parser)
      throws EndpointException
  {
    this.serverContext = serverContext;
    this.config = config;

    // Get configuration file argument
    StringArgument configFileArg = (StringArgument)
        parser.getNamedArgument("config-file");
    
    String configFilePath = null;
    if (configFileArg != null && configFileArg.isPresent())
    {
      configFilePath = configFileArg.getValue();
    }

    // Initialize configuration file loader if config file specified
    if (configFilePath != null && !configFilePath.trim().isEmpty())
    {
      try
      {
        this.configFileLoader = new ConfigFileLoader(configFilePath, serverContext);
        serverContext.debugInfo("Loaded configuration from file: " + configFilePath);
      }
      catch (Exception e)
      {
        throw new RuntimeException("Failed to load configuration file: " + 
            configFilePath + " - " + e.getMessage(), e);
      }
    }

    // Get inline arguments
    StringArgument groupBaseArg = (StringArgument)
        parser.getNamedArgument("group-base");
    StringArgument userLookupAttrArg = (StringArgument)
        parser.getNamedArgument("user-lookup-attribute");

    // Load configuration (inline arguments override config file)
    this.groupBasePath = getConfigValue(groupBaseArg, "scim2.group.base", "/Groups");
    this.userLookupAttribute = getConfigValue(userLookupAttrArg, "user.lookup.attribute", "uid");

    // Load retry and timeout configuration
    this.maxRetries = getConfigValueAsInt(null, "scim2.max.retries", 3);
    this.retryDelayMs = getConfigValueAsInt(null, "scim2.retry.delay.ms", 1000);

    // Validate required configuration
    if (groupBasePath == null || groupBasePath.trim().isEmpty())
    {
      throw new RuntimeException("group-base must be specified either as inline argument " +
          "or in config file (scim2.group.base)");
    }

    try
    {
      // Create SCIM2 client factory and initialize clients
      Scim2ClientFactory clientFactory = createClientFactory();
      this.scimService = clientFactory.createScimService();
      this.jaxrsClient = clientFactory.createJaxrsClient();

      // Get user base path for member helper
      String userBasePath = getConfigValue(null, "scim2.user.base", "/Users");

      // Initialize member helper
      this.memberHelper = new Scim2MemberHelper(
          scimService,
          userBasePath,
          groupBasePath,
          maxRetries,
          retryDelayMs);

      // Log successful initialization
      serverContext.debugInfo("SCIM2 Dynamic Group Destination initialized successfully");
      serverContext.debugInfo("  Group Base: " + groupBasePath);
      serverContext.debugInfo("  User Lookup Attribute: " + userLookupAttribute);
      serverContext.debugInfo("  Max Retries: " + maxRetries);
      serverContext.debugInfo("  Retry Delay: " + retryDelayMs + "ms");
    }
    catch (Exception e)
    {
      throw new RuntimeException("Failed to initialize SCIM2 clients: " + e.getMessage(), e);
    }
  }

  @Override
  public void finalizeSyncDestination()
  {
    if (jaxrsClient != null)
    {
      try
      {
        jaxrsClient.close();
      }
      catch (Exception e)
      {
        serverContext.debugInfo("Error closing JAX-RS client: " + e.getMessage());
      }
    }
  }

  @Override
  public String getCurrentEndpointURL()
  {
    if (configFileLoader != null)
    {
      String baseUrl = configFileLoader.getProperty("scim2.base.url");
      if (baseUrl != null)
      {
        return baseUrl;
      }
    }
    return "not configured";
  }

  @Override
  public List<Entry> fetchEntry(final Entry destEntryMappedFromSrc,
                                final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("fetchEntry called for DN: " + destEntryMappedFromSrc.getDN());

    // Extract group name from cn attribute
    Attribute cnAttr = destEntryMappedFromSrc.getAttribute("cn");
    if (cnAttr == null || cnAttr.getValue() == null)
    {
      operation.logInfo("No group name found in cn attribute");
      return Collections.emptyList();
    }

    String groupName = cnAttr.getValue();
    operation.logInfo("Looking up SCIM2 group: " + groupName);

    // Find SCIM2 group ID
    String scim2GroupId = memberHelper.findScim2GroupId(groupName, operation);
    
    if (scim2GroupId == null)
    {
      operation.logInfo("SCIM2 group not found: " + groupName);
      return Collections.emptyList();
    }

    // Create synthetic entry with group information
    Entry syntheticEntry = new Entry(destEntryMappedFromSrc.getDN());
    syntheticEntry.addAttribute("cn", groupName);
    syntheticEntry.addAttribute("scim2GroupId", scim2GroupId);

    operation.logInfo("Fetched group: " + groupName + " (ID: " + scim2GroupId + ")");
    
    return Arrays.asList(syntheticEntry);
  }

  @Override
  public void createEntry(final Entry entryToCreate,
                         final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("createEntry called for DN: " + entryToCreate.getDN());
    operation.logInfo("Groups must exist in SCIM2 before membership synchronization. " +
                     "Ensure groups are created separately.");
  }

  @Override
  public void modifyEntry(final Entry entryToModify,
                         final List<Modification> modsToApply,
                         final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("modifyEntry called for DN: " + entryToModify.getDN() +
                     " with " + modsToApply.size() + " modifications");

    // Extract group name from cn attribute, or from DN if attribute not present
    String groupName = null;
    Attribute cnAttr = entryToModify.getAttribute("cn");
    if (cnAttr != null && cnAttr.getValue() != null)
    {
      groupName = cnAttr.getValue();
      operation.logInfo("Extracted group name from cn attribute: " + groupName);
    }
    else
    {
      // Parse group name from DN (e.g., cn=dynamic-users,ou=Groups,dc=example,dc=com)
      try
      {
        DN dn = new DN(entryToModify.getDN());
        RDN rdn = dn.getRDN();
        if (rdn != null && rdn.hasAttribute("cn"))
        {
          groupName = rdn.getAttributeValues()[0];
          operation.logInfo("Extracted group name from DN: " + groupName);
        }
      }
      catch (Exception e)
      {
        operation.logInfo("Failed to parse group name from DN: " + e.getMessage());
      }
    }

    if (groupName == null)
    {
      operation.logInfo("No group name found in cn attribute or DN, cannot modify");
      return;
    }

    operation.logInfo("Looking up SCIM2 group ID for: " + groupName);

    // Look up SCIM2 group ID (don't rely on synthetic attribute from fetchEntry)
    String scim2GroupId = memberHelper.findScim2GroupId(groupName, operation);
    
    if (scim2GroupId == null)
    {
      operation.logInfo("SCIM2 group not found: " + groupName + ", cannot modify");
      return;
    }

    operation.logInfo("Processing modifications for group: " + groupName +
                     " (ID: " + scim2GroupId + ")");

    // Find members modification (dynamic groups only provide members attribute from source plugin)
    Modification membersModification = null;
    
    for (Modification mod : modsToApply)
    {
      String attrName = mod.getAttributeName();
      if ("members".equalsIgnoreCase(attrName))
      {
        membersModification = mod;
        break;
      }
    }

    if (membersModification == null)
    {
      operation.logInfo("No members modification found, skipping");
      return;
    }

    ModificationType modType = membersModification.getModificationType();
    String[] memberUserIds = membersModification.getValues();

    operation.logInfo("Modification type: " + modType +
                     ", member count: " + (memberUserIds != null ? memberUserIds.length : 0));

    // Dynamic groups only support REPLACE (full resync)
    if (ModificationType.REPLACE.equals(modType))
    {
      processGroupResync(scim2GroupId, groupName, memberUserIds, operation);
    }
    else
    {
      operation.logInfo("Dynamic groups only support REPLACE operations. " +
                       "Incremental ADD/DELETE not supported for groups with memberURL. " +
                       "Modification type " + modType + " ignored.");
    }
  }

  @Override
  public void deleteEntry(final Entry entryToDelete,
                         final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("deleteEntry called for DN: " + entryToDelete.getDN());
    operation.logInfo("Group deletion is not supported by this plugin. " +
                     "Groups should be managed separately.");
  }

  /**
   * Processes a full group membership resync using PUT operation.
   * Replaces the entire membership list in a single operation.
   * This is the only supported operation for dynamic groups.
   */
  private void processGroupResync(
      final String scim2GroupId,
      final String groupName,
      final String[] memberUserIds,
      final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("Processing group resync for: " + groupName +
                     " with " + (memberUserIds != null ? memberUserIds.length : 0) + " members");

    try
    {
      // Convert user IDs to SCIM2 members
      List<Member> scim2Members = memberHelper.convertUserIdsToScim2Members(
          memberUserIds, operation);

      operation.logInfo("Mapped " + scim2Members.size() + " members to SCIM2 IDs");

      // Fetch group metadata without members (optimize for large groups)
      // Use excludedAttributes to avoid fetching the members array
      String fetchUrl = getConfigValue(null, "scim2.base.url", "") +
                       groupBasePath + "/" + scim2GroupId + 
                       "?excludedAttributes=members";

      Response fetchResponse = jaxrsClient.target(fetchUrl)
          .request("application/scim+json")
          .get();

      int fetchStatus = fetchResponse.getStatus();
      
      if (fetchStatus < 200 || fetchStatus >= 300)
      {
        fetchResponse.close();
        throw new RuntimeException("Failed to fetch group metadata, status: " + fetchStatus);
      }

      String groupJson = fetchResponse.readEntity(String.class);
      fetchResponse.close();

      // Parse the group (without members) and add our new member list
      GroupResource group = SCIM_OBJECT_MAPPER.readValue(groupJson, GroupResource.class);
      group.setMembers(scim2Members);

      // Perform PUT operation
      String updateUrl = getConfigValue(null, "scim2.base.url", "") +
                        groupBasePath + "/" + scim2GroupId;

      String updatedGroupJson = SCIM_OBJECT_MAPPER.writeValueAsString(group);

      Response response = jaxrsClient.target(updateUrl)
          .request("application/scim+json")
          .put(Entity.entity(updatedGroupJson, "application/scim+json"));

      int statusCode = response.getStatus();
      response.close();

      if (statusCode >= 200 && statusCode < 300)
      {
        operation.logInfo("Successfully updated dynamic group " + groupName +
                         " with " + scim2Members.size() + " members");
      }
      else
      {
        throw new RuntimeException("PUT request failed with status: " + statusCode);
      }
    }
    catch (Exception e)
    {
      operation.logInfo("Error during group resync: " + e.getMessage());
      throw new RuntimeException("Failed to resync group " + groupName + ": " + e.getMessage(), e);
    }
  }

  /**
   * Creates a Scim2ClientFactory from configuration.
   */
  private Scim2ClientFactory createClientFactory()
  {
    String baseUrl = getConfigValue(null, "scim2.base.url", null);
    String userBase = getConfigValue(null, "scim2.user.base", "/Users");
    String authType = getConfigValue(null, "scim2.auth.type", "basic");
    String username = getConfigValue(null, "scim2.username", null);
    String password = getConfigValue(null, "scim2.password", null);
    String bearerToken = getConfigValue(null, "scim2.bearer.token", null);
    
    String trustStorePath = getConfigValue(null, "scim2.trust.store.path", null);
    String trustStorePassword = getConfigValue(null, "scim2.trust.store.password", null);
    String trustStoreType = getConfigValue(null, "scim2.trust.store.type", "JKS");
    boolean allowUntrustedCerts = "true".equalsIgnoreCase(
        getConfigValue(null, "scim2.allow.untrusted.certificates", "false"));
    
    String proxyHost = getConfigValue(null, "scim2.proxy.host", null);
    String proxyPort = getConfigValue(null, "scim2.proxy.port", null);
    String proxyUsername = getConfigValue(null, "scim2.proxy.username", null);
    String proxyPassword = getConfigValue(null, "scim2.proxy.password", null);
    String proxyType = getConfigValue(null, "scim2.proxy.type", "HTTP");
    
    int connectTimeout = getConfigValueAsInt(null, "scim2.connect.timeout.ms", 30000);
    int readTimeout = getConfigValueAsInt(null, "scim2.read.timeout.ms", 60000);

    if (baseUrl == null)
    {
      throw new RuntimeException("scim2.base.url must be specified in config file");
    }

    return new Scim2ClientFactory(
        serverContext, configFileLoader,
        baseUrl, userBase, groupBasePath, authType, username, password, bearerToken,
        trustStorePath, trustStorePassword, trustStoreType, allowUntrustedCerts,
        proxyHost, proxyPort, proxyUsername, proxyPassword, proxyType,
        connectTimeout, readTimeout);
  }

  /**
   * Gets a configuration value, with precedence: inline argument > config file > default.
   */
  private String getConfigValue(StringArgument arg, String configKey, String defaultValue)
  {
    // Check inline argument first
    if (arg != null && arg.isPresent())
    {
      return arg.getValue();
    }
    
    // Check config file
    if (configFileLoader != null && configKey != null)
    {
      String value = configFileLoader.getProperty(configKey);
      if (value != null)
      {
        return value;
      }
    }
    
    // Return default
    return defaultValue;
  }

  /**
   * Gets a configuration value as integer.
   */
  private int getConfigValueAsInt(StringArgument arg, String configKey, int defaultValue)
  {
    String strValue = getConfigValue(arg, configKey, null);
    if (strValue != null)
    {
      try
      {
        return Integer.parseInt(strValue);
      }
      catch (NumberFormatException e)
      {
        serverContext.debugInfo("Invalid integer value for " + configKey + ": " + strValue +
                               ", using default: " + defaultValue);
      }
    }
    return defaultValue;
  }
}

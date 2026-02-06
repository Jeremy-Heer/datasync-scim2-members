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
import com.unboundid.scim2.common.types.Name;
import com.unboundid.scim2.common.types.UserResource;
import com.unboundid.scim2.common.utils.JsonUtils;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;

import com.heer.sync.lib.ConfigFileLoader;
import com.heer.sync.lib.scim2.Scim2ClientFactory;
import com.heer.sync.lib.scim2.Scim2MemberHelper;
import com.heer.sync.lib.scim2.Scim2UserCreationHelper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helper class to hold parsed member mapping data
 */
class MemberMappingData
{
  String userId;
  String operationType;
  String dn;
  String jsonData;
  Map<String, String> userAttributes;
  
  public MemberMappingData(String userId, String operationType, String dn, String jsonData)
  {
    this.userId = userId;
    this.operationType = operationType;
    this.dn = dn;
    this.jsonData = jsonData;
    this.userAttributes = new java.util.HashMap<>();
    
    // Parse JSON if present
    if (jsonData != null && !jsonData.trim().isEmpty())
    {
      try
      {
        ObjectMapper mapper = JsonUtils.createObjectMapper();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = mapper.readValue(jsonData, Map.class);
        for (Map.Entry<String, Object> entry : map.entrySet())
        {
          userAttributes.put(entry.getKey(), String.valueOf(entry.getValue()));
        }
      }
      catch (Exception e)
      {
        // JSON parsing failed, leave empty
      }
    }
  }
  
  public boolean hasDeleteFlag()
  {
    return "true".equalsIgnoreCase(userAttributes.get("deleteUser"));
  }
}

/**
 * SCIM2 Static Group Destination plugin for synchronizing static group memberships.
 * 
 * This plugin handles incremental changes to static group memberships and full
 * group resync operations. It supports batching of member additions and deletions
 * to optimize performance when dealing with large membership changes.
 * 
 * Key Features:
 * - Incremental ADD/DELETE operations with batching (configurable threshold)
 * - Full REPLACE operations using PUT (resync mode)
 * - Integration with ConfigFileLoader for configuration management
 * - Retry logic with exponential backoff
 * 
 * Works with StaticGroupSourcePlugin which provides the 'members' attribute
 * containing user IDs (uid values).
 */
public class StaticGroupMemberDestination extends SyncDestination
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
  private Scim2UserCreationHelper userCreationHelper;

  // Configuration parameters
  private String baseUrl;
  private String userBasePath;
  private String groupBasePath;
  private String userLookupAttribute;
  private int staticGroupBatchThreshold;
  private int maxRetries;
  private int retryDelayMs;
  
  // SCIM attribute mappings for user creation
  private String[] scimUserAttributes;
  private Map<String, String> scimUserMappings;

  @Override
  public String getExtensionName()
  {
    return "SCIM2 Static Group Sync Destination";
  }

  @Override
  public String[] getExtensionDescription()
  {
    return new String[]
    {
      "This SCIM2 destination synchronizes static group membership changes to SCIM2 groups.",
      "It processes the 'members' attribute from StaticGroupSourcePlugin, which contains " +
      "user IDs (uid values), and updates the corresponding SCIM2 group by adding or removing users.",
      "The plugin supports both incremental changes (ADD/DELETE with batching) and full resync " +
      "(REPLACE using PUT). Batching optimizes performance for large membership changes."
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

    StringArgument batchThresholdArg = new StringArgument(
        null, "static-group-batch-threshold", false, 1, "{count}",
        "Number of member add/remove operations to batch into a single PATCH request. " +
        "If the number of operations exceeds this threshold, multiple PATCH requests " +
        "will be sent. This does not apply to REPLACE operations (resync), which always " +
        "use a single PUT request. Can be set via config file property: " +
        "static.group.batch.threshold (default: 50)");

    parser.addArgument(configFileArg);
    parser.addArgument(groupBaseArg);
    parser.addArgument(userLookupAttrArg);
    parser.addArgument(batchThresholdArg);
  }

  @Override
  public Map<List<String>, String> getExamplesArgumentSets()
  {
    final LinkedHashMap<List<String>, String> exampleMap =
        new LinkedHashMap<List<String>, String>();

    exampleMap.put(
        Arrays.asList("config-file=/opt/sync/config/scim-sync.properties",
                     "group-base=/Groups"),
        "Synchronize static group memberships using configuration file for " +
        "SCIM2 connection settings (base URL, authentication, etc.)");

    exampleMap.put(
        Arrays.asList("config-file=/opt/sync/config/scim-sync.properties",
                     "group-base=/Groups",
                     "user-lookup-attribute=uid",
                     "static-group-batch-threshold=50"),
        "Synchronize with explicit user lookup attribute and batch threshold. " +
        "Member additions/deletions will be batched in groups of 50 per PATCH request.");

    exampleMap.put(
        Arrays.asList("config-file=/opt/sync/config/scim-sync.properties",
                     "group-base=/Groups",
                     "static-group-batch-threshold=100"),
        "Use larger batch size for environments with high-performance SCIM2 endpoints " +
        "that can handle more operations per request.");

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
    StringArgument batchThresholdArg = (StringArgument)
        parser.getNamedArgument("static-group-batch-threshold");

    // Load configuration (inline arguments override config file)
    this.groupBasePath = getConfigValue(groupBaseArg, "scim2.group.base", "/Groups");
    this.userLookupAttribute = getConfigValue(userLookupAttrArg, "user.lookup.attribute", "uid");
    this.staticGroupBatchThreshold = getConfigValueAsInt(batchThresholdArg, 
        "static.group.batch.threshold", 50);

    // Load retry and timeout configuration
    this.maxRetries = getConfigValueAsInt(null, "scim2.max.retries", 3);
    this.retryDelayMs = getConfigValueAsInt(null, "scim2.retry.delay.ms", 1000);
    
    // Load SCIM user attribute mappings for user creation
    if (configFileLoader != null) {
      this.scimUserAttributes = configFileLoader.getPropertyList("scim.user.attributes");
      this.scimUserMappings = configFileLoader.getPropertyMap("scim.user.map.");
      serverContext.debugInfo("Loaded " + scimUserAttributes.length + 
                             " SCIM user attributes and " + scimUserMappings.size() + " mappings");
    } else {
      this.scimUserAttributes = new String[0];
      this.scimUserMappings = new java.util.HashMap<String, String>();
    }

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

      // Get base URL and user base path
      this.baseUrl = getConfigValue(null, "scim2.base.url", "");
      this.userBasePath = getConfigValue(null, "scim2.user.base", "/Users");

      // Initialize member helper
      this.memberHelper = new Scim2MemberHelper(
          scimService,
          userBasePath,
          groupBasePath,
          maxRetries,
          retryDelayMs);
      
      // Initialize user creation helper
      this.userCreationHelper = new Scim2UserCreationHelper(scimService, userBasePath);

      // Log successful initialization
      serverContext.debugInfo("SCIM2 Static Group Destination initialized successfully");
      serverContext.debugInfo("  Group Base: " + groupBasePath);
      serverContext.debugInfo("  User Lookup Attribute: " + userLookupAttribute);
      serverContext.debugInfo("  Batch Threshold: " + staticGroupBatchThreshold);
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
    
    // Create synthetic entry with group information
    // Even if group doesn't exist yet (scim2GroupId is null), we return an entry
    // so that the sync framework will call modifyEntry where we can process memberMappings
    Entry syntheticEntry = new Entry(destEntryMappedFromSrc.getDN());
    syntheticEntry.addAttribute("cn", groupName);
    
    if (scim2GroupId != null)
    {
      syntheticEntry.addAttribute("scim2GroupId", scim2GroupId);
      operation.logInfo("Fetched group: " + groupName + " (ID: " + scim2GroupId + ")");
    }
    else
    {
      operation.logInfo("SCIM2 group not found: " + groupName + " - will attempt lookup during modify");
    }
    
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
      // Parse group name from DN (e.g., cn=admins,ou=Groups,dc=example,dc=com)
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

    // Debug: Log all modifications
    operation.logInfo("DEBUG: modsToApply has " + modsToApply.size() + " modifications");
    for (Modification mod : modsToApply)
    {
      String[] values = mod.getValues();
      operation.logInfo("DEBUG: Modification: " + mod.getModificationType() + " " + 
                       mod.getAttributeName() + " = " + 
                       (values != null ? values.length + " values" : "no values"));
    }

    // Enhanced: Retrieve memberMappings which now contains operation type
    // Format: userId::operationType::DN
    String[] memberMappings = null;
    
    // Look for memberMappings modification in modsToApply (added by source plugin)
    for (Modification mod : modsToApply)
    {
      if ("memberMappings".equalsIgnoreCase(mod.getAttributeName()))
      {
        memberMappings = mod.getValues();
        operation.logInfo("Found memberMappings modification with " + 
                         (memberMappings != null ? memberMappings.length : 0) + " mappings");
        break;
      }
    }
    
    if (memberMappings != null && memberMappings.length > 0)
    {
      // Parse mappings and group by operation type
      // Enhanced format supports JSON: userId::operationType::DN::{"attr1":"val1","deleteUser":"true"}
      Map<String, List<MemberMappingData>> operationGroups = new java.util.HashMap<>();
      operationGroups.put("ADD", new ArrayList<>());
      operationGroups.put("DELETE", new ArrayList<>());
      operationGroups.put("REPLACE", new ArrayList<>());
      
      for (String mapping : memberMappings)
      {
        // Parse format: userId::operationType::DN or userId::operationType::DN::{JSON}
        String[] parts = mapping.split("::", 4);
        if (parts.length >= 3)
        {
          String userId = parts[0];
          String operationType = parts[1];
          String dn = parts[2];
          String jsonData = parts.length > 3 ? parts[3] : null;
          
          MemberMappingData data = new MemberMappingData(userId, operationType, dn, jsonData);
          
          if (operationGroups.containsKey(operationType))
          {
            operationGroups.get(operationType).add(data);
            operation.logInfo("Parsed mapping: userId=" + userId + ", operation=" + operationType + 
                            ", dn=" + dn + ", hasJson=" + (jsonData != null));
          }
          else
          {
            operation.logInfo("WARNING: Unknown operation type '" + operationType + "' in mapping: " + mapping);
          }
        }
        else
        {
          operation.logInfo("WARNING: Invalid mapping format (expected at least 3 parts): " + mapping);
        }
      }
      
      // Process each operation type
      if (!operationGroups.get("ADD").isEmpty())
      {
        List<MemberMappingData> mappings = operationGroups.get("ADD");
        operation.logInfo("Processing ADD operation with " + mappings.size() + " members");
        processGroupMemberAdditionsEnhanced(scim2GroupId, groupName, mappings, operation);
      }
      
      if (!operationGroups.get("DELETE").isEmpty())
      {
        List<MemberMappingData> mappings = operationGroups.get("DELETE");
        operation.logInfo("Processing DELETE operation with " + mappings.size() + " members");
        processGroupMemberDeletionsEnhanced(scim2GroupId, groupName, mappings, operation);
      }
      
      if (!operationGroups.get("REPLACE").isEmpty())
      {
        List<MemberMappingData> mappings = operationGroups.get("REPLACE");
        operation.logInfo("Processing REPLACE operation with " + mappings.size() + " members (full resync)");
        processGroupResyncEnhanced(scim2GroupId, groupName, mappings, operation);
      }
      
      return;  // Done processing static group with enhanced memberMappings
    }
    
    // Fallback: Process modifications from the modsToApply list
    // This handles cases where StaticGroupSourcePlugin isn't used (e.g., dynamic groups)
    operation.logInfo("No memberMappings found - checking for dynamic group member modifications");

    // Find members, member, or uniqueMember modification
    Modification membersModification = null;
    boolean needsLookup = false;
    
    for (Modification mod : modsToApply)
    {
      String attrName = mod.getAttributeName();
      if ("members".equalsIgnoreCase(attrName))
      {
        membersModification = mod;
        needsLookup = false;  // Already has user IDs
        break;
      }
      else if ("member".equalsIgnoreCase(attrName) || "uniqueMember".equalsIgnoreCase(attrName))
      {
        membersModification = mod;
        needsLookup = true;  // Contains DNs, need to extract user IDs
        break;
      }
    }

    if (membersModification == null)
    {
      operation.logInfo("No members/member/uniqueMember modification found, skipping");
      return;
    }

    ModificationType fallbackModType = membersModification.getModificationType();
    String[] memberValues = membersModification.getValues();
    String[] memberUserIds = null;

    // If we have member/uniqueMember DNs, extract user IDs from them
    if (needsLookup && memberValues != null && memberValues.length > 0)
    {
      operation.logInfo("Extracting user IDs from " + memberValues.length + " member DNs");
      List<String> userIds = new ArrayList<String>();
      
      for (String memberDN : memberValues)
      {
        // Extract uid from DN like "uid=user123,ou=Users,dc=example,dc=com"
        try
        {
          DN dn = new DN(memberDN);
          RDN rdn = dn.getRDN();
          if (rdn != null && rdn.hasAttribute(userLookupAttribute))
          {
            String userId = rdn.getAttributeValues()[0];
            userIds.add(userId);
            operation.logInfo("Extracted user ID '" + userId + "' from DN: " + memberDN);
          }
          else
          {
            operation.logInfo("Could not extract " + userLookupAttribute + 
                            " from member DN: " + memberDN);
          }
        }
        catch (Exception e)
        {
          operation.logInfo("Error parsing member DN '" + memberDN + "': " + e.getMessage());
        }
      }
      
      memberUserIds = userIds.toArray(new String[0]);
    }
    else
    {
      memberUserIds = memberValues;
    }

    operation.logInfo("Modification type: " + fallbackModType +
                     ", member count: " + (memberUserIds != null ? memberUserIds.length : 0));

    // Route to appropriate handler based on modification type
    if (ModificationType.REPLACE.equals(fallbackModType))
    {
      // Resync mode: use PUT to replace entire membership
      processGroupResync(scim2GroupId, groupName, memberUserIds, operation);
    }
    else if (ModificationType.ADD.equals(fallbackModType))
    {
      // Incremental mode: add members with batching
      processGroupMemberAdditions(scim2GroupId, groupName, memberUserIds, operation);
    }
    else if (ModificationType.DELETE.equals(fallbackModType))
    {
      // Incremental mode: remove members with batching
      processGroupMemberDeletions(scim2GroupId, groupName, memberUserIds, operation);
    }
    else
    {
      operation.logInfo("Unsupported modification type: " + fallbackModType);
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
        operation.logInfo("Successfully updated group " + groupName +
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
   * Processes member additions with batching support.
   * If the number of additions exceeds the batch threshold, multiple PATCH requests are sent.
   */
  private void processGroupMemberAdditions(
      final String scim2GroupId,
      final String groupName,
      final String[] memberUserIds,
      final SyncOperation operation)
      throws EndpointException
  {
    if (memberUserIds == null || memberUserIds.length == 0)
    {
      operation.logInfo("No members to add");
      return;
    }

    operation.logInfo("Processing " + memberUserIds.length + " member additions for: " + groupName);

    // Convert user IDs to SCIM2 members
    List<Member> scim2Members = memberHelper.convertUserIdsToScim2Members(
        memberUserIds, operation);

    if (scim2Members.isEmpty())
    {
      operation.logInfo("No valid SCIM2 members found to add");
      return;
    }

    // Process in batches
    int totalMembers = scim2Members.size();
    int batchCount = (int) Math.ceil((double) totalMembers / staticGroupBatchThreshold);

    operation.logInfo("Adding " + totalMembers + " members in " + batchCount + " batch(es)");

    for (int i = 0; i < batchCount; i++)
    {
      int startIdx = i * staticGroupBatchThreshold;
      int endIdx = Math.min(startIdx + staticGroupBatchThreshold, totalMembers);
      List<Member> batchMembers = scim2Members.subList(startIdx, endIdx);

      operation.logInfo("Processing batch " + (i + 1) + "/" + batchCount +
                       " (" + batchMembers.size() + " members)");

      sendPatchAddMembers(scim2GroupId, groupName, batchMembers, operation);
    }

    operation.logInfo("Successfully added " + totalMembers + " members to group: " + groupName);
  }

  /**
   * Processes member deletions with batching support.
   * If the number of deletions exceeds the batch threshold, multiple PATCH requests are sent.
   */
  private void processGroupMemberDeletions(
      final String scim2GroupId,
      final String groupName,
      final String[] memberUserIds,
      final SyncOperation operation)
      throws EndpointException
  {
    if (memberUserIds == null || memberUserIds.length == 0)
    {
      operation.logInfo("No members to remove");
      return;
    }

    operation.logInfo("Processing " + memberUserIds.length + " member deletions for: " + groupName);

    // Convert user IDs to SCIM2 members
    List<Member> scim2Members = memberHelper.convertUserIdsToScim2Members(
        memberUserIds, operation);

    if (scim2Members.isEmpty())
    {
      operation.logInfo("No valid SCIM2 members found to remove");
      return;
    }

    // Process in batches
    int totalMembers = scim2Members.size();
    int batchCount = (int) Math.ceil((double) totalMembers / staticGroupBatchThreshold);

    operation.logInfo("Removing " + totalMembers + " members in " + batchCount + " batch(es)");

    for (int i = 0; i < batchCount; i++)
    {
      int startIdx = i * staticGroupBatchThreshold;
      int endIdx = Math.min(startIdx + staticGroupBatchThreshold, totalMembers);
      List<Member> batchMembers = scim2Members.subList(startIdx, endIdx);

      operation.logInfo("Processing batch " + (i + 1) + "/" + batchCount +
                       " (" + batchMembers.size() + " members)");

      sendPatchRemoveMembers(scim2GroupId, groupName, batchMembers, operation);
    }

    operation.logInfo("Successfully removed " + totalMembers + " members from group: " + groupName);
  }

  /**
   * Sends a PATCH request to add members to a group.
   */
  private void sendPatchAddMembers(
      final String scim2GroupId,
      final String groupName,
      final List<Member> members,
      final SyncOperation operation)
      throws EndpointException
  {
    try
    {
      // Build PATCH request JSON
      ObjectNode patchOp = SCIM_OBJECT_MAPPER.createObjectNode();
      ArrayNode operations = SCIM_OBJECT_MAPPER.createArrayNode();

      ObjectNode addOp = SCIM_OBJECT_MAPPER.createObjectNode();
      addOp.put("op", "add");
      addOp.put("path", "members");

      ArrayNode valueArray = SCIM_OBJECT_MAPPER.createArrayNode();
      for (Member member : members)
      {
        ObjectNode memberNode = SCIM_OBJECT_MAPPER.createObjectNode();
        memberNode.put("value", member.getValue());
        if (member.getRef() != null)
        {
          memberNode.put("$ref", member.getRef().toString());
        }
        valueArray.add(memberNode);
      }
      addOp.set("value", valueArray);
      operations.add(addOp);

      patchOp.set("Operations", operations);

      // Send PATCH request
      String patchUrl = getConfigValue(null, "scim2.base.url", "") +
                       groupBasePath + "/" + scim2GroupId;

      String patchJson = SCIM_OBJECT_MAPPER.writeValueAsString(patchOp);

      Response response = jaxrsClient.target(patchUrl)
          .request("application/scim+json")
          .method("PATCH", Entity.entity(patchJson, "application/scim+json"));

      int statusCode = response.getStatus();
      response.close();

      if (statusCode >= 200 && statusCode < 300)
      {
        operation.logInfo("Successfully added " + members.size() + " members");
      }
      else
      {
        throw new RuntimeException("PATCH add failed with status: " + statusCode);
      }
    }
    catch (Exception e)
    {
      operation.logInfo("Error adding members: " + e.getMessage());
      throw new RuntimeException("Failed to add members to group " + groupName + ": " + e.getMessage(), e);
    }
  }

  /**
   * Sends a PATCH request to remove members from a group.
   */
  private void sendPatchRemoveMembers(
      final String scim2GroupId,
      final String groupName,
      final List<Member> members,
      final SyncOperation operation)
      throws EndpointException
  {
    try
    {
      // Build PATCH request JSON
      ObjectNode patchOp = SCIM_OBJECT_MAPPER.createObjectNode();
      ArrayNode operations = SCIM_OBJECT_MAPPER.createArrayNode();

      for (Member member : members)
      {
        ObjectNode removeOp = SCIM_OBJECT_MAPPER.createObjectNode();
        removeOp.put("op", "remove");
        removeOp.put("path", "members[value eq \"" + member.getValue() + "\"]");
        operations.add(removeOp);
      }

      patchOp.set("Operations", operations);

      // Send PATCH request
      String patchUrl = getConfigValue(null, "scim2.base.url", "") +
                       groupBasePath + "/" + scim2GroupId;

      String patchJson = SCIM_OBJECT_MAPPER.writeValueAsString(patchOp);

      Response response = jaxrsClient.target(patchUrl)
          .request("application/scim+json")
          .method("PATCH", Entity.entity(patchJson, "application/scim+json"));

      int statusCode = response.getStatus();
      response.close();

      if (statusCode >= 200 && statusCode < 300)
      {
        operation.logInfo("Successfully removed " + members.size() + " members");
      }
      else
      {
        throw new RuntimeException("PATCH remove failed with status: " + statusCode);
      }
    }
    catch (Exception e)
    {
      operation.logInfo("Error removing members: " + e.getMessage());
      throw new RuntimeException("Failed to remove members from group " + groupName + ": " + e.getMessage(), e);
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

  // ===== ENHANCED METHODS WITH USER CREATION/DELETION SUPPORT =====
  
  /**
   * Enhanced version that handles user creation when 404 occurs.
   */
  private void processGroupMemberAdditionsEnhanced(
      final String scim2GroupId,
      final String groupName,
      final List<MemberMappingData> mappings,
      final SyncOperation operation)
      throws EndpointException
  {
    if (mappings == null || mappings.isEmpty())
    {
      operation.logInfo("No members to add");
      return;
    }

    operation.logInfo("Processing " + mappings.size() + " enhanced member additions for: " + groupName);

    // Convert to SCIM2 members, creating users as needed
    List<Member> scim2Members = new ArrayList<>();
    
    for (MemberMappingData mapping : mappings)
    {
      String userId = mapping.userId;
      
      // Try to resolve user
      String scim2UserId = memberHelper.findScim2UserId(userId, operation);
      
      if (scim2UserId == null && mapping.userAttributes != null && !mapping.userAttributes.isEmpty())
      {
        // User not found, try to create it
        operation.logInfo("User " + userId + " not found, attempting to create from JSON data");
        
        boolean created = userCreationHelper.createUserFromAttributes(userId, mapping.userAttributes, operation);
        if (created)
        {
          // Retry resolution after creation
          scim2UserId = memberHelper.findScim2UserId(userId, operation);
        }
      }
      
      if (scim2UserId != null)
      {
        Member member = new Member();
        member.setValue(scim2UserId);
        try {
          member.setRef(new java.net.URI(userBasePath + "/" + scim2UserId));
        } catch (java.net.URISyntaxException e) {
          // Continue without $ref
        }
        scim2Members.add(member);
      }
      else
      {
        operation.logInfo("WARNING: Skipping user " + userId + " - could not resolve or create");
      }
    }

    if (scim2Members.isEmpty())
    {
      operation.logInfo("No valid SCIM2 members found to add");
      return;
    }

    // Process in batches
    int totalMembers = scim2Members.size();
    int batchCount = (int) Math.ceil((double) totalMembers / staticGroupBatchThreshold);

    operation.logInfo("Adding " + totalMembers + " members in " + batchCount + " batch(es)");

    for (int i = 0; i < batchCount; i++)
    {
      int startIdx = i * staticGroupBatchThreshold;
      int endIdx = Math.min(startIdx + staticGroupBatchThreshold, totalMembers);
      List<Member> batchMembers = scim2Members.subList(startIdx, endIdx);

      operation.logInfo("Processing batch " + (i + 1) + "/" + batchCount +
                       " (" + batchMembers.size() + " members)");

      sendPatchAddMembers(scim2GroupId, groupName, batchMembers, operation);
    }

    operation.logInfo("Successfully added " + totalMembers + " members to group: " + groupName);
  }

  /**
   * Enhanced version that handles user deletion when deleteUser flag is set.
   */
  private void processGroupMemberDeletionsEnhanced(
      final String scim2GroupId,
      final String groupName,
      final List<MemberMappingData> mappings,
      final SyncOperation operation)
      throws EndpointException
  {
    if (mappings == null || mappings.isEmpty())
    {
      operation.logInfo("No members to remove");
      return;
    }

    operation.logInfo("Processing " + mappings.size() + " enhanced member deletions for: " + groupName);

    // Convert to SCIM2 members
    List<Member> scim2Members = new ArrayList<>();
    List<String> usersToDelete = new ArrayList<>();
    
    for (MemberMappingData mapping : mappings)
    {
      String scim2UserId = memberHelper.findScim2UserId(mapping.userId, operation);
      
      if (scim2UserId != null)
      {
        Member member = new Member();
        member.setValue(scim2UserId);
        try {
          member.setRef(new java.net.URI(userBasePath + "/" + scim2UserId));
        } catch (java.net.URISyntaxException e) {
          // Continue without $ref
        }
        scim2Members.add(member);
        
        // Check if user should be deleted after removal
        if (mapping.hasDeleteFlag())
        {
          usersToDelete.add(mapping.userId);
          operation.logInfo("User " + mapping.userId + " marked for deletion after group removal");
        }
      }
      else
      {
        operation.logInfo("WARNING: User " + mapping.userId + " not found in SCIM2, skipping removal");
      }
    }

    if (scim2Members.isEmpty())
    {
      operation.logInfo("No valid SCIM2 members found to remove");
      return;
    }

    // Process in batches
    int totalMembers = scim2Members.size();
    int batchCount = (int) Math.ceil((double) totalMembers / staticGroupBatchThreshold);

    operation.logInfo("Removing " + totalMembers + " members in " + batchCount + " batch(es)");

    for (int i = 0; i < batchCount; i++)
    {
      int startIdx = i * staticGroupBatchThreshold;
      int endIdx = Math.min(startIdx + staticGroupBatchThreshold, totalMembers);
      List<Member> batchMembers = scim2Members.subList(startIdx, endIdx);

      operation.logInfo("Processing batch " + (i + 1) + "/" + batchCount +
                       " (" + batchMembers.size() + " members)");

      sendPatchRemoveMembers(scim2GroupId, groupName, batchMembers, operation);
    }

    operation.logInfo("Successfully removed " + totalMembers + " members from group: " + groupName);
    
    // Delete users if flagged
    for (String userId : usersToDelete)
    {
      deleteUserById(userId, operation);
    }
  }

  /**
   * Enhanced version that handles full resync with user creation.
   */
  private void processGroupResyncEnhanced(
      final String scim2GroupId,
      final String groupName,
      final List<MemberMappingData> mappings,
      final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("Processing full resync (REPLACE) for group: " + groupName);

    // Convert to user IDs array, creating users as needed
    List<String> validUserIds = new ArrayList<>();
    
    for (MemberMappingData mapping : mappings)
    {
      String userId = mapping.userId;
      
      // Try to resolve user
      String scim2UserId = memberHelper.findScim2UserId(userId, operation);
      
      if (scim2UserId == null && mapping.userAttributes != null && !mapping.userAttributes.isEmpty())
      {
        // User not found, try to create it
        operation.logInfo("User " + userId + " not found, attempting to create from JSON data");
        
        boolean created = userCreationHelper.createUserFromAttributes(userId, mapping.userAttributes, operation);
        if (created)
        {
          // Retry resolution after creation
          scim2UserId = memberHelper.findScim2UserId(userId, operation);
        }
      }
      
      if (scim2UserId != null)
      {
        validUserIds.add(userId);
      }
      else
      {
        operation.logInfo("WARNING: Skipping user " + userId + " - could not resolve or create");
      }
    }

    operation.logInfo("Resyncing group with " + validUserIds.size() + " members");

    // Use existing processGroupResync method
    processGroupResync(scim2GroupId, groupName, 
        validUserIds.toArray(new String[0]), operation);
  }

  /**
   * Deletes a user by userId.
   */
  private void deleteUserById(String userId, SyncOperation operation)
  {
    try
    {
      operation.logInfo("Deleting user: " + userId);
      
      // Resolve to SCIM2 ID
      String scim2Id = memberHelper.findScim2UserId(userId, operation);
      
      if (scim2Id == null)
      {
        operation.logInfo("WARNING: User " + userId + " not found in SCIM2, skipping deletion");
        return;
      }
      
      // Delete via SCIM2 API using URI
      java.net.URI deleteUri = new java.net.URI(baseUrl + userBasePath + "/" + scim2Id);
      scimService.delete(deleteUri);
      
      operation.logInfo("Successfully deleted user: " + userId + " (SCIM2 ID: " + scim2Id + ")");
    }
    catch (Exception e)
    {
      operation.logInfo("ERROR: Failed to delete user " + userId + ": " + e.getMessage());
    }
  }

  /**
   * Gets a configuration value, with precedence: inline argument > config file > default.
   */
  private String getConfigValue(StringArgument arg, String configKey, String defaultValue)
  {
    return configFileLoader.getValueWithFallback(arg, configKey, defaultValue);
  }

  /**
   * Gets a configuration value as integer.
   */
  private int getConfigValueAsInt(StringArgument arg, String configKey, int defaultValue)
  {
    // Check argument first
    if (arg != null && arg.isPresent())
    {
      try {
        return Integer.parseInt(arg.getValue());
      } catch (NumberFormatException e) {
        serverContext.debugInfo("Invalid integer value for argument: " + arg.getValue());
      }
    }
    
    // Use ConfigFileLoader's getIntProperty
    return configFileLoader != null ? configFileLoader.getIntProperty(configKey, defaultValue) : defaultValue;
  }
}

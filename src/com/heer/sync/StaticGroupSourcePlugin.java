/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at
 * docs/licenses/cddl.txt
 * or http://www.opensource.org/licenses/cddl1.php.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at
 * docs/licenses/cddl.txt.  If applicable,
 * add the following below this CDDL HEADER, with the fields enclosed
 * by brackets "[]" replaced with your own identifying information:
 *      Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 *
 *      Portions Copyright 2010-2025 Ping Identity Corporation
 */
package com.heer.sync;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import com.heer.sync.lib.ConfigFileLoader;
import com.heer.sync.lib.ConfigLockManager;
import com.heer.sync.lib.GroupTypeDetector;
import com.heer.sync.lib.LoggingHelper;
import com.heer.sync.lib.UserIdLookupUtil;
import com.unboundid.directory.sdk.sync.api.LDAPSyncSourcePlugin;
import com.unboundid.directory.sdk.sync.config.LDAPSyncSourcePluginConfig;
import com.unboundid.directory.sdk.sync.types.PostStepResult;
import com.unboundid.directory.sdk.sync.types.PreStepResult;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeLogEntry;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;

/**
 * LDAP sync source plugin for handling static group resync operations.
 * Processes groups with member or uniqueMember attributes, looks up each
 * member DN to retrieve the user ID, and constructs a members attribute
 * for synchronization to SCIM2 destination.
 * 
 * <p>This plugin is part of the refactored architecture that separates
 * static and dynamic group processing into focused, single-purpose plugins.
 * It works in conjunction with a destination plugin that processes the
 * synthetic members attribute.
 * 
 * <p>Configuration can be provided via a shared configuration file or
 * inline arguments. Inline arguments override file-based configuration.
 * 
 * <p><strong>IMPORTANT:</strong> This plugin requires Standard Sync Mode.
 * Configure your sync pipe with: {@code --set sync-mode:standard}
 * 
 * <p>Configuration arguments:
 * <UL>
 *   <LI>config-file -- (Optional) Path to shared Java properties file containing
 *                      common configuration. Properties: user.id.attribute, group.filter</LI>
 *   <LI>user-id-attribute -- The LDAP attribute on user entries containing the
 *                            unique user ID (e.g., uid, sAMAccountName). Required if
 *                            config-file is not provided or doesn't contain this property.</LI>
 *   <LI>group-filter -- (Optional) LDAP filter to determine which static groups should
 *                       have their membership expanded. If not specified, all static
 *                       groups will be processed.</LI>
 * </UL>
 */
public class StaticGroupSourcePlugin extends LDAPSyncSourcePlugin
{
  private static final String ARG_NAME_CONFIG_FILE = "config-file";
  private static final String ARG_NAME_USER_ID_ATTRIBUTE = "user-id-attribute";
  private static final String ARG_NAME_GROUP_FILTER = "group-filter";
  
  private static final String PROP_USER_ID_ATTRIBUTE = "user.id.attribute";
  private static final String PROP_GROUP_FILTER = "group.filter";
  private static final String PROP_USER_LIFECYCLE_MODE = "user.lifecycle.mode";
  private static final String PROP_SCIM_USER_ATTRIBUTES = "scim.user.attributes";
  private static final String PROP_SCIM_USER_MAP_PREFIX = "scim.user.map.";
  
  // The server context for the server in which this extension is running
  private SyncServerContext serverContext;
  
  // Configuration lock manager for thread-safe config updates
  private final ConfigLockManager lockManager = new ConfigLockManager();
  
  // Configuration file loader (may be null if using inline config)
  private ConfigFileLoader configFileLoader;
  
  // The LDAP attribute on user entries containing the unique user ID
  private String userIdAttribute;
  
  // Optional LDAP filter to determine which groups should have membership expanded
  private Filter groupFilter;
  
  // User lifecycle mode (static-group-memberships or dynamic-group-memberships)
  private String userLifecycleMode;
  
  // SCIM user attributes to map from LDAP
  private String[] scimUserAttributes;
  
  // SCIM user attribute mappings (SCIM attr -> LDAP attr)
  private Map<String, String> scimUserMappings;

  @Override
  public String getExtensionName()
  {
    return "SCIM2 Static Group Sync Source Plugin";
  }

  @Override
  public String[] getExtensionDescription()
  {
    return new String[]
    {
      "This LDAP sync source plugin handles static group resync operations. It processes " +
      "groups with member or uniqueMember attributes (groupOfNames, groupOfUniqueNames), " +
      "looks up each member DN to retrieve the user ID, and constructs a members attribute " +
      "containing all member user IDs.",
      
      "This plugin is part of a refactored architecture that separates static and dynamic " +
      "group processing. It focuses solely on static groups, making it simpler, more testable, " +
      "and easier to maintain than the monolithic approach.",
      
      "Configuration can be provided via a shared properties file (config-file argument) or " +
      "inline arguments. Inline arguments override file-based configuration. This enables " +
      "sharing configuration across multiple plugins while allowing per-plugin customization.",
      
      "IMPORTANT: This plugin requires Standard Sync Mode. Configure your sync pipe with: " +
      "--set sync-mode:standard"
    };
  }

  @Override
  public void defineConfigArguments(final ArgumentParser parser)
      throws ArgumentException
  {
    // Add argument for optional configuration file
    StringArgument configFileArg = new StringArgument(
        null,
        ARG_NAME_CONFIG_FILE,
        false,
        1,
        "{path}",
        "Path to shared Java properties file containing common configuration. " +
        "Properties: user.id.attribute (required), group.filter (optional). " +
        "Inline arguments override file-based configuration. " +
        "Example: /opt/sync/config/scim-sync.properties");
    parser.addArgument(configFileArg);
    
    // Add argument for user ID attribute
    StringArgument userIdArg = new StringArgument(
        null,
        ARG_NAME_USER_ID_ATTRIBUTE,
        false,
        1,
        "{attr}",
        "The name of the LDAP attribute on user entries that contains the unique user ID " +
        "(e.g., uid, sAMAccountName). This value will be extracted from each member user " +
        "and added to the members attribute. Required if config-file is not provided or " +
        "doesn't contain user.id.attribute property. Overrides file-based configuration.");
    userIdArg.setValueRegex(Pattern.compile("^[a-zA-Z][a-zA-Z0-9\\-]*$"),
                            "A valid attribute name is required.");
    parser.addArgument(userIdArg);
    
    // Add argument for optional group filter
    StringArgument groupFilterArg = new StringArgument(
        null,
        ARG_NAME_GROUP_FILTER,
        false,
        1,
        "{filter}",
        "An optional LDAP filter to determine which static groups should have their " +
        "membership expanded. If not specified, all groups with member or uniqueMember " +
        "attributes will be processed. Examples: '(cn=scim-*)' to process only groups " +
        "starting with 'scim-', or '(description=*sync*)' to process groups with 'sync' " +
        "in their description. Overrides file-based configuration.");
    parser.addArgument(groupFilterArg);
  }

  @Override
  public void initializeLDAPSyncSourcePlugin(
      final SyncServerContext serverContext,
      final LDAPSyncSourcePluginConfig config,
      final ArgumentParser parser)
      throws LDAPException
  {
    this.serverContext = serverContext;
    setConfig(config, parser);
    
    LoggingHelper.logInfo(null, LoggingHelper.formatConfigLoadMessage(
        getExtensionName(), 
        configFileLoader != null ? configFileLoader.getConfigFilePath() : null));
  }

  @Override
  public boolean isConfigurationAcceptable(
      final LDAPSyncSourcePluginConfig config,
      final ArgumentParser parser,
      final List<String> unacceptableReasons)
  {
    // Try to load configuration to validate
    String configFilePath = ((StringArgument)parser.getNamedArgument(
        ARG_NAME_CONFIG_FILE)).getValue();
    String inlineUserId = ((StringArgument)parser.getNamedArgument(
        ARG_NAME_USER_ID_ATTRIBUTE)).getValue();
    
    // Must have user-id-attribute from file or inline
    if (configFilePath == null && inlineUserId == null)
    {
      unacceptableReasons.add("Must provide either config-file with user.id.attribute " +
                              "property or user-id-attribute argument");
      return false;
    }
    
    // If config file is specified, verify it exists and can be read
    if (configFilePath != null)
    {
      try
      {
        ConfigFileLoader testLoader = new ConfigFileLoader(configFilePath, serverContext);
        
        // If inline user ID not provided, must be in file
        if (inlineUserId == null && !testLoader.hasProperty(PROP_USER_ID_ATTRIBUTE))
        {
          unacceptableReasons.add("Configuration file " + configFilePath + 
                                  " does not contain required property: " + 
                                  PROP_USER_ID_ATTRIBUTE);
          return false;
        }
      }
      catch (IOException e)
      {
        unacceptableReasons.add("Cannot read configuration file: " + e.getMessage());
        return false;
      }
    }
    
    return true;
  }

  @Override
  public ResultCode applyConfiguration(
      final LDAPSyncSourcePluginConfig config,
      final ArgumentParser parser,
      final List<String> adminActionsRequired,
      final List<String> messages)
  {
    setConfig(config, parser);
    
    // Reload config file if it exists (supports credential updates)
    if (configFileLoader != null)
    {
      try
      {
        configFileLoader.reload();
        messages.add("Configuration reloaded from file: " + 
                    configFileLoader.getConfigFilePath());
      }
      catch (IOException e)
      {
        messages.add("Warning: Could not reload configuration file: " + e.getMessage());
      }
    }
    
    return ResultCode.SUCCESS;
  }

  /**
   * Sets the configuration for this plugin, merging file-based and inline configuration.
   * Inline arguments override file-based configuration.
   */
  private void setConfig(final LDAPSyncSourcePluginConfig config,
                         final ArgumentParser parser)
  {
    lockManager.writeLock().lock();
    try
    {
      // Load configuration file if specified
      StringArgument configFileArg = (StringArgument)parser.getNamedArgument(
          ARG_NAME_CONFIG_FILE);
      
      if (configFileArg != null && configFileArg.isPresent())
      {
        String configFilePath = configFileArg.getValue();
        try
        {
          this.configFileLoader = new ConfigFileLoader(configFilePath, serverContext);
          LoggingHelper.logDebug(serverContext, 
              "Loaded configuration file: " + configFilePath);
        }
        catch (IOException e)
        {
          LoggingHelper.logWarning(serverContext, 
              "Could not load configuration file: " + e.getMessage());
          this.configFileLoader = null;
        }
      }
      else
      {
        this.configFileLoader = null;
      }
      
      // Get user ID attribute (inline overrides file)
      StringArgument userIdArg = (StringArgument)parser.getNamedArgument(
          ARG_NAME_USER_ID_ATTRIBUTE);
      
      if (userIdArg != null && userIdArg.isPresent())
      {
        this.userIdAttribute = userIdArg.getValue();
      }
      else if (configFileLoader != null)
      {
        this.userIdAttribute = configFileLoader.getProperty(PROP_USER_ID_ATTRIBUTE);
      }
      else
      {
        this.userIdAttribute = null;
      }
      
      // Get group filter (inline overrides file)
      StringArgument groupFilterArg = (StringArgument)parser.getNamedArgument(
          ARG_NAME_GROUP_FILTER);
      
      String filterString = null;
      if (groupFilterArg != null && groupFilterArg.isPresent())
      {
        filterString = groupFilterArg.getValue();
      }
      else if (configFileLoader != null)
      {
        filterString = configFileLoader.getProperty(PROP_GROUP_FILTER);
      }
      
      if (filterString != null && !filterString.trim().isEmpty())
      {
        try
        {
          this.groupFilter = Filter.create(filterString);
        }
        catch (LDAPException e)
        {
          LoggingHelper.logWarning(serverContext, 
              "Invalid group filter '" + filterString + "': " + e.getMessage());
          this.groupFilter = null;
        }
      }
      else
      {
        this.groupFilter = null;
      }
      
      // Load user lifecycle mode
      if (configFileLoader != null)
      {
        this.userLifecycleMode = configFileLoader.getProperty(PROP_USER_LIFECYCLE_MODE, "dynamic-group-memberships");
      }
      else
      {
        this.userLifecycleMode = "dynamic-group-memberships";
      }
      
      // Load SCIM user attributes list
      if (configFileLoader != null)
      {
        this.scimUserAttributes = configFileLoader.getPropertyList(PROP_SCIM_USER_ATTRIBUTES);
      }
      else
      {
        this.scimUserAttributes = new String[0];
      }
      
      // Load SCIM user attribute mappings
      if (configFileLoader != null)
      {
        this.scimUserMappings = configFileLoader.getPropertyMap(PROP_SCIM_USER_MAP_PREFIX);
      }
      else
      {
        this.scimUserMappings = new HashMap<String, String>();
      }
    }
    finally
    {
      lockManager.writeLock().unlock();
    }
  }

  @Override
  public Map<List<String>, String> getExamplesArgumentSets()
  {
    final LinkedHashMap<List<String>,String> exampleMap = 
        new LinkedHashMap<List<String>,String>(3);

    exampleMap.put(
        Arrays.asList(ARG_NAME_USER_ID_ATTRIBUTE + "=uid"),
        "Processes all static groups (groupOfNames, groupOfUniqueNames), looks up each " +
        "member DN to retrieve the uid attribute, and constructs a members attribute for " +
        "synchronization to SCIM2.");

    exampleMap.put(
        Arrays.asList(
            ARG_NAME_CONFIG_FILE + "=/opt/sync/config/scim-sync.properties"),
        "Loads configuration from shared properties file. File must contain " +
        "user.id.attribute property and optionally group.filter property.");

    exampleMap.put(
        Arrays.asList(
            ARG_NAME_CONFIG_FILE + "=/opt/sync/config/scim-sync.properties",
            ARG_NAME_GROUP_FILTER + "=(cn=scim-*)"),
        "Loads base configuration from file but overrides group.filter with inline value. " +
        "Only processes static groups whose cn starts with 'scim-'.");

    return exampleMap;
  }
  
  /**
   * Builds a JSON-encoded member mapping with user attributes and lifecycle metadata.
   * 
   * Format: userId::operationType::DN::{"attr1":"value1","attr2":"value2",...}
   * 
   * For ADD/REPLACE operations in static-group-memberships mode:
   * - Fetches user entry from LDAP
   * - Includes SCIM attribute mappings for user creation
   * 
   * For DELETE operations in static-group-memberships mode:
   * - Checks isMemberOf to determine if user should be deleted
   * - Sets deleteUser flag if no other in-scope groups remain
   * 
   * @param sourceConnection LDAP connection to fetch user details
   * @param userId The user ID extracted from DN
   * @param operationType ADD, DELETE, or REPLACE
   * @param dn The user's LDAP DN
   * @param operation Sync operation for logging
   * @return JSON-encoded member mapping string
   */
  private String buildMemberMapping(final LDAPInterface sourceConnection,
                                    final String userId,
                                    final String operationType,
                                    final String dn,
                                    final SyncOperation operation)
  {
    // Basic format without user attributes
    String basicMapping = userId + "::" + operationType + "::" + dn;
    
    // If no SCIM user attributes configured, return basic format
    if (scimUserAttributes == null || scimUserAttributes.length == 0)
    {
      return basicMapping;
    }
    
    try
    {
      Map<String, String> userData = new HashMap<String, String>();
      
      // For ADD/REPLACE in static-group-memberships mode, fetch user attributes for creation
      if ("static-group-memberships".equalsIgnoreCase(userLifecycleMode) &&
          ("ADD".equals(operationType) || "REPLACE".equals(operationType)))
      {
        // Build list of LDAP attributes to fetch
        List<String> ldapAttrsToFetch = new ArrayList<String>();
        for (String scimAttr : scimUserAttributes)
        {
          String ldapAttr = scimUserMappings.get(scimAttr);
          if (ldapAttr != null && !ldapAttr.isEmpty())
          {
            ldapAttrsToFetch.add(ldapAttr);
          }
        }
        
        if (!ldapAttrsToFetch.isEmpty())
        {
          // Fetch user entry with required attributes
          Entry userEntry = sourceConnection.getEntry(dn, ldapAttrsToFetch.toArray(new String[0]));
          if (userEntry != null)
          {
            // Map LDAP attributes to SCIM attributes
            for (String scimAttr : scimUserAttributes)
            {
              String ldapAttr = scimUserMappings.get(scimAttr);
              if (ldapAttr != null)
              {
                String value = userEntry.getAttributeValue(ldapAttr);
                if (value != null && !value.isEmpty())
                {
                  userData.put(scimAttr, value);
                }
              }
            }
            LoggingHelper.logDebug(serverContext,
                "Fetched " + userData.size() + " user attributes for " + userId);
          }
        }
      }
      
      // For DELETE in static-group-memberships mode, check isMemberOf
      if ("static-group-memberships".equalsIgnoreCase(userLifecycleMode) &&
          "DELETE".equals(operationType) && groupFilter != null)
      {
        // Fetch user's isMemberOf attribute
        Entry userEntry = sourceConnection.getEntry(dn, "isMemberOf");
        if (userEntry != null)
        {
          String[] memberOfDNs = userEntry.getAttributeValues("isMemberOf");
          boolean hasOtherInScopeGroups = false;
          
          if (memberOfDNs != null && memberOfDNs.length > 0)
          {
            // Check if any remaining groups match group.filter
            for (String groupDN : memberOfDNs)
            {
              try
              {
                Entry groupEntry = sourceConnection.getEntry(groupDN, "*");
                if (groupEntry != null && groupFilter.matchesEntry(groupEntry))
                {
                  hasOtherInScopeGroups = true;
                  break;
                }
              }
              catch (LDAPException e)
              {
                LoggingHelper.logDebug(serverContext,
                    "Error checking group " + groupDN + ": " + e.getMessage());
              }
            }
          }
          
          // If no other in-scope groups, mark user for deletion
          if (!hasOtherInScopeGroups)
          {
            userData.put("deleteUser", "true");
            LoggingHelper.logInfo(operation,
                "User " + userId + " has no other in-scope groups - marked for deletion");
          }
        }
      }
      
      // Build JSON string for user data
      if (!userData.isEmpty())
      {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : userData.entrySet())
        {
          if (!first)
          {
            json.append(",");
          }
          first = false;
          // Simple JSON encoding - escape quotes and backslashes
          String key = entry.getKey().replace("\\", "\\\\").replace("\"", "\\\"");
          String value = entry.getValue().replace("\\", "\\\\").replace("\"", "\\\"");
          json.append("\"").append(key).append("\":\"").append(value).append("\"");
        }
        json.append("}");
        
        return basicMapping + "::" + json.toString();
      }
    }
    catch (LDAPException e)
    {
      LoggingHelper.logInfo(operation,
          "Error fetching user details for " + dn + ": " + e.getMessage());
    }
    
    return basicMapping;
  }

  @Override
  public PostStepResult postFetch(final LDAPInterface sourceConnection,
                                  final AtomicReference<Entry> fetchedEntryRef,
                                  final SyncOperation operation)
      throws LDAPException
  {
    lockManager.readLock().lock();
    try
    {
      Entry entry = fetchedEntryRef.get();
      if (entry == null)
      {
        return PostStepResult.CONTINUE;
      }

      // Ensure cn and objectClass attributes are present (may be missing in notification mode)
      // These attributes are required for proper group type detection and destination processing
      boolean needsRefetch = false;
      if (!entry.hasAttribute("cn"))
      {
        LoggingHelper.logDebug(serverContext, 
            "Entry " + entry.getDN() + " is missing cn attribute - will refetch from source");
        needsRefetch = true;
      }
      if (!entry.hasAttribute("objectClass"))
      {
        LoggingHelper.logDebug(serverContext, 
            "Entry " + entry.getDN() + " is missing objectClass attribute - will refetch from source");
        needsRefetch = true;
      }
      
      if (needsRefetch)
      {
        try
        {
          Entry fullEntry = sourceConnection.getEntry(entry.getDN(), "cn", "objectClass");
          if (fullEntry != null)
          {
            // Add missing attributes to the fetched entry
            if (!entry.hasAttribute("cn") && fullEntry.hasAttribute("cn"))
            {
              entry.addAttribute(fullEntry.getAttribute("cn"));
              LoggingHelper.logDebug(serverContext, 
                  "Added cn attribute: " + fullEntry.getAttributeValue("cn"));
            }
            if (!entry.hasAttribute("objectClass") && fullEntry.hasAttribute("objectClass"))
            {
              entry.addAttribute(fullEntry.getAttribute("objectClass"));
              LoggingHelper.logDebug(serverContext, 
                  "Added objectClass attribute");
            }
            // Update the reference so sync framework sees the modified entry
            fetchedEntryRef.set(entry);
          }
          else
          {
            LoggingHelper.logWarning(serverContext, 
                "Could not refetch entry " + entry.getDN() + " from source - may not be processed correctly");
          }
        }
        catch (LDAPException e)
        {
          LoggingHelper.logWarning(serverContext, 
              "Error refetching entry " + entry.getDN() + ": " + e.getMessage());
        }
      }

      // EARLY FILTER: Check if this group matches the configured filter FIRST (if specified)
      // This prevents unnecessary processing of groups that won't be synchronized
      if (groupFilter != null && !groupFilter.matchesEntry(entry))
      {
        LoggingHelper.logInfo(operation, 
            "StaticGroupSourcePlugin: Group does not match filter '" + 
            groupFilter + "' - filtered from SCIM2 sync: " + entry.getDN());
        return PostStepResult.ABORT_OPERATION; // BLOCK this event upstream
      }

      // Check if this is a static group
      if (!GroupTypeDetector.isStaticGroup(entry))
      {
        LoggingHelper.logDebug(serverContext, 
            "Entry " + entry.getDN() + " is not a static group - skipping");
        return PostStepResult.CONTINUE;
      }

      LoggingHelper.logInfo(operation, 
          "Processing static group: " + entry.getDN());

      // ENHANCED: Create memberMappings with format: userId::operationType::DN
      // This single attribute contains all information needed by the destination:
      // - userId: The user ID extracted from the DN
      // - operationType: ADD, DELETE, or REPLACE (from changelog)
      // - DN: The original LDAP DN for reference
      //
      // For incremental changes (ADD/DELETE), only changed members are included.
      // For full resync (no changelog), all current members with REPLACE operation.
      List<String> memberMappings = new ArrayList<String>();

      // Get current member DNs (needed for resync scenario)
      String[] memberDNs = entry.getAttributeValues("member");
      String[] uniqueMemberDNs = entry.getAttributeValues("uniqueMember");

      try
      {
        ChangeLogEntry changelogEntry = operation.getChangeLogEntry();
        
        if (changelogEntry != null)
        {
          // INCREMENTAL CHANGE: Use changelog modifications to get exact changes with operation type
          LoggingHelper.logInfo(operation,
              "Found changelog entry - processing incremental member changes");
          
          List<Modification> modifications = changelogEntry.getModifications();
          boolean foundMemberModification = false;
          
          for (Modification mod : modifications)
          {
            String attrName = mod.getAttributeName();
            
            // Only process member/uniqueMember attributes
            if ("member".equalsIgnoreCase(attrName) || "uniqueMember".equalsIgnoreCase(attrName))
            {
              foundMemberModification = true;
              ModificationType modType = mod.getModificationType();
              String[] dns = mod.getValues();
              
              if (dns != null && dns.length > 0)
              {
                String operationType;
                if (ModificationType.ADD.equals(modType))
                {
                  operationType = "ADD";
                }
                else if (ModificationType.DELETE.equals(modType))
                {
                  operationType = "DELETE";
                }
                else if (ModificationType.REPLACE.equals(modType))
                {
                  operationType = "REPLACE";
                }
                else
                {
                  // Increment type - treat as ADD
                  operationType = "ADD";
                }
                
                LoggingHelper.logInfo(operation,
                    "Processing " + operationType + " operation on " + attrName + 
                    " with " + dns.length + " values");
                
                // Create mapping for each DN in this modification
                for (String dn : dns)
                {
                  String userId = UserIdLookupUtil.lookupUserIdFromDN(
                      sourceConnection, dn, userIdAttribute, operation);
                  if (userId != null)
                  {
                    // Build JSON mapping with user attributes and lifecycle metadata
                    String mapping = buildMemberMapping(sourceConnection, userId, operationType, dn, operation);
                    memberMappings.add(mapping);
                    LoggingHelper.logInfo(operation,
                        "Added mapping: " + mapping);
                  }
                  else
                  {
                    LoggingHelper.logInfo(operation,
                        "WARNING: Could not lookup user ID for DN: " + dn);
                  }
                }
              }
            }
          }
          
          if (!foundMemberModification)
          {
            LoggingHelper.logInfo(operation,
                "No member/uniqueMember modifications found in changelog - may be metadata-only change");
          }
        }
        else
        {
          // FULL RESYNC: No changelog entry, create REPLACE mappings for all current members
          LoggingHelper.logInfo(operation,
              "No changelog entry - performing full resync with REPLACE operation");
          
          if (memberDNs != null)
          {
            for (String memberDN : memberDNs)
            {
              String userId = UserIdLookupUtil.lookupUserIdFromDN(
                  sourceConnection, memberDN, userIdAttribute, operation);
              if (userId != null)
              {
                String mapping = buildMemberMapping(sourceConnection, userId, "REPLACE", memberDN, operation);
                memberMappings.add(mapping);
              }
            }
          }
          
          if (uniqueMemberDNs != null)
          {
            for (String uniqueMemberDN : uniqueMemberDNs)
            {
              String userId = UserIdLookupUtil.lookupUserIdFromDN(
                  sourceConnection, uniqueMemberDN, userIdAttribute, operation);
              if (userId != null)
              {
                String mapping = buildMemberMapping(sourceConnection, userId, "REPLACE", uniqueMemberDN, operation);
                memberMappings.add(mapping);
              }
            }
          }
          
          LoggingHelper.logInfo(operation,
              "Created " + memberMappings.size() + " REPLACE mappings for full resync");
        }
      }
      catch (Exception e)
      {
        LoggingHelper.logInfo(operation,
            "Error processing changelog: " + e.getMessage() + " - falling back to full resync");
        
        // Fall back to REPLACE for all current members
        memberMappings.clear();
        
        if (memberDNs != null)
        {
          for (String memberDN : memberDNs)
          {
            String userId = UserIdLookupUtil.lookupUserIdFromDN(
                sourceConnection, memberDN, userIdAttribute, operation);
            if (userId != null)
            {
              String mapping = buildMemberMapping(sourceConnection, userId, "REPLACE", memberDN, operation);
              memberMappings.add(mapping);
            }
          }
        }
        
        if (uniqueMemberDNs != null)
        {
          for (String uniqueMemberDN : uniqueMemberDNs)
          {
            String userId = UserIdLookupUtil.lookupUserIdFromDN(
                sourceConnection, uniqueMemberDN, userIdAttribute, operation);
            if (userId != null)
            {
              String mapping = buildMemberMapping(sourceConnection, userId, "REPLACE", uniqueMemberDN, operation);
              memberMappings.add(mapping);
            }
          }
        }
      }

      // Add the memberMappings attribute to the group entry
      if (memberMappings.isEmpty())
      {
        LoggingHelper.logInfo(operation, 
            "No member mappings created for group: " + entry.getDN());
        entry.setAttribute(new Attribute("memberMappings", new String[0]));
      }
      else
      {
        LoggingHelper.logInfo(operation, 
            "Created " + memberMappings.size() + " member mappings for group: " + 
            entry.getDN());
        entry.setAttribute(new Attribute("memberMappings", memberMappings));
      }
      
      // Debug: Verify the attribute was added
      Attribute verifyMappings = entry.getAttribute("memberMappings");
      LoggingHelper.logInfo(operation,
          "DEBUG: After setAttribute, memberMappings=" + 
          (verifyMappings != null ? verifyMappings.getValues().length : 0) + " values");

      // Update the reference so sync framework passes the modified entry to destination
      fetchedEntryRef.set(entry);
      LoggingHelper.logInfo(operation,
          "DEBUG: Updated fetchedEntryRef with modified entry");

      // Signal the destination plugin that memberMappings attribute has been computed and should be processed
      // The operation type is now embedded in each mapping value
      operation.addModifiedDestinationAttribute("memberMappings");
      LoggingHelper.logInfo(operation,
          "Added memberMappings to modified destination attributes (" + 
          memberMappings.size() + " mappings)");

      return PostStepResult.CONTINUE;
    }
    finally
    {
      lockManager.readLock().unlock();
    }
  }

  @Override
  public void toString(final StringBuilder buffer)
  {
    buffer.append("StaticGroupSourcePlugin(userIdAttribute='");
    buffer.append(userIdAttribute);
    buffer.append("', groupFilter='");
    buffer.append(groupFilter != null ? groupFilter.toString() : "null");
    buffer.append("', configFile='");
    buffer.append(configFileLoader != null ? configFileLoader.getConfigFilePath() : "null");
    buffer.append("')");
  }
}

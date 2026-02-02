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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import com.heer.sync.lib.ConfigFileLoader;
import com.heer.sync.lib.ConfigLockManager;
import com.heer.sync.lib.GroupTypeDetector;
import com.heer.sync.lib.LoggingHelper;
import com.unboundid.directory.sdk.sync.api.LDAPSyncSourcePlugin;
import com.unboundid.directory.sdk.sync.config.LDAPSyncSourcePluginConfig;
import com.unboundid.directory.sdk.sync.types.PostStepResult;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;

/**
 * LDAP sync source plugin for handling dynamic group resync operations.
 * Processes groups with memberURL attributes, parses the LDAP URL to
 * determine membership criteria, queries for matching users, and constructs
 * a members attribute for synchronization to SCIM2 destination.
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
 *   <LI>group-filter -- (Optional) LDAP filter to determine which dynamic groups should
 *                       have their membership expanded. If not specified, all dynamic
 *                       groups will be processed.</LI>
 * </UL>
 */
public class DynamicGroupSourcePlugin extends LDAPSyncSourcePlugin
{
  private static final String ARG_NAME_CONFIG_FILE = "config-file";
  private static final String ARG_NAME_USER_ID_ATTRIBUTE = "user-id-attribute";
  private static final String ARG_NAME_GROUP_FILTER = "group-filter";
  
  private static final String PROP_USER_ID_ATTRIBUTE = "user.id.attribute";
  private static final String PROP_GROUP_FILTER = "group.filter";
  
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

  @Override
  public String getExtensionName()
  {
    return "SCIM2 Dynamic Group Sync Source Plugin";
  }

  @Override
  public String[] getExtensionDescription()
  {
    return new String[]
    {
      "This LDAP sync source plugin handles dynamic group resync operations. It processes " +
      "groups with memberURL attributes, parses the LDAP URL to determine membership " +
      "criteria (base DN, scope, filter), queries for matching users, and constructs a " +
      "members attribute containing all member user IDs.",
      
      "This plugin is part of a refactored architecture that separates static and dynamic " +
      "group processing. It focuses solely on dynamic groups, making it simpler, more testable, " +
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
        "found via memberURL queries and added to the members attribute. Required if " +
        "config-file is not provided or doesn't contain user.id.attribute property. " +
        "Overrides file-based configuration.");
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
        "An optional LDAP filter to determine which dynamic groups should have their " +
        "membership expanded. If not specified, all groups with memberURL attributes will " +
        "be processed. Examples: '(cn=scim-*)' to process only groups starting with 'scim-', " +
        "or '(description=*sync*)' to process groups with 'sync' in their description. " +
        "Overrides file-based configuration.");
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
        "Processes all dynamic groups with memberURL attributes, parses each LDAP URL, " +
        "queries for matching users, extracts uid values, and constructs a members attribute " +
        "for synchronization to SCIM2.");

    exampleMap.put(
        Arrays.asList(
            ARG_NAME_CONFIG_FILE + "=/opt/sync/config/scim-sync.properties"),
        "Loads configuration from shared properties file. File must contain " +
        "user.id.attribute property and optionally group.filter property.");

    exampleMap.put(
        Arrays.asList(
            ARG_NAME_CONFIG_FILE + "=/opt/sync/config/scim-sync.properties",
            ARG_NAME_GROUP_FILTER + "=(cn=dynamic-*)"),
        "Loads base configuration from file but overrides group.filter with inline value. " +
        "Only processes dynamic groups whose cn starts with 'dynamic-'.");

    return exampleMap;
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
            "DynamicGroupSourcePlugin: Group does not match filter '" + 
            groupFilter + "' - filtered from SCIM2 sync: " + entry.getDN());
        return PostStepResult.ABORT_OPERATION; // BLOCK this event upstream
      }

      // Check if this is a dynamic group
      if (!GroupTypeDetector.isDynamicGroup(entry))
      {
        LoggingHelper.logDebug(serverContext, 
            "Entry " + entry.getDN() + " is not a dynamic group - skipping");
        return PostStepResult.CONTINUE;
      }

      // Get memberURL attributes
      String[] memberUrls = entry.getAttributeValues("memberURL");
      
      LoggingHelper.logInfo(operation, 
          "Processing dynamic group: " + entry.getDN() + " with " + 
          memberUrls.length + " memberURL(s)");

      // Collect all member user IDs
      List<String> memberUserIds = new ArrayList<String>();

      // Process each memberURL
      for (String memberUrl : memberUrls)
      {
        if (memberUrl == null || memberUrl.trim().isEmpty())
        {
          continue;
        }

        LoggingHelper.logInfo(operation, "Parsing memberURL: " + memberUrl);

        // Parse the LDAP URL
        LDAPURL ldapURL = null;
        try
        {
          ldapURL = new LDAPURL(memberUrl);
        }
        catch (LDAPException e)
        {
          LoggingHelper.logInfo(operation, 
              "Could not parse memberURL: " + memberUrl + " - " + e.getMessage());
          continue;
        }

        // Extract search parameters from the LDAP URL
        DN baseDN = ldapURL.getBaseDN();
        SearchScope scope = ldapURL.getScope();
        Filter filter = ldapURL.getFilter();

        // Use default values if not specified in URL
        if (baseDN == null)
        {
          LoggingHelper.logInfo(operation, 
              "memberURL does not contain a base DN, skipping: " + memberUrl);
          continue;
        }

        if (scope == null)
        {
          scope = SearchScope.SUB; // Default to subtree scope
        }

        if (filter == null)
        {
          filter = Filter.createPresenceFilter("objectClass"); // Default to (objectClass=*)
        }

        // Perform search to find matching users
        try
        {
          SearchRequest searchRequest = new SearchRequest(
              baseDN.toString(),
              scope,
              filter,
              userIdAttribute);

          LoggingHelper.logInfo(operation, 
              "Searching for group members with base DN: " + baseDN + 
              ", scope: " + scope + ", filter: " + filter);

          List<SearchResultEntry> searchResults = 
              sourceConnection.search(searchRequest).getSearchEntries();

          LoggingHelper.logInfo(operation, 
              "Found " + searchResults.size() + " matching users");

          // Extract user ID from each result
          for (SearchResultEntry userEntry : searchResults)
          {
            String userId = userEntry.getAttributeValue(userIdAttribute);
            if (userId != null && !userId.trim().isEmpty())
            {
              memberUserIds.add(userId);
            }
            else
            {
              LoggingHelper.logInfo(operation, 
                  "Warning: User entry " + userEntry.getDN() + 
                  " does not have " + userIdAttribute + " attribute");
            }
          }
        }
        catch (LDAPException e)
        {
          LoggingHelper.logError(operation, 
              "Error searching for group members: " + e.getMessage());
          // Continue processing other memberURLs
        }
      }

      // Add the members attribute to the group entry
      if (memberUserIds.isEmpty())
      {
        LoggingHelper.logInfo(operation, 
            "No member user IDs found for group: " + entry.getDN());
        entry.setAttribute(new Attribute("members", new String[0]));
      }
      else
      {
        LoggingHelper.logInfo(operation, 
            "Adding " + memberUserIds.size() + " member user IDs to group: " + 
            entry.getDN());
        entry.setAttribute(new Attribute("members", memberUserIds));
      }

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
    buffer.append("DynamicGroupSourcePlugin(userIdAttribute='");
    buffer.append(userIdAttribute);
    buffer.append("', groupFilter='");
    buffer.append(groupFilter != null ? groupFilter.toString() : "null");
    buffer.append("', configFile='");
    buffer.append(configFileLoader != null ? configFileLoader.getConfigFilePath() : "null");
    buffer.append("')");
  }
}

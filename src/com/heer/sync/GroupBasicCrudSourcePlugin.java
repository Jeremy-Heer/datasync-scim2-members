/*
 * Copyright 2024-2025 Jeremy Heer
 * Licensed under the Apache License, Version 2.0
 */
package com.heer.sync;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.heer.sync.lib.ConfigFileLoader;
import com.heer.sync.lib.ConfigLockManager;
import com.heer.sync.lib.LoggingHelper;
import com.unboundid.directory.sdk.sync.api.LDAPSyncSourcePlugin;
import com.unboundid.directory.sdk.sync.config.LDAPSyncSourcePluginConfig;
import com.unboundid.directory.sdk.sync.types.PostStepResult;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;

/**
 * Source plugin for Groups-Basic-CRUD sync pipe.
 * <p>
 * Filters group events by checking if the group matches a configured LDAP filter.
 * Only groups matching the filter are in scope for SCIM2 synchronization.
 * </p>
 *
 * <h2>Filtering Strategy:</h2>
 * <ul>
 *   <li>ALLOW: Group matches LDAP filter (e.g., cn=scim-*)</li>
 *   <li>BLOCK: Group does NOT match LDAP filter</li>
 *   <li>ALLOW: All groups if no filter is configured</li>
 * </ul>
 *
 * <h2>Use Case:</h2>
 * <p>
 * This plugin ensures only groups matching specific criteria (e.g., groups with a specific
 * naming pattern or description) are created/updated/deleted in the SCIM2 destination.
 * Groups not matching the filter are filtered out completely, preventing unnecessary
 * SCIM2 API queries.
 * </p>
 *
 * <h2>Configuration:</h2>
 * <pre>
 * group-filter=(cn=scim-*)
 * </pre>
 *
 * @author Jeremy Heer
 */
public class GroupBasicCrudSourcePlugin extends LDAPSyncSourcePlugin
{
  private static final String ARG_NAME_CONFIG_FILE = "config-file";
  private static final String ARG_NAME_GROUP_FILTER = "group-filter";
  
  private static final String PROP_GROUP_FILTER = "group.filter";
  
  private SyncServerContext serverContext;
  private final ConfigLockManager lockManager = new ConfigLockManager();
  private ConfigFileLoader configFileLoader;
  private Filter groupFilter;
  
  @Override
  public String getExtensionName()
  {
    return "Group Basic CRUD Source Plugin";
  }
  
  @Override
  public String[] getExtensionDescription()
  {
    return new String[]
    {
      "Filters group CRUD events for the Groups-Basic-CRUD sync pipe. Only allows groups " +
      "matching a configured LDAP filter to be synchronized to SCIM2.",
      
      "This plugin evaluates each group entry against the configured filter. Groups not " +
      "matching are filtered upstream, preventing unnecessary SCIM2 API queries and " +
      "misleading 'not found' errors.",
      
      "If no filter is configured, all groups are allowed. Works as part of a multi-pipe " +
      "architecture where different pipes handle basic CRUD, static membership, and dynamic " +
      "membership separately."
    };
  }
  
  @Override
  public void defineConfigArguments(final ArgumentParser parser)
      throws ArgumentException
  {
    StringArgument configFileArg = new StringArgument(
        null,
        ARG_NAME_CONFIG_FILE,
        false,
        1,
        "{path}",
        "Path to shared Java properties file containing common configuration. " +
        "Property: group.filter (optional). " +
        "Inline arguments override file-based configuration.");
    parser.addArgument(configFileArg);
    
    StringArgument groupFilterArg = new StringArgument(
        null,
        ARG_NAME_GROUP_FILTER,
        false,
        1,
        "{filter}",
        "LDAP filter to determine which groups should be synchronized. " +
        "Examples: '(cn=scim-*)' to sync only groups starting with 'scim-', or " +
        "'(description=*sync*)' to sync groups with 'sync' in their description. " +
        "If not specified, all groups are synchronized. Overrides file-based configuration.");
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
    String configFilePath = ((StringArgument)parser.getNamedArgument(
        ARG_NAME_CONFIG_FILE)).getValue();
    
    if (configFilePath != null)
    {
      try
      {
        new ConfigFileLoader(configFilePath, serverContext);
      }
      catch (IOException e)
      {
        unacceptableReasons.add("Cannot read configuration file: " + e.getMessage());
        return false;
      }
    }
    
    // Validate filter syntax if provided
    StringArgument filterArg = (StringArgument)parser.getNamedArgument(ARG_NAME_GROUP_FILTER);
    if (filterArg != null && filterArg.isPresent())
    {
      try
      {
        Filter.create(filterArg.getValue());
      }
      catch (LDAPException e)
      {
        unacceptableReasons.add("Invalid LDAP filter: " + e.getMessage());
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
        try
        {
          this.configFileLoader = new ConfigFileLoader(configFileArg.getValue(), serverContext);
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
      
      // Get group filter (inline overrides file)
      StringArgument filterArg = (StringArgument)parser.getNamedArgument(ARG_NAME_GROUP_FILTER);
      
      String filterString = null;
      if (filterArg != null && filterArg.isPresent())
      {
        filterString = filterArg.getValue();
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
        Arrays.asList(ARG_NAME_GROUP_FILTER + "=(cn=scim-*)"),
        "Filters groups based on cn attribute. Only groups whose cn starts with 'scim-' " +
        "are synchronized to SCIM2.");

    exampleMap.put(
        Arrays.asList(
            ARG_NAME_CONFIG_FILE + "=/opt/sync/config/scim-sync.properties"),
        "Loads configuration from shared properties file. If file contains group.filter " +
        "property, it will be used. Otherwise all groups are synchronized.");

    exampleMap.put(
        Arrays.asList(
            ARG_NAME_CONFIG_FILE + "=/opt/sync/config/scim-sync.properties",
            ARG_NAME_GROUP_FILTER + "=(description=*azure*)"),
        "Loads base configuration from file but overrides group.filter. Only groups with " +
        "'azure' in their description are synchronized.");

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
      
      // If no filter configured, allow all groups
      if (groupFilter == null)
      {
        LoggingHelper.logInfo(operation, 
            "GroupBasicCrudSourcePlugin: No filter configured - allowing group " + 
            entry.getDN());
        return PostStepResult.CONTINUE;
      }
      
      // Check if group matches filter
      if (!groupFilter.matchesEntry(entry))
      {
        LoggingHelper.logInfo(operation, 
            "GroupBasicCrudSourcePlugin: Group " + entry.getDN() + 
            " does not match filter '" + groupFilter + "' - filtered from SCIM2 sync");
        return PostStepResult.ABORT_OPERATION;
      }
      
      LoggingHelper.logInfo(operation, 
          "GroupBasicCrudSourcePlugin: Group " + entry.getDN() + 
          " matches filter - allowed");
      
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
    buffer.append("GroupBasicCrudSourcePlugin(groupFilter='");
    buffer.append(groupFilter != null ? groupFilter.toString() : "null");
    buffer.append("', configFile='");
    buffer.append(configFileLoader != null ? configFileLoader.getConfigFilePath() : "null");
    buffer.append("')");
  }
}

/*
 * Copyright 2024-2025 Jeremy Heer
 * Licensed under the Apache License, Version 2.0
 */
package com.heer.sync;

import java.io.IOException;
import java.util.ArrayList;
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
import com.unboundid.ldap.sdk.ChangeLogEntry;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;

/**
 * Source plugin for Users-Group-Membership sync pipe.
 * <p>
 * Filters user MODIFY events to only allow changes where group membership attributes
 * were modified. This prevents unnecessary SCIM2 PATCH operations for attribute
 * changes that don't affect group membership.
 * </p>
 *
 * <h2>Filtering Strategy:</h2>
 * <ul>
 *   <li>ALLOW: User MODIFY with group membership attribute changes (detected via changelog)</li>
 *   <li>BLOCK: User MODIFY without group membership attribute changes</li>
 *   <li>BLOCK: User CREATE events (handled by Users-Basic-CRUD pipe)</li>
 *   <li>BLOCK: User DELETE events (handled by Users-Basic-CRUD pipe)</li>
 * </ul>
 *
 * <h2>Use Case:</h2>
 * <p>
 * This plugin works in changelog/notification mode to detect incremental group membership
 * changes. When a user's scim-groups attribute is modified, this plugin allows the event
 * to flow to the destination which will generate a SCIM2 PATCH operation to update the
 * user's group memberships.
 * </p>
 *
 * <h2>Configuration:</h2>
 * <pre>
 * group-membership-attributes=scim-groups
 * sync-mode=notification
 * </pre>
 *
 * @author Jeremy Heer
 */
public class UserGroupMembershipSourcePlugin extends LDAPSyncSourcePlugin
{
  private static final String ARG_NAME_CONFIG_FILE = "config-file";
  private static final String ARG_NAME_GROUP_MEMBERSHIP_ATTRIBUTES = "group-membership-attributes";
  
  private static final String PROP_GROUP_MEMBERSHIP_ATTRIBUTES = "group.membership.attributes";
  
  private SyncServerContext serverContext;
  private final ConfigLockManager lockManager = new ConfigLockManager();
  private ConfigFileLoader configFileLoader;
  private List<String> groupMembershipAttributes;
  
  @Override
  public String getExtensionName()
  {
    return "User Group Membership Source Plugin";
  }
  
  @Override
  public String[] getExtensionDescription()
  {
    return new String[]
    {
      "Filters user group membership change events for the Users-Group-Membership sync pipe. " +
      "Only allows user MODIFY operations where group membership attributes were changed.",
      
      "This plugin inspects the LDAP changelog to determine if the modification includes " +
      "changes to configured group membership attributes (e.g., scim-groups). Events without " +
      "group membership changes are filtered upstream.",
      
      "Requires changelog/notification sync mode. Works as part of a multi-pipe architecture " +
      "where this pipe specifically handles incremental group membership updates via SCIM2 PATCH."
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
        "Property: group.membership.attributes (required). " +
        "Inline arguments override file-based configuration.");
    parser.addArgument(configFileArg);
    
    StringArgument groupMembershipArg = new StringArgument(
        null,
        ARG_NAME_GROUP_MEMBERSHIP_ATTRIBUTES,
        false,
        1,
        "{attr}",
        "Comma-separated list of LDAP attributes that indicate group membership " +
        "(e.g., 'scim-groups' or 'memberOf,scim-groups'). Only modifications to " +
        "these attributes will be synchronized. Required if config-file is not provided. " +
        "Overrides file-based configuration.");
    parser.addArgument(groupMembershipArg);
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
    String inlineAttr = ((StringArgument)parser.getNamedArgument(
        ARG_NAME_GROUP_MEMBERSHIP_ATTRIBUTES)).getValue();
    
    if (configFilePath == null && inlineAttr == null)
    {
      unacceptableReasons.add("Must provide either config-file with " +
          "group.membership.attributes property or group-membership-attributes argument");
      return false;
    }
    
    if (configFilePath != null)
    {
      try
      {
        ConfigFileLoader testLoader = new ConfigFileLoader(configFilePath, serverContext);
        
        if (inlineAttr == null && !testLoader.hasProperty(PROP_GROUP_MEMBERSHIP_ATTRIBUTES))
        {
          unacceptableReasons.add("Configuration file does not contain required property: " + 
              PROP_GROUP_MEMBERSHIP_ATTRIBUTES);
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
      
      // Get group membership attributes (inline overrides file)
      StringArgument membershipArg = (StringArgument)parser.getNamedArgument(
          ARG_NAME_GROUP_MEMBERSHIP_ATTRIBUTES);
      
      String attributesString = null;
      if (membershipArg != null && membershipArg.isPresent())
      {
        attributesString = membershipArg.getValue();
      }
      else if (configFileLoader != null)
      {
        attributesString = configFileLoader.getProperty(PROP_GROUP_MEMBERSHIP_ATTRIBUTES);
      }
      
      if (attributesString != null && !attributesString.trim().isEmpty())
      {
        String[] attrs = attributesString.split(",");
        this.groupMembershipAttributes = new ArrayList<String>();
        for (String attr : attrs)
        {
          String trimmed = attr.trim();
          if (!trimmed.isEmpty())
          {
            this.groupMembershipAttributes.add(trimmed.toLowerCase());
          }
        }
      }
      else
      {
        this.groupMembershipAttributes = new ArrayList<String>();
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
        new LinkedHashMap<List<String>,String>(2);

    exampleMap.put(
        Arrays.asList(ARG_NAME_GROUP_MEMBERSHIP_ATTRIBUTES + "=scim-groups"),
        "Filters user modifications to only allow changes to 'scim-groups' attribute. " +
        "Other attribute modifications are filtered out.");

    exampleMap.put(
        Arrays.asList(
            ARG_NAME_CONFIG_FILE + "=/opt/sync/config/scim-sync.properties"),
        "Loads configuration from shared properties file containing " +
        "group.membership.attributes property.");

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
      
      // Get changelog entry to inspect modifications
      ChangeLogEntry changelogEntry = operation.getChangeLogEntry();
      
      if (changelogEntry == null)
      {
        LoggingHelper.logInfo(operation, 
            "UserGroupMembershipSourcePlugin: No changelog entry available for " + 
            entry.getDN() + " - cannot determine if group membership changed");
        return PostStepResult.ABORT_OPERATION;
      }
      
      // Check if any modification is to a group membership attribute
      List<Modification> modifications = changelogEntry.getModifications();
      if (modifications == null || modifications.isEmpty())
      {
        LoggingHelper.logInfo(operation, 
            "UserGroupMembershipSourcePlugin: No modifications in changelog for " + 
            entry.getDN() + " - filtered");
        return PostStepResult.ABORT_OPERATION;
      }
      
      boolean hasGroupMembershipChange = false;
      for (Modification mod : modifications)
      {
        String attrName = mod.getAttributeName().toLowerCase();
        if (groupMembershipAttributes.contains(attrName))
        {
          hasGroupMembershipChange = true;
          LoggingHelper.logInfo(operation, 
              "UserGroupMembershipSourcePlugin: Detected change to group membership attribute: " + 
              attrName);
          break;
        }
      }
      
      if (!hasGroupMembershipChange)
      {
        LoggingHelper.logInfo(operation, 
            "UserGroupMembershipSourcePlugin: User " + entry.getDN() + 
            " has no group membership changes - filtered");
        return PostStepResult.ABORT_OPERATION;
      }
      
      LoggingHelper.logInfo(operation, 
          "UserGroupMembershipSourcePlugin: User " + entry.getDN() + 
          " has group membership modification - allowed");
      
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
    buffer.append("UserGroupMembershipSourcePlugin(groupMembershipAttributes=");
    buffer.append(groupMembershipAttributes);
    buffer.append(", configFile='");
    buffer.append(configFileLoader != null ? configFileLoader.getConfigFilePath() : "null");
    buffer.append("')");
  }
}

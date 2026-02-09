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
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;

/**
 * Source plugin for Users-Basic-CRUD sync pipe.
 * <p>
 * Filters user events by checking if user has group membership attributes populated.
 * Only users WITH group membership attributes are in scope for SCIM2 synchronization.
 * </p>
 *
 * <h2>Filtering Strategy:</h2>
 * <ul>
 *   <li>ALLOW: User with group membership attributes populated (in SCIM2 scope)</li>
 *   <li>BLOCK: User without group membership attributes (not in SCIM2 scope)</li>
 * </ul>
 *
 * <h2>Use Case:</h2>
 * <p>
 * This plugin ensures only users participating in SCIM2 group membership synchronization
 * are created/updated/deleted in the SCIM2 destination. Users without the configured
 * group membership attribute (e.g., scim-groups) are filtered out completely.
 * </p>
 *
 * <h2>Configuration:</h2>
 * <pre>
 * group-membership-attributes=scim-groups
 * </pre>
 *
 * @author Jeremy Heer
 */
public class UserBasicCrudSourcePlugin extends LDAPSyncSourcePlugin
{
  private static final String ARG_NAME_CONFIG_FILE = "config-file";
  private static final String ARG_NAME_GROUP_MEMBERSHIP_ATTRIBUTES = "group-membership-attributes";
  
  private static final String PROP_GROUP_MEMBERSHIP_ATTRIBUTES = "group.membership.attributes";
  private static final String PROP_USER_LIFECYCLE_MODE = "user.lifecycle.mode";
  
  private SyncServerContext serverContext;
  private final ConfigLockManager lockManager = new ConfigLockManager();
  private ConfigFileLoader configFileLoader;
  private List<String> groupMembershipAttributes;
  private String userLifecycleMode;
  
  @Override
  public String getExtensionName()
  {
    return "User Basic CRUD Source Plugin";
  }
  
  @Override
  public String[] getExtensionDescription()
  {
    return new String[]
    {
      "Filters user CRUD events for the Users-Basic-CRUD sync pipe. Only allows users " +
      "with group membership attributes populated to be synchronized to SCIM2.",
      
      "This plugin checks if the user entry has the configured group membership attribute(s) " +
      "with non-empty values. Users without these attributes are filtered upstream, preventing " +
      "unnecessary SCIM2 API queries and misleading 'not found' errors.",
      
      "Works as part of a multi-pipe architecture where different pipes handle different " +
      "aspects of user and group synchronization."
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
        "(e.g., 'scim-groups' or 'memberOf,scim-groups'). Users must have at least " +
        "one of these attributes with a non-empty value to be synchronized. " +
        "Required if config-file is not provided. Overrides file-based configuration.");
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
      
      // Get user lifecycle mode from config file
      if (configFileLoader != null)
      {
        this.userLifecycleMode = configFileLoader.getProperty(PROP_USER_LIFECYCLE_MODE);
      }
      else
      {
        this.userLifecycleMode = null;
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
        "Filters users based on 'scim-groups' attribute. Only users with this attribute " +
        "populated are synchronized to SCIM2.");

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
      
      // For DELETE operations, always allow through
      // User might be member of static groups (membership tracked in group entry, not user entry)
      // and virtual attributes like isMemberOf don't appear in changelog
      if (operation.getType() == com.unboundid.directory.sdk.sync.types.SyncOperationType.DELETE)
      {
        LoggingHelper.logInfo(operation,
            "UserBasicCrudSourcePlugin: User " + entry.getDN() + 
            " DELETE operation - allowed (may be in static groups)");
        return PostStepResult.CONTINUE;
      }
      
      // For RESYNC operations, always allow through
      // RESYNC operations need to process all users to ensure destination is in sync with source
      if (operation.getType() == com.unboundid.directory.sdk.sync.types.SyncOperationType.RESYNC)
      {
        // For static-group-memberships mode, fetch isMemberOf attribute and add to entry
        if ("static-group-memberships".equalsIgnoreCase(userLifecycleMode))
        {
          try
          {
            // Fetch the user entry with isMemberOf attribute
            Entry fullEntry = sourceConnection.getEntry(entry.getDN(), "isMemberOf");
            if (fullEntry != null)
            {
              Attribute isMemberOf = fullEntry.getAttribute("isMemberOf");
              if (isMemberOf != null && isMemberOf.hasValue())
              {
                // Add isMemberOf to the fetched entry
                Entry updatedEntry = entry.duplicate();
                updatedEntry.addAttribute(isMemberOf);
                fetchedEntryRef.set(updatedEntry);
                
                LoggingHelper.logInfo(operation,
                    "UserBasicCrudSourcePlugin: Added isMemberOf attribute with " + 
                    isMemberOf.size() + " values to user " + entry.getDN());
              }
            }
          }
          catch (LDAPException e)
          {
            LoggingHelper.logWarning(serverContext,
                "UserBasicCrudSourcePlugin: Failed to fetch isMemberOf for user " + 
                entry.getDN() + ": " + e.getMessage());
          }
        }
        
        LoggingHelper.logInfo(operation,
            "UserBasicCrudSourcePlugin: User " + entry.getDN() + 
            " RESYNC operation - allowed (full sync required)");
        return PostStepResult.CONTINUE;
      }
      
      // For CREATE/MODIFY operations, check if user has group membership attributes
      boolean hasGroupMembership = false;
      for (String attrName : groupMembershipAttributes)
      {
        Attribute attr = entry.getAttribute(attrName);
        if (attr != null && attr.hasValue())
        {
          hasGroupMembership = true;
          break;
        }
      }
      
      if (!hasGroupMembership)
      {
        LoggingHelper.logInfo(operation, 
            "UserBasicCrudSourcePlugin: User " + entry.getDN() + 
            " has no group membership attributes - filtered from SCIM2 sync");
        return PostStepResult.ABORT_OPERATION;
      }
      
      LoggingHelper.logInfo(operation, 
          "UserBasicCrudSourcePlugin: User " + entry.getDN() + 
          " has group membership - allowed");
      
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
    buffer.append("UserBasicCrudSourcePlugin(groupMembershipAttributes=");
    buffer.append(groupMembershipAttributes);
    buffer.append(", configFile='");
    buffer.append(configFileLoader != null ? configFileLoader.getConfigFilePath() : "null");
    buffer.append("')");
  }
}

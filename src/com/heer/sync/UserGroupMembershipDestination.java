/*
 * Copyright 2024 Jeremy Heer
 * Licensed under the Apache License, Version 2.0
 */
package com.heer.sync;

import com.unboundid.directory.sdk.sync.api.SyncDestination;
import com.unboundid.directory.sdk.sync.config.SyncDestinationConfig;
import com.unboundid.directory.sdk.sync.types.EndpointException;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeLogEntry;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;

import com.unboundid.scim2.client.ScimService;
import com.unboundid.scim2.common.ScimResource;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.filters.Filter;
import com.unboundid.scim2.common.messages.ListResponse;
import com.unboundid.scim2.common.types.GroupResource;
import com.unboundid.scim2.common.types.UserResource;

import com.heer.sync.lib.ConfigFileLoader;
import com.heer.sync.lib.scim2.Scim2ClientFactory;
import com.heer.sync.lib.scim2.Scim2MemberHelper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * USER-DRIVEN incremental group membership synchronization plugin.
 * <p>
 * This destination plugin monitors user attribute changes (trigger attributes like 'scim-groups')
 * and updates SCIM2 group memberships incrementally. It processes ADD, DELETE, and REPLACE
 * operations for efficient synchronization.
 * </p>
 * 
 * <h2>TRIGGER ATTRIBUTE MODEL</h2>
 * <p>
 * This plugin monitors REAL LDAP attributes that produce changelog events. Virtual attributes
 * like 'memberOf' will NOT work because they don't generate changelog entries.
 * </p>
 * 
 * <h3>Configuration Example:</h3>
 * <pre>
 * group-membership-attributes=scim-groups
 * user-lookup-attribute=uid
 * </pre>
 * 
 * <h3>How It Works:</h3>
 * <ul>
 *   <li>ADD: scim-groups=qa-team → User added to SCIM2 qa-team group</li>
 *   <li>DELETE: scim-groups=developers → User removed from SCIM2 developers group</li>
 *   <li>REPLACE: Syncs exact set (adds missing, removes extra)</li>
 * </ul>
 * 
 * <h2>Synchronization Modes:</h2>
 * <ul>
 *   <li><b>Standard Mode:</b> fetchEntry retrieves current memberships from SCIM2 for comparison</li>
 *   <li><b>Notification Mode:</b> Uses changelog before/after values for incremental updates</li>
 * </ul>
 * 
 * <h2>Shared Libraries:</h2>
 * <ul>
 *   <li>Scim2ClientFactory - REST client with auth/SSL/proxy configuration</li>
 *   <li>Scim2MemberHelper - Reusable SCIM2 operations (optimized queries)</li>
 *   <li>ConfigFileLoader - Shared configuration file support</li>
 * </ul>
 * 
 * @author Jeremy Heer
 */
public class UserGroupMembershipDestination extends SyncDestination
{
  // Sync Server Context for logging
  private SyncServerContext serverContext;
  
  // SCIM2 client factory and service
  private Scim2ClientFactory clientFactory;
  private jakarta.ws.rs.client.Client jaxrsClient;
  private ScimService scimService;
  
  // Helper utilities
  private Scim2MemberHelper memberHelper;
  private ConfigFileLoader configLoader;
  
  // Configuration parameters
  private String baseUrl;
  private String userBasePath = "/Users";
  private String groupBasePath = "/Groups";
  private String usernameLookupAttribute;
  private String[] groupMembershipAttributes;
  private boolean disableGroupMembershipLookups = false;
  
  // Retry configuration
  private int maxRetries = 3;
  private long retryDelayMs = 1000;
  
  /**
   * Functional interface for operations that can be retried.
   */
  @FunctionalInterface
  private interface RetryableOperation<T> {
    T execute() throws Exception;
  }
  
  @Override
  public String getExtensionName()
  {
    return "SCIM2 User Group Membership Destination";
  }
  
  @Override
  public String[] getExtensionDescription()
  {
    return new String[] {
      "USER-DRIVEN incremental group membership synchronization.",
      "Monitors user attribute changes (trigger attributes like 'scim-groups')",
      "and updates SCIM2 group memberships incrementally.",
      "",
      "TRIGGER ATTRIBUTE MODEL:",
      "- Monitors REAL LDAP attributes (e.g., scim-groups, custom attributes)",
      "- These attributes MUST produce changelog events",
      "- Virtual attributes like 'memberOf' will NOT work (no changelog)",
      "",
      "Configuration example:",
      "group-membership-attributes=scim-groups",
      "user-lookup-attribute=uid"
    };
  }
  
  @Override
  public void defineConfigArguments(final ArgumentParser parser) throws ArgumentException
  {
    // Shared config file (optional)
    parser.addArgument(new FileArgument(
        null, "config-file", false, 1,
        "{path}",
        "Path to shared configuration properties file. When provided, common " +
        "settings (base-url, credentials, SSL, proxy) are loaded from this file. " +
        "Individual arguments override file settings.",
        true, true, true, false));
    
    // SCIM2 endpoint configuration
    parser.addArgument(new StringArgument(
        null, "scim2-base-url", false, 1,
        "{url}",
        "The base URL of the SCIM2 endpoint (e.g., https://example.com/scim/v2). " +
        "Required - can be provided via argument or config file."));
    
    parser.addArgument(new StringArgument(
        null, "scim2-user-base", false, 1,
        "{path}",
        "The base path for SCIM2 users (default: /Users)",
        "/Users"));
    
    parser.addArgument(new StringArgument(
        null, "scim2-group-base", false, 1,
        "{path}",
        "The base path for SCIM2 groups (default: /Groups)",
        "/Groups"));
    
    // Authentication
    parser.addArgument(new StringArgument(
        null, "scim2-username", false, 1,
        "{username}",
        "Username for HTTP basic authentication"));
    
    parser.addArgument(new StringArgument(
        null, "scim2-password", false, 1,
        "{password}",
        "Password for HTTP basic authentication"));
    
    parser.addArgument(new StringArgument(
        null, "scim2-bearer-token", false, 1,
        "{token}",
        "Bearer token for OAuth authentication"));
    
    // SSL configuration
    parser.addArgument(new StringArgument(
        null, "scim2-trust-store-path", false, 1,
        "{path}",
        "Path to trust store file for SSL verification"));
    
    parser.addArgument(new StringArgument(
        null, "scim2-trust-store-password", false, 1,
        "{password}",
        "Password for trust store"));
    
    parser.addArgument(new StringArgument(
        null, "scim2-trust-store-type", false, 1,
        "{type}",
        "Trust store type (default: JKS)",
        "JKS"));
    
    // Proxy configuration
    parser.addArgument(new StringArgument(
        null, "scim2-proxy-host", false, 1,
        "{host}",
        "HTTP proxy host"));
    
    parser.addArgument(new StringArgument(
        null, "scim2-proxy-port", false, 1,
        "{port}",
        "HTTP proxy port"));
    
    parser.addArgument(new StringArgument(
        null, "scim2-proxy-username", false, 1,
        "{username}",
        "HTTP proxy username"));
    
    parser.addArgument(new StringArgument(
        null, "scim2-proxy-password", false, 1,
        "{password}",
        "HTTP proxy password"));
    
    // User/Group mapping
    parser.addArgument(new StringArgument(
        null, "user-lookup-attribute", false, 1,
        "{attribute}",
        "LDAP attribute used to lookup users (e.g., uid, sAMAccountName). " +
        "Must map to SCIM2 userName field. " +
        "Required - can be provided via argument or config file."));
    
    parser.addArgument(new StringArgument(
        null, "group-membership-attributes", false, 0,
        "{attribute}",
        "LDAP attributes that trigger group membership updates (e.g., scim-groups). " +
        "These MUST be real attributes that produce changelog events. " +
        "Virtual attributes like 'memberOf' will NOT work. " +
        "Required - can be provided via argument or config file."));
    
    // Performance optimization
    parser.addArgument(new BooleanArgument(
        null, "disable-group-membership-lookups",
        "Disable querying SCIM2 for current group memberships. " +
        "Use in notification mode with changelog support to improve performance. " +
        "REPLACE operations will use changelog before-values instead of SCIM2 lookups."));
    
    // Retry configuration
    parser.addArgument(new StringArgument(
        null, "scim2-max-retries", false, 1,
        "{count}",
        "Maximum number of retry attempts for failed SCIM2 operations (default: 3)",
        "3"));
    
    parser.addArgument(new StringArgument(
        null, "scim2-retry-delay-ms", false, 1,
        "{milliseconds}",
        "Initial delay between retry attempts in milliseconds (default: 1000). " +
        "Uses exponential backoff.",
        "1000"));
  }
  
  @Override
  public void initializeSyncDestination(
      final SyncServerContext serverContext,
      final SyncDestinationConfig config,
      final ArgumentParser parser) throws EndpointException
  {
    this.serverContext = serverContext;
    
    try {
      // Load shared config file if provided
      FileArgument configFileArg = (FileArgument) parser.getNamedArgument("config-file");
      if (configFileArg != null && configFileArg.isPresent()) {
        configLoader = new ConfigFileLoader(configFileArg.getValue().getAbsolutePath(), serverContext);
        serverContext.debugInfo("Loaded shared configuration from: " + 
                                configFileArg.getValue().getAbsolutePath());
      }
      
      // Get base URL (required) - check both argument name and config file property name
      baseUrl = getConfigValue(parser, "scim2-base-url", "scim2.base.url", null);
      if (baseUrl == null || baseUrl.trim().isEmpty()) {
        throw new RuntimeException("scim2-base-url is required");
      }
      
      // Get paths - check both argument names and config file property names
      userBasePath = getConfigValue(parser, "scim2-user-base", "scim2.user.base", "/Users");
      groupBasePath = getConfigValue(parser, "scim2-group-base", "scim2.group.base", "/Groups");
      
      // Get user lookup attribute (required)
      usernameLookupAttribute = getConfigValue(parser, "user-lookup-attribute", "user.lookup.attribute", null);
      if (usernameLookupAttribute == null || usernameLookupAttribute.trim().isEmpty()) {
        throw new RuntimeException("user-lookup-attribute is required (provide via argument or config file)");
      }
      
      // Get group membership attributes (required)
      StringArgument groupAttrArg = (StringArgument) parser.getNamedArgument("group-membership-attributes");
      List<String> groupAttrList = new ArrayList<>();
      
      // First check command-line arguments
      if (groupAttrArg != null && groupAttrArg.isPresent() && !groupAttrArg.getValues().isEmpty()) {
        groupAttrList = groupAttrArg.getValues();
      }
      // If not provided via argument, check config file
      else if (configLoader != null) {
        String groupAttrValue = configLoader.getProperty("group.membership.attributes");
        if (groupAttrValue != null && !groupAttrValue.trim().isEmpty()) {
          // Split by comma and trim whitespace
          String[] attrs = groupAttrValue.split(",");
          for (String attr : attrs) {
            String trimmed = attr.trim();
            if (!trimmed.isEmpty()) {
              groupAttrList.add(trimmed);
            }
          }
        }
      }
      
      if (groupAttrList.isEmpty()) {
        throw new RuntimeException("group-membership-attributes is required (provide via argument or config file)");
      }
      groupMembershipAttributes = groupAttrList.toArray(new String[0]);
      
      // Get performance options
      BooleanArgument disableLookupsArg = (BooleanArgument) parser.getNamedArgument("disable-group-membership-lookups");
      if (disableLookupsArg != null && disableLookupsArg.isPresent()) {
        disableGroupMembershipLookups = true;
        serverContext.debugInfo("Group membership lookups disabled - using changelog mode");
      }
      
      // Get retry configuration
      String maxRetriesStr = getConfigValue(parser, "scim2-max-retries", "scim2.max.retries", "3");
      String retryDelayStr = getConfigValue(parser, "scim2-retry-delay-ms", "scim2.retry.delay.ms", "1000");
      
      try {
        maxRetries = Integer.parseInt(maxRetriesStr);
        retryDelayMs = Long.parseLong(retryDelayStr);
      } catch (NumberFormatException e) {
        throw new RuntimeException("Invalid retry configuration: " + e.getMessage());
      }
      
      // Initialize SCIM2 client using shared factory
      String authType = "basic";
      if (getConfigValue(parser, "scim2-bearer-token", "scim2.bearer.token", null) != null) {
        authType = "bearer";
      }
      
      clientFactory = new Scim2ClientFactory(
          serverContext, configLoader,
          baseUrl, userBasePath, groupBasePath,
          authType,
          getConfigValue(parser, "scim2-username", "scim2.username", null),
          getConfigValue(parser, "scim2-password", "scim2.password", null),
          getConfigValue(parser, "scim2-bearer-token", "scim2.bearer.token", null),
          getConfigValue(parser, "scim2-trust-store-path", "scim2.trust.store.path", null),
          getConfigValue(parser, "scim2-trust-store-password", "scim2.trust.store.password", null),
          getConfigValue(parser, "scim2-trust-store-type", "scim2.trust.store.type", "JKS"),
          false, // allowUntrustedCertificates
          getConfigValue(parser, "scim2-proxy-host", "scim2.proxy.host", null),
          getConfigValue(parser, "scim2-proxy-port", "scim2.proxy.port", null),
          getConfigValue(parser, "scim2-proxy-username", "scim2.proxy.username", null),
          getConfigValue(parser, "scim2-proxy-password", "scim2.proxy.password", null),
          "HTTP", // proxyType
          30000, // connectTimeoutMs
          60000  // readTimeoutMs
      );
      
      scimService = clientFactory.createScimService();
      jaxrsClient = clientFactory.createJaxrsClient();
      
      // Initialize helper
      memberHelper = new Scim2MemberHelper(scimService, userBasePath, groupBasePath, maxRetries, (int)retryDelayMs);
      
      serverContext.debugInfo("Initialized SCIM2 User Group Membership Destination:");
      serverContext.debugInfo("  Base URL: " + baseUrl);
      serverContext.debugInfo("  User lookup attribute: " + usernameLookupAttribute);
      serverContext.debugInfo("  Group membership attributes: " + Arrays.toString(groupMembershipAttributes));
      serverContext.debugInfo("  Disable lookups: " + disableGroupMembershipLookups);
      serverContext.debugInfo("  Max retries: " + maxRetries);
      serverContext.debugInfo("  Retry delay: " + retryDelayMs + "ms");
      
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize SCIM2 User Group Membership Destination: " + 
                                  e.getMessage(), e);
    }
  }
  
  /**
   * Gets a configuration value from either command-line argument or config file.
   * Command-line arguments take precedence over config file values.
   * 
   * @param parser ArgumentParser with command-line arguments
   * @param argName Command-line argument name
   * @param configPropertyName Config file property name (may differ from argName)
   * @param defaultValue Default value if not found
   * @return The configuration value
   */
  private String getConfigValue(final ArgumentParser parser, final String argName, 
                                 final String configPropertyName, final String defaultValue)
  {
    StringArgument arg = (StringArgument) parser.getNamedArgument(argName);
    
    // Check command-line argument first
    if (arg != null && arg.isPresent()) {
      return arg.getValue();
    }
    
    // Check config file using the config property name
    if (configLoader != null) {
      String value = configLoader.getProperty(configPropertyName);
      if (value != null && !value.trim().isEmpty()) {
        return value;
      }
    }
    
    // Return default
    return defaultValue;
  }
  
  @Override
  public void finalizeSyncDestination()
  {
    if (jaxrsClient != null) {
      try {
        jaxrsClient.close();
      } catch (Exception e) {
        serverContext.debugInfo("Error closing JAX-RS client: " + e.getMessage());
      }
    }
  }
  
  @Override
  public String getCurrentEndpointURL()
  {
    return baseUrl != null ? baseUrl : "not configured";
  }
  
  /**
   * Fetches a user entry and populates it with current group memberships.
   * In standard sync mode, this enables accurate comparison between source and destination.
   */
  @Override
  public List<Entry> fetchEntry(final Entry destEntryMappedFromSrc, final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("fetchEntry called for DN: " + destEntryMappedFromSrc.getDN());
    
    // Note: Filtering is now handled upstream by UserGroupMembershipSourcePlugin
    // This method only processes events that have group membership changes
    
    // Extract username
    String username = null;
    Attribute usernameAttr = destEntryMappedFromSrc.getAttribute(usernameLookupAttribute);
    
    if (usernameAttr != null && usernameAttr.getValue() != null) {
      username = usernameAttr.getValue();
    } else {
      operation.logInfo("fetchEntry - No username found in entry");
      return Arrays.asList();
    }
    
    // Search for corresponding SCIM2 user
    String scim2UserId = memberHelper.findScim2UserId(username, operation);
    if (scim2UserId == null) {
      operation.logInfo("fetchEntry - SCIM2 user not found: " + username);
      return Arrays.asList();
    }
    
    // Create synthetic entry with user details
    Entry syntheticEntry = new Entry(destEntryMappedFromSrc.getDN());
    syntheticEntry.addAttribute(usernameLookupAttribute, username);
    syntheticEntry.addAttribute("scim2UserId", scim2UserId);
    
    // Populate current group memberships from SCIM2
    populateCurrentGroupMemberships(syntheticEntry, scim2UserId, operation);
    
    operation.logInfo("fetchEntry - Fetched user: " + username + " (SCIM2 ID: " + scim2UserId + ")");
    
    return Arrays.asList(syntheticEntry);
  }
  
  /**
   * Populates synthetic entry with current group memberships from SCIM2.
   * Used in standard sync mode for accurate comparison.
   */
  private void populateCurrentGroupMemberships(final Entry syntheticEntry, final String scim2UserId,
      final SyncOperation operation)
  {
    try {
      // Initialize all group membership attributes with empty values
      for (String groupAttr : groupMembershipAttributes) {
        syntheticEntry.addAttribute(groupAttr, new String[0]);
      }
      
      // Skip SCIM2 lookup if disabled
      if (disableGroupMembershipLookups) {
        operation.logInfo("Group membership lookups disabled - skipping population for user " + scim2UserId);
        return;
      }
      
      // Query SCIM2 for current group memberships
      Filter userMemberFilter = Filter.eq("members.value", scim2UserId);
      
      ListResponse<GroupResource> groupSearchResponse = 
          scimService.searchRequest(groupBasePath)
              .filter(userMemberFilter.toString())
              .attributes("id", "displayName") // Optimized - only request essentials
              .invoke(GroupResource.class);
      
      if (groupSearchResponse.getTotalResults() > 0) {
        List<String> currentGroupNames = new ArrayList<String>();
        for (GroupResource group : groupSearchResponse.getResources()) {
          String displayName = group.getDisplayName();
          if (displayName != null && !displayName.trim().isEmpty()) {
            currentGroupNames.add(displayName);
          }
        }
        
        if (!currentGroupNames.isEmpty()) {
          // Add current memberships to first configured attribute
          String primaryGroupAttr = groupMembershipAttributes[0];
          syntheticEntry.setAttribute(primaryGroupAttr, currentGroupNames.toArray(new String[0]));
          
          operation.logInfo("Populated " + currentGroupNames.size() + 
                           " current group memberships for user " + scim2UserId);
        }
      }
      
    } catch (Exception e) {
      operation.logInfo("Error populating current group memberships: " + e.getMessage());
      // Continue with empty attributes - sync will still work
    }
  }
  
  @Override
  public void createEntry(final Entry entryToCreate, final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("createEntry - Not supported for user group membership sync: " + 
                     entryToCreate.getDN());
  }
  
  /**
   * Processes user entry modifications to detect and sync group membership changes.
   * Handles ADD, DELETE, and REPLACE operations for trigger attributes.
   */
  @Override
  public void modifyEntry(final Entry entryToModify, final List<Modification> modsToApply,
      final SyncOperation operation) throws EndpointException
  {
    operation.logInfo("modifyEntry called for DN: " + entryToModify.getDN() + 
                     " with " + modsToApply.size() + " modifications");
    
    // OPTIMIZATION: Check if any modifications are for group membership attributes
    // Avoid expensive SCIM2 user lookup if no group membership changes
    boolean hasGroupMembershipChanges = false;
    for (Modification mod : modsToApply) {
      if (isGroupMembershipModification(mod)) {
        hasGroupMembershipChanges = true;
        break;
      }
    }
    
    if (!hasGroupMembershipChanges) {
      operation.logInfo("modifyEntry - No group membership modifications found - skipping SCIM2 processing");
      return;
    }
    
    // Get username and SCIM2 user ID (only when needed)
    String username = null;
    String scim2UserId = null;
    
    // Try synthetic entry (standard mode)
    Attribute userAttr = entryToModify.getAttribute(usernameLookupAttribute);
    if (userAttr != null && userAttr.getValue() != null) {
      username = userAttr.getValue();
    }
    
    Attribute scim2UserIdAttr = entryToModify.getAttribute("scim2UserId");
    if (scim2UserIdAttr != null && scim2UserIdAttr.getValue() != null) {
      scim2UserId = scim2UserIdAttr.getValue();
    } else if (username != null) {
      // Notification mode - lookup SCIM2 user ID
      scim2UserId = memberHelper.findScim2UserId(username, operation);
    }
    
    if (username == null || scim2UserId == null) {
      operation.logInfo("Skipping entry - missing username or SCIM2 user ID");
      return;
    }
    
    // Process each group membership modification
    for (Modification mod : modsToApply) {
      if (isGroupMembershipModification(mod)) {
        processGroupMembershipModification(mod, scim2UserId, operation);
      }
    }
    
    operation.logInfo("Processed group membership changes for user: " + username);
  }
  
  /**
   * Checks if a modification is for a group membership trigger attribute.
   */
  private boolean isGroupMembershipModification(final Modification modification)
  {
    String attrName = modification.getAttributeName();
    for (String groupAttr : groupMembershipAttributes) {
      if (groupAttr.equalsIgnoreCase(attrName)) {
        return true;
      }
    }
    return false;
  }
  
  /**
   * Processes group membership modification by routing to appropriate handler.
   * Handles ADD, DELETE, and REPLACE operations.
   */
  private void processGroupMembershipModification(final Modification modification,
      final String scim2UserId, final SyncOperation operation) throws EndpointException
  {
    ModificationType modType = modification.getModificationType();
    String[] values = modification.getValues();
    
    if (ModificationType.REPLACE.equals(modType)) {
      // REPLACE: Ensure exact match with source
      processGroupMembershipReplace(modification.getAttributeName(), values, scim2UserId, operation);
      return;
    }
    
    if (ModificationType.DELETE.equals(modType) && (values == null || values.length == 0)) {
      // DELETE all: Remove from all groups for this attribute
      operation.logInfo("Processing DELETE all for attribute: " + modification.getAttributeName());
      processDeleteAllGroupMemberships(modification.getAttributeName(), scim2UserId, operation);
      return;
    }
    
    // Handle ADD and DELETE with specific values
    if (values == null || values.length == 0) {
      return;
    }
    
    for (String groupName : values) {
      if (groupName == null || groupName.trim().isEmpty()) {
        continue;
      }
      
      groupName = groupName.trim();
      String scim2GroupId = memberHelper.findScim2GroupId(groupName, operation);
      
      if (scim2GroupId == null) {
        operation.logInfo("Skipping group - not found in SCIM2: " + groupName);
        continue;
      }
      
      try {
        if (ModificationType.ADD.equals(modType)) {
          addUserToScim2Group(scim2GroupId, scim2UserId, operation);
          operation.logInfo("Added user to group: " + groupName);
        } else if (ModificationType.DELETE.equals(modType)) {
          removeUserFromScim2Group(scim2GroupId, scim2UserId, operation);
          operation.logInfo("Removed user from group: " + groupName);
        }
      } catch (Exception e) {
        operation.logInfo("Error processing group " + groupName + ": " + e.getMessage());
        throw new RuntimeException("Error processing group membership", e);
      }
    }
  }
  
  /**
   * Processes REPLACE operation by calculating diff and updating SCIM2.
   * Adds user to new groups and removes from old groups.
   */
  private void processGroupMembershipReplace(final String attributeName, final String[] newGroupNames,
      final String scim2UserId, final SyncOperation operation) throws EndpointException
  {
    // Get current group memberships
    List<String> currentGroups = getCurrentGroupMembershipsForReplace(attributeName, scim2UserId, operation);
    
    // Build target group list
    List<String> targetGroups = new ArrayList<String>();
    if (newGroupNames != null) {
      for (String groupName : newGroupNames) {
        if (groupName != null && !groupName.trim().isEmpty()) {
          targetGroups.add(groupName.trim());
        }
      }
    }
    
    // Calculate diff
    List<String> groupsToAdd = new ArrayList<String>(targetGroups);
    groupsToAdd.removeAll(currentGroups);
    
    List<String> groupsToRemove = new ArrayList<String>(currentGroups);
    groupsToRemove.removeAll(targetGroups);
    
    operation.logInfo("REPLACE for " + attributeName + ": adding " + groupsToAdd.size() + 
                     " groups, removing " + groupsToRemove.size() + " groups");
    
    // Add to new groups
    for (String groupName : groupsToAdd) {
      String scim2GroupId = memberHelper.findScim2GroupId(groupName, operation);
      if (scim2GroupId != null) {
        try {
          addUserToScim2Group(scim2GroupId, scim2UserId, operation);
          operation.logInfo("Added user to group: " + groupName);
        } catch (Exception e) {
          operation.logInfo("Error adding to group " + groupName + ": " + e.getMessage());
        }
      }
    }
    
    // Remove from old groups
    for (String groupName : groupsToRemove) {
      String scim2GroupId = memberHelper.findScim2GroupId(groupName, operation);
      if (scim2GroupId != null) {
        try {
          removeUserFromScim2Group(scim2GroupId, scim2UserId, operation);
          operation.logInfo("Removed user from group: " + groupName);
        } catch (Exception e) {
          operation.logInfo("Error removing from group " + groupName + ": " + e.getMessage());
        }
      }
    }
  }
  
  /**
   * Processes DELETE all operation - removes user from all current groups.
   */
  private void processDeleteAllGroupMemberships(final String attributeName, final String scim2UserId,
      final SyncOperation operation) throws EndpointException
  {
    List<String> currentGroups = getCurrentGroupMembershipsForAttribute(attributeName, scim2UserId, operation);
    
    if (currentGroups.isEmpty()) {
      operation.logInfo("User has no current group memberships for " + attributeName);
      return;
    }
    
    operation.logInfo("DELETE all for " + attributeName + ": removing from " + 
                     currentGroups.size() + " groups");
    
    for (String groupName : currentGroups) {
      String scim2GroupId = memberHelper.findScim2GroupId(groupName, operation);
      if (scim2GroupId != null) {
        try {
          removeUserFromScim2Group(scim2GroupId, scim2UserId, operation);
          operation.logInfo("Removed user from group: " + groupName);
        } catch (Exception e) {
          operation.logInfo("Error removing from group " + groupName + ": " + e.getMessage());
        }
      }
    }
  }
  
  /**
   * Gets current group memberships for REPLACE operations.
   * In notification mode with lookups disabled, uses changelog before-values.
   */
  private List<String> getCurrentGroupMembershipsForReplace(final String attributeName,
      final String scim2UserId, final SyncOperation operation)
  {
    if (disableGroupMembershipLookups) {
      List<String> beforeGroups = getBeforeGroupsFromChangelog(attributeName, operation);
      if (beforeGroups != null) {
        operation.logInfo("Using changelog before values - found " + beforeGroups.size() + " groups");
        return beforeGroups;
      }
      operation.logInfo("No changelog values - returning empty list");
      return new ArrayList<String>();
    }
    
    return getCurrentGroupMembershipsForAttribute(attributeName, scim2UserId, operation);
  }
  
  /**
   * Retrieves current group memberships by querying SCIM2.
   * Optimized to request only essential attributes.
   */
  private List<String> getCurrentGroupMembershipsForAttribute(final String attributeName,
      final String scim2UserId, final SyncOperation operation)
  {
    List<String> currentGroups = new ArrayList<String>();
    
    if (disableGroupMembershipLookups) {
      operation.logInfo("Group membership lookups disabled - returning empty list");
      return currentGroups;
    }
    
    try {
      Filter userMemberFilter = Filter.eq("members.value", scim2UserId);
      
      ListResponse<GroupResource> groupSearchResponse = 
          scimService.searchRequest(groupBasePath)
              .filter(userMemberFilter.toString())
              .attributes("id", "displayName") // Optimized
              .invoke(GroupResource.class);
      
      if (groupSearchResponse.getTotalResults() > 0) {
        for (GroupResource group : groupSearchResponse.getResources()) {
          String displayName = group.getDisplayName();
          if (displayName != null && !displayName.trim().isEmpty()) {
            currentGroups.add(displayName);
          }
        }
      }
      
      operation.logInfo("Found " + currentGroups.size() + " current groups for " + attributeName);
      
    } catch (Exception e) {
      operation.logInfo("Error retrieving current groups: " + e.getMessage());
    }
    
    return currentGroups;
  }
  
  /**
   * Extracts before-values from changelog for REPLACE operations.
   * Used in notification mode when lookups are disabled.
   */
  private List<String> getBeforeGroupsFromChangelog(final String attributeName,
      final SyncOperation operation)
  {
    try {
      ChangeLogEntry changeLogEntry = operation.getChangeLogEntry();
      if (changeLogEntry != null) {
        Attribute beforeValuesAttr = changeLogEntry.getAttribute("ds-changelog-before-values");
        if (beforeValuesAttr != null) {
          List<String> beforeGroups = new ArrayList<String>();
          
          // Parse format: "attribute: value\nattribute: value"
          for (String beforeValue : beforeValuesAttr.getValues()) {
            if (beforeValue.startsWith(attributeName + ":")) {
              String groupName = beforeValue.substring(attributeName.length() + 1).trim();
              if (!groupName.isEmpty()) {
                beforeGroups.add(groupName);
              }
            }
          }
          
          if (!beforeGroups.isEmpty()) {
            operation.logInfo("Extracted " + beforeGroups.size() + " before groups from changelog");
            return beforeGroups;
          }
        }
      }
    } catch (Exception e) {
      operation.logInfo("Error extracting before groups from changelog: " + e.getMessage());
    }
    
    return null;
  }
  
  @Override
  public void deleteEntry(final Entry entryToDelete, final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("deleteEntry - Not supported for user group membership sync: " + 
                     entryToDelete.getDN());
  }
  
  /**
   * Adds a user to a SCIM2 group using PATCH operation.
   */
  private void addUserToScim2Group(final String groupId, final String userId,
      final SyncOperation operation) throws Exception
  {
    try {
      // Use PATCH operation to add member
      String patchJson = createAddMemberPatchJson(userId);
      
      jakarta.ws.rs.client.Client client = clientFactory.createJaxrsClient();
      jakarta.ws.rs.client.WebTarget target = client.target(baseUrl + groupBasePath + "/" + groupId);
      jakarta.ws.rs.core.Response response = target.request("application/scim+json")
          .method("PATCH", jakarta.ws.rs.client.Entity.entity(patchJson, "application/scim+json"));
      
      if (response.getStatus() >= 200 && response.getStatus() < 300) {
        operation.logInfo("Added user " + userId + " to group " + groupId);
      } else {
        String errorBody = response.hasEntity() ? response.readEntity(String.class) : "No response body";
        throw new RuntimeException("PATCH request failed with status: " + response.getStatus() + 
                               " - " + errorBody);
      }
      response.close();
      client.close();
      
    } catch (Exception e) {
      operation.logInfo("Error adding user " + userId + " to group " + groupId + ": " + e.getMessage());
      throw e;
    }
  }
  
  /**
   * Removes a user from a SCIM2 group using PATCH operation.
   */
  private void removeUserFromScim2Group(final String groupId, final String userId,
      final SyncOperation operation) throws Exception
  {
    try {
      // Use PATCH operation to remove member
      String patchJson = createRemoveMemberPatchJson(userId);
      
      jakarta.ws.rs.client.Client client = clientFactory.createJaxrsClient();
      jakarta.ws.rs.client.WebTarget target = client.target(baseUrl + groupBasePath + "/" + groupId);
      jakarta.ws.rs.core.Response response = target.request("application/scim+json")
          .method("PATCH", jakarta.ws.rs.client.Entity.entity(patchJson, "application/scim+json"));
      
      if (response.getStatus() >= 200 && response.getStatus() < 300) {
        operation.logInfo("Removed user " + userId + " from group " + groupId);
      } else {
        String errorBody = response.hasEntity() ? response.readEntity(String.class) : "No response body";
        throw new RuntimeException("PATCH request failed with status: " + response.getStatus() + 
                               " - " + errorBody);
      }
      response.close();
      client.close();
      
    } catch (Exception e) {
      operation.logInfo("Error removing user " + userId + " from group " + groupId + ": " + e.getMessage());
      throw e;
    }
  }
  
  /**
   * Creates JSON for PATCH operation to add a member.
   */
  private String createAddMemberPatchJson(final String userId) throws Exception
  {
    return "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"]," +
           "\"Operations\":[{\"op\":\"add\",\"path\":\"members\"," +
           "\"value\":[{\"value\":\"" + userId + "\"}]}]}";
  }
  
  /**
   * Creates JSON for PATCH operation to remove a member.
   */
  private String createRemoveMemberPatchJson(final String userId) throws Exception
  {
    return "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"]," +
           "\"Operations\":[{\"op\":\"remove\",\"path\":\"members[value eq \\\"" + 
           userId + "\\\"]\"}]}";
  }
}

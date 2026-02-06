/*
 * Copyright 2025 Jeremy Heer
 * Licensed under the Apache License, Version 2.0
 */
package com.heer.sync;

import com.unboundid.directory.sdk.sync.api.SyncDestination;
import com.unboundid.directory.sdk.sync.config.SyncDestinationConfig;
import com.unboundid.directory.sdk.sync.types.EndpointException;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;

import com.unboundid.scim2.client.ScimService;
import com.unboundid.scim2.common.exceptions.ResourceNotFoundException;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.messages.ListResponse;
import com.unboundid.scim2.common.types.Email;
import com.unboundid.scim2.common.types.Name;
import com.unboundid.scim2.common.types.UserResource;

import com.heer.sync.lib.ConfigFileLoader;
import com.heer.sync.lib.scim2.Scim2ClientFactory;
import com.heer.sync.lib.scim2.Scim2MemberHelper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Custom SCIM2 destination for Users-Basic-CRUD sync pipe.
 * <p>
 * This destination plugin handles user CREATE, UPDATE, and DELETE operations with
 * configurable SCIM2 attribute mappings and user lifecycle management.
 * </p>
 * 
 * <h2>User Lifecycle Management:</h2>
 * <p>
 * Supports two modes controlled by user.lifecycle.mode property:
 * </p>
 * <ul>
 *   <li><b>dynamic-group-memberships:</b> Users scoped by group.membership.attributes presence.
 *       Users deleted when all values removed from all configured attributes.</li>
 *   <li><b>static-group-memberships:</b> Users scoped by membership in groups matching group.filter.
 *       Users deleted when removed from all in-scope groups (checked via isMemberOf).</li>
 * </ul>
 * 
 * <h2>SCIM Attribute Mapping:</h2>
 * <p>
 * Configurable via scim.user.attributes and scim.user.map.* properties:
 * </p>
 * <pre>
 * scim.user.attributes=userName,name.formatted,name.familyName,name.givenName,displayName
 * scim.user.map.userName=uid
 * scim.user.map.name.formatted=cn
 * scim.user.map.name.familyName=sn
 * scim.user.map.name.givenName=givenName
 * scim.user.map.displayName=displayName
 * </pre>
 * 
 * @author Jeremy Heer
 */
public class UserBasicCrudDestination extends SyncDestination
{
  private SyncServerContext serverContext;
  
  // SCIM2 client components
  private Scim2ClientFactory clientFactory;
  private jakarta.ws.rs.client.Client jaxrsClient;
  private ScimService scimService;
  
  // Configuration
  private ConfigFileLoader configLoader;
  private String baseUrl;
  private String userBasePath = "/Users";
  private String groupBasePath = "/Groups";
  private String usernameLookupAttribute;
  private String userLifecycleMode;
  private String[] groupMembershipAttributes;
  private Filter groupFilter;
  
  // Helper utilities
  private Scim2MemberHelper memberHelper;
  
  // SCIM attribute mappings
  private String[] scimUserAttributes;
  private Map<String, String> scimUserMappings;
  
  // Retry configuration
  private int maxRetries = 3;
  private long retryDelayMs = 1000;
  
  @Override
  public String getExtensionName()
  {
    return "SCIM2 User Basic CRUD Destination";
  }
  
  @Override
  public String[] getExtensionDescription()
  {
    return new String[] {
      "Custom SCIM2 destination for Users-Basic-CRUD pipe with lifecycle management.",
      "",
      "Features:",
      "- Configurable SCIM2 attribute mappings from LDAP",
      "- User lifecycle management (dynamic-group-memberships or static-group-memberships)",
      "- Automatic user deletion when out of scope",
      "- Resync support with scope validation",
      "",
      "Configuration example:",
      "user.lifecycle.mode=static-group-memberships",
      "scim.user.attributes=userName,name.formatted,name.familyName,name.givenName",
      "scim.user.map.userName=uid",
      "scim.user.map.name.formatted=cn",
      "scim.user.map.name.familyName=sn",
      "scim.user.map.name.givenName=givenName"
    };
  }
  
  @Override
  public void defineConfigArguments(final ArgumentParser parser) throws ArgumentException
  {
    // Shared config file
    parser.addArgument(new FileArgument(
        null, "config-file", true, 1,
        "{path}",
        "Path to shared configuration properties file containing SCIM2 connection settings, " +
        "attribute mappings, and lifecycle configuration.",
        true, true, true, false));
    
    // SCIM2 endpoint configuration
    parser.addArgument(new StringArgument(
        null, "scim2-base-url", false, 1,
        "{url}",
        "The base URL of the SCIM2 endpoint (e.g., https://example.com/scim/v2). " +
        "Can be provided via config file."));
    
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
    
    // User lookup attribute
    parser.addArgument(new StringArgument(
        null, "user-lookup-attribute", false, 1,
        "{attribute}",
        "LDAP attribute used to lookup users in SCIM2 (maps to userName field). " +
        "Required - can be provided via config file."));
  }
  
  @Override
  public void initializeSyncDestination(
      final SyncServerContext serverContext,
      final SyncDestinationConfig config,
      final ArgumentParser parser) throws EndpointException
  {
    this.serverContext = serverContext;
    
    try {
      // Load shared config file
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
      
      // Get user lookup attribute
      usernameLookupAttribute = getConfigValue(parser, "user-lookup-attribute", "user.lookup.attribute", null);
      if (usernameLookupAttribute == null || usernameLookupAttribute.trim().isEmpty()) {
        throw new RuntimeException("user-lookup-attribute is required");
      }
      
      // Load user lifecycle configuration
      userLifecycleMode = configLoader.getProperty("user.lifecycle.mode", "dynamic-group-memberships");
      
      // Load group membership attributes (for dynamic-group-memberships mode)
      String groupMembershipAttrStr = configLoader.getProperty("group.membership.attributes");
      if (groupMembershipAttrStr != null && !groupMembershipAttrStr.trim().isEmpty()) {
        groupMembershipAttributes = configLoader.getPropertyList("group.membership.attributes");
      } else {
        groupMembershipAttributes = new String[0];
      }
      
      // Load group filter (for static-group-memberships mode)
      String groupFilterStr = configLoader.getProperty("group.filter");
      if (groupFilterStr != null && !groupFilterStr.trim().isEmpty()) {
        try {
          groupFilter = Filter.create(groupFilterStr);
        } catch (Exception e) {
          serverContext.debugWarning("Invalid group.filter: " + e.getMessage());
          groupFilter = null;
        }
      }
      
      // Load SCIM user attributes
      scimUserAttributes = configLoader.getPropertyList("scim.user.attributes");
      scimUserMappings = configLoader.getPropertyMap("scim.user.map.");
      
      // Get retry configuration
      maxRetries = configLoader.getIntProperty("scim2.max.retries", 3);
      retryDelayMs = configLoader.getIntProperty("scim2.retry.delay.ms", 1000);
      
      // Initialize SCIM2 client
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
          false,
          getConfigValue(parser, "scim2-proxy-host", "scim2.proxy.host", null),
          getConfigValue(parser, "scim2-proxy-port", "scim2.proxy.port", null),
          getConfigValue(parser, "scim2-proxy-username", "scim2.proxy.username", null),
          getConfigValue(parser, "scim2-proxy-password", "scim2.proxy.password", null),
          "HTTP",
          30000,
          60000
      );
      
      scimService = clientFactory.createScimService();
      jaxrsClient = clientFactory.createJaxrsClient();
      
      // Initialize helper
      memberHelper = new Scim2MemberHelper(scimService, userBasePath, groupBasePath, maxRetries, (int)retryDelayMs);
      
      serverContext.debugInfo("Initialized SCIM2 User Basic CRUD Destination:");
      serverContext.debugInfo("  Base URL: " + baseUrl);
      serverContext.debugInfo("  User lookup attribute: " + usernameLookupAttribute);
      serverContext.debugInfo("  Lifecycle mode: " + userLifecycleMode);
      serverContext.debugInfo("  SCIM attributes: " + Arrays.toString(scimUserAttributes));
      
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize SCIM2 User Basic CRUD Destination: " + 
                                  e.getMessage(), e);
    }
  }
  
  private String getConfigValue(final ArgumentParser parser, final String argName, 
                                 final String configPropertyName, final String defaultValue)
  {
    StringArgument arg = (StringArgument) parser.getNamedArgument(argName);
    return configLoader.getValueWithFallback(arg, configPropertyName, defaultValue);
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
  
  @Override
  public List<Entry> fetchEntry(final Entry destEntryMappedFromSrc, final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("fetchEntry called for DN: " + destEntryMappedFromSrc.getDN());
    
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
    try {
      com.unboundid.scim2.common.filters.Filter filter = 
          com.unboundid.scim2.common.filters.Filter.eq("userName", username);
      
      ListResponse<UserResource> searchResponse = 
          scimService.searchRequest(userBasePath)
              .filter(filter.toString())
              .page(1, 1)
              .invoke(UserResource.class);
      
      if (searchResponse.getTotalResults() > 0) {
        UserResource user = searchResponse.getResources().get(0);
        
        // Create synthetic entry with user details
        Entry syntheticEntry = new Entry(destEntryMappedFromSrc.getDN());
        syntheticEntry.addAttribute(usernameLookupAttribute, username);
        syntheticEntry.addAttribute("scim2UserId", user.getId());
        
        // Add mapped attributes
        for (String scimAttr : scimUserAttributes) {
          String value = getScimAttributeValue(user, scimAttr);
          if (value != null) {
            syntheticEntry.addAttribute(scimAttr, value);
          }
        }
        
        operation.logInfo("fetchEntry - Found user: " + username + " (ID: " + user.getId() + ")");
        return Arrays.asList(syntheticEntry);
      }
      
      operation.logInfo("fetchEntry - User not found: " + username);
      return Arrays.asList();
      
    } catch (Exception e) {
      operation.logInfo("fetchEntry - Error searching for user: " + e.getMessage());
      return Arrays.asList();
    }
  }
  
  @Override
  public void createEntry(final Entry entryToCreate, final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("createEntry called for DN: " + entryToCreate.getDN());
    
    // Check if user is in scope before creating
    if (!isUserInScope(entryToCreate, operation)) {
      operation.logInfo("User not in scope - skipping creation: " + entryToCreate.getDN());
      return;
    }
    
    try {
      // Build UserResource from LDAP entry
      UserResource user = buildUserResource(entryToCreate, operation);
      
      // Create user in SCIM2
      UserResource created = scimService.create(userBasePath, user);
      
      operation.logInfo("Created user: " + created.getUserName() + " (ID: " + created.getId() + ")");
      
    } catch (ScimException e) {
      if (e.getScimError() != null && e.getScimError().getStatus() == 409) {
        operation.logInfo("User already exists (409 Conflict) - skipping creation");
      } else {
        operation.logInfo("Error creating user: " + e.getMessage());
        throw new RuntimeException("Failed to create user", e);
      }
    } catch (Exception e) {
      operation.logInfo("Error creating user: " + e.getMessage());
      throw new RuntimeException("Failed to create user", e);
    }
  }
  
  @Override
  public void modifyEntry(final Entry entryToModify, final List<Modification> modsToApply,
      final SyncOperation operation) throws EndpointException
  {
    operation.logInfo("modifyEntry called for DN: " + entryToModify.getDN());
    
    // Check if user is still in scope using source entry (not destination synthetic entry)
    // The source entry contains all LDAP attributes including group membership attributes
    Entry sourceEntry = operation.getSourceEntry();
    if (sourceEntry == null) {
      // Should not happen in standard sync mode, but handle gracefully
      operation.logInfo("WARNING: Source entry not available - assuming user stays in scope");
    } else {
      operation.logInfo("Checking scope using source entry with all LDAP attributes");
      if (!isUserInScope(sourceEntry, operation)) {
        operation.logInfo("User no longer in scope - will be deleted");
        deleteUserIfExists(entryToModify, operation);
        return;
      }
    }
    
    // Extract username
    String username = null;
    Attribute usernameAttr = entryToModify.getAttribute(usernameLookupAttribute);
    if (usernameAttr != null && usernameAttr.getValue() != null) {
      username = usernameAttr.getValue();
    }
    
    if (username == null) {
      operation.logInfo("No username found - skipping modify");
      return;
    }
    
    try {
      // Find existing user
      String userId = memberHelper.findScim2UserId(username, operation);
      if (userId == null) {
        operation.logInfo("User not found in SCIM2 - skipping modify: " + username);
        return;
      }
      
      // Retrieve current user
      UserResource user = scimService.retrieve(userBasePath, userId, UserResource.class);
      
      // Apply modifications
      boolean modified = false;
      for (Modification mod : modsToApply) {
        String attrName = mod.getAttributeName();
        
        // Find SCIM attribute for this LDAP attribute
        String scimAttr = null;
        for (Map.Entry<String, String> mapping : scimUserMappings.entrySet()) {
          if (mapping.getValue().equalsIgnoreCase(attrName)) {
            scimAttr = mapping.getKey();
            break;
          }
        }
        
        if (scimAttr != null && mod.getValues() != null && mod.getValues().length > 0) {
          String newValue = mod.getValues()[0];
          setScimAttributeValue(user, scimAttr, newValue);
          modified = true;
          operation.logInfo("Updated " + scimAttr + " = " + newValue);
        }
      }
      
      if (modified) {
        scimService.replace(user);
        operation.logInfo("Updated user: " + username);
      }
      
    } catch (Exception e) {
      operation.logInfo("Error modifying user: " + e.getMessage());
      throw new RuntimeException("Failed to modify user", e);
    }
  }
  
  @Override
  public void deleteEntry(final Entry entryToDelete, final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("deleteEntry called for DN: " + entryToDelete.getDN());
    
    // Extract username
    String username = null;
    Attribute usernameAttr = entryToDelete.getAttribute(usernameLookupAttribute);
    if (usernameAttr != null && usernameAttr.getValue() != null) {
      username = usernameAttr.getValue();
    }
    
    if (username == null) {
      operation.logInfo("No username found - skipping delete");
      return;
    }
    
    try {
      String userId = memberHelper.findScim2UserId(username, operation);
      if (userId != null) {
        // Remove user from all groups before deletion
        removeUserFromAllGroups(userId, username, operation);
        
        // Delete the user
        scimService.delete(userBasePath, userId);
        operation.logInfo("Deleted user: " + username + " (ID: " + userId + ")");
      } else {
        operation.logInfo("User not found in SCIM2 - skipping delete: " + username);
      }
    } catch (ResourceNotFoundException e) {
      operation.logInfo("User already deleted - skipping: " + username);
    } catch (Exception e) {
      operation.logInfo("Error deleting user: " + e.getMessage());
      throw new RuntimeException("Failed to delete user", e);
    }
  }
  
  /**
   * Removes user from all groups before deletion.
   */
  private void removeUserFromAllGroups(final String userId, final String username,
      final SyncOperation operation)
  {
    try {
      // Query for all groups the user is a member of
      com.unboundid.scim2.common.filters.Filter userMemberFilter = 
          com.unboundid.scim2.common.filters.Filter.eq("members.value", userId);
      
      ListResponse<com.unboundid.scim2.common.types.GroupResource> groupSearchResponse = 
          scimService.searchRequest(groupBasePath)
              .filter(userMemberFilter.toString())
              .attributes("id", "displayName")
              .invoke(com.unboundid.scim2.common.types.GroupResource.class);
      
      if (groupSearchResponse.getTotalResults() > 0) {
        operation.logInfo("Removing user " + username + " from " + 
                         groupSearchResponse.getTotalResults() + " groups before deletion");
        
        for (com.unboundid.scim2.common.types.GroupResource group : groupSearchResponse.getResources()) {
          try {
            removeUserFromGroup(group.getId(), userId, operation);
            operation.logInfo("Removed user from group: " + group.getDisplayName());
          } catch (Exception e) {
            operation.logInfo("Warning: Failed to remove user from group " + 
                             group.getDisplayName() + ": " + e.getMessage());
            // Continue with other groups
          }
        }
      } else {
        operation.logInfo("User " + username + " is not a member of any groups");
      }
    } catch (Exception e) {
      operation.logInfo("Warning: Error querying user's group memberships: " + e.getMessage());
      // Continue with user deletion even if group cleanup fails
    }
  }
  
  /**
   * Removes user from a specific group using PATCH operation.
   */
  private void removeUserFromGroup(final String groupId, final String userId,
      final SyncOperation operation) throws Exception
  {
    memberHelper.removeUserFromGroup(groupId, userId, baseUrl, operation);
  }
  
  /**
   * Checks if user is in scope based on lifecycle mode.
   */
  private boolean isUserInScope(final Entry entry, final SyncOperation operation)
  {
    if ("dynamic-group-memberships".equalsIgnoreCase(userLifecycleMode)) {
      // Check if user has any group membership attributes with values
      for (String attrName : groupMembershipAttributes) {
        Attribute attr = entry.getAttribute(attrName);
        if (attr != null && attr.hasValue()) {
          return true;
        }
      }
      operation.logInfo("User not in scope (dynamic): no group membership attributes");
      return false;
      
    } else if ("static-group-memberships".equalsIgnoreCase(userLifecycleMode)) {
      // Check if user is member of any groups matching group.filter
      if (groupFilter != null) {
        Attribute isMemberOf = entry.getAttribute("isMemberOf");
        
        if (isMemberOf != null) {
          String[] groupDNs = isMemberOf.getValues();
          if (groupDNs != null) {
            for (String groupDNStr : groupDNs) {
              try {
                // Parse the group DN and extract CN
                DN groupDN = new DN(groupDNStr);
                RDN rdn = groupDN.getRDN();
                if (rdn != null) {
                  String cn = rdn.getAttributeValues()[0];
                  
                  // Create a synthetic entry with just the CN to test against filter
                  Entry testEntry = new Entry(groupDNStr);
                  testEntry.addAttribute("cn", cn);
                  
                  // Test if this group matches the filter
                  if (groupFilter.matchesEntry(testEntry)) {
                    operation.logInfo("User in scope (static): member of matching group " + cn);
                    return true;
                  }
                }
              } catch (Exception e) {
                operation.logInfo("Warning: Could not parse group DN: " + groupDNStr + " - " + e.getMessage());
                // Continue checking other groups
              }
            }
          }
        }
        operation.logInfo("User not in scope (static): not member of any in-scope groups");
        return false;
      }
      // No filter means all users are in scope
      return true;
    }
    
    // Default: in scope
    return true;
  }
  
  /**
   * Deletes user if exists in SCIM2.
   */
  private void deleteUserIfExists(final Entry entry, final SyncOperation operation)
  {
    try {
      String username = null;
      Attribute usernameAttr = entry.getAttribute(usernameLookupAttribute);
      if (usernameAttr != null && usernameAttr.getValue() != null) {
        username = usernameAttr.getValue();
      }
      
      if (username != null) {
        String userId = memberHelper.findScim2UserId(username, operation);
        if (userId != null) {
          scimService.delete(userBasePath, userId);
          operation.logInfo("Deleted out-of-scope user: " + username);
        }
      }
    } catch (Exception e) {
      operation.logInfo("Error deleting out-of-scope user: " + e.getMessage());
    }
  }
  
  /**
   * Builds a SCIM2 UserResource from LDAP entry.
   */
  private UserResource buildUserResource(final Entry entry, final SyncOperation operation)
  {
    UserResource user = new UserResource();
    
    // Set userName (required)
    String username = entry.getAttributeValue(usernameLookupAttribute);
    if (username != null) {
      user.setUserName(username);
    }
    
    // Map other attributes
    for (String scimAttr : scimUserAttributes) {
      String ldapAttr = scimUserMappings.get(scimAttr);
      if (ldapAttr != null) {
        String value = entry.getAttributeValue(ldapAttr);
        if (value != null) {
          setScimAttributeValue(user, scimAttr, value);
        }
      }
    }
    
    return user;
  }
  
  /**
   * Gets SCIM attribute value from UserResource.
   */
  private String getScimAttributeValue(final UserResource user, final String scimAttr)
  {
    if ("userName".equals(scimAttr)) {
      return user.getUserName();
    } else if ("displayName".equals(scimAttr)) {
      return user.getDisplayName();
    } else if (scimAttr.startsWith("name.")) {
      Name name = user.getName();
      if (name != null) {
        String subAttr = scimAttr.substring(5);
        if ("formatted".equals(subAttr)) return name.getFormatted();
        if ("familyName".equals(subAttr)) return name.getFamilyName();
        if ("givenName".equals(subAttr)) return name.getGivenName();
        if ("middleName".equals(subAttr)) return name.getMiddleName();
      }
    } else if (scimAttr.startsWith("emails.")) {
      List<Email> emails = user.getEmails();
      if (emails != null && !emails.isEmpty()) {
        return emails.get(0).getValue();
      }
    }
    return null;
  }
  
  /**
   * Sets SCIM attribute value on UserResource.
   */
  private void setScimAttributeValue(final UserResource user, final String scimAttr, final String value)
  {
    if ("userName".equals(scimAttr)) {
      user.setUserName(value);
    } else if ("displayName".equals(scimAttr)) {
      user.setDisplayName(value);
    } else if (scimAttr.startsWith("name.")) {
      Name name = user.getName();
      if (name == null) {
        name = new Name();
        user.setName(name);
      }
      String subAttr = scimAttr.substring(5);
      if ("formatted".equals(subAttr)) name.setFormatted(value);
      if ("familyName".equals(subAttr)) name.setFamilyName(value);
      if ("givenName".equals(subAttr)) name.setGivenName(value);
      if ("middleName".equals(subAttr)) name.setMiddleName(value);
    } else if (scimAttr.startsWith("emails.")) {
      Email email = new Email();
      email.setValue(value);
      email.setPrimary(true);
      user.setEmails(Arrays.asList(email));
    }
  }
}

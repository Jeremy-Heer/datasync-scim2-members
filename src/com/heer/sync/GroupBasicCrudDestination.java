/*
 * Copyright 2025 Corp Heer
 */

package com.heer.sync;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.unboundid.directory.sdk.sync.api.SyncDestination;
import com.unboundid.directory.sdk.sync.config.SyncDestinationConfig;
import com.unboundid.directory.sdk.sync.types.EndpointException;
import com.unboundid.directory.sdk.sync.types.SetStartpointOptions;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.scim2.client.ScimService;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.filters.Filter;
import com.unboundid.scim2.common.types.GroupResource;
import com.unboundid.scim2.common.utils.JsonUtils;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;

import com.heer.sync.lib.ConfigFileLoader;
import com.heer.sync.lib.scim2.Scim2ClientFactory;
import com.heer.sync.lib.scim2.Scim2MemberHelper;

import jakarta.ws.rs.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * SCIM2 Group Basic CRUD Destination Plugin.
 * 
 * <p>This plugin handles CREATE, UPDATE, and DELETE operations for groups in SCIM2.
 * It supports configurable attribute mappings from LDAP group entries to SCIM2 GroupResource objects.</p>
 * 
 * <h2>Key Features:</h2>
 * <ul>
 *   <li>CREATE: Creates new groups in SCIM2 with mapped attributes</li>
 *   <li>UPDATE: Modifies existing group attributes (non-membership changes)</li>
 *   <li>DELETE: Removes groups from SCIM2</li>
 *   <li>Configurable attribute mappings via scim.group.map.* properties</li>
 * </ul>
 * 
 * <h2>Configuration:</h2>
 * <pre>
 * scim.group.attributes=cn,description
 * scim.group.map.displayName=cn
 * scim.group.map.externalId=entryUUID
 * </pre>
 * 
 * <h2>Sync Pipe Architecture:</h2>
 * <p>This destination works with group source plugins that filter and prepare group entries
 * for synchronization. Member management should be handled by separate sync pipes.</p>
 * 
 * @author Corp Heer
 */
public class GroupBasicCrudDestination extends SyncDestination
{
  private static final ObjectMapper OBJECT_MAPPER = JsonUtils.createObjectMapper();
  
  private SyncServerContext serverContext;
  private ConfigFileLoader configFileLoader;
  private ScimService scimService;
  private Client jaxrsClient;
  private Scim2MemberHelper memberHelper;
  
  private String baseUrl;
  private String groupBasePath;
  private String groupNameAttribute;
  private String[] scimGroupAttributes;
  private Map<String, String> scimGroupMappings;
  
  @Override
  public String getExtensionName()
  {
    return "SCIM2 Group Basic CRUD Destination";
  }
  
  @Override
  public String[] getExtensionDescription()
  {
    return new String[]
    {
      "Handles CREATE, UPDATE, and DELETE operations for groups in SCIM2.",
      "Supports configurable attribute mappings from LDAP to SCIM2 GroupResource.",
      "",
      "Configuration:",
      "  scim.group.attributes=cn,description",
      "  scim.group.map.displayName=cn",
      "",
      "Works with group source plugins for filtering and attribute preparation."
    };
  }
  
  @Override
  public void defineConfigArguments(final ArgumentParser parser)
      throws ArgumentException
  {
    // Shared config file
    parser.addArgument(new FileArgument(
        null, "config-file", true, 1,
        "{path}",
        "Path to shared configuration properties file containing SCIM2 connection settings " +
        "and group attribute mappings.",
        true, true, true, false));
  }
  
  @Override
  public void initializeSyncDestination(
      final SyncServerContext serverContext,
      final SyncDestinationConfig config,
      final ArgumentParser parser)
      throws EndpointException
  {
    this.serverContext = serverContext;
    
    // Load configuration file
    FileArgument configFileArg = (FileArgument)parser.getNamedArgument("config-file");
    if (configFileArg != null && configFileArg.isPresent())
    {
      try
      {
        this.configFileLoader = new ConfigFileLoader(configFileArg.getValue().getAbsolutePath(), serverContext);
      }
      catch (IOException e)
      {
        throw new RuntimeException("Failed to load configuration file: " + e.getMessage(), e);
      }
    }
    else
    {
      throw new RuntimeException("config-file argument is required");
    }
    
    // Load SCIM connection settings
    this.baseUrl = getConfigProperty("scim2.base.url");
    if (baseUrl == null)
    {
      throw new RuntimeException("scim2.base.url is required in configuration file");
    }
    
    this.groupBasePath = getConfigProperty("scim2.group.base", "/Groups");
    this.groupNameAttribute = getConfigProperty("group.name.attribute", "cn");
    
    // Load SCIM group attribute mappings
    String attrListStr = getConfigProperty("scim.group.attributes");
    if (attrListStr != null && !attrListStr.trim().isEmpty())
    {
      this.scimGroupAttributes = configFileLoader.getPropertyList("scim.group.attributes");
    }
    else
    {
      this.scimGroupAttributes = new String[0];
    }
    
    this.scimGroupMappings = configFileLoader.getPropertyMap("scim.group.map.");
    
    // Create SCIM2 client
    Scim2ClientFactory factory = createClientFactory();
    this.scimService = factory.createScimService();
    this.jaxrsClient = factory.createJaxrsClient();
    
    // Initialize member helper
    String userBasePath = getConfigProperty("scim2.user.base", "/Users");
    this.memberHelper = new Scim2MemberHelper(
        scimService, userBasePath, groupBasePath,
        Integer.parseInt(getConfigProperty("scim2.max.retries", "3")),
        Integer.parseInt(getConfigProperty("scim2.retry.delay.ms", "1000")));
    
    serverContext.debugInfo("Initialized GroupBasicCrudDestination with " + 
                           scimGroupMappings.size() + " attribute mappings");
  }
  
  @Override
  public void createEntry(final Entry entry, final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("createEntry called for DN: " + entry.getDN());
    
    try
    {
      // Build GroupResource from entry
      GroupResource group = buildGroupResource(entry, operation);
      
      // Create in SCIM2
      GroupResource created = scimService.create(groupBasePath, group);
      
      operation.logInfo("Successfully created group: " + group.getDisplayName() + 
                       " (ID: " + created.getId() + ")");
    }
    catch (ScimException e)
    {
      operation.logInfo("ERROR: Failed to create group: " + e.getMessage());
      throw new RuntimeException("Failed to create group in SCIM2", e);
    }
    catch (Exception e)
    {
      operation.logInfo("ERROR: Unexpected error creating group: " + e.getMessage());
      throw new RuntimeException("Unexpected error creating group", e);
    }
  }
  
  @Override
  public void modifyEntry(final Entry entry, final List<Modification> mods,
                         final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("modifyEntry called for DN: " + entry.getDN() + 
                     " with " + mods.size() + " modifications");
    
    try
    {
      // Get group name to lookup SCIM2 ID
      String groupName = getGroupName(entry);
      if (groupName == null)
      {
        operation.logInfo("ERROR: Cannot determine group name from entry");
        throw new RuntimeException("Group name not found in entry");
      }
      
      // Find group in SCIM2
      String scim2GroupId = findScim2GroupId(groupName, operation);
      if (scim2GroupId == null)
      {
        operation.logInfo("WARNING: Group not found in SCIM2: " + groupName);
        return;
      }
      
      // Fetch current group
      GroupResource currentGroup = scimService.retrieve(groupBasePath, scim2GroupId, GroupResource.class);
      
      // Apply modifications to build updated group
      GroupResource updatedGroup = buildGroupResource(entry, operation);
      updatedGroup.setId(scim2GroupId);
      updatedGroup.setMeta(currentGroup.getMeta());
      
      // Update in SCIM2
      GroupResource updated = scimService.replace(updatedGroup);
      
      operation.logInfo("Successfully updated group: " + groupName);
    }
    catch (ScimException e)
    {
      operation.logInfo("ERROR: Failed to update group: " + e.getMessage());
      throw new RuntimeException("Failed to update group in SCIM2", e);
    }
    catch (Exception e)
    {
      operation.logInfo("ERROR: Unexpected error updating group: " + e.getMessage());
      throw new RuntimeException("Unexpected error updating group", e);
    }
  }
  
  @Override
  public void deleteEntry(final Entry entry, final SyncOperation operation)
      throws EndpointException
  {
    operation.logInfo("deleteEntry called for DN: " + entry.getDN());
    
    try
    {
      // Get group name to lookup SCIM2 ID
      String groupName = getGroupName(entry);
      if (groupName == null)
      {
        operation.logInfo("ERROR: Cannot determine group name from entry");
        throw new RuntimeException("Group name not found in entry");
      }
      
      // Find group in SCIM2
      String scim2GroupId = findScim2GroupId(groupName, operation);
      if (scim2GroupId == null)
      {
        operation.logInfo("WARNING: Group not found in SCIM2: " + groupName);
        return;
      }
      
      // Delete from SCIM2
      java.net.URI deleteUri = new java.net.URI(baseUrl + groupBasePath + "/" + scim2GroupId);
      scimService.delete(deleteUri);
      
      operation.logInfo("Successfully deleted group: " + groupName);
    }
    catch (ScimException e)
    {
      operation.logInfo("ERROR: Failed to delete group: " + e.getMessage());
      throw new RuntimeException("Failed to delete group from SCIM2", e);
    }
    catch (Exception e)
    {
      operation.logInfo("ERROR: Unexpected error deleting group: " + e.getMessage());
      throw new RuntimeException("Unexpected error deleting group", e);
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
    // Not used in notification/changelog mode
    return null;
  }
  
  public void setStartpoint(final SetStartpointOptions options, final String endpointURL,
                           final String authID, final String authPassword)
      throws EndpointException
  {
    // No special startpoint handling needed
  }
  
  /**
   * Builds a SCIM2 GroupResource from an LDAP entry using configured mappings.
   */
  private GroupResource buildGroupResource(final Entry entry, final SyncOperation operation)
  {
    GroupResource group = new GroupResource();
    
    // Set displayName (required)
    String displayName = getGroupName(entry);
    if (displayName == null || displayName.isEmpty())
    {
      operation.logInfo("WARNING: Group displayName is null or empty");
    }
    group.setDisplayName(displayName);
    
    // Apply attribute mappings
    for (Map.Entry<String, String> mapping : scimGroupMappings.entrySet())
    {
      String scimAttr = mapping.getKey();
      String ldapAttr = mapping.getValue();
      
      // Skip displayName if already set
      if ("displayName".equals(scimAttr))
      {
        continue;
      }
      
      String value = getAttributeValue(entry, ldapAttr);
      if (value != null && !value.isEmpty())
      {
        setScimAttributeValue(group, scimAttr, value, operation);
      }
    }
    
    return group;
  }
  
  /**
   * Sets a SCIM attribute value on the GroupResource.
   */
  private void setScimAttributeValue(GroupResource group, String attrPath, 
                                    String value, SyncOperation operation)
  {
    try
    {
      switch (attrPath)
      {
        case "externalId":
          group.setExternalId(value);
          break;
        // Add more attributes as needed
        default:
          operation.logInfo("WARNING: Unsupported group attribute: " + attrPath);
          break;
      }
    }
    catch (Exception e)
    {
      operation.logInfo("WARNING: Failed to set attribute " + attrPath + "=" + value + 
                       ": " + e.getMessage());
    }
  }
  
  /**
   * Gets the group name from the entry.
   */
  private String getGroupName(final Entry entry)
  {
    return getAttributeValue(entry, groupNameAttribute);
  }
  
  /**
   * Gets an attribute value from the entry.
   */
  private String getAttributeValue(final Entry entry, final String attrName)
  {
    Attribute attr = entry.getAttribute(attrName);
    if (attr != null && attr.getValue() != null)
    {
      return attr.getValue();
    }
    return null;
  }
  
  /**
   * Finds a SCIM2 group ID by displayName.
   */
  private String findScim2GroupId(final String groupName, final SyncOperation operation)
  {
    return memberHelper.findScim2GroupId(groupName, operation);
  }
  
  /**
   * Gets a configuration property value.
   */
  private String getConfigProperty(final String key)
  {
    return configFileLoader != null ? configFileLoader.getProperty(key) : null;
  }
  
  /**
   * Gets a configuration property with a default value.
   */
  private String getConfigProperty(final String key, final String defaultValue)
  {
    String value = getConfigProperty(key);
    return value != null ? value : defaultValue;
  }
  
  /**
   * Creates a Scim2ClientFactory from configuration.
   */
  private Scim2ClientFactory createClientFactory()
  {
    String userBase = getConfigProperty("scim2.user.base", "/Users");
    String authType = getConfigProperty("scim2.auth.type", "basic");
    String username = getConfigProperty("scim2.username");
    String password = getConfigProperty("scim2.password");
    String bearerToken = getConfigProperty("scim2.bearer.token");
    
    String trustStorePath = getConfigProperty("scim2.trust.store.path");
    String trustStorePassword = getConfigProperty("scim2.trust.store.password");
    String trustStoreType = getConfigProperty("scim2.trust.store.type", "JKS");
    boolean allowUntrustedCerts = "true".equalsIgnoreCase(
        getConfigProperty("scim2.allow.untrusted.certificates", "false"));
    
    String proxyHost = getConfigProperty("scim2.proxy.host");
    String proxyPort = getConfigProperty("scim2.proxy.port");
    String proxyUsername = getConfigProperty("scim2.proxy.username");
    String proxyPassword = getConfigProperty("scim2.proxy.password");
    String proxyType = getConfigProperty("scim2.proxy.type", "HTTP");
    
    int connectTimeout = getConfigPropertyAsInt("scim2.connect.timeout.ms", 30000);
    int readTimeout = getConfigPropertyAsInt("scim2.read.timeout.ms", 60000);

    return new Scim2ClientFactory(
        serverContext, configFileLoader,
        baseUrl, userBase, groupBasePath, authType, username, password, bearerToken,
        trustStorePath, trustStorePassword, trustStoreType, allowUntrustedCerts,
        proxyHost, proxyPort, proxyUsername, proxyPassword, proxyType,
        connectTimeout, readTimeout);
  }
  
  /**
   * Gets a configuration property as integer.
   */
  private int getConfigPropertyAsInt(final String key, final int defaultValue)
  {
    String strValue = getConfigProperty(key);
    if (strValue != null)
    {
      try
      {
        return Integer.parseInt(strValue);
      }
      catch (NumberFormatException e)
      {
        serverContext.debugInfo("Invalid integer value for " + key + ": " + strValue +
                               ", using default: " + defaultValue);
      }
    }
    return defaultValue;
  }
}

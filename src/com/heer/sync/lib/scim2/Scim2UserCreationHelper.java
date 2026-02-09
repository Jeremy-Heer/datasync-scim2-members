/*
 * Copyright 2025 Corp Heer
 */

package com.heer.sync.lib.scim2;

import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.scim2.client.ScimService;
import com.unboundid.scim2.common.types.Name;
import com.unboundid.scim2.common.types.UserResource;

import java.util.Map;

/**
 * Helper class for creating SCIM2 users from LDAP attribute mappings.
 * Provides shared user creation logic for both static and dynamic group destinations.
 */
public class Scim2UserCreationHelper
{
  private final ScimService scimService;
  private final String userBasePath;

  /**
   * Creates a new helper instance.
   *
   * @param scimService The SCIM service for creating users
   * @param userBasePath The base path for users (e.g., "/Users")
   */
  public Scim2UserCreationHelper(final ScimService scimService, final String userBasePath)
  {
    this.scimService = scimService;
    this.userBasePath = userBasePath;
  }

  /**
   * Creates a SCIM2 user from attribute mappings.
   *
   * @param userId The user ID (used as fallback for userName)
   * @param userAttributes Map of SCIM attribute names to values
   * @param operation The sync operation for logging
   * @return true if user was created successfully, false otherwise
   */
  public boolean createUserFromAttributes(final String userId,
                                          final Map<String, String> userAttributes,
                                          final SyncOperation operation)
  {
    if (userAttributes == null || userAttributes.isEmpty())
    {
      operation.logInfo("No user attributes provided for user: " + userId);
      return false;
    }

    try
    {
      operation.logInfo("Creating user: " + userId);

      // Build UserResource from attributes
      UserResource user = new UserResource();

      // Set userName (required)
      String userName = userAttributes.get("userName");
      if (userName == null || userName.isEmpty())
      {
        userName = userId;
      }
      user.setUserName(userName);

      // Apply all other attribute mappings
      for (Map.Entry<String, String> attr : userAttributes.entrySet())
      {
        String attrName = attr.getKey();
        String attrValue = attr.getValue();

        // Skip special flags and userName (already set)
        if ("deleteUser".equals(attrName) || "userName".equals(attrName))
        {
          continue;
        }

        setScimAttributeValue(user, attrName, attrValue, operation);
      }

      // Create via SCIM2 API
      UserResource created = scimService.create(userBasePath, user);

      operation.logInfo("Successfully created user: " + userName + " (ID: " + created.getId() + ")");
      return true;
    }
    catch (Exception e)
    {
      operation.logInfo("ERROR: Failed to create user " + userId + ": " + e.getMessage());
      return false;
    }
  }

  /**
   * Sets a SCIM attribute value on a UserResource, handling nested paths like "name.givenName".
   *
   * @param user The UserResource to update
   * @param attrPath The attribute path (may be nested with dots)
   * @param value The value to set
   * @param operation The sync operation for logging
   */
  public void setScimAttributeValue(final UserResource user,
                                     final String attrPath,
                                     final String value,
                                     final SyncOperation operation)
  {
    try
    {
      if (attrPath.contains("."))
      {
        // Handle nested attributes
        String[] parts = attrPath.split("\\.", 2);
        String parent = parts[0];
        String child = parts[1];

        if ("name".equals(parent))
        {
          Name name = user.getName();
          if (name == null)
          {
            name = new Name();
            user.setName(name);
          }

          switch (child)
          {
            case "formatted":
              name.setFormatted(value);
              break;
            case "familyName":
              name.setFamilyName(value);
              break;
            case "givenName":
              name.setGivenName(value);
              break;
            case "middleName":
              name.setMiddleName(value);
              break;
            case "honorificPrefix":
              name.setHonorificPrefix(value);
              break;
            case "honorificSuffix":
              name.setHonorificSuffix(value);
              break;
            default:
              operation.logInfo("Unsupported name attribute: " + child);
          }
        }
        else if ("emails".equals(parent))
        {
          // Handle email attributes - for now just log
          operation.logInfo("Email attribute handling not yet implemented: " + attrPath);
        }
        // Add more nested attribute handlers as needed
      }
      else
      {
        // Simple attributes
        switch (attrPath)
        {
          case "displayName":
            user.setDisplayName(value);
            break;
          case "active":
            user.setActive(Boolean.parseBoolean(value));
            break;
          case "title":
            user.setTitle(value);
            break;
          case "nickName":
            user.setNickName(value);
            break;
          case "locale":
            user.setLocale(value);
            break;
          case "timezone":
            user.setTimezone(value);
            break;
          case "profileUrl":
            try
            {
              user.setProfileUrl(new java.net.URI(value));
            }
            catch (java.net.URISyntaxException e)
            {
              operation.logInfo("Invalid URI for profileUrl: " + value);
            }
            break;
          default:
            operation.logInfo("Unsupported SCIM attribute: " + attrPath);
        }
      }
    }
    catch (Exception e)
    {
      operation.logInfo("Error setting SCIM attribute " + attrPath + ": " + e.getMessage());
    }
  }
}

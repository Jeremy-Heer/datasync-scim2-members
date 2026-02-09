/*
 * Copyright 2025 Corp Heer
 */

package com.heer.sync.lib.scim2;

import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.scim2.client.ScimService;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.exceptions.ResourceNotFoundException;

import java.net.URI;

/**
 * Helper utility for cleaning up orphaned SCIM2 resources (users and groups)
 * that no longer exist in the authoritative LDAP directory.
 * <p>
 * This helper is designed to be used with a reverse sync pipe where SCIM2
 * acts as the source and LDAP acts as the destination for existence checks.
 * When entries are not found in LDAP during a resync, they are deleted from SCIM2.
 */
public class Scim2OrphanCleanupHelper
{
  private final ScimService scimService;
  private final String baseUrl;
  private final String userBasePath;
  private final String groupBasePath;
  private final int maxRetries;
  private final int retryDelayMs;

  /**
   * Creates a new Scim2OrphanCleanupHelper.
   *
   * @param scimService The SCIM2 service client
   * @param baseUrl The base URL for SCIM2 endpoint (e.g., https://api.example.com/scim/v2)
   * @param userBasePath The base path for SCIM2 users (e.g., /Users)
   * @param groupBasePath The base path for SCIM2 groups (e.g., /Groups)
   * @param maxRetries Maximum retry attempts for failed operations (default: 3)
   * @param retryDelayMs Initial retry delay in milliseconds (default: 1000)
   */
  public Scim2OrphanCleanupHelper(
      final ScimService scimService,
      final String baseUrl,
      final String userBasePath,
      final String groupBasePath,
      final int maxRetries,
      final int retryDelayMs)
  {
    this.scimService = scimService;
    this.baseUrl = baseUrl;
    this.userBasePath = userBasePath;
    this.groupBasePath = groupBasePath;
    this.maxRetries = maxRetries;
    this.retryDelayMs = retryDelayMs;
  }

  /**
   * Deletes a user from SCIM2 by their SCIM2 user ID.
   * This method includes retry logic with exponential backoff.
   *
   * @param scim2UserId The SCIM2 user ID (not the userName)
   * @param operation Sync operation for logging (may be null)
   * @return true if the user was deleted, false if not found
   * @throws RuntimeException If deletion fails after all retries
   */
  public boolean deleteUser(final String scim2UserId, final SyncOperation operation)
  {
    if (scim2UserId == null || scim2UserId.trim().isEmpty())
    {
      if (operation != null)
      {
        operation.logInfo("CLEANUP: Skipping delete - null or empty user ID");
      }
      return false;
    }

    try
    {
      // Execute deletion with retry logic
      Scim2RetryHelper.executeWithRetry(
        () -> {
          scimService.delete(userBasePath, scim2UserId);
          return null;
        },
        maxRetries,
        retryDelayMs,
        operation
      );

      if (operation != null)
      {
        operation.logInfo("CLEANUP: Successfully deleted orphaned user from SCIM2 - ID: " + scim2UserId);
      }
      return true;
    }
    catch (ResourceNotFoundException e)
    {
      if (operation != null)
      {
        operation.logInfo("CLEANUP: User already deleted from SCIM2 - ID: " + scim2UserId);
      }
      return false;
    }
    catch (Exception e)
    {
      if (operation != null)
      {
        operation.logInfo("CLEANUP ERROR: Failed to delete user after " + (maxRetries + 1) + 
                         " attempts - ID: " + scim2UserId + " - " + e.getMessage());
      }
      throw new RuntimeException("Failed to delete user from SCIM2: " + scim2UserId, e);
    }
  }

  /**
   * Deletes a group from SCIM2 by their SCIM2 group ID.
   * This method includes retry logic with exponential backoff.
   *
   * @param scim2GroupId The SCIM2 group ID (not the displayName)
   * @param operation Sync operation for logging (may be null)
   * @return true if the group was deleted, false if not found
   * @throws RuntimeException If deletion fails after all retries
   */
  public boolean deleteGroup(final String scim2GroupId, final SyncOperation operation)
  {
    if (scim2GroupId == null || scim2GroupId.trim().isEmpty())
    {
      if (operation != null)
      {
        operation.logInfo("CLEANUP: Skipping delete - null or empty group ID");
      }
      return false;
    }

    try
    {
      // Build delete URI
      final URI deleteUri = new URI(baseUrl + groupBasePath + "/" + scim2GroupId);

      // Execute deletion with retry logic
      Scim2RetryHelper.executeWithRetry(
        () -> {
          scimService.delete(deleteUri);
          return null;
        },
        maxRetries,
        retryDelayMs,
        operation
      );

      if (operation != null)
      {
        operation.logInfo("CLEANUP: Successfully deleted orphaned group from SCIM2 - ID: " + scim2GroupId);
      }
      return true;
    }
    catch (ResourceNotFoundException e)
    {
      if (operation != null)
      {
        operation.logInfo("CLEANUP: Group already deleted from SCIM2 - ID: " + scim2GroupId);
      }
      return false;
    }
    catch (Exception e)
    {
      if (operation != null)
      {
        operation.logInfo("CLEANUP ERROR: Failed to delete group after " + (maxRetries + 1) + 
                         " attempts - ID: " + scim2GroupId + " - " + e.getMessage());
      }
      throw new RuntimeException("Failed to delete group from SCIM2: " + scim2GroupId, e);
    }
  }

  /**
   * Deletes a user or group based on the resource type.
   *
   * @param resourceType The type of resource ("user" or "group")
   * @param scim2ResourceId The SCIM2 resource ID
   * @param operation Sync operation for logging (may be null)
   * @return true if the resource was deleted, false if not found
   * @throws RuntimeException If deletion fails after all retries
   */
  public boolean deleteResource(
      final String resourceType,
      final String scim2ResourceId,
      final SyncOperation operation)
  {
    if ("user".equalsIgnoreCase(resourceType))
    {
      return deleteUser(scim2ResourceId, operation);
    }
    else if ("group".equalsIgnoreCase(resourceType))
    {
      return deleteGroup(scim2ResourceId, operation);
    }
    else
    {
      if (operation != null)
      {
        operation.logInfo("CLEANUP ERROR: Unknown resource type: " + resourceType);
      }
      throw new IllegalArgumentException("Unknown resource type: " + resourceType);
    }
  }
}

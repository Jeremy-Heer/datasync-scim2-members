/*
 * Copyright 2025 Corp Heer
 */

package com.heer.sync.lib.scim2;

import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.scim2.client.ScimService;
import com.unboundid.scim2.common.types.Member;
import com.unboundid.scim2.common.types.UserResource;
import com.unboundid.scim2.common.types.GroupResource;
import com.unboundid.scim2.common.filters.Filter;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.messages.PatchOperation;
import com.unboundid.scim2.common.messages.PatchRequest;
import com.unboundid.scim2.common.Path;
import com.unboundid.scim2.common.GenericScimResource;
import com.unboundid.scim2.common.utils.JsonUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Collections;

/**
 * Helper utility for SCIM2 member operations, including user ID lookup
 * and conversion of user IDs to SCIM2 Member objects.
 */
public class Scim2MemberHelper
{
  private final ScimService scimService;
  private final String userBasePath;
  private final String groupBasePath;
  private final int maxRetries;
  private final int retryDelayMs;

  /**
   * Creates a new Scim2MemberHelper.
   *
   * @param scimService The SCIM2 service client
   * @param userBasePath The base path for SCIM2 users (e.g., /Users)
   * @param groupBasePath The base path for SCIM2 groups (e.g., /Groups)
   * @param maxRetries Maximum retry attempts for failed operations
   * @param retryDelayMs Initial retry delay in milliseconds
   */
  public Scim2MemberHelper(
      final ScimService scimService,
      final String userBasePath,
      final String groupBasePath,
      final int maxRetries,
      final int retryDelayMs)
  {
    this.scimService = scimService;
    this.userBasePath = userBasePath;
    this.groupBasePath = groupBasePath;
    this.maxRetries = maxRetries;
    this.retryDelayMs = retryDelayMs;
  }

  /**
   * Converts an array of user IDs (uid values) to a list of SCIM2 Member objects.
   * Each user ID is looked up in SCIM2 to find the corresponding user resource ID.
   *
   * @param userIds Array of user IDs (uid values from LDAP)
   * @param operation Sync operation for logging (may be null)
   * @return List of SCIM2 Member objects for found users
   */
  public List<Member> convertUserIdsToScim2Members(
      final String[] userIds,
      final SyncOperation operation)
  {
    List<Member> members = new ArrayList<Member>();
    
    if (userIds == null || userIds.length == 0)
    {
      return members;
    }
    
    for (String userId : userIds)
    {
      if (userId == null || userId.trim().isEmpty())
      {
        continue;
      }
      
      userId = userId.trim();
      String scim2UserId = findScim2UserId(userId, operation);
      
      if (scim2UserId != null)
      {
        Member member = new Member();
        member.setValue(scim2UserId);
        try {
          member.setRef(new java.net.URI(userBasePath + "/" + scim2UserId));
        } catch (java.net.URISyntaxException e) {
          // Log but continue without $ref
          if (operation != null) {
            operation.logInfo("Invalid URI for member ref: " + e.getMessage());
          }
        }
        members.add(member);
        
        if (operation != null)
        {
          operation.logInfo("Mapped user ID '" + userId + "' to SCIM2 user ID: " + scim2UserId);
        }
      }
      else
      {
        if (operation != null)
        {
          operation.logInfo("WARNING: Could not find SCIM2 user for user ID: " + userId);
        }
      }
    }
    
    return members;
  }

  /**
   * Searches for a SCIM2 user by userName attribute and returns the user's ID.
   *
   * @param username The userName to search for
   * @param operation Sync operation for logging (may be null)
   * @return The SCIM2 user ID if found, null otherwise
   */
  public String findScim2UserId(
      final String username,
      final SyncOperation operation)
  {
    try
    {
      return Scim2RetryHelper.executeWithRetry(() -> {
        // Search for user with userName attribute
        Filter filter = Filter.eq("userName", username);
        
        List<UserResource> users = scimService.searchRequest(userBasePath)
            .filter(filter.toString())
            .page(1, 1)
            .invoke(UserResource.class)
            .getResources();
        
        if (users != null && !users.isEmpty())
        {
          UserResource user = users.get(0);
          String userId = user.getId();
          
          if (operation != null)
          {
            operation.logInfo("Found SCIM2 user: " + username + " with ID: " + userId);
          }
          
          return userId;
        }
        else
        {
          if (operation != null)
          {
            operation.logInfo("No SCIM2 user found with userName: " + username);
          }
          return null;
        }
        
      }, maxRetries, retryDelayMs, operation);
    }
    catch (Exception e)
    {
      if (operation != null)
      {
        operation.logInfo("Error searching for SCIM2 user '" + username + "': " + e.getMessage());
      }
      return null;
    }
  }

  /**
   * Searches for a SCIM2 group by displayName attribute and returns the group's ID.
   *
   * @param groupName The displayName to search for
   * @param operation Sync operation for logging (may be null)
   * @return The SCIM2 group ID if found, null otherwise
   */
  public String findScim2GroupId(
      final String groupName,
      final SyncOperation operation)
  {
    try
    {
      return Scim2RetryHelper.executeWithRetry(() -> {
        // Search for group with displayName attribute
        Filter filter = Filter.eq("displayName", groupName);
        
        // Only request id and displayName attributes to optimize for large groups
        List<GroupResource> groups = scimService.searchRequest(groupBasePath)
            .filter(filter.toString())
            .attributes("id", "displayName")
            .page(1, 1)
            .invoke(GroupResource.class)
            .getResources();
        
        if (groups != null && !groups.isEmpty())
        {
          GroupResource group = groups.get(0);
          String groupId = group.getId();
          
          if (operation != null)
          {
            operation.logInfo("Found SCIM2 group: " + groupName + " with ID: " + groupId);
          }
          
          return groupId;
        }
        else
        {
          if (operation != null)
          {
            operation.logInfo("No SCIM2 group found with displayName: " + groupName);
          }
          return null;
        }
        
      }, maxRetries, retryDelayMs, operation);
    }
    catch (Exception e)
    {
      if (operation != null)
      {
        operation.logInfo("Error searching for SCIM2 group '" + groupName + "': " + e.getMessage());
      }
      return null;
    }
  }
  
  /**
   * Adds a user to a SCIM2 group using PATCH operation.
   * 
   * @param groupId The SCIM2 group ID
   * @param userId The SCIM2 user ID
   * @param baseUrl The SCIM2 base URL (not used with ScimService)
   * @param operation Sync operation for logging (may be null)
   * @throws Exception if the PATCH operation fails
   */
  public void addUserToGroup(final String groupId, final String userId, 
      final String baseUrl, final SyncOperation operation) throws Exception
  {
    try {
      // Create member object to add
      Member memberToAdd = new Member();
      memberToAdd.setValue(userId);
      
      // Convert Member to JsonNode using SCIM SDK utilities
      JsonNode memberNode = JsonUtils.valueToNode(memberToAdd);
      
      // Create a JsonNode array containing the member
      ArrayNode membersArrayNode = JsonUtils.getJsonNodeFactory().arrayNode();
      membersArrayNode.add(memberNode);
      
      // Create PATCH operation using SDK's factory method
      PatchOperation patchOp = PatchOperation.add("members", membersArrayNode);
      
      PatchRequest patchRequest = new PatchRequest(patchOp);
      
      // Execute PATCH using ScimService.modify() method
      // Returns GenericScimResource since we don't need the response
      scimService.modify(groupBasePath, groupId, patchRequest, GenericScimResource.class);
      
      if (operation != null) {
        operation.logInfo("Added user " + userId + " to group " + groupId);
      }
    } catch (Exception e) {
      if (operation != null) {
        operation.logInfo("Error adding user " + userId + " to group " + groupId + ": " + e.getMessage());
      }
      throw e;
    }
  }
  
  /**
   * Removes a user from a SCIM2 group using PATCH operation.
   * 
   * @param groupId The SCIM2 group ID
   * @param userId The SCIM2 user ID
   * @param baseUrl The SCIM2 base URL (not used with ScimService)
   * @param operation Sync operation for logging (may be null)
   * @throws Exception if the PATCH operation fails
   */
  public void removeUserFromGroup(final String groupId, final String userId,
      final String baseUrl, final SyncOperation operation) throws Exception
  {
    try {
      // Create PATCH operation to remove member with filter
      // Using path with value filter: members[value eq "userId"]
      PatchOperation patchOp = PatchOperation.remove(
          Path.fromString("members[value eq \"" + userId + "\"]"));
      
      PatchRequest patchRequest = new PatchRequest(patchOp);
      
      // Execute PATCH using ScimService.modify() method
      // Returns GenericScimResource since we don't need the response
      scimService.modify(groupBasePath, groupId, patchRequest, GenericScimResource.class);
      
      if (operation != null) {
        operation.logInfo("Removed user " + userId + " from group " + groupId);
      }
    } catch (Exception e) {
      if (operation != null) {
        operation.logInfo("Error removing user " + userId + " from group " + groupId + ": " + e.getMessage());
      }
      throw e;
    }
  }
}

# PATCH Method Improvement: Using SCIM2 SDK POJOs with ObjectMapper

## Overview
Updated the PATCH operation methods to use SCIM2 SDK's `PatchRequest` and `PatchOperation` POJOs with the pre-configured ObjectMapper, replacing manual JSON string construction.

## Problem with Previous Implementation

### Before: Manual JSON String Construction
```java
private String createAddMemberPatchJson(final String userId) {
  StringBuilder json = new StringBuilder();
  json.append("{");
  json.append("\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],");
  json.append("\"Operations\":[{");
  json.append("\"op\":\"add\",");
  json.append("\"path\":\"members\",");
  json.append("\"value\":[{");
  json.append("\"value\":\"").append(userId).append("\",");
  json.append("\"$ref\":\"").append(baseUrl).append(userBasePath).append("/").append(userId).append("\"");
  json.append("}]");
  json.append("}]");
  json.append("}");
  return json.toString();
}
```

**Issues:**
- ❌ Error-prone manual JSON construction
- ❌ Hard to maintain and read
- ❌ Could include null values if Member object had them
- ❌ No compile-time type safety
- ❌ String concatenation for complex nested structures
- ❌ Doesn't leverage SCIM2 SDK's built-in capabilities

## New Implementation: SCIM2 SDK POJOs + ObjectMapper

### After: Using SDK POJOs
```java
private String createAddMemberPatchJson(final String userId) throws Exception {
  // Create a Member object with proper structure
  Member member = new Member();
  member.setValue(userId);
  member.setRef(URI.create(baseUrl + userBasePath + "/" + userId));
  
  // Convert Member to JsonNode using SCIM SDK's pre-configured ObjectMapper
  // This ensures null values are excluded
  JsonNode memberNode = JsonUtils.valueToNode(member);
  
  // Create a JsonNode array containing the member
  JsonNode membersArrayNode = SCIM_OBJECT_MAPPER.createArrayNode().add(memberNode);
  
  // Create PatchOperation using SDK's factory method
  PatchOperation addOperation = PatchOperation.add("members", membersArrayNode);
  
  // Create PatchRequest with the operation
  PatchRequest patchRequest = new PatchRequest(addOperation);
  
  // Serialize to JSON using SCIM SDK's ObjectMapper to exclude null values
  return SCIM_OBJECT_MAPPER.writeValueAsString(patchRequest);
}
```

### Remove Operation
```java
private String createRemoveMemberPatchJson(final String userId) throws Exception {
  // Create PatchOperation using SDK's factory method with filter path
  // Path format: members[value eq "userId"]
  Path removePath = Path.fromString("members[value eq \"" + userId + "\"]");
  PatchOperation removeOperation = PatchOperation.remove(removePath);
  
  // Create PatchRequest with the operation
  PatchRequest patchRequest = new PatchRequest(removeOperation);
  
  // Serialize to JSON using SCIM SDK's ObjectMapper to exclude null values
  return SCIM_OBJECT_MAPPER.writeValueAsString(patchRequest);
}
```

## Benefits of New Implementation

### 1. Type Safety
✅ Uses strongly-typed SCIM2 SDK classes:
- `PatchRequest`
- `PatchOperation`
- `Member`
- `Path`

### 2. Null Value Handling
✅ Automatically excludes null values using SCIM SDK's ObjectMapper:
```java
SCIM_OBJECT_MAPPER.writeValueAsString(patchRequest)
```

### 3. Code Clarity
✅ Intent is clear - using domain objects instead of string manipulation
✅ Easier to understand the structure of the PATCH request
✅ Compile-time validation of the object structure

### 4. Maintainability
✅ Changes to SCIM2 spec handled by SDK updates
✅ Less code to maintain (SDK handles complexity)
✅ Reduced risk of typos or malformed JSON

### 5. Consistency
✅ Matches the PUT method's approach of using POJOs + ObjectMapper
✅ Consistent serialization across all HTTP methods
✅ Uniform null value handling throughout the codebase

### 6. SDK Best Practices
✅ Leverages SCIM2 SDK's built-in functionality
✅ Follows official SDK recommendations
✅ Uses pre-configured ObjectMapper from `JsonUtils.createObjectMapper()`

## Example JSON Output

### Add Member PATCH Request
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{
    "op": "add",
    "path": "members",
    "value": [{
      "value": "user123",
      "$ref": "https://example.com/scim/v2/Users/user123"
    }]
  }]
}
```

**Note:** No null values like `"type": null` or `"display": null` in the Member object!

### Remove Member PATCH Request
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{
    "op": "remove",
    "path": "members[value eq \"user123\"]"
  }]
}
```

## Changes Summary

### Added Imports
```java
import com.unboundid.scim2.common.messages.PatchRequest;
import com.unboundid.scim2.common.messages.PatchOperation;
import com.unboundid.scim2.common.Path;
import com.fasterxml.jackson.databind.JsonNode;
```

### Updated Methods
1. `createAddMemberPatchJson()` - Now uses PatchRequest/PatchOperation POJOs
2. `createRemoveMemberPatchJson()` - Now uses PatchRequest/PatchOperation POJOs
3. `addUserToScim2GroupViaPatch()` - Updated exception handling
4. `removeUserFromScim2GroupViaPatch()` - Updated exception handling

### Key Features
- ✅ Uses `JsonUtils.valueToNode()` to convert POJOs to JsonNode
- ✅ Uses `SCIM_OBJECT_MAPPER.writeValueAsString()` for serialization
- ✅ Uses `PatchOperation.add()` and `PatchOperation.remove()` factory methods
- ✅ Uses `Path.fromString()` for filter expressions
- ✅ Proper exception handling with try-catch blocks

## Comparison: PUT vs PATCH (Now Consistent)

### PUT Method
```java
// Serialize group using SCIM2 SDK's pre-configured ObjectMapper
String groupJson = SCIM_OBJECT_MAPPER.writeValueAsString(group);
Response response = target.request("application/scim+json")
    .put(Entity.entity(groupJson, "application/scim+json"));
```

### PATCH Method (Now Matches)
```java
// Serialize PatchRequest using SCIM2 SDK's pre-configured ObjectMapper
String patchJson = SCIM_OBJECT_MAPPER.writeValueAsString(patchRequest);
Response response = target.request("application/scim+json")
    .method("PATCH", Entity.entity(patchJson, "application/scim+json"));
```

**Both methods now:**
- ✅ Use POJOs (GroupResource vs PatchRequest)
- ✅ Use SCIM_OBJECT_MAPPER for serialization
- ✅ Exclude null values automatically
- ✅ Follow SCIM2 SDK best practices

## Testing
- ✅ Build completed successfully
- ✅ No compilation errors
- ✅ Ready for deployment and integration testing

## References
- [SCIM2 SDK Common Problems and FAQ](https://github.com/pingidentity/scim2/wiki/Common-Problems-and-FAQ#null-values-printed-in-api-requestsresponses)
- [RFC 7644 - SCIM Protocol](https://datatracker.ietf.org/doc/html/rfc7644)
- SCIM2 SDK JavaDoc for PatchRequest and PatchOperation classes

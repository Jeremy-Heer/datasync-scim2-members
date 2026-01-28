# Before and After: Null Value Handling in PUT Requests

## Problem Demonstration

### Before Fix (Using Default Jackson ObjectMapper)
When using `Entity.entity(group, "application/scim+json")` with default ObjectMapper:

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "id": "abc123",
  "externalId": null,
  "meta": null,
  "displayName": "Engineering Team",
  "members": [
    {
      "value": "user123",
      "$ref": "https://example.com/scim/v2/Users/user123",
      "type": null,
      "display": null
    }
  ],
  "description": null
}
```

**Issues:**
- Contains multiple `null` fields (`externalId`, `meta`, `description`, `type`, `display`)
- Increases payload size unnecessarily
- May cause issues with strict SCIM2 servers
- Not compliant with SCIM2 best practices

### After Fix (Using SCIM2 SDK's ObjectMapper)
When using `SCIM_OBJECT_MAPPER.writeValueAsString(group)`:

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "id": "abc123",
  "displayName": "Engineering Team",
  "members": [
    {
      "value": "user123",
      "$ref": "https://example.com/scim/v2/Users/user123"
    }
  ]
}
```

**Benefits:**
- ✅ Null values automatically excluded
- ✅ Smaller, cleaner payload
- ✅ SCIM2 specification compliant
- ✅ Better compatibility with SCIM2 service providers
- ✅ Follows official SDK recommendations

## Technical Details

The fix uses the SCIM2 SDK's pre-configured ObjectMapper:

```java
private static final ObjectMapper SCIM_OBJECT_MAPPER = JsonUtils.createObjectMapper();
```

This ObjectMapper is configured with:
- `JsonInclude.Include.NON_NULL` - Excludes null values
- Proper handling of SCIM2-specific attributes
- Optimized serialization settings for SCIM resources

## Code Change

### Before
```java
WebTarget target = jaxrsClient.target(putUrl);
Response response = target.request("application/scim+json")
    .put(Entity.entity(group, "application/scim+json"));
```

### After
```java
// Serialize group using SCIM2 SDK's pre-configured ObjectMapper
// This excludes null values and applies other SCIM-specific serialization settings
String groupJson = SCIM_OBJECT_MAPPER.writeValueAsString(group);

WebTarget target = jaxrsClient.target(putUrl);
Response response = target.request("application/scim+json")
    .put(Entity.entity(groupJson, "application/scim+json"));
```

## Reference
- [SCIM2 SDK Common Problems and FAQ](https://github.com/pingidentity/scim2/wiki/Common-Problems-and-FAQ#null-values-printed-in-api-requestsresponses)
- [SCIM2 Specification RFC 7644](https://datatracker.ietf.org/doc/html/rfc7644)

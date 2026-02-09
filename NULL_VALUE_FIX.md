# Fix: Remove Null Values from PUT Requests to SCIM2 Server

## Issue
The application was sending null values in PUT requests to the SCIM2 server, which is not compliant with the SCIM2 specification. Null values should be excluded from JSON payloads.

## Root Cause
When using JAX-RS `Entity.entity(group, "application/scim+json")` directly with a GroupResource object, Jackson's default ObjectMapper was being used for serialization. The default ObjectMapper configuration includes null values in the JSON output, which violates SCIM2 best practices.

## Solution Implemented
Following the guidance from the [SCIM2 SDK Common Problems and FAQ](https://github.com/pingidentity/scim2/wiki/Common-Problems-and-FAQ), we implemented the SDK-provided pre-configured ObjectMapper to properly serialize SCIM resources.

### Changes Made

#### 1. Added Required Imports
```java
import com.unboundid.scim2.common.utils.JsonUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
```

#### 2. Created Static Pre-configured ObjectMapper
```java
// Pre-configured ObjectMapper from SCIM2 SDK that properly handles null values
// and other SCIM-specific serialization requirements
private static final ObjectMapper SCIM_OBJECT_MAPPER = JsonUtils.createObjectMapper();
```

This ObjectMapper is created using `JsonUtils.createObjectMapper()` from the SCIM2 SDK, which provides a properly configured instance that:
- Excludes null values from JSON output
- Applies other SCIM-specific serialization settings
- Follows SCIM2 specification requirements

#### 3. Updated PUT Request Serialization
Modified the `processGroupResync()` method to use the SCIM ObjectMapper for serializing the GroupResource before sending the PUT request:

```java
// Serialize group using SCIM2 SDK's pre-configured ObjectMapper
// This excludes null values and applies other SCIM-specific serialization settings
// per the SCIM2 SDK documentation: https://github.com/pingidentity/scim2/wiki/Common-Problems-and-FAQ
String groupJson = SCIM_OBJECT_MAPPER.writeValueAsString(group);

WebTarget target = jaxrsClient.target(putUrl);
Response response = target.request("application/scim+json")
    .put(Entity.entity(groupJson, "application/scim+json"));
```

## Benefits
1. **SCIM2 Compliance**: JSON payloads now exclude null values as per SCIM2 specification
2. **Cleaner API Requests**: Reduced payload size by excluding unnecessary null fields
3. **Better Interoperability**: Improved compatibility with SCIM2 service providers
4. **SDK Best Practices**: Following official SCIM2 SDK recommendations

## Testing
- Build completed successfully
- No compilation errors
- Ready for deployment and testing with SCIM2 server

## Notes
- The SCIM ObjectMapper is created as a static final field to ensure it's only created once, as creating ObjectMapper instances is expensive
- Other PUT/PATCH operations that use `scimService.replace()` already benefit from the SDK's proper serialization
- PATCH operations that manually create JSON strings were already compliant and didn't require changes

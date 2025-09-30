# SCIM2 Group Sync Destination Plugin

This custom Ping Data Sync destination plugin synchronizes LDAP group membership changes to SCIM2 groups. When changes are made to designated group attributes on LDAP users, it updates the corresponding SCIM2 group by adding or removing the user.

## Overview

The plugin monitors specified LDAP attributes that contain group memberships and maps them to SCIM2 group names. When changes are detected through the data sync process, it:

1. Fetches the user name from the LDAP user
2. Searches the SCIM2 user base and retrieves the SCIM2 ID for the user
3. Searches the SCIM2 group base and retrieves the SCIM2 ID for the group
4. Performs an update on the SCIM2 group adding or removing the user using the user's SCIM2 ID

## Configuration Parameters

- `--group-membership-attributes` - LDAP attributes that contain group memberships (can be specified multiple times)
- `--user-lookup-attribute` - LDAP attribute to use for finding users in the SCIM2 destination (e.g., 'uid', 'mail')
- `--scim-base-url` - Base URL of the SCIM2 service (e.g., 'https://example.com/scim/v2')
- `--scim-user-base` - SCIM2 user endpoint base path (defaults to '/Users')
- `--scim-group-base` - SCIM2 group endpoint base path (defaults to '/Groups')
- `--scim-username` - Username for SCIM2 authentication (optional)
- `--scim-password` - Password for SCIM2 authentication (optional)

## Installation

1. Compile the plugin using the provided build system:
   ```bash
   ./build.sh
   ```

2. Copy the compiled JAR to your Ping Data Sync server

3. Configure the plugin in your sync pipe configuration

## Example Configuration

```xml
<ldap-sync-destination-plugin>
  <class-name>java.com.heer.sync.Scim2GroupSyncDestination</class-name>
  <plugin-argument>
    <name>group-membership-attributes</name>
    <value>memberOf</value>
  </plugin-argument>
  <plugin-argument>
    <name>group-membership-attributes</name>
    <value>departmentGroups</value>
  </plugin-argument>
  <plugin-argument>
    <name>user-lookup-attribute</name>
    <value>uid</value>
  </plugin-argument>
  <plugin-argument>
    <name>scim-base-url</name>
    <value>https://your-scim-service.com/scim/v2</value>
  </plugin-argument>
  <plugin-argument>
    <name>scim-user-base</name>
    <value>/Users</value>
  </plugin-argument>
  <plugin-argument>
    <name>scim-group-base</name>
    <value>/Groups</value>
  </plugin-argument>
  <plugin-argument>
    <name>scim-username</name>
    <value>scim-service-account</value>
  </plugin-argument>
  <plugin-argument>
    <name>scim-password</name>
    <value>your-password</value>
  </plugin-argument>
</ldap-sync-destination-plugin>
```

## How It Works

1. **Modification Detection**: The plugin hooks into the `preModify` method of the LDAP sync destination plugin API to detect changes to specified group membership attributes.

2. **User Resolution**: When a group membership change is detected, the plugin uses the configured user lookup attribute to find the corresponding SCIM2 user by searching the SCIM2 user endpoint.

3. **Group Resolution**: The plugin searches for the SCIM2 group using the group name from the LDAP attribute value.

4. **Group Membership Update**: Using SCIM2 PATCH operations, the plugin adds or removes the user from the group:
   - **ADD modifications**: Adds the user to the SCIM2 group
   - **DELETE modifications**: Removes the user from the SCIM2 group
   - **REPLACE modifications**: Currently treated as ADD (could be enhanced for more sophisticated logic)

## SCIM2 API Compatibility

The plugin uses standard SCIM2 API calls:
- **GET** requests to search for users and groups using filters
- **PATCH** requests to update group memberships using JSON Patch operations

## Authentication

The plugin supports Basic Authentication for SCIM2 service access. Credentials are configured through the `scim-username` and `scim-password` parameters.

## Error Handling

The plugin is designed to be resilient:
- Continues processing even if SCIM2 operations fail
- Logs detailed information for debugging
- Handles missing users or groups gracefully

## Dependencies

The plugin uses:
- Standard Java HTTP client (HttpURLConnection)
- Jackson JSON library for SCIM2 response parsing
- Ping Data Sync SDK for LDAP sync integration

## Logging

The plugin provides extensive debug logging to help troubleshoot synchronization issues:
- User and group lookup operations
- SCIM2 API calls and responses
- Group membership changes detected and processed

## Limitations

1. **REPLACE Operations**: Currently treats REPLACE modifications as ADD operations. Full implementation would require tracking previous values and calculating differences.

2. **Authentication**: Only supports Basic Authentication. Could be extended for OAuth or other authentication methods.

3. **Batch Operations**: Processes changes individually rather than batching multiple changes for efficiency.

## Future Enhancements

- Support for OAuth authentication
- Batch processing of multiple group changes
- More sophisticated REPLACE operation handling
- Configurable retry logic for failed SCIM2 operations
- Support for custom SCIM2 schemas and attributes
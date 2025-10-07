# Group Resync Implementation Summary

## Overview
This document describes the implementation of group resync functionality for the SCIM2 Group Membership Sync plugins. The implementation enables synchronization of dynamic LDAP groups to SCIM2 by expanding group membership at the source and applying it at the destination.

## Architecture

### Two-Plugin Approach

#### 1. Source Plugin: `LDAPSyncSourcePluginScim2GroupMembers`
**Purpose**: Expands dynamic LDAP group membership into a `members` attribute for synchronization.

**Key Features**:
- Detects dynamic groups (entries with `memberURL` attribute)
- Parses LDAP URLs to extract search criteria
- Queries LDAP to find matching users
- Extracts user IDs (configurable attribute, e.g., `uid`)
- Constructs multi-valued `members` attribute containing all user IDs

**Configuration**:
```
user-id-attribute: The LDAP attribute containing unique user IDs (e.g., uid, sAMAccountName)
```

**Example Configuration**:
```
user-id-attribute=uid
```

**Note**: The base DN for user searches is extracted directly from the `memberURL` attribute in each dynamic group, so no separate `search-base-dn` configuration is required.

#### 2. Destination Plugin: `Scim2GroupMemberDestination`
**Purpose**: Processes both incremental user membership changes and full group resync operations.

**Key Features**:
- **User Resync Operations**: Ignores `createEntry` calls for users (logs and returns)
- **Group Resync Operations**: Processes via `modifyEntry` method
- **Group Processing**:
  1. Detects group entries via `scim2GroupId` attribute
  2. Reads `members` attribute containing user IDs from source
  3. Searches SCIM2 for each user ID to get SCIM2 user IDs
  4. Constructs PUT operation to replace entire group membership
  5. Strips read-only attributes per RFC 7643

## Operating Modes

### Mode 1: User Membership Sync (Incremental)
**Flow**:
1. User attribute change detected (e.g., `memberOf` attribute)
2. `fetchEntry`: Maps LDAP user to SCIM2 user, retrieves current group memberships
3. Sync engine compares source vs destination memberships
4. `modifyEntry`: Processes differences, updates SCIM2 groups via PATCH/PUT

**Use Case**: Daily incremental synchronization of user group membership changes

### Mode 2: Group Resync (Full)
**Flow**:
1. Source Plugin:
   - Detects dynamic group with `memberURL`
   - Parses `memberURL`: `ldap:///ou=users,dc=example,dc=com??sub?(department=Engineering)`
   - Queries LDAP for matching users
   - Extracts `uid` from each user
   - Adds `members` attribute: `[alice, bob, charlie]`

2. Destination Plugin:
   - `fetchEntry`: Maps group by name to SCIM2 group ID
   - `createEntry`: Ignores user resync operations
   - `modifyEntry`: Detects group entry (has `scim2GroupId`)
   - `processGroupResync`:
     - Reads `members` attribute: `[alice, bob, charlie]`
     - Searches SCIM2 for each user ID
     - Builds SCIM2 members list with SCIM2 user IDs
     - Executes PUT to replace entire group membership

**Use Case**: Full resync of dynamic group memberships (scheduled or on-demand)

## Implementation Details

### Source Plugin Changes

#### Class Documentation
```java
/**
 * This LDAP sync source plugin handles group resync operations for dynamic LDAP groups,
 * constructing a members attribute containing user IDs for each group member.
 */
```

#### Configuration Arguments
- Replaced example arguments with:
  - `user-id-attribute`: User ID attribute to extract (e.g., uid)
- **Removed**: `search-base-dn` - Base DN is now extracted from each group's `memberURL` attribute

#### postFetch Method
Completely rewritten to:
1. Detect dynamic groups (check for `memberURL` attribute)
2. Parse LDAP URL using UnboundID LDAP SDK's `LDAPURL` class
3. Extract base DN, scope, and filter from the parsed URL
4. Execute search to find matching users
5. Extract user ID attribute from each user
6. Construct `members` attribute with collected user IDs

#### LDAP URL Parsing
- Uses UnboundID LDAP SDK's `com.unboundid.ldap.sdk.LDAPURL` class
- Provides robust parsing with proper error handling
- Automatically handles URL components (base DN, scope, filter, attributes)
- Defaults: scope=SUB, filter=(objectClass=*)

### Destination Plugin Changes

#### Class Documentation
Updated to describe both operating modes:
- User Membership Sync (Incremental)
- Group Resync (Full)

#### fetchEntry Method
Enhanced to handle both users and groups:
- **Users**: Original logic (maps to SCIM2 user, retrieves group memberships)
- **Groups**: New logic via `fetchGroupEntry()`
  - Maps group by `cn` attribute
  - Searches SCIM2 for matching group
  - Returns synthetic entry with `scim2GroupId` attribute

#### createEntry Method
Updated to ignore user resync operations:
```java
// Check if this is a user entry - ignore user resync operations
Attribute usernameAttr = entryToCreate.getAttribute(usernameLookupAttribute);
if (usernameAttr != null) {
  operation.logInfo("Ignoring user resync operation (createEntry) for user entry");
  return;
}
```

#### modifyEntry Method
Enhanced to route group operations:
```java
// Check if this is a group entry (has scim2GroupId attribute)
Attribute scim2GroupIdAttr = entryToModify.getAttribute("scim2GroupId");
if (scim2GroupIdAttr != null && scim2GroupIdAttr.getValue() != null) {
  // This is a group entry - process group resync
  processGroupResync(entryToModify, modsToApply, operation);
  return;
}
```

#### New Method: processGroupResync
Dedicated method for group resync operations:
1. Extracts `scim2GroupId` from entry
2. Finds `members` modification in `modsToApply`
3. Iterates through member user IDs
4. Searches SCIM2 for each user ID to get SCIM2 user ID
5. Builds list of `Member` objects with SCIM2 user IDs
6. Retrieves existing SCIM2 group
7. Replaces `members` list
8. Strips read-only attributes (per RFC 7643)
9. Executes PUT operation to update group

## LDAP URL Format

The source plugin uses the UnboundID LDAP SDK's `LDAPURL` class to parse LDAP URLs in the `memberURL` attribute:

**Format**: `ldap:///baseDN??scope?filter`

**Examples**:
```
ldap:///ou=users,dc=example,dc=com??sub?(department=Engineering)
ldap:///ou=users,dc=example,dc=com??sub?(title=Manager)
ldap:///ou=people,dc=example,dc=com??one?(objectClass=person)
```

**Components**:
- `baseDN`: Base DN for search (required - plugin will skip memberURL if missing)
- Attributes: (empty - not used in memberURL)
- `scope`: Search scope (base, one, sub/subtree) - defaults to `sub` if not specified
- `filter`: LDAP filter - defaults to `(objectClass=*)` if not specified

## Error Handling

### Source Plugin
- Logs warnings for unparseable LDAP URLs
- Continues processing other `memberURL` values on errors
- Adds empty `members` attribute if no users found
- Logs missing user ID attributes

### Destination Plugin
- Logs warnings for users not found in SCIM2
- Continues processing remaining users on individual failures
- Comprehensive logging at each step
- Maintains group membership even if some users can't be mapped

## Testing Recommendations

### Unit Tests
1. Source Plugin:
   - Test LDAP URL parsing with various formats
   - Test dynamic group membership expansion
   - Test handling of missing/invalid memberURLs
   - Test extraction of different user ID attributes

2. Destination Plugin:
   - Test user resync operation ignoring
   - Test group resync processing
   - Test SCIM2 user ID lookup
   - Test PUT operation execution

### Integration Tests
1. End-to-End Group Resync:
   - Create dynamic group in LDAP with memberURL
   - Trigger resync operation
   - Verify SCIM2 group membership matches expected users
   - Verify users are properly mapped

2. Mixed Operations:
   - Test incremental user membership changes
   - Test group resync operations
   - Verify both modes work independently

## Configuration Example

### Sync Pipe Configuration

```
# Source Plugin Configuration
ldap-sync-source-plugin.1.extension=com.heer.sync.LDAPSyncSourcePluginScim2GroupMembers
ldap-sync-source-plugin.1.user-id-attribute=uid

# Destination Plugin Configuration (existing)
sync-destination.extension=com.heer.sync.Scim2GroupMemberDestination
sync-destination.base-url=https://scim.example.com/scim/v2
sync-destination.user-base=/Users
sync-destination.group-base=/Groups
sync-destination.username=syncuser
sync-destination.password=password
sync-destination.group-membership-attributes=memberOf
sync-destination.username-lookup-attribute=uid
sync-destination.update-method=put
```

## Deployment

1. Compile both plugin classes
2. Package into JAR file
3. Copy JAR to Ping Data Sync extensions directory
4. Configure sync pipe with both plugins
5. Restart Ping Data Sync server
6. Configure resync schedule or trigger manual resync

## Benefits

1. **Dynamic Group Support**: Automatically expands dynamic group membership
2. **Accurate Synchronization**: Replaces entire membership list during resync
3. **Separation of Concerns**: Source handles expansion, destination handles SCIM2 updates
4. **Flexible Configuration**: Supports different user ID attributes and base DNs
5. **Error Resilience**: Continues processing on individual user lookup failures
6. **Production Ready**: Comprehensive logging and error handling

## Limitations

1. **Performance**: Large groups with many members may take time to process
2. **LDAP Dependency**: Requires LDAP URL parsing (standard format)
3. **User Existence**: Users must exist in SCIM2 before group membership can be synced
4. **PUT Operations Only**: Group resync uses PUT (not PATCH) for full replacement

## Future Enhancements

1. **Batch Processing**: Process users in batches for better performance
2. **Caching**: Cache user ID to SCIM2 ID mappings
3. **Parallel Processing**: Search for multiple users concurrently
4. **PATCH Support**: Optimize group updates with differential PATCH operations
5. **Metrics**: Add performance metrics for group resync operations

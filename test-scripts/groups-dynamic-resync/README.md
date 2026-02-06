# Groups-Dynamic-Resync Pipe Test Scripts

This directory contains test scripts for validating the **Groups-Dynamic-Resync** pipe event filtering and user creation capabilities.

## Pipe Overview

- **Pipe Name**: `Groups-Dynamic-Resync`
- **Source Plugin**: `DynamicGroupSourcePlugin` (enhanced with early filtering and user attribute collection)
- **Destination Plugin**: `DynamicGroupMemberDestination` (enhanced with user creation support)
- **Purpose**: Periodic resync of dynamic group memberships by executing `memberURL` queries

## New Feature: Automatic User Creation

The dynamic group pipe now supports **automatic user creation** similar to static groups. When configured with:
- `user.lifecycle.mode=dynamic-group-memberships`
- `scim.user.attributes=<attribute-list>`
- `scim.user.map.*=<LDAP-mappings>`

The source plugin fetches LDAP attributes for each member user and includes them in an enhanced `memberMappings` format. The destination plugin parses this data and creates users in SCIM2 if they don't exist before adding them to groups.

## Filtering Logic

The enhanced `DynamicGroupSourcePlugin` filters events based on:
- **Early Filter Check**: Group matches LDAP filter BEFORE memberURL execution
- **ALLOW**: Dynamic group matching filter with valid `memberURL`
- **BLOCK**: 
  - Group does NOT match LDAP filter
  - Non-dynamic groups (missing `memberURL` attribute)

## Test Coverage

| Test Script | Scenario | Expected Result |
|-------------|----------|-----------------|
| `test-dynamic-resync-matching-filter.sh` | Dynamic group resync (filter match) | **ALLOW** - Members synced to SCIM2 |
| `test-dynamic-resync-not-matching-filter.sh` | Dynamic group resync (no filter match) | **BLOCK** - Filtered upstream |
| `test-dynamic-no-memberurl.sh` | Entry without memberURL attribute | **BLOCK** - Not a dynamic group |
| `test-dynamic-user-creation.sh` | **NEW**: Dynamic group with non-existent users | **ALLOW** - Users created automatically in SCIM2 |

## Expected Log Messages

### Event ALLOWED (with user creation)
```
DynamicGroupSourcePlugin: Processing dynamic group cn=scim-qa-team,ou=Groups,dc=example,dc=com
DynamicGroupSourcePlugin: Executing memberURL search: ldap:///ou=SyncUsers,dc=example,dc=com??sub?(scim-groups=qa-team)
DynamicGroupSourcePlugin: Found 15 dynamic members
DynamicGroupSourcePlugin: Fetched 4 user attributes for uid=jdoe
DynamicGroupMemberDestination: User jdoe not found, attempting to create from JSON data
DynamicGroupMemberDestination: Successfully created user: jdoe (ID: 12345)
DynamicGroupMemberDestination: Resyncing group with 15 members
```

### Event ALLOWED (without user creation - legacy behavior)
```
DynamicGroupSourcePlugin: Processing dynamic group cn=scim-qa-team,ou=Groups,dc=example,dc=com
DynamicGroupSourcePlugin: Executing memberURL search: ldap:///ou=SyncUsers,dc=example,dc=com??sub?(scim-groups=qa-team)
DynamicGroupSourcePlugin: Found 15 dynamic members
DynamicGroupMemberDestination: WARNING: Skipping user jdoe - could not resolve or create
```

### Event BLOCKED (Early Filter)
```
DynamicGroupSourcePlugin: Group cn=local-admins,ou=Groups,dc=example,dc=com does not match filter - filtered from SCIM2 sync
```

### Event BLOCKED (Not Dynamic)
```
DynamicGroupSourcePlugin: Entry cn=scim-developers,ou=Groups,dc=example,dc=com is not a dynamic group - filtered
```

## Performance Enhancement

The early filter check (lines 463-479) prevents:
- Unnecessary LDAP queries via `memberURL` execution
- Processing members for out-of-scope groups
- Destination queries for filtered groups

This is critical for dynamic groups as `memberURL` queries can be expensive LDAP operations.

## Configuration

### Basic configuration (without user creation)
```properties
# Group filter for dynamic resync operations
group.filter=(cn=scim-*)

# User ID attribute
user.id.attribute=uid

# Resync schedule (e.g., every 6 hours)
dynamic.resync.interval=21600
```

### Enhanced configuration (with automatic user creation)
```properties
# Group filter for dynamic resync operations
group.filter=(cn=scim-*)

# User ID attribute
user.id.attribute=uid

# Enable user creation for dynamic groups
user.lifecycle.mode=dynamic-group-memberships

# SCIM user attributes to populate on creation
scim.user.attributes=userName,name.familyName,name.givenName,displayName

# LDAP to SCIM attribute mappings
scim.user.map.userName=uid
scim.user.map.name.familyName=sn
scim.user.map.name.givenName=givenName
scim.user.map.displayName=displayName

# Resync schedule (e.g., every 6 hours)
dynamic.resync.interval=21600
```

## Running Tests

```bash
# Run all tests for this pipe
./test-dynamic-resync-matching-filter.sh
./test-dynamic-resync-not-matching-filter.sh
./test-dynamic-no-memberurl.sh

# NEW: Test automatic user creation
./test-dynamic-user-creation.sh
```

## Test: Automatic User Creation (`test-dynamic-user-creation.sh`)

This test validates the new user creation capability:

1. Creates test users in LDAP only (not in SCIM2)
2. Creates a dynamic group with `memberURL` pointing to those users
3. Triggers group resync
4. Verifies users are automatically created in SCIM2
5. Verifies user attributes are mapped correctly
6. Verifies users are added to the group in SCIM2

**Prerequisites:**
- `user.lifecycle.mode=dynamic-group-memberships` configured
- `scim.user.attributes` and `scim.user.map.*` properties configured
- SCIM2 group must exist before user creation (groups not auto-created)

**Expected Outcome:**
- Users created in SCIM2 with mapped attributes from LDAP
- Users added as members to the group
- No errors in sync logs

## Resync Testing Notes

Dynamic group resync is triggered by:
1. Scheduled intervals (configured via `dynamic.resync.interval`)
2. Manual `resync` command via dsconfig

For testing, you may need to:
- Trigger manual resync: `bin/dsconfig resync --pipe Groups-Dynamic-Resync`
- Or wait for scheduled interval
- Or reduce interval temporarily for testing

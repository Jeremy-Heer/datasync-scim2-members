# Users-Group-Membership Pipe Test Scripts

This directory contains test scripts for validating the **Users-Group-Membership** pipe event filtering.

## Pipe Overview

- **Pipe Name**: `Users-Group-Membership`
- **Source Plugin**: `UserGroupMembershipSourcePlugin`
- **Destination Plugin**: `UserGroupMembershipDestination`
- **Purpose**: Sync user group membership changes detected via changelog as PATCH operations to SCIM2

## Filtering Logic

The `UserGroupMembershipSourcePlugin` filters events based on:
- **ALLOW**: User MODIFY with changelog showing group membership attribute changes
- **BLOCK**: 
  - User CREATE events (not relevant for this pipe)
  - User DELETE events (not relevant for this pipe)
  - User MODIFY without group membership attribute changes

## Test Coverage

| Test Script | Event # | Scenario | Expected Result |
|-------------|---------|----------|-----------------|
| `test-user-modify-group-added.sh` | 4 | User MODIFY - group added | **ALLOW** - PATCH to SCIM2 |
| `test-user-modify-group-removed.sh` | 5 | User MODIFY - group removed | **ALLOW** - PATCH to SCIM2 |
| `test-user-modify-no-group-change.sh` | 6 | User MODIFY - no group change | **BLOCK** - Filtered |

## Expected Log Messages

### Event ALLOWED
```
UserGroupMembershipSourcePlugin: User uid=jsmith,ou=SyncUsers,dc=example,dc=com has group membership modification - allowed
UserGroupMembershipSourcePlugin: Detected changes to attribute: scim-groups
```

### Event BLOCKED
```
UserGroupMembershipSourcePlugin: User uid=jsmith,ou=SyncUsers,dc=example,dc=com has no group membership changes - filtered
```

## Changelog Inspection

This plugin inspects the LDAP changelog to determine if group membership attributes changed:

```java
for (Modification mod : operation.getAllModifications()) {
  if (groupMembershipAttributes.contains(mod.getAttributeName().toLowerCase())) {
    return true; // Group membership changed
  }
}
```

## Configuration

Ensure your `scim-sync.properties` includes:
```properties
# Group membership attribute(s) to track
group.membership.attributes=scim-groups

# Enable changelog mode for this pipe
sync.mode=notification
```

## Running Tests

```bash
# Run all tests for this pipe
./test-user-modify-group-added.sh
./test-user-modify-group-removed.sh
./test-user-modify-no-group-change.sh
```

## SCIM2 PATCH Operations

When ALLOWED, this pipe generates SCIM2 PATCH operations:

**Group Added:**
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{
    "op": "add",
    "path": "groups",
    "value": [{"value": "scim-developers", "display": "Developers"}]
  }]
}
```

**Group Removed:**
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{
    "op": "remove",
    "path": "groups[value eq \"scim-qa-team\"]"
  }]
}
```

## Redundant Check Removal

Note: The destination plugin (`UserGroupMembershipDestination`) previously had a redundant changelog check in `fetchEntry()` that has been removed (lines 443-467). Filtering is now handled entirely by this source plugin.

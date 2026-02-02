# Groups-Dynamic-Resync Pipe Test Scripts

This directory contains test scripts for validating the **Groups-Dynamic-Resync** pipe event filtering.

## Pipe Overview

- **Pipe Name**: `Groups-Dynamic-Resync`
- **Source Plugin**: `DynamicGroupSourcePlugin` (enhanced with early filtering)
- **Destination Plugin**: `DynamicGroupMemberDestination`
- **Purpose**: Periodic resync of dynamic group memberships by executing `memberURL` queries

## Filtering Logic

The enhanced `DynamicGroupSourcePlugin` filters events based on:
- **Early Filter Check** (NEW): Group matches LDAP filter BEFORE memberURL execution
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

## Expected Log Messages

### Event ALLOWED
```
DynamicGroupSourcePlugin: Processing dynamic group cn=scim-qa-team,ou=Groups,dc=example,dc=com
DynamicGroupSourcePlugin: Executing memberURL search: ldap:///ou=SyncUsers,dc=example,dc=com??sub?(scim-groups=qa-team)
DynamicGroupSourcePlugin: Found 15 dynamic members
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

Ensure your `scim-sync.properties` includes:
```properties
# Group filter for dynamic resync operations
group.filter=(cn=scim-*)

# Resync schedule (e.g., every 6 hours)
dynamic.resync.interval=21600
```

## Running Tests

```bash
# Run all tests for this pipe
./test-dynamic-resync-matching-filter.sh
./test-dynamic-resync-not-matching-filter.sh
./test-dynamic-no-memberurl.sh
```

## Resync Testing Notes

Dynamic group resync is triggered by:
1. Scheduled intervals (configured via `dynamic.resync.interval`)
2. Manual `resync` command via dsconfig

For testing, you may need to:
- Trigger manual resync: `bin/dsconfig resync --pipe Groups-Dynamic-Resync`
- Or wait for scheduled interval
- Or reduce interval temporarily for testing

# Groups-Static-Members Pipe Test Scripts

This directory contains test scripts for validating the **Groups-Static-Members** pipe event filtering.

## Pipe Overview

- **Pipe Name**: `Groups-Static-Members`
- **Source Plugin**: `StaticGroupSourcePlugin` (enhanced with early filtering)
- **Destination Plugin**: `StaticGroupMemberDestination`
- **Purpose**: Sync static group membership changes to SCIM2 as member add/remove operations

## Filtering Logic

The enhanced `StaticGroupSourcePlugin` filters events based on:
- **Early Filter Check** (NEW): Group matches LDAP filter BEFORE member expansion
- **ALLOW**: Static group matching filter with member attribute changes
- **BLOCK**: 
  - Group does NOT match LDAP filter
  - Non-static groups (missing `member` attribute)
  - Static group with no member changes

## Test Coverage

| Test Script | Event # | Scenario | Expected Result |
|-------------|---------|----------|-----------------|
| `test-static-group-member-add-matching.sh` | 13 | Static group member ADD (filter match) | **ALLOW** - Member added in SCIM2 |
| `test-static-group-member-add-not-matching.sh` | 14 | Static group member ADD (no filter match) | **BLOCK** - Filtered upstream |
| `test-static-group-member-remove-matching.sh` | 17 | Static group member REMOVE (filter match) | **ALLOW** - Member removed in SCIM2 |

## Expected Log Messages

### Event ALLOWED
```
StaticGroupSourcePlugin: Processing static group cn=scim-developers,ou=Groups,dc=example,dc=com
StaticGroupSourcePlugin: Found 2 members to sync
```

### Event BLOCKED (Early Filter)
```
StaticGroupSourcePlugin: Group cn=local-staff,ou=Groups,dc=example,dc=com does not match filter - filtered from SCIM2 sync
```

### Event BLOCKED (Not Static)
```
StaticGroupSourcePlugin: Entry cn=scim-dynamic-qa,ou=Groups,dc=example,dc=com is not a static group - filtered
```

## Performance Enhancement

The early filter check (lines 463-479) prevents:
- Unnecessary member DN lookups in LDAP
- Processing members for out-of-scope groups
- Destination queries for filtered groups

## Configuration

Ensure your `scim-sync.properties` includes:
```properties
# Group filter for static member operations
group.filter=(cn=scim-*)
```

## Running Tests

```bash
# Run all tests for this pipe
./test-static-group-member-add-matching.sh
./test-static-group-member-add-not-matching.sh
./test-static-group-member-remove-matching.sh
```

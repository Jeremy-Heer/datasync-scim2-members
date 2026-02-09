# Groups-Basic-CRUD Pipe Test Scripts

This directory contains test scripts for validating the **Groups-Basic-CRUD** pipe event filtering.

## Pipe Overview

- **Pipe Name**: `Groups-Basic-CRUD`
- **Source Plugin**: `GroupBasicCrudSourcePlugin`
- **Destination Plugin**: Standard SCIM2 destination
- **Purpose**: Sync group CREATE/MODIFY/DELETE operations for groups matching the LDAP filter

## Filtering Logic

The `GroupBasicCrudSourcePlugin` filters events based on:
- **ALLOW**: Group matches LDAP filter (e.g., `cn=scim-*`)
- **BLOCK**: Group does NOT match LDAP filter

## Test Coverage

| Test Script | Event # | Scenario | Expected Result |
|-------------|---------|----------|-----------------|
| `test-group-create-matching-filter.sh` | 9 | Group CREATE matching filter | **ALLOW** - Created in SCIM2 |
| `test-group-create-not-matching-filter.sh` | 10 | Group CREATE NOT matching filter | **BLOCK** - NOT created in SCIM2 |
| `test-group-modify-matching-filter.sh` | 11 | Group MODIFY matching filter | **ALLOW** - Updated in SCIM2 |
| `test-group-modify-not-matching-filter.sh` | 12 | Group MODIFY NOT matching filter | **BLOCK** - NOT updated in SCIM2 |
| `test-group-delete-matching-filter.sh` | 15 | Group DELETE matching filter | **ALLOW** - Deleted in SCIM2 |
| `test-group-delete-not-matching-filter.sh` | 16 | Group DELETE NOT matching filter | **BLOCK** - Ignored (not in SCIM2) |

## Expected Log Messages

### Event ALLOWED
```
GroupBasicCrudSourcePlugin: Group cn=scim-developers,ou=Groups,dc=example,dc=com matches filter - allowed
```

### Event BLOCKED
```
GroupBasicCrudSourcePlugin: Group cn=local-staff,ou=Groups,dc=example,dc=com does not match filter - filtered from SCIM2 sync
```

## Configuration

Ensure your `scim-sync.properties` includes:
```properties
# Group filter for CRUD operations
group.filter=(cn=scim-*)
```

## Running Tests

```bash
# Run all tests for this pipe
./test-group-create-matching-filter.sh
./test-group-create-not-matching-filter.sh
./test-group-modify-matching-filter.sh
./test-group-modify-not-matching-filter.sh
./test-group-delete-matching-filter.sh
./test-group-delete-not-matching-filter.sh
```

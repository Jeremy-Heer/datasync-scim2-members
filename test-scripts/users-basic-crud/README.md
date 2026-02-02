# Users-Basic-CRUD Pipe Tests

Tests for **Pipe 1: Users-Basic-CRUD** sync pipe.

## Purpose

Validates that only users WITH group membership attributes are synchronized to SCIM2, and users WITHOUT are blocked upstream.

## Source Plugin

**UserBasicCrudSourcePlugin** - Filters users without `scim-groups` attribute

## Test Coverage

| Event | Test Script | Expected Result |
|-------|-------------|-----------------|
| Event 1: User CREATE without groups | `test-user-create-without-groups.sh` | 🚫 BLOCKED - No SCIM2 user created |
| Event 2: User CREATE with groups | `test-user-create-with-groups.sh` | ✅ ALLOWED - SCIM2 user created |
| Event 3: User MODIFY no group changes | `test-user-modify-standard.sh` | ✅ ALLOWED - SCIM2 user updated |
| Event 7: User DELETE with groups | `test-user-delete-with-groups.sh` | ✅ ALLOWED - SCIM2 user deleted |
| Event 8: User DELETE without groups | `test-user-delete-without-groups.sh` | 🚫 BLOCKED - No SCIM2 action |

## Running Tests

```bash
# Run all tests
./run-all-tests.sh

# Run individual test
./test-user-create-with-groups.sh
```

## Verification

```bash
# Check if user exists in SCIM2
./verify-scim2-users.sh jsmith
```

## Expected Log Messages

### Allowed Event (User with groups)
```
[INFO] UserBasicCrudSourcePlugin: User has group membership attributes - allowing SCIM2 sync: uid=jsmith,ou=Users,dc=example,dc=com
```

### Blocked Event (User without groups)
```
[INFO] UserBasicCrudSourcePlugin: User has no group membership attributes - filtered from SCIM2 sync: uid=jdoe,ou=Users,dc=example,dc=com
```

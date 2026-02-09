# SCIM2 Sync Testing Scripts

## Overview

This directory contains test scripts organized by sync pipe to validate event filtering and SCIM2 synchronization behavior. Each pipe has dedicated test scenarios covering the event matrix defined in [SYNC_EVENT_FILTERING.md](../SYNC_EVENT_FILTERING.md).

## Directory Structure

```
test-scripts/
├── users-basic-crud/          # Pipe 1 tests
├── groups-basic-crud/         # Pipe 2 tests
├── groups-static-members/     # Pipe 3 tests
├── groups-dynamic-resync/     # Pipe 4 tests
├── users-group-membership/    # Pipe 5 tests
├── common/                    # Shared utilities
└── README.md                  # This file
```

## Configuration

Before running tests, configure connection details in `common/config.sh`:

```bash
# LDAP Source Configuration
export LDAP_HOST="ldap.example.com"
export LDAP_PORT="389"
export LDAP_BIND_DN="cn=admin,dc=example,dc=com"
export LDAP_BIND_PW="changeme"
export LDAP_BASE_DN="dc=example,dc=com"

# SCIM2 Destination Configuration
export SCIM2_BASE_URL="https://scim.example.com/v2"
export SCIM2_AUTH_TOKEN="your-bearer-token-here"
export SCIM2_USER_ENDPOINT="/Users"
export SCIM2_GROUP_ENDPOINT="/Groups"
```

## Running Tests

### Run All Tests for a Pipe

```bash
cd test-scripts/users-basic-crud
./run-all-tests.sh
```

### Run Individual Test

```bash
cd test-scripts/users-basic-crud
./test-user-create-with-groups.sh
```

### Run Verification Only

```bash
cd test-scripts/users-basic-crud
./verify-scim2-users.sh jsmith
```

## Test Naming Convention

```
test-{entity}-{operation}-{condition}.sh
```

**Examples:**
- `test-user-create-with-groups.sh` - Test Event 2: User CREATE with group attributes
- `test-user-modify-no-groups.sh` - Test Event 3: User MODIFY without group changes
- `test-group-create-filtered.sh` - Test Event 10: Group CREATE matching filter

## Verification Scripts

Each pipe includes verification scripts to query SCIM2 endpoint and validate results:

- `verify-scim2-users.sh {username}` - Check user existence in SCIM2
- `verify-scim2-groups.sh {groupname}` - Check group existence in SCIM2
- `verify-scim2-memberships.sh {groupname}` - Check group members in SCIM2

## Common Utilities

Located in `common/` directory:

- `config.sh` - Shared configuration variables
- `ldap-utils.sh` - LDAP connection helpers (ldapadd, ldapmodify, ldapdelete)
- `scim2-utils.sh` - SCIM2 API helpers (GET, POST, PATCH, DELETE)
- `logger.sh` - Consistent logging functions

## Test Result Format

Each test prints results in this format:

```
[INFO] Running: Test User CREATE with groups
[INFO] Creating user jsmith with scim-groups attribute
[INFO] Waiting 5 seconds for sync...
[INFO] Verifying user in SCIM2...
[PASS] User jsmith found in SCIM2
[PASS] User has correct attributes
[INFO] Verifying group memberships...
[PASS] User is member of developers group
[PASS] User is member of qa-team group
[PASS] Test completed successfully

Summary:
  Total Checks: 4
  Passed: 4
  Failed: 0
```

## Exit Codes

- `0` - All tests passed
- `1` - One or more tests failed
- `2` - Configuration error
- `3` - Connection error (LDAP or SCIM2)

## Best Practices

1. **Clean Up After Tests** - Always delete test entries after validation
2. **Use Unique Names** - Append timestamps to avoid conflicts
3. **Wait for Sync** - Allow 5-10 seconds for sync to process events
4. **Check Logs** - Inspect Data Sync Server logs for filtering messages
5. **Isolate Tests** - Run one test at a time for clear results

## Troubleshooting

### Test Fails But Entry Exists in SCIM2

**Cause:** Event was NOT filtered (incorrect filter configuration)

**Solution:** Check source plugin filter configuration and logs

### Test Passes But Entry Missing in SCIM2

**Cause:** Event was filtered when it should have been allowed

**Solution:** Verify user has `scim-groups` attribute or group matches filter

### Connection Timeout

**Cause:** Incorrect LDAP_HOST or SCIM2_BASE_URL in config

**Solution:** Verify connectivity: `ldapsearch -H ldap://$LDAP_HOST` and `curl $SCIM2_BASE_URL`

### Authentication Failed

**Cause:** Invalid credentials in config

**Solution:** Test auth: `ldapwhoami -H ldap://$LDAP_HOST -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PW"`

## Contributing

When adding new tests:

1. Follow naming convention
2. Include verification step
3. Clean up test data
4. Document in pipe's README.md
5. Add to run-all-tests.sh

# SCIM2 User Group Membership Destination Plugin

## Overview

**Plugin Class:** `com.heer.sync.Scim2UserGroupMembershipDestination`  
**Purpose:** USER-DRIVEN incremental group membership synchronization  
**Version:** 2.11  
**Architecture:** Refactored with shared libraries

## Description

This destination plugin monitors user attribute changes (trigger attributes like `scim-groups`) and updates SCIM2 group memberships incrementally. It processes ADD, DELETE, and REPLACE operations for efficient synchronization without requiring full group resyncs.

## Key Features

- ✅ **User-driven incremental updates** - Monitors user entries, not group entries
- ✅ **Trigger attribute model** - Real LDAP attributes that produce changelog events
- ✅ **ADD/DELETE/REPLACE support** - All modification types handled correctly
- ✅ **Standard and notification modes** - Works in both sync modes
- ✅ **Shared library integration** - Uses Scim2ClientFactory, Scim2MemberHelper, ConfigFileLoader
- ✅ **Optimized queries** - Only requests essential attributes to minimize data transfer
- ✅ **Changelog support** - Can use changelog before-values to avoid lookups
- ✅ **Shared configuration** - Supports shared properties files

## Trigger Attribute Model

### Critical Understanding

This plugin monitors **REAL LDAP attributes** that produce changelog events:

✅ **WORKS:** `scim-groups` (real attribute)  
❌ **DOES NOT WORK:** `memberOf` (virtual attribute, no changelog)

### Example LDAP Schema

```ldif
# Define the trigger attribute
attributeTypes: ( 1.3.6.1.4.1.99999.1.1.1
  NAME 'scim-groups'
  DESC 'Group memberships for SCIM synchronization'
  EQUALITY caseIgnoreMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )

# Add to user object class
objectClasses: ( 1.3.6.1.4.1.99999.2.1.1
  NAME 'scimUser'
  SUP top
  AUXILIARY
  MAY scim-groups )
```

### Example User Entry

```ldif
dn: uid=jdoe,ou=users,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
objectClass: scimUser
uid: jdoe
cn: John Doe
scim-groups: developers
scim-groups: devops
scim-groups: qa-team
```

## How It Works

### ADD Operation
```ldif
modify: uid=jdoe,ou=users,dc=example,dc=com
add: scim-groups
scim-groups: production-team

# Result: jdoe added to SCIM2 "production-team" group
```

### DELETE Operation
```ldif
modify: uid=jdoe,ou=users,dc=example,dc=com
delete: scim-groups
scim-groups: qa-team

# Result: jdoe removed from SCIM2 "qa-team" group
```

### REPLACE Operation
```ldif
modify: uid=jdoe,ou=users,dc=example,dc=com
replace: scim-groups
scim-groups: developers
scim-groups: production-team

# Result: 
# - Adds jdoe to any groups in new list not in current
# - Removes jdoe from any groups in current not in new list
# - Final state: exactly matches source
```

## Configuration

### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `base-url` | SCIM2 endpoint URL | `https://scim.example.com/scim/v2` |
| `user-lookup-attribute` | LDAP attribute for username lookup | `uid` or `sAMAccountName` |
| `group-membership-attributes` | Trigger attribute(s) | `scim-groups` |

### Optional Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `config-file` | Shared configuration file path | None |
| `user-base-path` | SCIM2 users path | `/Users` |
| `group-base-path` | SCIM2 groups path | `/Groups` |
| `auth-username` | HTTP basic auth username | None |
| `auth-password` | HTTP basic auth password | None |
| `bearer-token` | OAuth bearer token | None |
| `trust-store-file` | SSL trust store path | None |
| `trust-store-password` | SSL trust store password | None |
| `proxy-host` | HTTP proxy host | None |
| `proxy-port` | HTTP proxy port | None |
| `disable-group-membership-lookups` | Skip SCIM2 lookups, use changelog | `false` |
| `max-retries` | Retry attempts for failed operations | `3` |
| `retry-delay-ms` | Initial retry delay (exponential backoff) | `1000` |

### Example Sync Pipe Configuration

#### Inline Arguments

```bash
dsconfig create-sync-pipe \
  --pipe-name "User Group Membership Sync" \
  --type third-party \
  --set "sync-source:LDAP Source" \
  --set "sync-destination:SCIM2 User Group Membership" \
  --set "started:true"

dsconfig create-sync-destination \
  --destination-name "SCIM2 User Group Membership" \
  --type third-party \
  --set "extension-class:com.heer.sync.Scim2UserGroupMembershipDestination" \
  --set "extension-argument:base-url=https://scim.example.com/scim/v2" \
  --set "extension-argument:user-lookup-attribute=uid" \
  --set "extension-argument:group-membership-attributes=scim-groups" \
  --set "extension-argument:auth-username=admin" \
  --set "extension-argument:auth-password=secret"
```

#### Shared Configuration File

**scim-sync.properties:**
```properties
# SCIM2 Endpoint
scim2.base.url=https://scim.example.com/scim/v2
scim2.user.base=/Users
scim2.group.base=/Groups

# Authentication
scim2.auth.type=basic
scim2.username=admin
scim2.password=secret

# SSL (optional)
scim2.trust.store.path=/path/to/truststore.jks
scim2.trust.store.password=changeit

# Performance
scim2.max.retries=3
scim2.retry.delay.ms=1000
```

**Sync Destination:**
```bash
dsconfig create-sync-destination \
  --destination-name "SCIM2 User Group Membership" \
  --type third-party \
  --set "extension-class:com.heer.sync.Scim2UserGroupMembershipDestination" \
  --set "extension-argument:config-file=/path/to/scim-sync.properties" \
  --set "extension-argument:user-lookup-attribute=uid" \
  --set "extension-argument:group-membership-attributes=scim-groups"
```

### Performance Optimization

For **notification mode with changelog support**, enable this optimization:

```bash
--set "extension-argument:disable-group-membership-lookups=true"
```

This avoids querying SCIM2 for current memberships during REPLACE operations, instead using changelog before-values. **Only use in notification mode!**

## Synchronization Modes

### Standard Mode

1. Source entry changes
2. fetchEntry() queries SCIM2 for current memberships
3. Sync engine compares source vs destination
4. modifyEntry() processes differences
5. Updates applied to SCIM2

### Notification Mode

1. Source entry changes
2. Changelog captures before/after values
3. modifyEntry() receives changelog entry
4. For REPLACE: Can use before-values if lookups disabled
5. Updates applied to SCIM2

## Architecture

### Shared Libraries

- **Scim2ClientFactory** - REST client with auth/SSL/proxy
- **Scim2MemberHelper** - Reusable SCIM2 operations (optimized)
- **ConfigFileLoader** - Shared configuration file support

### Operations

- **ADD** - Adds user to specified group(s)
- **DELETE** - Removes user from specified group(s)  
- **DELETE (no values)** - Removes user from ALL groups for attribute
- **REPLACE** - Calculates diff, adds missing, removes extra

### SCIM2 Protocol

Uses **PATCH operations** per RFC 7644:

**Add Member:**
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{
    "op": "add",
    "path": "members",
    "value": [{"value": "user-id-123"}]
  }]
}
```

**Remove Member:**
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{
    "op": "remove",
    "path": "members[value eq \"user-id-123\"]"
  }]
}
```

## Comparison with Other Plugins

### vs Scim2GroupMemberDestination (Original)

| Feature | Scim2UserGroupMembershipDestination | Scim2GroupMemberDestination |
|---------|-------------------------------------|----------------------------|
| **Entry Type** | User entries | User AND group entries |
| **Sync Model** | USER-driven incremental | Mixed (user + group) |
| **Trigger** | scim-groups attribute | scim-groups OR group members |
| **Operations** | ADD/DELETE/REPLACE | ADD/DELETE/REPLACE + resync |
| **Shared Libraries** | ✅ Yes | ❌ No (manual setup) |
| **Complexity** | Simple, focused | Complex, mixed purpose |
| **Use Case** | Dynamic group incremental | Both static and dynamic |

### vs Scim2DynamicGroupDestination

| Feature | Scim2UserGroupMembershipDestination | Scim2DynamicGroupDestination |
|---------|-------------------------------------|------------------------------|
| **Entry Type** | User entries | Group entries |
| **Sync Model** | USER-driven incremental | GROUP-driven resync |
| **Trigger** | User attribute changes | Group resync command |
| **Operations** | ADD/DELETE/REPLACE | REPLACE only |
| **Source Plugin** | None (direct user sync) | DynamicGroupSourcePlugin |
| **Use Case** | Real-time incremental | Periodic full sync |

### vs Scim2StaticGroupDestination

| Feature | Scim2UserGroupMembershipDestination | Scim2StaticGroupDestination |
|---------|-------------------------------------|---------------------------|
| **Entry Type** | User entries | Group entries |
| **Sync Model** | USER-driven | GROUP-driven |
| **Trigger** | scim-groups attribute | member/uniqueMember |
| **Operations** | ADD/DELETE/REPLACE | ADD/DELETE/REPLACE |
| **Group Type** | Dynamic (user-driven) | Static (group-driven) |
| **Use Case** | Dynamic group updates | Static group updates |

## Testing

### Manual Test Scenarios

#### Test 1: ADD Operation
```bash
# Add user to new group
ldapmodify -h localhost -p 389 -D "cn=admin" -w password <<EOF
dn: uid=jdoe,ou=users,dc=example,dc=com
changetype: modify
add: scim-groups
scim-groups: qa-team
EOF

# Verify in SCIM2
curl -u admin:password https://scim.example.com/scim/v2/Groups?filter=displayName+eq+%22qa-team%22
# Should show jdoe in members list
```

#### Test 2: DELETE Operation
```bash
# Remove user from group
ldapmodify -h localhost -p 389 -D "cn=admin" -w password <<EOF
dn: uid=jdoe,ou=users,dc=example,dc=com
changetype: modify
delete: scim-groups
scim-groups: developers
EOF

# Verify in SCIM2
curl -u admin:password https://scim.example.com/scim/v2/Groups?filter=displayName+eq+%22developers%22
# Should NOT show jdoe in members list
```

#### Test 3: REPLACE Operation
```bash
# Replace all group memberships
ldapmodify -h localhost -p 389 -D "cn=admin" -w password <<EOF
dn: uid=jdoe,ou=users,dc=example,dc=com
changetype: modify
replace: scim-groups
scim-groups: production-team
scim-groups: devops
EOF

# Verify in SCIM2
# jdoe should be in ONLY production-team and devops groups
# All other group memberships should be removed
```

### Verification Queries

```bash
# Check user's current groups in SCIM2
curl -u admin:password \
  "https://scim.example.com/scim/v2/Groups?filter=members.value+eq+%22<user-scim-id>%22&attributes=displayName"

# Check specific group membership
curl -u admin:password \
  "https://scim.example.com/scim/v2/Groups?filter=displayName+eq+%22groupname%22&attributes=id,displayName,members"
```

## Troubleshooting

### Plugin Not Loading

**Symptom:** Plugin class not found

**Solution:**
```bash
# Verify plugin in JAR
unzip -l Scim2GroupmemberSync.jar | grep Scim2UserGroupMembershipDestination

# Check extension.properties version matches
grep extension.version extension.properties

# Rebuild if necessary
./build.sh
```

### No Changelog Events

**Symptom:** Changes not detected

**Root Cause:** Using virtual attribute (memberOf)

**Solution:** Use real attribute (scim-groups) that produces changelog

```bash
# Verify attribute produces changelog
ldapmodify ... 
# Check changelog
ldapsearch -h localhost -p 389 -D "cn=admin" -w password \
  -b "cn=changelog" "(targetDN=uid=jdoe,*)" \
  | grep -A 5 "ds-changelog-before-values"
```

### Groups Not Found in SCIM2

**Symptom:** "Skipping group - not found in SCIM2"

**Solution:** Ensure groups exist in SCIM2 before sync

```bash
# Create groups in SCIM2 first
curl -X POST -u admin:password \
  -H "Content-Type: application/scim+json" \
  https://scim.example.com/scim/v2/Groups \
  -d '{"displayName": "developers", "members": []}'
```

### REPLACE Not Removing Old Groups

**Symptom:** User remains in groups after REPLACE

**Possible Causes:**
1. `disable-group-membership-lookups=true` without notification mode
2. Changelog before-values not available

**Solution:**
```bash
# Standard mode: Ensure lookups enabled (default)
# Notification mode: Verify changelog includes before-values

# Test query
ldapsearch -b "cn=changelog" "(targetDN=uid=jdoe,*)" ds-changelog-before-values
```

## Migration from Scim2GroupMemberDestination

If you're currently using Scim2GroupMemberDestination for dynamic group incremental updates:

### Steps

1. **Verify Configuration**
   - Note your current `group-membership-attributes` value
   - Ensure it's a real attribute (not memberOf)
   
2. **Create New Sync Destination**
   ```bash
   dsconfig create-sync-destination \
     --destination-name "SCIM2 User Group Membership - New" \
     --type third-party \
     --set "extension-class:com.heer.sync.Scim2UserGroupMembershipDestination" \
     --set "extension-argument:config-file=/path/to/scim-sync.properties" \
     --set "extension-argument:user-lookup-attribute=uid" \
     --set "extension-argument:group-membership-attributes=scim-groups"
   ```

3. **Test with New Sync Pipe**
   ```bash
   dsconfig create-sync-pipe \
     --pipe-name "User Group Membership Sync - Test" \
     --type third-party \
     --set "sync-source:LDAP Source" \
     --set "sync-destination:SCIM2 User Group Membership - New" \
     --set "started:false"
   
   # Test with single user
   # Verify results
   # Enable pipe
   ```

4. **Cutover**
   - Stop old pipe
   - Start new pipe
   - Monitor logs

### No Migration Path Needed

This plugin is **development only** - no production migration path required per project requirements.

## Best Practices

1. ✅ **Use Real Attributes** - Never use virtual attributes as triggers
2. ✅ **Create Groups First** - Ensure SCIM2 groups exist before sync
3. ✅ **Enable Changelog** - Use notification mode for best performance
4. ✅ **Monitor Logs** - Watch for "not found" messages
5. ✅ **Test REPLACE** - Verify diff calculation works correctly
6. ✅ **Use Shared Config** - Centralize common settings
7. ✅ **Start Small** - Test with single user before full deployment

## Related Documentation

- [PLUGIN_ARCHITECTURE.md](PLUGIN_ARCHITECTURE.md) - Complete architecture guide
- [DYNAMIC_GROUP_REFACTORING.md](DYNAMIC_GROUP_REFACTORING.md) - Refactoring summary
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Plugin quick reference
- [DYNAMIC_GROUP_TESTING_GUIDE.md](DYNAMIC_GROUP_TESTING_GUIDE.md) - Testing procedures

## Version History

- **2.11** - Initial release
  - Extracted user-driven logic from Scim2GroupMemberDestination
  - Integrated shared libraries (Scim2ClientFactory, Scim2MemberHelper, ConfigFileLoader)
  - Support for trigger attribute model (scim-groups)
  - ADD/DELETE/REPLACE operations
  - Standard and notification mode support
  - Optimized queries (attributes filtering)
  - Changelog before-values support
  - Shared configuration file support

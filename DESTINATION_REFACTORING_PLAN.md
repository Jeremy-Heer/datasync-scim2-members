# SCIM2 Destination Plugin Refactoring Implementation Plan

## Overview

Refactoring the monolithic 2,589-line `Scim2GroupMemberDestination.java` into three focused destination plugins with shared utilities.

## Architecture

### Three Destination Plugins

1. **Scim2UserMembershipDestination** (~1,500 lines)
   - Purpose: Incremental user-to-group synchronization
   - Monitors user attribute changes (memberOf, groups, etc.)
   - Updates SCIM2 groups by adding/removing users

2. **Scim2StaticGroupDestination** (~1,000 lines) **[NEW]**
   - Purpose: Static group membership synchronization (both incremental and resync)
   - Processes `members` attribute changes from StaticGroupSourcePlugin
   - Converts uid values → SCIM2 user IDs
   - **Incremental mode**: ADD/DELETE operations with batching (up to 50 per PATCH)
   - **Resync mode**: REPLACE operation using PUT
   - Threshold: `static-group-batch-threshold=50`

3. **Scim2GroupResyncDestination** (~900 lines)
   - Purpose: Dynamic group full membership resynchronization
   - Works with DynamicGroupSourcePlugin
   - Always uses PUT for full membership replacement
   - Simplified (no PATCH, no notification mode)

### Shared Utilities (lib/scim2/)

1. **Scim2ClientFactory** (~400 lines) ✅ CREATED
   - Creates configured ScimService and JAX-RS clients
   - Handles auth (basic/bearer), SSL/TLS, HTTP proxy
   - Supports ConfigFileLoader integration
   - Reduces ~300 lines duplication per plugin

2. **Scim2RetryHelper** (~80 lines)
   - Retry logic with exponential backoff
   - Configurable max retries and initial delay
   - Reduces ~60 lines duplication

3. **Scim2MemberHelper** (~150 lines)
   - `convertUserIdsToScim2Members(userIds[])` - Maps uid → SCIM2 Member objects
   - `findScim2UserId(username)` - Searches SCIM2 by userName
   - `findScim2GroupId(groupName)` - Searches SCIM2 by displayName
   - Shared by all three plugins

## Configuration File Support

All plugins support `--config-file` argument following source plugin pattern:

### Shared Properties (scim-sync.properties)
```properties
# SCIM2 endpoint
scim2.base.url=https://api.example.com/scim/v2
scim2.user.base=/Users
scim2.group.base=/Groups

# Authentication
scim2.auth.type=basic
scim2.username=syncuser
scim2.password=secret
# or
scim2.auth.type=bearer
scim2.bearer.token=eyJhbGc...

# SSL/TLS
scim2.trust.store.path=/opt/certs/truststore.jks
scim2.trust.store.password=changeit
scim2.trust.store.type=JKS
scim2.allow.untrusted.certificates=false

# HTTP Proxy
scim2.proxy.host=proxy.company.com
scim2.proxy.port=8080
scim2.proxy.username=proxyuser
scim2.proxy.password=proxypass
scim2.proxy.type=HTTP

# Performance
scim2.max.retries=3
scim2.retry.delay.ms=1000
scim2.connect.timeout.ms=30000
scim2.read.timeout.ms=60000
```

### Plugin-Specific Properties

**UserMembershipDestination:**
```properties
user.membership.attributes=memberOf,groups
user.lookup.attribute=uid
user.membership.update.method=patch
user.membership.disable.lookups=false
```

**StaticGroupDestination:**
```properties
static.group.batch.threshold=50
user.lookup.attribute=uid
```

**GroupResyncDestination:**
```properties
user.lookup.attribute=uid
```

## Static Group Batching Logic

### Batch Threshold: 50 operations

**Incremental ADD operations:**
```
If adds.size() <= threshold (50):
  - Single PATCH with all adds
Else:
  - Multiple PATCH requests, 50 operations each
  - Last PATCH has remainder
```

**Incremental DELETE operations:**
```
If deletes.size() <= threshold (50):
  - Single PATCH with all deletes
Else:
  - Multiple PATCH requests, 50 operations each
  - Last PATCH has remainder
```

**Mixed ADD + DELETE:**
```
Process adds (batched if > threshold)
Then process deletes (batched if > threshold)
```

**REPLACE (Resync):**
```
Always use PUT (replaces entire membership)
No batching - single operation
```

## Implementation Order

### Phase 1: Shared Utilities ✅
- [x] Scim2ClientFactory.java
- [ ] Scim2RetryHelper.java
- [ ] Scim2MemberHelper.java

### Phase 2: User Membership Destination
- [ ] Extract user-specific code from legacy plugin
- [ ] Integrate Scim2ClientFactory
- [ ] Add config file support
- [ ] Remove group resync code
- [ ] Test with user membership sync pipe

### Phase 3: Static Group Destination (NEW)
- [ ] Create new plugin from scratch
- [ ] Implement fetchGroupEntry()
- [ ] Implement modifyEntry() with mode detection (incremental vs resync)
- [ ] Implement batching logic for incremental operations
- [ ] Implement PUT for resync operations
- [ ] Add config file support
- [ ] Test with StaticGroupSourcePlugin

### Phase 4: Group Resync Destination
- [ ] Extract group resync code from legacy plugin
- [ ] Integrate Scim2ClientFactory
- [ ] Remove PATCH code (PUT only)
- [ ] Remove notification mode code
- [ ] Add config file support
- [ ] Test with DynamicGroupSourcePlugin

### Phase 5: Configuration & Documentation
- [ ] Update scim-sync.properties.example
- [ ] Create DESTINATION_MIGRATION_GUIDE.md
- [ ] Update build.xml
- [ ] Integration testing with all three plugins
- [ ] Update main README.md

## Sync Pipe Examples

### 1. User Membership Sync
```bash
dsconfig create-sync-pipe \
  --pipe-name "UserGroupMembershipSync" \
  --set sync-source-plugin:LDAPSource \
  --set sync-destination-plugin:Scim2UserMembershipDestination \
  --set "destination-plugin-arg:config-file=/opt/sync/config/scim-sync.properties" \
  --set "destination-plugin-arg:group-membership-attributes=memberOf" \
  --set "destination-plugin-arg:username-lookup-attribute=uid"
```

### 2. Static Group Incremental Sync
```bash
dsconfig create-sync-pipe \
  --pipe-name "StaticGroupIncrementalSync" \
  --set sync-source-plugin:StaticGroupSourcePlugin \
  --set sync-destination-plugin:Scim2StaticGroupDestination \
  --set "source-plugin-arg:config-file=/opt/sync/config/scim-sync.properties" \
  --set "destination-plugin-arg:config-file=/opt/sync/config/scim-sync.properties" \
  --set "destination-plugin-arg:static-group-batch-threshold=50"
```

### 3. Static Group Resync
```bash
realtime-sync resync \
  --pipe-name "StaticGroupIncrementalSync" \
  --useExistingEntry \
  --baseDN "cn=static-test,ou=Groups,dc=example,dc=com"
# Same plugin handles resync via REPLACE detection
```

### 4. Dynamic Group Resync
```bash
realtime-sync resync \
  --pipe-name "DynamicGroupResync" \
  --useExistingEntry \
  --baseDN "cn=dynamic-test,ou=Groups,dc=example,dc=com"
```

## Key Features

### Static Group Incremental Sync (NEW)

**Source Plugin Output:**
```ldif
dn: cn=developers,ou=Groups,dc=example,dc=com
cn: developers
members: jdoe
members: asmith
members: bwilson
```

**Destination Processing:**
1. Detect modification type (ADD/DELETE/REPLACE)
2. Convert uid values to SCIM2 user IDs
3. Batch operations if count > threshold
4. Execute PATCH operations (incremental) or PUT (resync)

**Example Scenarios:**

**Scenario 1: Add 10 users**
- Single PATCH with 10 add operations
- Efficient for small changes

**Scenario 2: Add 100 users**
- 2 PATCH requests: 50 + 50
- Prevents single large request

**Scenario 3: Add 5, Delete 3**
- Single PATCH with 5 adds
- Single PATCH with 3 deletes
- Separate operations by type

**Scenario 4: REPLACE with 200 users (resync)**
- Single PUT with entire membership list
- Most efficient for full replacement

## Testing Strategy

### Unit Tests
- Scim2ClientFactory: auth, SSL, proxy configuration
- Scim2RetryHelper: exponential backoff logic
- Scim2MemberHelper: uid → SCIM2 ID mapping
- Batching logic: threshold boundary conditions

### Integration Tests
- User membership sync with live SCIM2 endpoint
- Static group incremental with various batch sizes
- Static group resync with large groups (100+ members)
- Dynamic group resync with memberURL expansion
- Config file loading and override behavior

### Performance Tests
- Batch threshold optimization (test 25, 50, 100)
- Large group resync (1000+ members)
- Concurrent operations (multiple groups simultaneously)

## Benefits

✅ **Single Responsibility**: Each plugin has one clear purpose  
✅ **Reduced Complexity**: ~1,000 lines per plugin vs 2,589 monolithic  
✅ **Better Testability**: Independent plugin testing  
✅ **Operational Flexibility**: Different retry/timeout per pipe  
✅ **Configuration Sharing**: Reuse scim-sync.properties across plugins  
✅ **Performance Optimization**: Static group batching for large changes  
✅ **Clear Separation**: User sync vs static group vs dynamic group  

## Migration Path

1. Keep legacy `Scim2GroupMemberDestination.java` as reference
2. Create new plugins alongside legacy
3. Test new plugins in parallel with legacy
4. Switch pipes to new plugins one at a time
5. Deprecate legacy plugin after validation
6. Document lessons learned

## Next Steps

1. ✅ Create Scim2ClientFactory
2. Create remaining shared utilities (RetryHelper, MemberHelper)
3. Implement Scim2StaticGroupDestination (priority - new feature)
4. Implement Scim2UserMembershipDestination (extract from legacy)
5. Implement Scim2GroupResyncDestination (extract from legacy)
6. Testing and documentation
7. Production deployment

---

**Status**: Phase 1 in progress (shared utilities)  
**Target Completion**: 2 weeks  
**Risk Level**: Medium (new batching logic needs thorough testing)

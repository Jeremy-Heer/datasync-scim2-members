# Refactored Plugin Architecture

## Overview

The SCIM2 group synchronization plugins have been refactored into a clean, modular architecture that separates concerns and optimizes for performance. The architecture follows the Single Responsibility Principle, with each plugin focused on one specific task.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         LDAP Source                              │
│                   (Ping Data Sync Server)                        │
└───────────────────┬──────────────────┬──────────────────────────┘
                    │                  │
        Static Groups│                │Dynamic Groups
        (member/     │                │(memberURL)
         uniqueMember)│                │
                    │                  │
        ┌───────────▼──────────┐   ┌──▼──────────────────────┐
        │ StaticGroupSource    │   │ DynamicGroupSource      │
        │ Plugin               │   │ Plugin                  │
        │ ──────────────────── │   │ ─────────────────────── │
        │ • Extracts UIDs from │   │ • Parses memberURL      │
        │   member DNs         │   │ • Queries for members   │
        │ • Creates 'members'  │   │ • Creates 'members'     │
        │   attribute          │   │   attribute             │
        └───────────┬──────────┘   └──┬──────────────────────┘
                    │                  │
                    │                  │
        ┌───────────▼──────────┐   ┌──▼──────────────────────┐
        │ Scim2StaticGroup     │   │ Scim2DynamicGroup       │
        │ Destination          │   │ Destination             │
        │ ──────────────────── │   │ ─────────────────────── │
        │ • ADD/DELETE (batch) │   │ • REPLACE only (resync) │
        │ • REPLACE (resync)   │   │ • Optimized fetches     │
        │ • Optimized fetches  │   │ • Direct member DN      │
        │ • Direct member DN   │   │   processing            │
        │   processing         │   │                         │
        └───────────┬──────────┘   └──┬──────────────────────┘
                    │                  │
                    │                  │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │ SCIM2 Endpoint   │
                    │ (Target System)  │
                    └──────────────────┘
```

## Plugin Components

### 1. Source Plugins (LDAP)

#### StaticGroupSourcePlugin
**Purpose**: Processes static groups (groupOfNames, groupOfUniqueNames) during resync operations.

**Key Features**:
- Detects groups with `member` or `uniqueMember` attributes
- Looks up each member DN to retrieve the configured user ID attribute (e.g., `uid`)
- Constructs synthetic `members` attribute containing user IDs
- Supports optional group filtering for targeted synchronization

**Configuration**:
```properties
# Shared config file (optional)
config-file=/opt/sync/config/scim-sync.properties

# User ID attribute (e.g., uid, sAMAccountName)
user-id-attribute=uid

# Optional filter to limit which groups are processed
group-filter=(cn=scim-*)
```

#### DynamicGroupSourcePlugin
**Purpose**: Processes dynamic groups (groupOfURLs) with memberURL attributes.

**Key Features**:
- Detects groups with `memberURL` attributes
- Parses LDAP URL format to extract base DN, scope, and filter
- Queries LDAP to find all matching members
- Constructs synthetic `members` attribute containing user IDs
- Supports optional group filtering

**Configuration**:
```properties
# Shared config file (optional)
config-file=/opt/sync/config/scim-sync.properties

# User ID attribute
user-id-attribute=uid

# Optional filter to limit which groups are processed
group-filter=(cn=dynamic-*)
```

### 2. Destination Plugins (SCIM2)

#### Scim2StaticGroupDestination
**Purpose**: Synchronizes static group membership changes to SCIM2 endpoint.

**Key Features**:
- **Incremental Operations**: Supports ADD and DELETE with batching
  - Configurable batch threshold (default: 50 operations per PATCH)
  - Multiple PATCH requests for large membership changes
- **Resync Operations**: Uses PUT to replace entire membership
- **Direct DN Processing**: Can extract user IDs from member DNs directly
  - No source plugin needed for incremental changes
  - Works with both `members` attribute (from source) and `member`/`uniqueMember` (from LDAP)
- **Optimized Fetches**: Uses `?excludedAttributes=members` to reduce payload
- **Self-Contained**: Fully functional without source plugin for incremental sync

**Configuration**:
```properties
# Shared config file (required for SCIM2 connection details)
config-file=/opt/sync/config/scim-sync.properties

# SCIM2 groups endpoint
group-base=/Groups

# User lookup attribute (should match source plugin)
user-lookup-attribute=uid

# Batch threshold for ADD/DELETE operations
static-group-batch-threshold=50
```

**Supported Operations**:
- ✅ ModificationType.ADD → PATCH add members (batched)
- ✅ ModificationType.DELETE → PATCH remove members (batched)
- ✅ ModificationType.REPLACE → PUT replace all members (resync)

#### Scim2DynamicGroupDestination
**Purpose**: Synchronizes dynamic group membership to SCIM2 endpoint.

**Key Features**:
- **Resync Only**: Only supports REPLACE operations
  - Dynamic groups are computed from queries, not incremental changes
  - ADD/DELETE operations are not applicable
- **Direct DN Processing**: Can extract user IDs from memberURL results
- **Optimized Fetches**: Uses `?excludedAttributes=members` to reduce payload
- **Simplified Logic**: Focused solely on full membership replacement

**Configuration**:
```properties
# Shared config file (required for SCIM2 connection details)
config-file=/opt/sync/config/scim-sync.properties

# SCIM2 groups endpoint
group-base=/Groups

# User lookup attribute (should match source plugin)
user-lookup-attribute=uid
```

**Supported Operations**:
- ✅ ModificationType.REPLACE → PUT replace all members (resync)
- ❌ ModificationType.ADD → Not supported (logged and ignored)
- ❌ ModificationType.DELETE → Not supported (logged and ignored)

### 3. Shared Library Components

#### Scim2MemberHelper
**Purpose**: Common utility for SCIM2 member operations.

**Features**:
- User ID to SCIM2 user ID lookup (with retry logic)
- Group name to SCIM2 group ID lookup (**optimized with excludedAttributes**)
- Conversion of user IDs to SCIM2 Member objects

**Optimizations**:
```java
// Only requests id and displayName attributes, excludes members array
List<GroupResource> groups = scimService.searchRequest(groupBasePath)
    .filter(filter.toString())
    .attributes("id", "displayName")  // ← Optimization
    .page(1, 1)
    .invoke(GroupResource.class)
    .getResources();
```

#### ConfigFileLoader
Thread-safe configuration file loader supporting:
- Hot-reload capability
- Property access with caching
- Atomic reference updates

#### GroupTypeDetector
Centralized logic for identifying group types:
- `isDynamicGroup()` - Checks for memberURL or groupOfURLs
- `isStaticGroup()` - Checks for member/uniqueMember attributes
- `isGroup()` - Checks if entry is any type of group
- `getGroupTypeDescription()` - Human-readable type description

## Performance Optimizations

### 1. Optimized Group Lookups
**Problem**: Group lookups by displayName were fetching entire groups with all members.

**Solution**: Added `.attributes("id", "displayName")` to exclude members array.

**Impact**:
- Before: Fetching multi-megabyte responses for large groups
- After: Fetching ~1KB metadata only
- Applied to: `Scim2MemberHelper.findScim2GroupId()`

### 2. Optimized Resync Fetches
**Problem**: Resync operations fetched full groups before updating.

**Solution**: Added `?excludedAttributes=members` query parameter to GET requests.

**Impact**:
- Reduces network bandwidth during resync
- Faster response times for large groups
- Applied to: `processGroupResync()` methods in both destination plugins

### 3. Direct Member DN Processing
**Problem**: Incremental changes to static groups required source plugin.

**Solution**: Destination plugins now extract user IDs directly from member DNs.

**Impact**:
- Source plugin optional for incremental static group changes
- Reduced complexity and processing overhead
- Simplified architecture

### 4. Batching Support
**Feature**: Configurable batching for ADD/DELETE operations in static groups.

**Configuration**: `static-group-batch-threshold` (default: 50)

**Impact**:
- Prevents SCIM2 endpoint overload with large operations
- Distributes load across multiple requests
- Better error recovery (partial failures possible)

## Configuration Guide

### Shared Configuration File (scim-sync.properties)

```properties
# SCIM2 Endpoint Configuration
scim2.base.url=https://scim.example.com/scim/v2
scim2.user.base=/Users
scim2.group.base=/Groups

# Authentication
scim2.auth.type=basic
scim2.username=sync-user
scim2.password=sync-password

# Or Bearer Token
# scim2.auth.type=bearer
# scim2.bearer.token=your-bearer-token-here

# SSL/TLS Configuration
scim2.trust.store.path=/opt/sync/config/truststore.jks
scim2.trust.store.password=changeit
scim2.trust.store.type=JKS
# scim2.allow.untrusted.certificates=false

# Proxy Configuration (optional)
# scim2.proxy.host=proxy.example.com
# scim2.proxy.port=8080
# scim2.proxy.username=proxy-user
# scim2.proxy.password=proxy-pass
# scim2.proxy.type=HTTP

# Timeouts and Retries
scim2.connect.timeout.ms=30000
scim2.read.timeout.ms=60000
scim2.max.retries=3
scim2.retry.delay.ms=1000

# User ID Attribute
user.id.attribute=uid
user.lookup.attribute=uid

# Group Filter (optional - limits which groups are processed)
group.filter=(cn=scim-*)

# Static Group Batching
static.group.batch.threshold=50
```

### Sync Pipe Configuration Examples

#### Example 1: Static Groups with Incremental Sync (No Source Plugin Needed)
```bash
dsconfig create-sync-pipe \
  --pipe-name "LDAP-to-SCIM2-StaticGroups" \
  --set sync-mode:standard \
  --set source-dn-pattern:"cn=*,ou=Groups,dc=example,dc=com" \
  --set destination-type:third-party \
  --set destination-class:com.heer.sync.Scim2StaticGroupDestination \
  --set destination-argument:"config-file=/opt/sync/config/scim-sync.properties" \
  --set destination-argument:"group-base=/Groups" \
  --set destination-argument:"user-lookup-attribute=uid" \
  --set destination-argument:"static-group-batch-threshold=50"
```

#### Example 2: Static Groups with Resync (Using Source Plugin)
```bash
dsconfig create-sync-pipe \
  --pipe-name "LDAP-to-SCIM2-StaticGroups-Resync" \
  --set sync-mode:standard \
  --set source-dn-pattern:"cn=*,ou=Groups,dc=example,dc=com" \
  --set sync-class:com.heer.sync.StaticGroupSourcePlugin \
  --set extension-argument:"config-file=/opt/sync/config/scim-sync.properties" \
  --set extension-argument:"user-id-attribute=uid" \
  --set extension-argument:"group-filter=(cn=scim-*)" \
  --set destination-type:third-party \
  --set destination-class:com.heer.sync.Scim2StaticGroupDestination \
  --set destination-argument:"config-file=/opt/sync/config/scim-sync.properties" \
  --set destination-argument:"group-base=/Groups"
```

#### Example 3: Dynamic Groups (Resync Only)
```bash
dsconfig create-sync-pipe \
  --pipe-name "LDAP-to-SCIM2-DynamicGroups" \
  --set sync-mode:standard \
  --set source-dn-pattern:"cn=*,ou=Groups,dc=example,dc=com" \
  --set sync-class:com.heer.sync.DynamicGroupSourcePlugin \
  --set extension-argument:"config-file=/opt/sync/config/scim-sync.properties" \
  --set extension-argument:"user-id-attribute=uid" \
  --set extension-argument:"group-filter=(objectClass=groupOfURLs)" \
  --set destination-type:third-party \
  --set destination-class:com.heer.sync.Scim2DynamicGroupDestination \
  --set destination-argument:"config-file=/opt/sync/config/scim-sync.properties" \
  --set destination-argument:"group-base=/Groups"
```

## Migration from Legacy Architecture

### Old Architecture (Monolithic)
- `LDAPSyncSourcePluginScim2GroupMembers` - Handled both static and dynamic groups
- `Scim2GroupMemberDestination` - Complex destination with many responsibilities
- Mixed concerns and difficult to test

### New Architecture (Modular)
- Separated static and dynamic group processing
- Each plugin has single, focused responsibility
- Easier to test, maintain, and extend
- Performance optimizations throughout

### Migration Steps
1. ✅ Create new destination plugins (StaticGroupDestination, DynamicGroupDestination)
2. ✅ Extract shared utilities (Scim2MemberHelper, ConfigFileLoader, GroupTypeDetector)
3. ✅ Optimize SCIM2 queries (excludedAttributes, attributes filtering)
4. ✅ Implement direct DN processing in destinations
5. ✅ Add batching support for static groups
6. ⏸️ Deprecate legacy plugins (keep for backward compatibility)

## Testing Recommendations

### Unit Testing
- Test GroupTypeDetector with various group entries
- Test UserIdLookupUtil DN parsing logic
- Test ConfigFileLoader hot-reload capability

### Integration Testing
- Test static group ADD operations (with batching)
- Test static group DELETE operations (with batching)
- Test static group REPLACE operations (resync)
- Test dynamic group REPLACE operations (resync)
- Test optimized SCIM2 queries (verify excludedAttributes)
- Test direct DN processing (without source plugin)

### Performance Testing
- Measure group lookup times (with/without optimization)
- Measure resync times for large groups (1000+ members)
- Measure batching performance (various thresholds)
- Monitor network bandwidth utilization

## Deployment Checklist

- [ ] Build version 2.11 or later
- [ ] Update sync pipes to use new destination classes
- [ ] Configure shared properties file (scim-sync.properties)
- [ ] Test incremental sync (static groups without source plugin)
- [ ] Test resync operations (with source plugins)
- [ ] Verify batching threshold is appropriate for environment
- [ ] Monitor SCIM2 endpoint performance
- [ ] Review logs for optimization confirmations
- [ ] Backup existing configuration before migration
- [ ] Document any customizations or deviations

## Troubleshooting

### Issue: Group lookup queries too slow
**Solution**: Verify `.attributes("id", "displayName")` is being used (check logs for "optimized" messages)

### Issue: SCIM2 endpoint overwhelmed with requests
**Solution**: Reduce `static.group.batch.threshold` to send smaller batches

### Issue: Dynamic group ADD/DELETE operations ignored
**Expected**: Dynamic groups only support REPLACE operations. Check logs for explanation message.

### Issue: Incremental sync not working for static groups
**Solution**: Either use StaticGroupSourcePlugin OR ensure destination can extract UIDs from member DNs

### Issue: Configuration changes not taking effect
**Solution**: Restart sync server or use ConfigFileLoader hot-reload feature (if implemented)

## Version History

### Version 2.11 (Current)
- ✅ Created Scim2DynamicGroupDestination plugin
- ✅ Optimized Scim2MemberHelper.findScim2GroupId() with attributes filtering
- ✅ Fixed extension.properties formatting
- ✅ Updated architecture documentation

### Version 2.10
- Optimized processGroupResync() with excludedAttributes parameter
- Reduced GET payload from MBs to ~1KB for large groups

### Version 2.9
- Added direct member DN processing to StaticGroupDestination
- Made StaticGroupSourcePlugin optional for incremental changes
- Fixed Content-Type headers (application/scim+json)

### Version 2.6-2.8
- Created refactored plugin architecture
- Separated static and dynamic group processing
- Implemented shared library components
- Added batching support for static groups

## Future Enhancements

### Planned
- [ ] Add caching layer for SCIM2 user/group ID lookups
- [ ] Implement parallel batch processing
- [ ] Add metrics collection and reporting
- [ ] Create admin UI for configuration management

### Under Consideration
- [ ] Support for nested groups
- [ ] Bi-directional synchronization
- [ ] Conflict resolution strategies
- [ ] Delta sync optimization

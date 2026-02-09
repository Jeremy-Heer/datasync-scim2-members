# SCIM2 Sync Pipe Architecture

## Overview

This document describes the complete multi-pipe synchronization architecture for provisioning LDAP users and groups to SCIM2 destinations. The architecture uses **5 specialized sync pipes** with source-side event filtering to ensure only relevant changes are synchronized to the SCIM2 endpoint.

### Architecture Goals

1. **Selective Provisioning** - Only sync users/groups that are in scope for SCIM2 integration
2. **Upstream Filtering** - Block unnecessary events at source plugins before reaching destinations
3. **Minimal SCIM2 Queries** - Reduce API calls by filtering early in the pipeline
4. **Clear Separation** - Dedicated pipes for basic CRUD vs membership synchronization
5. **Maintainability** - Consistent naming conventions across all components

---

## Naming Conventions

### Sync Pipe Naming Pattern
```
{Scope}-{Entity}-{Purpose}
```

**Examples:**
- `Users-Basic-CRUD` - User creation/deletion/modification
- `Groups-Static-Members` - Static group membership synchronization
- `Users-Group-Membership` - User-driven group membership updates

### Source Plugin Naming Pattern
```
{Entity}{Purpose}SourcePlugin
```

**Examples:**
- `UserBasicCrudSourcePlugin` - Filters users for basic CRUD operations
- `StaticGroupSourcePlugin` - Processes static groups
- `UserGroupMembershipSourcePlugin` - Filters user group membership changes

### Destination Plugin Naming Pattern
```
{Entity}{Purpose}Destination
```

**Examples:**
- `UserBasicCrudDestination` - Creates/updates/deletes SCIM2 users
- `StaticGroupMemberDestination` - Syncs static group memberships to SCIM2
- `UserGroupMembershipDestination` - Updates SCIM2 group memberships from user changes

### Configuration Property Naming Pattern
```
{entity}.{purpose}.{property}
```

**Examples:**
- `user.group.membership.attributes` - User attributes that trigger membership sync
- `group.filter` - LDAP filter for group selection
- `user.lookup.attribute` - Attribute for user identification

---

## Sync Pipe Architecture

### Pipe 1: Users-Basic-CRUD

**Purpose:** Synchronize basic user lifecycle (create, modify, delete) for users in SCIM2 scope

| Component | Name | Implementation |
|-----------|------|----------------|
| **Source Plugin** | UserBasicCrudSourcePlugin | Filters users without group membership attributes |
| **Sync Pipe** | Users-Basic-CRUD | Standard sync mode |
| **Destination Plugin** | UserBasicCrudDestination | Native SCIM2 destination (no custom extension) |

**Filtering Strategy:**
- ALLOW: User CREATE/MODIFY/DELETE if user has group membership attributes populated
- BLOCK: User events without group membership attributes (not in sync scope)

**Event Flow:**
```
LDAP User Event → UserBasicCrudSourcePlugin.postFetch()
                ↓ (filters users without group attrs)
                → Sync Pipe (base DN filter)
                ↓
                → SCIM2 Destination (CREATE/UPDATE/DELETE)
```

---

### Pipe 2: Groups-Basic-CRUD

**Purpose:** Synchronize group lifecycle (create, modify, delete) for filtered groups

| Component | Name | Implementation |
|-----------|------|----------------|
| **Source Plugin** | GroupBasicCrudSourcePlugin | Filters groups against configured LDAP filter |
| **Sync Pipe** | Groups-Basic-CRUD | Standard sync mode |
| **Destination Plugin** | GroupBasicCrudDestination | Native SCIM2 destination (no custom extension) |

**Filtering Strategy:**
- ALLOW: Group CREATE/MODIFY/DELETE if group matches `group.filter`
- BLOCK: Group events that don't match filter (not in sync scope)

**Event Flow:**
```
LDAP Group Event → GroupBasicCrudSourcePlugin.postFetch()
                 ↓ (evaluates group.filter)
                 → Sync Pipe (base DN filter)
                 ↓
                 → SCIM2 Destination (CREATE/UPDATE/DELETE group without members)
```

---

### Pipe 3: Groups-Static-Members

**Purpose:** Synchronize static group memberships (member/uniqueMember attributes)

| Component | Name | Implementation |
|-----------|------|----------------|
| **Source Plugin** | StaticGroupSourcePlugin | Filters groups + expands static members |
| **Sync Pipe** | Groups-Static-Members | Standard sync mode |
| **Destination Plugin** | StaticGroupMemberDestination | Custom plugin for member sync |

**Filtering Strategy:**
- ALLOW: Static group MODIFY if group matches `group.filter` and has member changes
- BLOCK: Non-static groups, non-matching groups, non-member modifications

**Event Flow:**
```
LDAP Static Group Event → StaticGroupSourcePlugin.postFetch()
                         ↓ (filters by group.filter, expands members)
                         → Sync Pipe
                         ↓
                         → StaticGroupMemberDestination (PATCH group members)
```

---

### Pipe 4: Groups-Dynamic-Resync

**Purpose:** Full resynchronization of dynamic group memberships (memberURL/groupOfURLs)

| Component | Name | Implementation |
|-----------|------|----------------|
| **Source Plugin** | DynamicGroupSourcePlugin | Filters groups + executes LDAP URLs |
| **Sync Pipe** | Groups-Dynamic-Resync | Standard sync mode (resync) |
| **Destination Plugin** | DynamicGroupMemberDestination | Custom plugin for full member replacement |

**Filtering Strategy:**
- ALLOW: Dynamic group MODIFY if group matches `group.filter`
- BLOCK: Non-dynamic groups, non-matching groups

**Event Flow:**
```
LDAP Dynamic Group Event → DynamicGroupSourcePlugin.postFetch()
                          ↓ (filters by group.filter, executes memberURL)
                          → Sync Pipe
                          ↓
                          → DynamicGroupMemberDestination (REPLACE all members)
```

---

### Pipe 5: Users-Group-Membership

**Purpose:** Incremental user group membership updates (user-driven model)

| Component | Name | Implementation |
|-----------|------|----------------|
| **Source Plugin** | UserGroupMembershipSourcePlugin | Filters user events without group attribute changes |
| **Sync Pipe** | Users-Group-Membership | Standard sync mode |
| **Destination Plugin** | UserGroupMembershipDestination | Custom plugin for incremental membership updates |

**Filtering Strategy:**
- ALLOW: User MODIFY if changelog contains group membership attribute changes
- BLOCK: User events without group membership attribute modifications

**Event Flow:**
```
LDAP User Event → UserGroupMembershipSourcePlugin.postFetch()
                ↓ (checks changelog for group membership attr modifications)
                → Sync Pipe
                ↓
                → UserGroupMembershipDestination (PATCH add/remove user from groups)
```

---

## Multi-Level Filtering Strategy

Each pipe implements filtering at multiple levels for maximum efficiency:

### Level 1: Base DN Filter (Native Ping Data Sync)
```bash
--set source-base-dn:"ou=SyncUsers,dc=example,dc=com"
```
- **Performance:** Fastest (filters before plugin execution)
- **Use:** Organizational unit restrictions
- **Applied:** All pipes

### Level 2: Source Plugin postFetch() Filter
```java
public PostStepResult postFetch(...) {
  if (!matchesCriteria(entry)) {
    operation.logInfo("Entry filtered - does not match sync criteria");
    return PostStepResult.CONTINUE; // Skip this event
  }
  return PostStepResult.CONTINUE;
}
```
- **Performance:** Fast (LDAP filter evaluation or changelog inspection)
- **Use:** Group filters, user attribute checks, event type filtering
- **Applied:** All pipes with source plugins

### Level 3: Attribute-Based Filter
```java
if (!isGroupMembershipModification(modification)) {
  continue; // Skip non-membership changes
}
```
- **Performance:** Medium (requires attribute access)
- **Use:** Filter specific attribute modifications
- **Applied:** Membership sync pipes (3, 4, 5)

### Level 4: Destination Validation (Removed - Now Redundant)
- **Previous Use:** Defense-in-depth checks at destination
- **Status:** Removed in favor of upstream filtering for clarity

---

## Event Matrix

See [SYNC_EVENT_FILTERING.md](SYNC_EVENT_FILTERING.md) for complete event-by-event filtering decisions.

### Summary

| Event Type | Pipe 1 | Pipe 2 | Pipe 3 | Pipe 4 | Pipe 5 |
|------------|--------|--------|--------|--------|--------|
| User CREATE (no group attrs) | BLOCK | - | - | - | BLOCK |
| User CREATE (with group attrs) | ALLOW | - | - | - | ALLOW |
| User MODIFY (no group changes) | ALLOW | - | - | - | BLOCK |
| User MODIFY (group changes) | ALLOW | - | - | - | ALLOW |
| User DELETE | ALLOW | - | - | - | ALLOW |
| Group CREATE (not filtered) | - | BLOCK | BLOCK | BLOCK | - |
| Group CREATE (filtered match) | - | ALLOW | ALLOW | ALLOW | - |
| Group MODIFY (not filtered) | - | BLOCK | BLOCK | BLOCK | - |
| Group MODIFY (filtered, static) | - | ALLOW | ALLOW | - | - |
| Group MODIFY (filtered, dynamic) | - | ALLOW | - | ALLOW | - |
| Group DELETE | - | ALLOW | ALLOW | ALLOW | - |

---

## Configuration Examples

### Pipe 1: Users-Basic-CRUD Configuration

```bash
# Sync Source
dsconfig create-sync-source \
  --source-name "LDAP-Users" \
  --type ldap \
  --set base-dn:"ou=Users,dc=example,dc=com" \
  --set server:ldap.example.com:389

# Sync Source Plugin
dsconfig create-sync-source-plugin \
  --plugin-name "User-Basic-CRUD-Filter" \
  --source-name "LDAP-Users" \
  --type third-party \
  --set extension-class:com.heer.sync.UserBasicCrudSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties" \
  --set "extension-argument:group-membership-attributes=scim-groups"

# Sync Destination
dsconfig create-sync-destination \
  --destination-name "SCIM2-Users" \
  --type scim2 \
  --set base-url:"https://scim.example.com/v2" \
  --set user-endpoint:"/Users" \
  --set authentication-method:bearer-token \
  --set bearer-token:{token}

# Sync Pipe
dsconfig create-sync-pipe \
  --pipe-name "Users-Basic-CRUD" \
  --sync-source:"LDAP-Users" \
  --sync-destination:"SCIM2-Users" \
  --set started:true \
  --set sync-mode:standard \
  --set source-base-dn:"ou=SyncUsers,dc=example,dc=com" \
  --set destination-base-dn:"Users"
```

### Pipe 2: Groups-Basic-CRUD Configuration

```bash
# Sync Source
dsconfig create-sync-source \
  --source-name "LDAP-Groups" \
  --type ldap \
  --set base-dn:"ou=Groups,dc=example,dc=com" \
  --set server:ldap.example.com:389

# Sync Source Plugin
dsconfig create-sync-source-plugin \
  --plugin-name "Group-Basic-CRUD-Filter" \
  --source-name "LDAP-Groups" \
  --type third-party \
  --set extension-class:com.heer.sync.GroupBasicCrudSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties" \
  --set "extension-argument:group-filter=(cn=scim-*)"

# Sync Destination
dsconfig create-sync-destination \
  --destination-name "SCIM2-Groups" \
  --type scim2 \
  --set base-url:"https://scim.example.com/v2" \
  --set group-endpoint:"/Groups" \
  --set authentication-method:bearer-token \
  --set bearer-token:{token}

# Sync Pipe
dsconfig create-sync-pipe \
  --pipe-name "Groups-Basic-CRUD" \
  --sync-source:"LDAP-Groups" \
  --sync-destination:"SCIM2-Groups" \
  --set started:true \
  --set sync-mode:standard \
  --set source-base-dn:"ou=SyncGroups,dc=example,dc=com" \
  --set destination-base-dn:"Groups"
```

### Pipe 3: Groups-Static-Members Configuration

```bash
# Sync Source Plugin
dsconfig create-sync-source-plugin \
  --plugin-name "Static-Group-Members-Source" \
  --source-name "LDAP-Groups" \
  --type third-party \
  --set extension-class:com.heer.sync.StaticGroupSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties" \
  --set "extension-argument:group-filter=(cn=scim-*)" \
  --set "extension-argument:user-id-attribute=uid"

# Sync Destination Plugin
dsconfig create-sync-destination-plugin \
  --plugin-name "Static-Group-Members-Destination" \
  --destination-name "SCIM2-Groups" \
  --type third-party \
  --set extension-class:com.heer.sync.StaticGroupMemberDestination \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties"

# Sync Pipe
dsconfig create-sync-pipe \
  --pipe-name "Groups-Static-Members" \
  --sync-source:"LDAP-Groups" \
  --sync-destination:"SCIM2-Groups" \
  --set started:true \
  --set sync-mode:standard \
  --set source-base-dn:"ou=SyncGroups,dc=example,dc=com" \
  --set destination-base-dn:"Groups"
```

### Pipe 4: Groups-Dynamic-Resync Configuration

```bash
# Sync Source Plugin
dsconfig create-sync-source-plugin \
  --plugin-name "Dynamic-Group-Resync-Source" \
  --source-name "LDAP-Groups" \
  --type third-party \
  --set extension-class:com.heer.sync.DynamicGroupSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties" \
  --set "extension-argument:group-filter=(cn=scim-*)" \
  --set "extension-argument:user-id-attribute=uid"

# Sync Destination Plugin
dsconfig create-sync-destination-plugin \
  --plugin-name "Dynamic-Group-Resync-Destination" \
  --destination-name "SCIM2-Groups" \
  --type third-party \
  --set extension-class:com.heer.sync.DynamicGroupMemberDestination \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties"

# Sync Pipe
dsconfig create-sync-pipe \
  --pipe-name "Groups-Dynamic-Resync" \
  --sync-source:"LDAP-Groups" \
  --sync-destination:"SCIM2-Groups" \
  --set started:true \
  --set sync-mode:standard \
  --set source-base-dn:"ou=SyncGroups,dc=example,dc=com" \
  --set destination-base-dn:"Groups"
```

### Pipe 5: Users-Group-Membership Configuration

```bash
# Sync Source Plugin
dsconfig create-sync-source-plugin \
  --plugin-name "User-Group-Membership-Source" \
  --source-name "LDAP-Users" \
  --type third-party \
  --set extension-class:com.heer.sync.UserGroupMembershipSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties" \
  --set "extension-argument:group-membership-attributes=scim-groups"

# Sync Destination Plugin
dsconfig create-sync-destination-plugin \
  --plugin-name "User-Group-Membership-Destination" \
  --destination-name "SCIM2-Users" \
  --type third-party \
  --set extension-class:com.heer.sync.UserGroupMembershipDestination \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties" \
  --set "extension-argument:group-membership-attributes=scim-groups" \
  --set "extension-argument:user-lookup-attribute=uid"

# Sync Pipe
dsconfig create-sync-pipe \
  --pipe-name "Users-Group-Membership" \
  --sync-source:"LDAP-Users" \
  --sync-destination:"SCIM2-Users" \
  --set started:true \
  --set sync-mode:standard \
  --set source-base-dn:"ou=SyncUsers,dc=example,dc=com" \
  --set destination-base-dn:"Users"
```

---

## dsconfig Command Reference

### Copy your actual dsconfig commands here for each pipe:

#### Pipe 1: Users-Basic-CRUD
```bash
dsconfig create-sync-source \
    --source-name "LDAP-User-Basic-CRUD"  \
    --type ping-identity  \
    --set base-dn:ou=Users,dc=jeremy,dc=net  \
    --set "server:LDAP UsersAndGroups"  \
    --set use-changelog-batch-request:true 

dsconfig create-sync-pipe \
    --pipe-name "Users-Basic-CRUD"  \
    --set started:true  \
    --set "sync-source:LDAP-User-Basic-CRUD"  \
    --set "sync-destination:SCIM-User-Basic-CRUD"  \
    --set "change-detection-polling-interval:5 s" 

dsconfig create-sync-class \
    --pipe-name "Users-Basic-CRUD""  \
    --class-name Users  \
    --set include-base-dn:ou=Users,dc=jeremy,dc=net  \
    --set "include-filter:(objectClass=inetOrgPerson)"  \
    --set auto-mapped-source-attribute:-all-  \
    --set modifies-as-creates:true  \
    --set creates-as-modifies:true 
```

#### Pipe 2: Groups-Basic-CRUD
```bash
dsconfig create-sync-source \
    --source-name LDAP-Groups  \
    --type ping-identity  \
    --set base-dn:ou=Groups,dc=jeremy,dc=net  \
    --set "server:LDAP UsersAndGroups"  \
    --set use-changelog-batch-request:true 

dsconfig create-sync-pipe \
    --pipe-name "Groups-Basic-CRUD"  \
    --set started:true  \
    --set "sync-source:LDAP-Groups "  \
    --set "sync-destination:GroupsBasicCrudDestination"  \
    --set "change-detection-polling-interval:5 s" 

dsconfig create-sync-class \
    --pipe-name "Groups-Basic-CRUD"  \
    --class-name Groups  \
    --set include-base-dn:ou=Groups,dc=jeremy,dc=net  \
    --set "include-filter:(objectClass=groupOfNames)"  \
    --set "include-filter:(objectClass=groupOfURLs)"  \
    --set "include-filter:(objectClass=groupOfUniqueNames)"  \
    --set auto-mapped-source-attribute:-all-  \
    --set modifies-as-creates:true  \
    --set creates-as-modifies:true 
```

#### Pipe 3: Groups-Static-Members
```bash
dsconfig create-sync-pipe \
    --pipe-name "Groups-Static-Members"  \
    --set started:true  \
    --set "sync-source:LDAP Static Group Members"  \
    --set "sync-destination:SCIM Static Group Members"  \
    --set "change-detection-polling-interval:5 s" 

dsconfig create-sync-class \
    --pipe-name "Groups-Static-Members"  \
    --class-name Groups  \
    --set include-base-dn:ou=Groups,dc=jeremy,dc=net  \
    --set "include-filter:(objectClass=groupOfNames)"  \
    --set "include-filter:(objectClass=groupOfUniqueNames)"  \
    --set auto-mapped-source-attribute:-all-  \
    --set synchronize-creates:false  \
    --set synchronize-deletes:false  \
    --set allow-destination-renames:false  \
    --set replace-all-attr-values:false 
```

#### Pipe 4: Groups-Dynamic-Resync
```bash
dsconfig create-sync-pipe \
    --pipe-name "Groups-Dynamic-Resync"  \
    --set started:true  \
    --set "sync-source:LDAP Dynamic Group Members Resync"  \
    --set "sync-destination:SCIM Dynamic Group Members Resync"  \
    --set "change-detection-polling-interval:5 s" 

dsconfig create-sync-class \
    --pipe-name "Groups-Dynamic-Resync"  \
    --class-name Groups  \
    --set include-base-dn:ou=Groups,dc=jeremy,dc=net  \
    --set "include-filter:(objectClass=groupOfURLs)"  \
    --set auto-mapped-source-attribute:-all- 
```

#### Pipe 5: Users-Group-Membership
```bash
dsconfig create-sync-pipe \
    --pipe-name "Users-Group-Membership"  \
    --set started:true  \
    --set "sync-source:LDAP-Users-Group-Membership"  \
    --set "sync-destination:SCIM-Users-Group-Membership"  \
    --set "change-detection-polling-interval:5 s" 

dsconfig create-sync-class \
    --pipe-name "Users-Group-Membership"  \
    --class-name Users  \
    --set include-base-dn:ou=Users,dc=jeremy,dc=net  \
    --set "include-filter:(objectClass=scim-groups)"  \
    --set auto-mapped-source-attribute:scim-groups  \
    --set auto-mapped-source-attribute:uid  \
    --set synchronize-creates:false  \
    --set synchronize-deletes:false  \
    --set allow-destination-renames:false  \
    --set replace-all-attr-values:false 
```

---

## Data Flow Diagrams

### User Lifecycle Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    LDAP Source Events                           │
└───────────────┬─────────────────────────────────┬───────────────┘
                │                                 │
        User CREATE/MODIFY/DELETE        User MODIFY (group attrs)
                │                                 │
                ▼                                 ▼
    ┌───────────────────────┐       ┌───────────────────────────┐
    │ UserBasicCrudSource   │       │ UserGroupMembership       │
    │ SourcePlugin          │       │ SourcePlugin              │
    │                       │       │                           │
    │ Filter: has group     │       │ Filter: changelog has     │
    │ membership attrs?     │       │ group attr changes?       │
    └───────┬───────────────┘       └───────┬───────────────────┘
            │ ALLOW                         │ ALLOW
            ▼                               ▼
    ┌───────────────────┐           ┌───────────────────────────┐
    │ Users-Basic-CRUD  │           │ Users-Group-Membership    │
    │ Sync Pipe         │           │ Sync Pipe                 │
    └───────┬───────────┘           └───────┬───────────────────┘
            │                               │
            ▼                               ▼
    ┌───────────────────┐           ┌───────────────────────────┐
    │ SCIM2 /Users      │           │ SCIM2 /Groups/{id}        │
    │ CREATE/UPDATE/    │           │ PATCH add/remove members  │
    │ DELETE user       │           │                           │
    └───────────────────┘           └───────────────────────────┘
```

### Group Lifecycle Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    LDAP Source Events                           │
└───┬───────────────────┬────────────────────┬────────────────────┘
    │                   │                    │
Group CREATE/DELETE  Static Group      Dynamic Group
                     MODIFY (members)   MODIFY (memberURL)
    │                   │                    │
    ▼                   ▼                    ▼
┌─────────────┐  ┌─────────────────┐  ┌──────────────────┐
│ GroupBasic  │  │ StaticGroup     │  │ DynamicGroup     │
│ CrudSource  │  │ SourcePlugin    │  │ SourcePlugin     │
│ Plugin      │  │                 │  │                  │
│ Filter:     │  │ Filter: matches │  │ Filter: matches  │
│ matches     │  │ group.filter    │  │ group.filter     │
│ group.filter│  │ + expand        │  │ + execute        │
│             │  │ members         │  │ memberURL        │
└──────┬──────┘  └────────┬────────┘  └────────┬─────────┘
       │ ALLOW            │ ALLOW              │ ALLOW
       ▼                  ▼                    ▼
┌─────────────┐  ┌─────────────────┐  ┌──────────────────┐
│ Groups-     │  │ Groups-Static-  │  │ Groups-Dynamic-  │
│ Basic-CRUD  │  │ Members Pipe    │  │ Resync Pipe      │
└──────┬──────┘  └────────┬────────┘  └────────┬─────────┘
       │                  │                    │
       ▼                  ▼                    ▼
┌─────────────┐  ┌─────────────────┐  ┌──────────────────┐
│ SCIM2       │  │ SCIM2           │  │ SCIM2            │
│ /Groups     │  │ /Groups/{id}    │  │ /Groups/{id}     │
│ CREATE/     │  │ PATCH add/      │  │ PUT replace all  │
│ UPDATE/     │  │ remove members  │  │ members          │
│ DELETE      │  │                 │  │                  │
└─────────────┘  └─────────────────┘  └──────────────────┘
```

---

## Performance Considerations

### Filtering Order (Fastest to Slowest)

1. **Base DN Filter** - Native Ping Data Sync (filters before plugin)
2. **LDAP Filter Match** - Source plugin `postFetch()` with LDAP filter
3. **Changelog Inspection** - Source plugin examining modification types
4. **Attribute Value Check** - Reading entry attributes
5. **SCIM2 API Calls** - Network roundtrip (AVOID with upstream filtering)

### Optimization Tips

1. **Use narrow base DNs** - `ou=SyncUsers` instead of entire directory
2. **Index filter attributes** - Ensure `cn`, `scim-groups`, etc. are indexed in LDAP
3. **Enable batch operations** - Set `static-group-batch-threshold=50` for bulk updates
4. **Disable unnecessary lookups** - Use `disable-group-membership-lookups=true` in notification mode
5. **Monitor filter effectiveness** - Check logs for "filtered" messages to tune filters

---

## Testing Strategy

See [test-scripts/](test-scripts/) directory for pipe-specific test scenarios.

### Test Organization

```
test-scripts/
├── users-basic-crud/
│   ├── test-user-create-with-groups.sh
│   ├── test-user-create-without-groups.sh
│   ├── test-user-modify-standard.sh
│   └── verify-scim2-users.sh
├── groups-basic-crud/
│   ├── test-group-create-filtered.sh
│   ├── test-group-create-unfiltered.sh
│   └── verify-scim2-groups.sh
├── groups-static-members/
│   ├── test-static-group-add-member.sh
│   ├── test-static-group-remove-member.sh
│   └── verify-scim2-memberships.sh
├── groups-dynamic-resync/
│   ├── test-dynamic-group-resync.sh
│   └── verify-scim2-dynamic-members.sh
├── users-group-membership/
│   ├── test-user-add-group-attr.sh
│   ├── test-user-remove-group-attr.sh
│   └── verify-scim2-user-groups.sh
└── README.md
```

---

## Troubleshooting

### Common Issues

**Issue:** Events reaching destination but being skipped
- **Cause:** Source plugin filtering working correctly
- **Solution:** Check logs for "filtered" messages, adjust filters if needed

**Issue:** Duplicate membership operations
- **Cause:** Multiple pipes processing same event
- **Solution:** Ensure each pipe has distinct `source-base-dn` or source plugin filtering

**Issue:** "Not found" errors in destination logs
- **Cause:** Source plugin passed event but SCIM2 resource doesn't exist
- **Solution:** Ensure Pipe 1/2 (basic CRUD) runs before membership pipes

**Issue:** Missing group memberships
- **Cause:** Group not matching `group.filter`
- **Solution:** Verify group matches filter with `ldapsearch`, adjust filter or group attributes

---

## Migration from Previous Architecture

### Deprecated Plugins

| Old Plugin | New Plugin | Migration Notes |
|------------|------------|-----------------|
| Scim2GroupMemberDestination | StaticGroupMemberDestination | Rename + split logic |
| Scim2UserGroupMembershipDestination | UserGroupMembershipDestination | Rename only |
| (none) | UserBasicCrudSourcePlugin | New - add filtering |
| (none) | GroupBasicCrudSourcePlugin | New - add filtering |
| (none) | UserGroupMembershipSourcePlugin | New - add filtering |

### Migration Steps

1. **Stop all existing sync pipes**
2. **Deploy renamed plugins** (build and install new JAR)
3. **Update dsconfig** with new component names
4. **Add source plugins** for all pipes
5. **Test each pipe independently** before enabling all
6. **Monitor logs** for filtering effectiveness
7. **Tune filters** based on actual event patterns

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.10 | 2026-02-02 | Multi-pipe architecture with upstream filtering |
| 2.9 | 2024-12-XX | Previous monolithic architecture |

---

## Additional Documentation

- [SYNC_EVENT_FILTERING.md](SYNC_EVENT_FILTERING.md) - Complete event filtering matrix
- [GROUP_FILTER_ENHANCEMENT.md](GROUP_FILTER_ENHANCEMENT.md) - Group filter implementation details
- [PLUGIN_ARCHITECTURE.md](PLUGIN_ARCHITECTURE.md) - Plugin development guide
- [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) - Production deployment checklist

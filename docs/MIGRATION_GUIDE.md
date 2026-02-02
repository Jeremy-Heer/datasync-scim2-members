# Migration Guide: Monolithic to Focused Plugin Architecture

This guide helps you migrate from the monolithic `LDAPSyncSourcePluginScim2GroupMembers` plugin to the new focused, purpose-driven plugin architecture.

## Overview

The refactored architecture splits functionality into separate plugins:

### Old Architecture (Monolithic)
- **Single source plugin**: `LDAPSyncSourcePluginScim2GroupMembers` (handles both static and dynamic groups)
- **Single destination plugin**: `Scim2GroupMemberDestination` (handles users and groups)
- **Configuration**: Inline arguments only
- **Complexity**: 754 lines (source) + 2589 lines (destination)

### New Architecture (Focused)
- **Two source plugins**: `StaticGroupSourcePlugin` and `DynamicGroupSourcePlugin`
- **Shared utilities**: `lib` package with reusable components
- **Configuration**: Shared properties file + optional inline overrides
- **Benefits**: Cleaner separation of concerns, easier testing, shared configuration

## Migration Benefits

✅ **Simplified maintenance** - Each plugin has single responsibility  
✅ **Better testability** - Focused plugins easier to unit test  
✅ **Shared configuration** - Reduce duplication across plugins  
✅ **Credential reload** - Update credentials without restart  
✅ **Independent deployment** - Deploy static/dynamic plugins separately  
✅ **Standard Mode only** - Removed 150+ lines of notification mode complexity  

## Prerequisites

### Required Changes

1. **Sync Mode**: Must use **Standard Mode** (notification mode no longer supported)
   ```bash
   --set sync-mode:standard
   ```

2. **Java Version**: Requires Java 8 or higher (no change from existing)

3. **Ping Data Sync Version**: Compatible with existing versions (tested with 8.x+)

### Configuration File Preparation

Create a shared configuration file (optional but recommended):

```bash
# Copy example file
cp config/scim-sync.properties.example /opt/sync/config/scim-sync.properties

# Edit with your settings
vi /opt/sync/config/scim-sync.properties

# Set appropriate permissions
chmod 600 /opt/sync/config/scim-sync.properties
chown sync-user:sync-group /opt/sync/config/scim-sync.properties
```

## Migration Paths

Choose the migration path that fits your needs:

### Path 1: Direct Replacement (Recommended)

Replace the monolithic plugin with focused plugins in separate sync pipes.

**When to use:**
- Starting fresh deployment
- Want clean separation of static/dynamic groups
- Can create new sync pipes

### Path 2: Gradual Migration

Run old and new plugins side-by-side, gradually migrate groups.

**When to use:**
- Need zero-downtime migration
- Want to test new plugins before full cutover
- Have complex group hierarchy

### Path 3: Side-by-Side (Keep Both)

Keep legacy plugin as reference while using new plugins.

**When to use:**
- Development/testing phase
- Need to compare behavior
- Incremental rollout

## Step-by-Step Migration

### Step 1: Build the New Plugins

```bash
cd /path/to/scim-plugin
ant clean compile
ant package

# Verify extension JAR is created
ls -l build/corp.heer.Scim2GroupmemberSync-*.zip
```

### Step 2: Install Extension

```bash
# Extract to extension directory
cd /opt/ping-sync/extensions
unzip /path/to/build/corp.heer.Scim2GroupmemberSync-*.zip

# Restart server to load extensions
bin/stop-server
bin/start-server
```

### Step 3: Create Configuration File (Optional)

```bash
# Create shared configuration
cat > /opt/sync/config/scim-sync.properties << 'EOF'
user.id.attribute=uid
group.filter=(cn=scim-*)
EOF

chmod 600 /opt/sync/config/scim-sync.properties
chown sync-user:sync-group /opt/sync/config/scim-sync.properties
```

### Step 4: Create Static Group Source Plugin

```bash
dsconfig create-sync-source-plugin \
  --plugin-name "Scim2StaticGroupSource" \
  --type third-party \
  --set enabled:true \
  --set extension-class:com.heer.sync.StaticGroupSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties"
```

**Or without configuration file:**

```bash
dsconfig create-sync-source-plugin \
  --plugin-name "Scim2StaticGroupSource" \
  --type third-party \
  --set enabled:true \
  --set extension-class:com.heer.sync.StaticGroupSourcePlugin \
  --set "extension-argument:user-id-attribute=uid" \
  --set "extension-argument:group-filter=(cn=scim-*)"
```

### Step 5: Create Dynamic Group Source Plugin

```bash
dsconfig create-sync-source-plugin \
  --plugin-name "Scim2DynamicGroupSource" \
  --type third-party \
  --set enabled:true \
  --set extension-class:com.heer.sync.DynamicGroupSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties"
```

### Step 6: Create Sync Pipes

**Static Group Sync Pipe:**

```bash
dsconfig create-sync-pipe \
  --pipe-name "StaticGroupMembershipPipe" \
  --set sync-source-plugin:Scim2StaticGroupSource \
  --set sync-destination-plugin:Scim2GroupMemberDestination \
  --set sync-mode:standard \
  --set started:true \
  --set source-base-dn:"ou=Groups,dc=example,dc=com" \
  --set destination-base-dn:"Groups"
```

**Dynamic Group Sync Pipe:**

```bash
dsconfig create-sync-pipe \
  --pipe-name "DynamicGroupMembershipPipe" \
  --set sync-source-plugin:Scim2DynamicGroupSource \
  --set sync-destination-plugin:Scim2GroupMemberDestination \
  --set sync-mode:standard \
  --set started:true \
  --set source-base-dn:"ou=Groups,dc=example,dc=com" \
  --set destination-base-dn:"Groups"
```

### Step 7: Test with Resync

**Test static group resync:**

```bash
realtime-sync resync \
  --pipe-name "StaticGroupMembershipPipe" \
  --useExistingEntry \
  --baseDN "cn=static-test-group,ou=Groups,dc=example,dc=com"
```

**Test dynamic group resync:**

```bash
realtime-sync resync \
  --pipe-name "DynamicGroupMembershipPipe" \
  --useExistingEntry \
  --baseDN "cn=dynamic-test-group,ou=Groups,dc=example,dc=com"
```

### Step 8: Monitor and Verify

```bash
# Check sync pipe status
dsconfig list-sync-pipes --property started --property last-sync-time

# Check logs for errors
tail -f /opt/ping-sync/logs/errors

# Check debug logs (if enabled)
tail -f /opt/ping-sync/logs/debug
```

### Step 9: Disable Old Plugin (After Testing)

```bash
# Stop old sync pipe
dsconfig set-sync-pipe-prop \
  --pipe-name "OldGroupMembershipPipe" \
  --set started:false

# Or delete old configuration entirely
dsconfig delete-sync-pipe --pipe-name "OldGroupMembershipPipe"
dsconfig delete-sync-source-plugin --plugin-name "OldScim2GroupSource"
```

## Configuration Mapping

### Old Plugin Arguments → New Plugin Arguments

| Old Argument | New Plugin(s) | New Argument | Notes |
|--------------|---------------|--------------|-------|
| `user-id-attribute` | Both | `user-id-attribute` or `config-file` | Can be in shared file |
| `group-filter` | Both | `group-filter` or `config-file` | Can be in shared file |
| N/A | Both | `config-file` | NEW: Shared configuration support |

### Sync Pipe Settings

| Old Setting | New Setting | Notes |
|-------------|-------------|-------|
| `sync-mode:notification` | `sync-mode:standard` | **REQUIRED CHANGE** |
| `sync-mode:standard` | `sync-mode:standard` | No change needed |
| Single pipe for all groups | Separate pipes for static/dynamic | **ARCHITECTURE CHANGE** |

## Common Patterns

### Pattern 1: All Groups with Shared Config

**Configuration File:**
```properties
user.id.attribute=uid
# No group filter - process all groups
```

**Static Group Pipe:**
```bash
dsconfig create-sync-pipe \
  --pipe-name "StaticGroups" \
  --set sync-source-plugin:Scim2StaticGroupSource \
  --set sync-mode:standard \
  --set source-base-dn:"ou=Groups,dc=example,dc=com"
```

**Dynamic Group Pipe:**
```bash
dsconfig create-sync-pipe \
  --pipe-name "DynamicGroups" \
  --set sync-source-plugin:Scim2DynamicGroupSource \
  --set sync-mode:standard \
  --set source-base-dn:"ou=Groups,dc=example,dc=com"
```

### Pattern 2: Filtered Groups with Inline Config

**Static groups starting with "scim-":**
```bash
dsconfig create-sync-source-plugin \
  --plugin-name "FilteredStaticGroupSource" \
  --type third-party \
  --set extension-class:com.heer.sync.StaticGroupSourcePlugin \
  --set "extension-argument:user-id-attribute=uid" \
  --set "extension-argument:group-filter=(cn=scim-*)"
```

**Dynamic groups starting with "dynamic-":**
```bash
dsconfig create-sync-source-plugin \
  --plugin-name "FilteredDynamicGroupSource" \
  --type third-party \
  --set extension-class:com.heer.sync.DynamicGroupSourcePlugin \
  --set "extension-argument:user-id-attribute=uid" \
  --set "extension-argument:group-filter=(cn=dynamic-*)"
```

### Pattern 3: Mixed Configuration (File + Overrides)

**Shared file with per-plugin overrides:**

**File: `/opt/sync/config/scim-sync.properties`**
```properties
user.id.attribute=uid
group.filter=(cn=scim-*)
```

**Static plugin (uses file defaults):**
```bash
dsconfig create-sync-source-plugin \
  --plugin-name "StaticGroupSource" \
  --type third-party \
  --set extension-class:com.heer.sync.StaticGroupSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties"
```

**Dynamic plugin (overrides filter):**
```bash
dsconfig create-sync-source-plugin \
  --plugin-name "DynamicGroupSource" \
  --type third-party \
  --set extension-class:com.heer.sync.DynamicGroupSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties" \
  --set "extension-argument:group-filter=(cn=dynamic-*)"
  # Inline override: only dynamic-* groups
```

## Rollback Procedure

If you need to rollback to the old plugin:

### Step 1: Stop New Pipes

```bash
dsconfig set-sync-pipe-prop \
  --pipe-name "StaticGroupMembershipPipe" \
  --set started:false

dsconfig set-sync-pipe-prop \
  --pipe-name "DynamicGroupMembershipPipe" \
  --set started:false
```

### Step 2: Re-enable Old Pipe

```bash
dsconfig set-sync-pipe-prop \
  --pipe-name "OldGroupMembershipPipe" \
  --set started:true
```

### Step 3: Verify Old Plugin Works

```bash
realtime-sync resync \
  --pipe-name "OldGroupMembershipPipe" \
  --useExistingEntry \
  --baseDN "cn=test-group,ou=Groups,dc=example,dc=com"
```

## Troubleshooting

### Issue: Plugin Not Found

**Symptom:**
```
Extension class com.heer.sync.StaticGroupSourcePlugin not found
```

**Solution:**
```bash
# Verify extension is installed
ls -l /opt/ping-sync/extensions/

# Verify classes are in JAR
unzip -l /opt/ping-sync/extensions/lib/heer-sync-extensions.jar | grep Static

# Restart server to reload extensions
bin/stop-server && bin/start-server
```

### Issue: Configuration File Not Loading

**Symptom:**
```
Cannot read configuration file: /opt/sync/config/scim-sync.properties
```

**Solution:**
```bash
# Check file exists
ls -l /opt/sync/config/scim-sync.properties

# Check permissions
chmod 600 /opt/sync/config/scim-sync.properties

# Check ownership
chown sync-user:sync-group /opt/sync/config/scim-sync.properties
```

### Issue: Groups Not Processing

**Symptom:**
```
Entry cn=mygroup,ou=Groups,dc=example,dc=com is not a static group - skipping
```

**Solution:**
```bash
# Verify group has member/uniqueMember attributes (static) or memberURL (dynamic)
ldapsearch -h localhost -p 1389 \
  -D "cn=Directory Manager" -w password \
  -b "cn=mygroup,ou=Groups,dc=example,dc=com" \
  "(objectClass=*)" member uniqueMember memberURL

# Check group filter matches
# If filter is (cn=scim-*), group cn must start with "scim-"
```

### Issue: Standard Mode Not Set

**Symptom:**
```
Warning: This plugin requires Standard Sync Mode
```

**Solution:**
```bash
dsconfig set-sync-pipe-prop \
  --pipe-name "StaticGroupMembershipPipe" \
  --set sync-mode:standard
```

## Testing Checklist

Before completing migration:

- [ ] New extension installed and loaded
- [ ] Configuration file created (if using)
- [ ] Static group source plugin created
- [ ] Dynamic group source plugin created
- [ ] Sync pipes created with `sync-mode:standard`
- [ ] Test resync of static group successful
- [ ] Test resync of dynamic group successful
- [ ] SCIM2 destination shows correct group members
- [ ] Logs show no errors
- [ ] Credential reload works (if using config file)
- [ ] Old plugin disabled/removed

## Performance Considerations

### Separate Pipes vs Single Pipe

**Old Architecture:**
- Single pipe processes all groups
- Both static and dynamic logic run for every group

**New Architecture:**
- Separate pipes for static and dynamic
- Each plugin only runs its logic
- Better performance if groups are type-specific

### Group Filter Impact

**Without filter:**
```properties
# Processes ALL groups - expensive for large directories
```

**With filter:**
```properties
group.filter=(cn=scim-*)
# Only processes matching groups - much faster
```

## Support and References

- **Configuration File Reference**: See [CONFIGURATION_FILE.md](CONFIGURATION_FILE.md)
- **Architecture Overview**: See [GROUP_RESYNC_IMPLEMENTATION.md](GROUP_RESYNC_IMPLEMENTATION.md)
- **Legacy Plugin**: Kept in repository as `LDAPSyncSourcePluginScim2GroupMembers.java`
- **Issue Tracking**: Report issues via GitHub or support channel

## Next Steps

After successful migration:

1. **Monitor for 1-2 weeks** - Ensure stability
2. **Remove old plugin** - Clean up legacy configuration
3. **Document customizations** - Update runbooks
4. **Train team** - Share new architecture knowledge
5. **Consider destination split** - Future enhancement to separate user/group destinations

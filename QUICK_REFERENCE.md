# Quick Reference - SCIM2 Group Sync Plugins v2.11

## Plugin Selection Guide

### Static Groups (member/uniqueMember)

**Incremental Sync** (ADD/DELETE without source plugin):
```bash
Destination: com.heer.sync.Scim2StaticGroupDestination
Source Plugin: None required
Operations: ADD, DELETE, REPLACE
```

**Resync** (with source plugin):
```bash
Source: com.heer.sync.StaticGroupSourcePlugin
Destination: com.heer.sync.Scim2StaticGroupDestination
Operations: REPLACE
```

### Dynamic Groups (memberURL)

**Resync Only**:
```bash
Source: com.heer.sync.DynamicGroupSourcePlugin
Destination: com.heer.sync.Scim2DynamicGroupDestination
Operations: REPLACE only
```

## Configuration Properties

### Required (scim-sync.properties)
```properties
scim2.base.url=https://scim.example.com/scim/v2
scim2.auth.type=basic
scim2.username=sync-user
scim2.password=sync-password
user.id.attribute=uid
```

### Optional Performance Tuning
```properties
static.group.batch.threshold=50
scim2.max.retries=3
scim2.connect.timeout.ms=30000
```

## Key Optimizations

1. **Group Lookups**: `.attributes("id", "displayName")` - Reduces payload by >99%
2. **Resync Fetches**: `?excludedAttributes=members` - Faster group updates
3. **Batching**: Configurable threshold prevents endpoint overload
4. **Direct DN Processing**: No source plugin needed for static incremental

## Common Commands

**Build**:
```bash
./build.sh
# Output: build/corp.heer.Scim2GroupmemberSync-2.11.zip
```

**Deploy**:
```bash
cd /opt/PingDataSync/config/server-sdk-extensions
unzip corp.heer.Scim2GroupmemberSync-2.11.zip
```

**Verify**:
```bash
ls /opt/PingDataSync/config/server-sdk-extensions/corp.heer.Scim2GroupmemberSync-2.11/
```

## Troubleshooting

**Slow Queries** → Check logs for "optimized" messages  
**Endpoint Overload** → Reduce batch threshold  
**Dynamic ADD/DELETE Ignored** → Expected (REPLACE only)  
**Config Not Loading** → Verify file path and permissions

## Documentation
- **Full Architecture**: PLUGIN_ARCHITECTURE.md
- **Refactoring Details**: DYNAMIC_GROUP_REFACTORING.md

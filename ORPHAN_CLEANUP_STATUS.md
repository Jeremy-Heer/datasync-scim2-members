# SCIM2 Orphan Cleanup Implementation Status

## Summary

Implementation of SCIM2 orphan cleanup functionality has been started but requires SDK compatibility adjustments. The proposed architecture using `SyncSource` API is not compatible with the current UnboundID SDK version used in this project.

## What Was Created

### 1. Scim2OrphanCleanupHelper ✅ COMPLETE
**File:** `src/com/heer/sync/lib/scim2/Scim2OrphanCleanupHelper.java`

Reusable helper class for deleting orphaned SCIM2 resources with retry logic. This class is fully functional and can be used in any solution.

**Features:**
- `deleteUser(scim2UserId, operation)` - Delete user by SCIM2 ID
- `deleteGroup(scim2GroupId, operation)` - Delete group by SCIM2 ID
- Exponential backoff retry logic (reuses `Scim2RetryHelper`)
- Comprehensive logging
- ResourceNotFound handling

### 2-4. SyncSource-based Plugins ❌ NOT COMPATIBLE

**Files Created (need rework):**
- `src/com/heer/sync/Scim2UserOrphanCheckSource.java`
- `src/com/heer/sync/Scim2GroupOrphanCheckSource.java`
- `src/com/heer/sync/Scim2OrphanCleanupPlugin.java`

These files use `com.unboundid.directory.sdk.sync.api.SyncSource` which appears to not be available or have a different API in the current SDK version.

**Compilation Errors:**
- `EndpointException` constructor signature mismatch
- `acknowledgeCompletedOps()` signature requires `LinkedList` not `List`
- `DN.escapeRDNValue()` method doesn't exist
- `SyncOperation.isDryRun()` method doesn't exist
- Missing `toString(StringBuilder)` method required by plugin interfaces

## Alternative Approaches

Given the SDK limitations, here are viable alternatives:

### Option 1: Standalone Cleanup Tool (RECOMMENDED)

Create a standalone Java application that:
1. Uses the existing `Scim2ClientFactory` and `Scim2OrphanCleanupHelper`
2. Connects to both LDAP and SCIM2
3. Queries all users/groups from both systems
4. Compares and identifies orphans
5. Deletes orphans from SCIM2

**Advantages:**
- No SDK compatibility issues
- Can run independently on schedule (cron)
- Full control over logic and error handling
- Supports dry-run mode easily
- Can generate detailed reports

**Implementation:**
- Create `src/com/heer/sync/tools/Scim2OrphanCleanupTool.java`
- Use existing helper classes
- Run with: `java -cp ... com.heer.sync.tools.Scim2OrphanCleanupTool --config scim-sync.properties --dry-run`

### Option 2: LDAP-Triggered Cleanup via Modified Source Plugin

Modify existing source plugins to detect when entries are deleted from LDAP and trigger SCIM2 cleanup:

1. Enhance `UserBasicCrudSourcePlugin` and `GroupBasicCrudSourcePlugin`
2. In `postFetch()` method, detect DELETE operations
3. Call `Scim2OrphanCleanupHelper` to delete from SCIM2
4. This handles cleanup reactively as deletions occur in LDAP

**Advantages:**
- Works with existing SDK and plugin architecture
- Automatic cleanup when LDAP changes
- No separate resync process needed

**Disadvantages:**
- Only cleans up when LDAP deletions are detected
- Doesn't handle existing orphans (would need one-time manual cleanup first)

### Option 3: Scheduled Groovy Script

Use Ping Data Sync Server's Groovy scripting capability:

1. Create a Groovy script in `example-groovy-scripts/`
2. Script queries SCIM2 and LDAP
3. Compares and deletes orphans
4. Schedule via Data Sync Server's recurring task framework

**Advantages:**
- Supported by Ping Data Sync Server
- No compilation needed
- Can be modified without rebuilding

**Disadvantages:**
- Groovy learning curve
- Less type-safe than Java

## Recommended Next Steps

1. **Immediate:** Implement Option 1 (Standalone Tool)
   - Quickest path to working solution
   - Reuses `Scim2OrphanCleanupHelper` (already complete)
   - Can run manually or via cron
   - Provides dry-run capability

2. **Future Enhancement:** Implement Option 2 (LDAP-Triggered Cleanup)
   - Provides automatic ongoing cleanup
   - Prevents orphans from accumulating

3. **Archive:** Remove or archive the incompatible SyncSource files
   - `Scim2UserOrphanCheckSource.java`
   - `Scim2GroupOrphanCheckSource.java`
   - `Scim2OrphanCleanupPlugin.java`

## Configuration Added

The following configuration was added to `config/scim-sync.properties.example`:

```properties
# ORPHAN CLEANUP CONFIGURATION
cleanup.resource.type=user          # or 'group'
cleanup.page.size=100               # SCIM2 query page size
ldap.base.dn=ou=Users,dc=example,dc=com  # LDAP base DN for queries
```

This configuration can be used by whichever solution approach is chosen.

## Files Status

| File | Status | Action Needed |
|------|--------|---------------|
| `Scim2OrphanCleanupHelper.java` | ✅ Complete | None - ready to use |
| `Scim2UserOrphanCheckSource.java` | ❌ Won't compile | Remove or rework |
| `Scim2GroupOrphanCheckSource.java` | ❌ Won't compile | Remove or rework |
| `Scim2OrphanCleanupPlugin.java` | ❌ Won't compile | Remove or rework |
| `scim-sync.properties.example` | ✅ Updated | None |

## Conclusion

The SCIM2 orphan cleanup helper class is complete and functional. The original SyncSource-based approach is not compatible with the current SDK. A standalone cleanup tool (Option 1) is recommended as the most practical solution that can be implemented quickly using the existing helper infrastructure.

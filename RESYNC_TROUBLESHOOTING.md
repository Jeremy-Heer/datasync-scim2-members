# Group Resync Troubleshooting Guide

## Issue Summary

During group resync operations, groups are going to `createEntry` instead of `modifyEntry`, which indicates that `fetchEntry` is not successfully finding the groups in the SCIM2 destination.

### Expected Flow
1. **fetchEntry** - Should find the group in SCIM2 by displayName and return a synthetic entry with `scim2GroupId`
2. **modifyEntry** - Should receive the synthetic entry and call `processGroupResync` to update membership

### Actual Flow (from logs)
1. Source plugin processes dynamic group and adds members attribute ✓
2. **createEntry** is called (meaning fetchEntry returned empty) ✗
3. Group membership is NOT updated

## Root Cause Analysis

The issue is that `fetchEntry` is not finding the group in SCIM2, which can happen if:

1. **Group doesn't exist in SCIM2** - The group needs to exist in the destination before resync
2. **DisplayName mismatch** - The SCIM2 group's `displayName` must match exactly (case-sensitive) with the LDAP group's `cn` attribute
3. **SCIM2 connection issue** - The SCIM2 service may not be properly initialized or accessible
4. **fetchEntry not being called** - In some sync modes, fetchEntry might be skipped

## Enhanced Logging Added

The following logging enhancements have been added to help diagnose the issue:

### 1. fetchEntry Method
- Logs when fetchEntry is called with the DN
- Logs full entry details in debug mode
- Logs analysis of cn and username attributes
- Logs routing decision (group vs user)

### 2. fetchGroupEntry Method
- Logs start of group lookup
- Logs extracted group name
- Logs search operation details
- Logs success/failure of SCIM2 group lookup
- Logs created synthetic entry in debug mode

### 3. findScim2GroupId Method (Critical)
- Logs search parameters (displayName, base path, filter)
- Logs full SCIM2 request URL in debug mode
- Logs search results (totalResults, resources returned)
- Logs each result with ID and displayName in debug mode
- Logs detailed error messages for exceptions

### 4. createEntry Method
- Logs when createEntry is called
- Logs full entry in debug mode
- Logs analysis of cn and username attributes
- **Logs warning that group should have been modified, not created**
- **Provides troubleshooting hints**

### 5. modifyEntry Method
- Logs when modifyEntry is called
- Logs full entry and modifications in debug mode
- Logs analysis of entry type (group vs user)
- Logs routing decision

## Troubleshooting Steps

### Step 1: Enable Debug Logging

Enable debug logging in your Data Sync Server to see detailed trace information:

```bash
# In dsconfig or via console
dsconfig set-log-publisher-prop \
  --publisher-name "File-Based Debug Logger" \
  --set enabled:true \
  --set default-debug-level:verbose
```

Or add to your sync pipe configuration:
```
debug-level: verbose
```

### Step 2: Run Resync and Review Logs

Run the resync operation and look for these key log messages:

```
# Expected sequence:
fetchEntry called for DN: cn=admins,ou=Groups,dc=quinn,dc=net
fetchEntry - Detected GROUP entry, routing to fetchGroupEntry
fetchGroupEntry - Starting group lookup for DN: cn=admins,ou=Groups,dc=quinn,dc=net
fetchGroupEntry - Extracted group name: admins
findScim2GroupId - Searching for SCIM2 group with displayName: 'admins'
findScim2GroupId - SUCCESS: Found SCIM2 group ID: <ID> with displayName: admins
modifyEntry called for DN: cn=admins,ou=Groups,dc=quinn,dc=net
modifyEntry - Detected GROUP entry with SCIM2 ID, routing to processGroupResync
```

### Step 3: Check for Common Issues

#### Issue 1: Group Doesn't Exist in SCIM2
**Symptom:**
```
findScim2GroupId - WARNING: No SCIM2 group found for displayName: 'admins'
```

**Solution:** Create the group in SCIM2 first. The group must exist before resync can update its membership.

#### Issue 2: DisplayName Mismatch
**Symptom:**
```
fetchGroupEntry - Extracted group name: admins
findScim2GroupId - WARNING: No SCIM2 group found for displayName: 'admins'
```

**Solution:** 
- Check the SCIM2 group's displayName field (case-sensitive)
- Verify it matches exactly with the LDAP cn attribute
- Common issues: "admins" vs "Admins", extra spaces, different values

#### Issue 3: SCIM2 Connection Problem
**Symptom:**
```
findScim2GroupId - ERROR: SCIM service not initialized
```
or
```
findScim2GroupId - SCIM Error searching for group 'admins': ...
```

**Solution:**
- Check SCIM2 endpoint is accessible
- Verify credentials are correct
- Check network connectivity
- Review SCIM2 endpoint logs

#### Issue 4: fetchEntry Not Called
**Symptom:** No fetchEntry logs at all, straight to createEntry

**Solution:**
- Check sync pipe configuration
- Ensure sync class is configured correctly
- Verify sync mode (standard vs notification)
- Check if "create-if-necessary" is enabled

### Step 4: Manual SCIM2 Verification

Test the SCIM2 endpoint directly to verify the group exists:

```bash
# Search for the group
curl -X GET \
  "https://your-scim-endpoint/scim/v2/Groups?filter=displayName%20eq%20%22admins%22" \
  -H "Authorization: Basic $(echo -n 'username:password' | base64)" \
  -H "Content-Type: application/scim+json"
```

Expected response should show the group with:
- `id`: The unique identifier
- `displayName`: Should exactly match LDAP cn value

## Configuration Recommendations

### Sync Pipe Configuration

Ensure your sync pipe has these settings:

```
# sync-pipe.properties
sync-class: Groups
sync-mode: standard
create-if-necessary: false
```

**Important:** `create-if-necessary: false` ensures that groups must exist in the destination. This prevents accidental group creation during resync.

### Attribute Mapping

Ensure proper attribute mapping in your sync pipe:

```
# Map cn to displayName for group lookups
map-attribute: cn -> displayName
```

## Next Steps

1. **Run resync with debug logging enabled**
2. **Search logs for the key messages listed above**
3. **Identify which issue matches your symptoms**
4. **Follow the corresponding solution**
5. **If issue persists, collect logs and review:**
   - Full fetchEntry sequence
   - SCIM2 search request/response
   - Any error messages

## Additional Debug Information

The enhanced logging includes:

- **operation.logInfo()**: Always logged to resync.log
- **serverContext.debugInfo()**: Only logged when debug level is verbose/trace
- Full entry LDIF dumps in debug mode
- Full modification lists in debug mode
- SCIM2 request/response details in debug mode
- Stack traces for exceptions in debug mode

This comprehensive logging should help identify exactly where the group lookup is failing.

# Dynamic Group End-to-End Testing Guide

## Overview

This guide provides step-by-step instructions for testing the dynamic group synchronization from LDAP to SCIM2.

## Architecture

```
LDAP Dynamic Group → DynamicGroupSourcePlugin → Sync Framework → Scim2DynamicGroupDestination → SCIM2
(memberURL)          (parses URL, queries      (passes         (converts to SCIM2,              (updates
                      members, creates          members         performs PUT)                   group)
                      members attribute)        attribute)
```

## Prerequisites

1. **LDAP Source** with dynamic groups (groupOfURLs with memberURL attributes)
2. **SCIM2 Endpoint** with groups already created
3. **Ping Data Sync Server** version compatible with SDK
4. **Plugin deployed**: corp.heer.Scim2GroupmemberSync-2.11.zip

## Step 1: Prepare Test Data

### Create Dynamic Group in LDAP

```ldif
dn: cn=dynamic-engineers,ou=Groups,dc=example,dc=com
objectClass: top
objectClass: groupOfURLs
cn: dynamic-engineers
memberURL: ldap:///ou=Users,dc=example,dc=com??sub?(department=Engineering)
description: All engineering department users
```

### Create Test Users in LDAP

```ldif
dn: uid=alice,ou=Users,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice Smith
sn: Smith
department: Engineering

dn: uid=bob,ou=Users,dc=example,dc=com
objectClass: inetOrgPerson
uid: bob
cn: Bob Jones
sn: Jones
department: Engineering

dn: uid=charlie,ou=Users,dc=example,dc=com
objectClass: inetOrgPerson
uid: charlie
cn: Charlie Brown
sn: Brown
department: Sales
```

### Create Group in SCIM2 Endpoint

```bash
curl -X POST https://scim.example.com/scim/v2/Groups \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "dynamic-engineers",
    "members": []
  }'
```

## Step 2: Configuration Files

### Create scim-sync.properties

```properties
# /opt/sync/config/scim-sync.properties

# SCIM2 Endpoint Configuration
scim2.base.url=https://scim.example.com/scim/v2
scim2.user.base=/Users
scim2.group.base=/Groups

# Authentication
scim2.auth.type=basic
scim2.username=sync-admin
scim2.password=SecurePassword123!

# Or Bearer Token
# scim2.auth.type=bearer
# scim2.bearer.token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# SSL/TLS Configuration (if using self-signed certs)
# scim2.allow.untrusted.certificates=true
# Or use truststore:
# scim2.trust.store.path=/opt/sync/config/truststore.jks
# scim2.trust.store.password=changeit
# scim2.trust.store.type=JKS

# Timeouts and Retries
scim2.connect.timeout.ms=30000
scim2.read.timeout.ms=60000
scim2.max.retries=3
scim2.retry.delay.ms=1000

# User ID Attribute (must match LDAP attribute)
user.id.attribute=uid

# Optional: Filter which groups to process
# group.filter=(cn=dynamic-*)
```

**Important**: Secure this file with appropriate permissions:
```bash
chmod 600 /opt/sync/config/scim-sync.properties
chown sync-user:sync-group /opt/sync/config/scim-sync.properties
```

## Step 3: Deploy Plugin

```bash
# Stop sync server
/opt/PingDataSync/bin/stop-server

# Deploy plugin
cd /opt/PingDataSync/config/server-sdk-extensions
unzip /path/to/corp.heer.Scim2GroupmemberSync-2.11.zip

# Verify deployment
ls -l corp.heer.Scim2GroupmemberSync-2.11/
# Should see:
# - Scim2GroupmemberSync.jar
# - config/
# - docs/
# - lib/

# Start sync server
/opt/PingDataSync/bin/start-server
```

## Step 4: Create Sync Pipe

```bash
# Create sync pipe for dynamic groups
dsconfig create-sync-pipe \
  --pipe-name "LDAP-to-SCIM2-DynamicGroups" \
  --set description:"Synchronize dynamic group memberships from LDAP to SCIM2" \
  --set sync-mode:standard \
  --set source-dn-pattern:"cn=dynamic-*,ou=Groups,dc=example,dc=com" \
  --set sync-class:com.heer.sync.DynamicGroupSourcePlugin \
  --set extension-argument:"config-file=/opt/sync/config/scim-sync.properties" \
  --set extension-argument:"user-id-attribute=uid" \
  --set destination-type:third-party \
  --set destination-class:com.heer.sync.Scim2DynamicGroupDestination \
  --set destination-argument:"config-file=/opt/sync/config/scim-sync.properties" \
  --set destination-argument:"group-base=/Groups" \
  --set destination-argument:"user-lookup-attribute=uid"
```

**Alternative: Using group filter in sync pipe**

```bash
dsconfig create-sync-pipe \
  --pipe-name "LDAP-to-SCIM2-DynamicGroups-Filtered" \
  --set sync-mode:standard \
  --set source-dn-pattern:"cn=*,ou=Groups,dc=example,dc=com" \
  --set sync-class:com.heer.sync.DynamicGroupSourcePlugin \
  --set extension-argument:"config-file=/opt/sync/config/scim-sync.properties" \
  --set extension-argument:"user-id-attribute=uid" \
  --set extension-argument:"group-filter=(cn=dynamic-*)" \
  --set destination-type:third-party \
  --set destination-class:com.heer.sync.Scim2DynamicGroupDestination \
  --set destination-argument:"config-file=/opt/sync/config/scim-sync.properties" \
  --set destination-argument:"group-base=/Groups"
```

## Step 5: Initial Resync

```bash
# Perform initial resync to populate dynamic group memberships
realtime-sync resync \
  --pipe-name "LDAP-to-SCIM2-DynamicGroups" \
  --source-entry-dn "cn=dynamic-engineers,ou=Groups,dc=example,dc=com"
```

## Step 6: Verify Synchronization

### Check Sync Server Logs

```bash
tail -f /opt/PingDataSync/logs/sync

# Look for:
# - "Processing dynamic group: cn=dynamic-engineers,..."
# - "Parsing memberURL: ldap:///ou=Users,..."
# - "Searching for group members with base DN: ou=Users,..."
# - "Found 2 matching users"
# - "Adding 2 member user IDs to group"
# - "Looking up SCIM2 group ID for: dynamic-engineers"
# - "Mapped 2 members to SCIM2 IDs"
# - "Successfully updated dynamic group dynamic-engineers with 2 members"
```

### Verify in SCIM2 Endpoint

```bash
# Get group to verify members
curl -X GET "https://scim.example.com/scim/v2/Groups?filter=displayName+eq+%22dynamic-engineers%22" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Accept: application/scim+json"

# Should return:
# {
#   "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
#   "id": "abc123...",
#   "displayName": "dynamic-engineers",
#   "members": [
#     {"value": "user-id-alice", "$ref": "https://scim.example.com/scim/v2/Users/user-id-alice"},
#     {"value": "user-id-bob", "$ref": "https://scim.example.com/scim/v2/Users/user-id-bob"}
#   ]
# }
```

## Step 7: Test Dynamic Membership Changes

### Test 1: Add New User to Department

```ldif
# Create new user in Engineering department
dn: uid=diana,ou=Users,dc=example,dc=com
objectClass: inetOrgPerson
uid: diana
cn: Diana Prince
sn: Prince
department: Engineering
```

```bash
# Trigger resync (dynamic groups require resync)
realtime-sync resync \
  --pipe-name "LDAP-to-SCIM2-DynamicGroups" \
  --source-entry-dn "cn=dynamic-engineers,ou=Groups,dc=example,dc=com"

# Verify diana is now in the group
curl -X GET "https://scim.example.com/scim/v2/Groups?filter=displayName+eq+%22dynamic-engineers%22" \
  -H "Authorization: Bearer YOUR_TOKEN"
# Should now show 3 members including diana
```

### Test 2: Change User Department

```ldif
# Move alice from Engineering to Sales
dn: uid=alice,ou=Users,dc=example,dc=com
changetype: modify
replace: department
department: Sales
```

```bash
# Trigger resync
realtime-sync resync \
  --pipe-name "LDAP-to-SCIM2-DynamicGroups" \
  --source-entry-dn "cn=dynamic-engineers,ou=Groups,dc=example,dc=com"

# Verify alice is no longer in the group
curl -X GET "https://scim.example.com/scim/v2/Groups?filter=displayName+eq+%22dynamic-engineers%22" \
  -H "Authorization: Bearer YOUR_TOKEN"
# Should now show only bob and diana
```

### Test 3: Complex memberURL

```ldif
# Create dynamic group with complex filter
dn: cn=dynamic-senior-engineers,ou=Groups,dc=example,dc=com
objectClass: groupOfURLs
cn: dynamic-senior-engineers
memberURL: ldap:///ou=Users,dc=example,dc=com??sub?(&(department=Engineering)(title=Senior*))
```

```bash
# Resync to test
realtime-sync resync \
  --pipe-name "LDAP-to-SCIM2-DynamicGroups" \
  --source-entry-dn "cn=dynamic-senior-engineers,ou=Groups,dc=example,dc=com"
```

## Step 8: Monitor Performance

### Check Query Optimization

```bash
# Enable debug logging
dsconfig set-log-publisher-prop \
  --publisher-name "File-Based Debug Logger" \
  --set enabled:true

tail -f /opt/PingDataSync/logs/debug

# Look for optimizations:
# - "optimized - excludes members"
# - "Only request id and displayName attributes"
# - GET requests with "?excludedAttributes=members"
```

### Monitor Network Traffic

```bash
# Use tcpdump to verify query parameters
tcpdump -i any -A -s 0 'tcp port 443 and host scim.example.com' | grep -i 'excludedattributes'

# Should see:
# GET /scim/v2/Groups/abc123?excludedAttributes=members
```

## Troubleshooting

### Issue: "No member user IDs found for group"

**Cause**: memberURL query returned no results

**Solutions**:
1. Verify base DN in memberURL exists
2. Check filter matches expected users
3. Verify scope (sub vs one) is appropriate
4. Test query manually:
   ```bash
   ldapsearch -b "ou=Users,dc=example,dc=com" \
              -s sub \
              "(department=Engineering)" \
              uid
   ```

### Issue: "Could not parse memberURL"

**Cause**: Invalid LDAP URL syntax

**Solutions**:
1. Verify URL format: `ldap:///baseDN??scope?filter`
2. Common formats:
   - `ldap:///ou=Users,dc=example,dc=com??sub?(department=Engineering)`
   - `ldap:///ou=Users,dc=example,dc=com??one?(objectClass=inetOrgPerson)`

### Issue: "No SCIM2 group found"

**Cause**: Group doesn't exist in SCIM2 endpoint

**Solutions**:
1. Create group in SCIM2 first
2. Verify displayName matches exactly (case-sensitive)
3. Check group base path configuration

### Issue: "Dynamic groups only support REPLACE operations"

**Cause**: Sync framework sent ADD/DELETE modification

**Expected**: This is normal behavior. Dynamic groups only support full resync.

**Action**: Configure sync pipe for resync-only mode.

### Issue: Slow resync performance

**Cause**: Large memberURL queries or many groups

**Solutions**:
1. Add indexes on LDAP attributes (department, title, etc.)
2. Use more specific memberURL filters
3. Consider splitting into multiple smaller groups
4. Verify optimization is working (check for `excludedAttributes` in logs)

## Performance Tips

1. **Optimize memberURL Filters**:
   - Use indexed attributes
   - Be as specific as possible
   - Avoid wildcard-heavy filters

2. **Batch Processing**:
   - Process multiple groups in parallel if possible
   - Schedule resyncs during off-peak hours

3. **Monitoring**:
   - Watch LDAP query performance
   - Monitor SCIM2 endpoint response times
   - Track sync operation duration

4. **Indexes**:
   ```bash
   # Example: Create index on department attribute
   dsconfig create-local-db-index \
     --backend-name userRoot \
     --index-name department \
     --set index-type:equality
   ```

## Example Test Script

```bash
#!/bin/bash
# test-dynamic-groups.sh

PIPE_NAME="LDAP-to-SCIM2-DynamicGroups"
GROUP_DN="cn=dynamic-engineers,ou=Groups,dc=example,dc=com"
SCIM_URL="https://scim.example.com/scim/v2"
TOKEN="YOUR_TOKEN"

echo "1. Performing initial resync..."
realtime-sync resync --pipe-name "$PIPE_NAME" --source-entry-dn "$GROUP_DN"

echo "2. Fetching group from SCIM2..."
curl -s "$SCIM_URL/Groups?filter=displayName+eq+%22dynamic-engineers%22" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/scim+json" | jq '.Resources[0].members | length'

echo "3. Adding new user to Engineering..."
ldapadd -h localhost -p 389 -D "cn=admin,dc=example,dc=com" -w password << EOF
dn: uid=test-user,ou=Users,dc=example,dc=com
objectClass: inetOrgPerson
uid: test-user
cn: Test User
sn: User
department: Engineering
EOF

echo "4. Waiting 2 seconds..."
sleep 2

echo "5. Re-syncing group..."
realtime-sync resync --pipe-name "$PIPE_NAME" --source-entry-dn "$GROUP_DN"

echo "6. Verifying new member count..."
curl -s "$SCIM_URL/Groups?filter=displayName+eq+%22dynamic-engineers%22" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/scim+json" | jq '.Resources[0].members | length'

echo "Test complete!"
```

## Success Criteria

✅ **Initial Resync**: All users matching memberURL appear in SCIM2 group  
✅ **Add User**: New matching user appears after resync  
✅ **Remove User**: User removed when no longer matches filter  
✅ **Complex Filters**: AND/OR conditions work correctly  
✅ **Performance**: Queries use `excludedAttributes` optimization  
✅ **Error Handling**: Invalid memberURLs logged but don't break sync  
✅ **Logs**: Clear, informative log messages throughout process

## Next Steps

1. ✅ Test basic dynamic group sync
2. ✅ Test with multiple memberURLs per group
3. ✅ Test with complex filters
4. ✅ Verify performance optimizations
5. ✅ Test error scenarios
6. 🔄 Move to production

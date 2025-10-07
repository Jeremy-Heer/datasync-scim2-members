# Quick Start Guide

**SCIM2 Group Membership Sync Plugin**  
**Version**: 1.18

---

## 5-Minute Setup

### 1. Build & Deploy

```bash
# Build
./build.sh

# Deploy to Ping Data Sync
cd /opt/ping-datasync/extensions
unzip /path/to/corp.heer.Scim2GroupmemberSync-1.18.zip
```

### 2. Basic Configuration

```bash
# Create sync pipe with destination plugin
dsconfig create-sync-pipe \
  --pipe-name "GroupMembershipSync" \
  --type sync-pipe \
  --set extension-class:com.heer.sync.Scim2GroupMemberDestination \
  --set extension-argument:"base-url=https://your-scim-endpoint.com/scim/v2" \
  --set extension-argument:"user-base-path=/Users" \
  --set extension-argument:"group-base-path=/Groups" \
  --set extension-argument:"auth-type=bearer" \
  --set extension-argument:"bearer-token=YOUR_TOKEN_HERE" \
  --set extension-argument:"group-membership-attributes=memberOf" \
  --set extension-argument:"username-lookup-attribute=uid"
```

### 3. Test Connection

```bash
# Enable sync pipe
dsconfig set-sync-pipe-prop \
  --pipe-name "GroupMembershipSync" \
  --set started:true

# Check logs
tail -f logs/sync
```

---

## Common Commands

### User Membership Sync

```bash
# Start realtime sync
realtime-sync start --pipe-name "GroupMembershipSync"

# Check status
realtime-sync status --pipe-name "GroupMembershipSync"

# View recent changes
realtime-sync list-sync-history \
  --pipe-name "GroupMembershipSync" \
  --maxResults 10
```

### Group Resync

```bash
# First, add source plugin for dynamic groups
dsconfig create-ldap-sync-source-plugin \
  --plugin-name "GroupMemberExpander" \
  --type ldap-sync-source-plugin-scim2-group-members \
  --set enabled:true \
  --set user-id-attribute:uid \
  --pipe-name "GroupMembershipSync"

# Run full group resync
realtime-sync resync \
  --pipe-name "GroupMembershipSync" \
  --useExistingEntry \
  --source-base-dn "cn=developers,ou=groups,dc=example,dc=com"
```

---

## Configuration Recipes

### Recipe 1: Okta Integration

```bash
dsconfig set-sync-destination-prop \
  --pipe-name "OktaSync" \
  --set base-url:"https://dev-123456.okta.com/api/v1/scim/v2" \
  --set auth-type:bearer \
  --set bearer-token:"00abc..." \
  --set update-method:patch
```

### Recipe 2: Azure AD Integration

```bash
dsconfig set-sync-destination-prop \
  --pipe-name "AzureSync" \
  --set base-url:"https://graph.microsoft.com/beta/scim" \
  --set auth-type:bearer \
  --set bearer-token:"eyJ0..." \
  --set username-lookup-attribute:userPrincipalName
```

### Recipe 3: Performance Optimization

```bash
# For large groups or slow endpoints
dsconfig set-sync-destination-prop \
  --pipe-name "GroupMembershipSync" \
  --set disable-group-membership-lookups:true \
  --set max-retries:5 \
  --set retry-delay-ms:2000
```

### Recipe 4: Behind Corporate Proxy

```bash
dsconfig set-sync-destination-prop \
  --pipe-name "GroupMembershipSync" \
  --set proxy-host:"proxy.company.com" \
  --set proxy-port:8080 \
  --set proxy-username:"proxyuser" \
  --set proxy-password:"proxypass"
```

---

## Troubleshooting Quick Fixes

### Issue: "No SCIM2 user found"

```bash
# Check username attribute mapping
dsconfig get-sync-destination-prop \
  --pipe-name "GroupMembershipSync" \
  --property username-lookup-attribute

# Verify SCIM2 userName field matches LDAP attribute
```

### Issue: "Group does not exist"

```bash
# Groups must exist in SCIM2 first
# Create groups manually or via separate process
# Verify displayName in SCIM2 matches cn in LDAP (case-sensitive)
```

### Issue: Performance Degradation

```bash
# Enable optimization flag
dsconfig set-sync-destination-prop \
  --pipe-name "GroupMembershipSync" \
  --set disable-group-membership-lookups:true
```

### Issue: Connection Timeouts

```bash
# Increase timeouts
dsconfig set-sync-destination-prop \
  --pipe-name "GroupMembershipSync" \
  --set connect-timeout-ms:60000 \
  --set read-timeout-ms:120000
```

---

## Monitoring Commands

### Check Sync Status

```bash
# Overall status
status

# Pipe-specific status
dsconfig get-sync-pipe-prop \
  --pipe-name "GroupMembershipSync" \
  --property last-sync-time
```

### View Logs

```bash
# Real-time sync logs
tail -f logs/sync

# Error logs
grep ERROR logs/sync | tail -20

# Debug logs (if enabled)
tail -f logs/debug
```

### Performance Metrics

```bash
# Check processing rate
realtime-sync status --pipe-name "GroupMembershipSync" \
  --showProcessingRate

# View recent operations
realtime-sync list-sync-history \
  --pipe-name "GroupMembershipSync" \
  --maxResults 50
```

---

## Emergency Procedures

### Stop Sync Immediately

```bash
# Stop realtime sync
realtime-sync stop --pipe-name "GroupMembershipSync"

# Disable pipe
dsconfig set-sync-pipe-prop \
  --pipe-name "GroupMembershipSync" \
  --set started:false
```

### Rollback Changes

```bash
# Note: SCIM2 changes are immediate and cannot be automatically rolled back
# Manual intervention required to restore previous group memberships
# Always test in non-production first!
```

### Enable Debug Logging

```bash
# Enable debug logging
dsconfig set-log-publisher-prop \
  --publisher-name "File-Based Debug Logger" \
  --set enabled:true \
  --set default-debug-level:verbose

# View debug logs
tail -f logs/debug

# Disable when done (important for performance)
dsconfig set-log-publisher-prop \
  --publisher-name "File-Based Debug Logger" \
  --set enabled:false
```

---

## Testing Checklist

### ✅ Pre-Production Testing

```bash
# 1. Test user sync
# Manually add user to LDAP group
# Verify user appears in SCIM2 group

# 2. Test user removal
# Remove user from LDAP group
# Verify user removed from SCIM2 group

# 3. Test group resync
# Run resync command
# Verify all members match in SCIM2

# 4. Test error handling
# Temporarily break connection
# Verify retry logic works
# Restore connection

# 5. Test performance
# Sync large group (500+ members)
# Monitor processing time
# Check for errors
```

---

## Best Practices

### ✅ DO

- ✅ Test in non-production environment first
- ✅ Use PATCH method (default) for better performance
- ✅ Enable debug logging during initial setup
- ✅ Monitor logs regularly
- ✅ Keep credentials secure
- ✅ Use HTTPS for SCIM2 endpoints
- ✅ Document your specific configuration

### ❌ DON'T

- ❌ Use `allow-untrusted-certificates:true` in production
- ❌ Expose credentials in logs or documentation
- ❌ Run resync without `--useExistingEntry` flag
- ❌ Skip testing in non-production
- ❌ Ignore error messages
- ❌ Disable retry logic without good reason
- ❌ Use notification mode without understanding implications

---

## Getting Help

### Resources

1. **Full Documentation**: See [README.md](README.md)
2. **Production Guide**: See [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md)
3. **Troubleshooting**: See [RESYNC_TROUBLESHOOTING.md](RESYNC_TROUBLESHOOTING.md)
4. **GitHub Issues**: https://github.com/Jeremy-Heer/datasync-scim2-members/issues

### Log Analysis

```bash
# Find all errors in last hour
awk -v cutoff="$(date -d '1 hour ago' '+%Y-%m-%d %H:%M:%S')" \
  '$0 >= cutoff' logs/sync | grep ERROR

# Count operations by type
grep "operation:" logs/sync | \
  awk '{print $NF}' | sort | uniq -c

# Find slow operations (>5 seconds)
grep "completed in" logs/sync | \
  awk '$NF > 5000' | tail -20
```

---

## Quick Reference: Configuration Parameters

| Parameter | Required | Default | Purpose |
|-----------|----------|---------|---------|
| `base-url` | ✅ | - | SCIM2 endpoint URL |
| `user-base-path` | ✅ | - | Users resource path |
| `group-base-path` | ✅ | - | Groups resource path |
| `group-membership-attributes` | ✅ | - | LDAP group attributes |
| `username-lookup-attribute` | ✅ | - | User matching attribute |
| `auth-type` | ✅ | - | `basic` or `bearer` |
| `update-method` | ❌ | `patch` | `patch` or `put` |
| `max-retries` | ❌ | `3` | Retry attempts |
| `disable-group-membership-lookups` | ❌ | `false` | Performance flag |

---

**Need more help?** See the full [README.md](README.md) or [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md)

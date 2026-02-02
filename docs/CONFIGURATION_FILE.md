# Configuration File Reference

This document describes the shared configuration file system for the refactored SCIM2 sync plugins.

## Overview

The refactored plugin architecture supports shared configuration via Java Properties files, enabling:

- **Consistent configuration** across multiple plugins (static groups, dynamic groups, destinations)
- **Credential updates without restart** via automatic file modification detection
- **Reduced duplication** by centralizing common settings
- **Flexibility** with inline argument overrides for per-plugin customization

## Configuration File Format

Configuration files use standard Java Properties format:

```properties
# Comments start with #
key=value
multi.word.key=multi word value

# No quotes needed for values
user.id.attribute=uid
scim2.base.url=https://api.example.com/scim/v2
```

## Configuration Priority

When both a configuration file and inline arguments are provided:

1. **Inline arguments take precedence** - Always override file values
2. **File provides defaults** - Used when inline arguments not specified
3. **Built-in defaults** - Used when neither file nor inline arguments provide a value

Example:
```bash
# File contains: user.id.attribute=uid
# Inline argument: --user-id-attribute sAMAccountName
# Result: sAMAccountName is used (inline wins)
```

## File Location

The configuration file path is specified via the `--config-file` argument:

```bash
dsconfig create-sync-source-plugin \
  --plugin-name "StaticGroupSource" \
  --type third-party \
  --set extension-class:com.heer.sync.StaticGroupSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties"
```

**Recommended locations:**
- `/opt/sync/config/scim-sync.properties` (Linux/Unix)
- `/etc/ping-sync/scim-sync.properties` (System-wide)
- `C:\ProgramData\PingIdentity\Sync\config\scim-sync.properties` (Windows)

## Security Considerations

Configuration files may contain sensitive credentials (passwords, tokens). Protect them appropriately:

### File Permissions

```bash
# Set restrictive permissions (owner read/write only)
chmod 600 /opt/sync/config/scim-sync.properties

# Set appropriate ownership
chown sync-server-user:sync-server-group /opt/sync/config/scim-sync.properties
```

### Encryption (Future Enhancement)

Current version stores credentials in plaintext. Consider:

- External secret management (HashiCorp Vault, AWS Secrets Manager)
- Encrypted properties with key management
- Environment variable substitution

## Automatic Reload

The `ConfigFileLoader` utility automatically detects file modifications and reloads configuration:

### When Reload Occurs

1. **On every read operation** - File modification time is checked
2. **On applyConfiguration()** - When plugin configuration is updated via dsconfig
3. **Lazy reload** - Only reloads if file timestamp has changed

### Reload Use Cases

**Credential rotation without restart:**
```bash
# 1. Update configuration file
echo "scim2.auth.token=new-token-value" >> /opt/sync/config/scim-sync.properties

# 2. Plugin automatically detects change on next sync operation
#    OR trigger reload explicitly:
dsconfig set-sync-source-plugin-prop \
  --plugin-name "StaticGroupSource" \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties"
```

**Password updates:**
```bash
# Edit file with new password
vi /opt/sync/config/scim-sync.properties

# Reload is automatic on next sync operation
# No server restart required
```

### Reload Behavior

- **Thread-safe** - Uses read-write locks for concurrent access
- **Atomic** - Configuration updates are all-or-nothing
- **Logged** - File reloads are logged at DEBUG level
- **Graceful failure** - Read errors don't crash the plugin, previous config retained

## Configuration Properties Reference

### Source Plugin Properties

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `user.id.attribute` | Yes | - | LDAP attribute containing user ID (e.g., `uid`, `sAMAccountName`) |
| `group.filter` | No | All groups | LDAP filter to select which groups to process |

### Destination Plugin Properties (Future)

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `scim2.base.url` | Yes | - | SCIM2 API base URL |
| `scim2.auth.method` | Yes | - | Authentication method (`basic`, `bearer`, `oauth`) |
| `scim2.auth.username` | Conditional | - | Username for basic auth |
| `scim2.auth.password` | Conditional | - | Password for basic auth |
| `scim2.auth.token` | Conditional | - | Bearer token |
| `scim2.update.method` | No | `PATCH` | Update method (`PATCH` or `PUT`) |
| `scim2.max.retries` | No | `3` | Maximum retry attempts |
| `scim2.retry.delay.ms` | No | `1000` | Initial retry delay (milliseconds) |

## Plugin Configuration Examples

### Example 1: File-Only Configuration

**File: `/opt/sync/config/scim-sync.properties`**
```properties
user.id.attribute=uid
group.filter=(cn=scim-*)
```

**Plugin Configuration:**
```bash
dsconfig create-sync-source-plugin \
  --plugin-name "StaticGroupSource" \
  --type third-party \
  --set extension-class:com.heer.sync.StaticGroupSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties"
```

### Example 2: File + Inline Override

**File: `/opt/sync/config/scim-sync.properties`**
```properties
user.id.attribute=uid
group.filter=(cn=scim-*)
```

**Plugin Configuration (overrides filter):**
```bash
dsconfig create-sync-source-plugin \
  --plugin-name "DynamicGroupSource" \
  --type third-party \
  --set extension-class:com.heer.sync.DynamicGroupSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties" \
  --set "extension-argument:group-filter=(cn=dynamic-*)"
  # Inline filter overrides file's (cn=scim-*)
```

### Example 3: Inline-Only Configuration

**Plugin Configuration (no file):**
```bash
dsconfig create-sync-source-plugin \
  --plugin-name "StaticGroupSource" \
  --type third-party \
  --set extension-class:com.heer.sync.StaticGroupSourcePlugin \
  --set "extension-argument:user-id-attribute=sAMAccountName" \
  --set "extension-argument:group-filter=(cn=admins)"
```

### Example 4: Shared File Across Multiple Plugins

**File: `/opt/sync/config/scim-sync.properties`** (shared)
```properties
user.id.attribute=uid
group.filter=(cn=scim-*)
```

**Static Group Plugin:**
```bash
dsconfig create-sync-source-plugin \
  --plugin-name "StaticGroupSource" \
  --type third-party \
  --set extension-class:com.heer.sync.StaticGroupSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties"
```

**Dynamic Group Plugin (same file):**
```bash
dsconfig create-sync-source-plugin \
  --plugin-name "DynamicGroupSource" \
  --type third-party \
  --set extension-class:com.heer.sync.DynamicGroupSourcePlugin \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties"
```

Both plugins share the same configuration file, ensuring consistency.

## Troubleshooting

### Configuration Not Loading

**Check file permissions:**
```bash
ls -l /opt/sync/config/scim-sync.properties
# Should show: -rw------- or -rw-r--r--
```

**Check file ownership:**
```bash
ls -l /opt/sync/config/scim-sync.properties
# Owner should be the sync server process user
```

**Check logs for errors:**
```bash
tail -f /opt/ping-sync/logs/errors
# Look for: "Cannot read configuration file" or "Configuration file does not exist"
```

### Configuration Not Reloading

**Verify file modification time changed:**
```bash
touch /opt/sync/config/scim-sync.properties
# This updates the timestamp, triggering reload
```

**Check debug logs:**
```bash
tail -f /opt/ping-sync/logs/debug
# Look for: "Configuration file has been modified, reloading"
```

**Force reload via dsconfig:**
```bash
dsconfig set-sync-source-plugin-prop \
  --plugin-name "StaticGroupSource" \
  --set "extension-argument:config-file=/opt/sync/config/scim-sync.properties"
# applyConfiguration() triggers explicit reload
```

### Property Not Found

**Check property name spelling:**
```properties
# Correct:
user.id.attribute=uid

# Incorrect (underscore instead of dot):
user_id_attribute=uid
```

**Check for trailing whitespace:**
```properties
# Incorrect (space after equals):
user.id.attribute= uid

# Correct:
user.id.attribute=uid
```

**Verify inline argument isn't overriding:**
```bash
# Check if inline argument is taking precedence
dsconfig get-sync-source-plugin-prop \
  --plugin-name "StaticGroupSource" \
  --property extension-argument
```

## Best Practices

1. **Use shared file for common settings** - Avoid duplication across plugins
2. **Use inline arguments for plugin-specific settings** - Per-plugin customization
3. **Protect credentials** - Set restrictive file permissions (600)
4. **Version control** - Keep example file in version control, actual file outside
5. **Document overrides** - Comment why inline arguments override file values
6. **Test reload** - Verify credential updates work without restart
7. **Monitor logs** - Watch for reload events and configuration errors

## Future Enhancements

Potential improvements to consider:

- **Environment variable substitution** - `${SCIM_TOKEN}` in properties files
- **Encrypted properties** - Encrypt sensitive values at rest
- **External secret management** - Integration with Vault, AWS Secrets Manager
- **Configuration validation** - Syntax checking and property validation
- **Hot reload notification** - Explicit notification when config changes
- **Configuration UI** - Web-based configuration editor

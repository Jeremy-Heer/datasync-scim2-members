# SCIM2 Group Membership Sync Plugin for Ping Data Sync

[![License](https://img.shields.io/badge/license-CDDL-blue.svg)](LICENSE)
[![Ping Identity](https://img.shields.io/badge/Ping-Identity-green.svg)](https://www.pingidentity.com/)

A production-ready Ping Data Sync extension for synchronizing LDAP group memberships to SCIM2 endpoints. Supports both incremental user membership changes and full group resync operations, including dynamic LDAP groups.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Destination Plugin Configuration](#destination-plugin-configuration)
  - [Source Plugin Configuration](#source-plugin-configuration)
- [Operating Modes](#operating-modes)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)
- [Performance Optimization](#performance-optimization)
- [Security Considerations](#security-considerations)
- [Support](#support)

## Overview

This extension provides two complementary plugins for Ping Data Sync:

1. **Scim2GroupMemberDestination** - Synchronizes group membership changes from LDAP to SCIM2 endpoints
2. **LDAPSyncSourcePluginScim2GroupMembers** - Expands dynamic LDAP groups for resync operations

Together, these plugins enable comprehensive group membership synchronization between LDAP directories and SCIM2-compliant identity providers (IdPs) such as Okta, Azure AD, OneLogin, and others.

## Features

### Core Capabilities

- ✅ **Incremental User Membership Sync** - Real-time synchronization of user group membership changes
- ✅ **Full Group Resync** - Complete group membership replacement for dynamic and static groups
- ✅ **Dynamic Group Support** - Automatically expands LDAP dynamic groups (memberURL) during resync
- ✅ **Multiple Authentication Methods** - Basic Auth and OAuth Bearer Token support
- ✅ **Flexible Update Methods** - Configurable PATCH (recommended) or PUT operations
- ✅ **RFC Compliance** - Fully compliant with RFC 7644 (SCIM 2.0 Protocol) and RFC 7643 (SCIM 2.0 Core Schema)

### Advanced Features

- 🔧 **Performance Optimization** - Configurable group membership lookup behavior
- 🔧 **Automatic Retry** - Exponential backoff for transient failures
- 🔧 **SSL/TLS Support** - Custom truststore or certificate validation bypass (dev/test)
- 🔧 **HTTP Proxy Support** - Configurable proxy with authentication
- 🔧 **Comprehensive Logging** - Detailed debug logging for troubleshooting
- 🔧 **Thread-Safe** - Designed for concurrent multi-threaded synchronization

### Operational Features

- 📊 **Accurate Comparison** - Fetches current SCIM2 state for precise delta calculation
- 📊 **Cleanup on Resync** - Removes extra group memberships during full resync
- 📊 **Notification Mode Support** - Works with both standard and notification sync modes
- 📊 **Configurable Timeouts** - Connect and read timeout settings
- 📊 **Multiple Group Attributes** - Supports synchronizing multiple LDAP group membership attributes

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      Ping Data Sync Server                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Sync Pipe Configuration                       │  │
│  │  • Source: LDAP Directory                                 │  │
│  │  • Destination: SCIM2 Endpoint                            │  │
│  │  • Mode: Standard (recommended) or Notification           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                           │                                       │
│          ┌────────────────┴────────────────┐                    │
│          ▼                                  ▼                     │
│  ┌──────────────────┐            ┌──────────────────────┐       │
│  │  Source Plugin   │            │  Destination Plugin   │       │
│  │                  │            │                       │       │
│  │  Expands dynamic │            │  Updates SCIM2 group  │       │
│  │  groups via      │──────────▶│  memberships via      │       │
│  │  memberURL       │            │  PATCH or PUT         │       │
│  │  queries         │            │                       │       │
│  └──────────────────┘            └──────────────────────┘       │
│                                              │                    │
└──────────────────────────────────────────────┼───────────────────┘
                                               │
                                               ▼
                                   ┌────────────────────┐
                                   │  SCIM2 Endpoint    │
                                   │  (Okta, Azure AD,  │
                                   │   OneLogin, etc.)  │
                                   └────────────────────┘
```

### Synchronization Flow

#### User Membership Sync (Incremental)

```
1. LDAP Change: User added to group "developers"
         ↓
2. Ping Data Sync detects change
         ↓
3. Source Plugin: Pass-through (no modification)
         ↓
4. Destination Plugin:
   a. fetchEntry: Map LDAP user to SCIM2 user (get current groups)
   b. Compare source vs destination group memberships
   c. modifyEntry: Add user to SCIM2 "developers" group via PATCH/PUT
         ↓
5. SCIM2 Endpoint: User membership updated
```

#### Group Resync (Full)

```
1. Resync Command: dsconfig resync --useExistingEntry
         ↓
2. Source Plugin:
   a. Detect dynamic group (memberURL attribute)
   b. Parse LDAP URL: baseDN, scope, filter
   c. Query LDAP for matching users
   d. Extract uid from each user
   e. Add "members" attribute with all uids
         ↓
3. Destination Plugin:
   a. fetchEntry: Map LDAP group to SCIM2 group by name
   b. modifyEntry: Detect group entry (has scim2GroupId)
   c. processGroupResync:
      - Read members attribute (user IDs)
      - Search SCIM2 for each user ID
      - Collect SCIM2 user IDs
      - PUT entire membership list to SCIM2 group
         ↓
4. SCIM2 Endpoint: Group membership completely replaced
```

## Requirements

### Server Requirements

- **Ping Data Sync**: Version 8.0 or higher
- **Java**: OpenJDK 11 or higher (included with Ping Data Sync)
- **LDAP Directory**: Any LDAP v3 compliant directory
- **SCIM2 Endpoint**: RFC 7644 compliant SCIM 2.0 service

### Dependencies (Included)

All dependencies are included in the `sdk-libs/` directory:

- UnboundID LDAP SDK for Java
- UnboundID Server SDK
- UnboundID SCIM2 SDK (Client & Common)
- Jackson (JSON processing)
- Jakarta WS RS API & Jersey Client
- Apache HttpClient

### Network Requirements

- HTTPS connectivity to SCIM2 endpoint
- LDAP/LDAPS connectivity to source directory
- Optionally: HTTP proxy support if behind corporate firewall

## Installation

### 1. Build the Extension

```bash
# Clone the repository
git clone https://github.com/Jeremy-Heer/datasync-scim2-members.git
cd datasync-scim2-members

# Build using provided script (Linux/macOS)
./build.sh

# Or on Windows
build.bat
```

The build produces: `build/corp.heer.Scim2GroupmemberSync-[version].zip`

### 2. Deploy to Ping Data Sync

```bash
# Extract to Ping Data Sync server extensions directory
cd /path/to/ping-datasync/extensions
unzip /path/to/corp.heer.Scim2GroupmemberSync-[version].zip

# Verify extraction
ls -la corp.heer.Scim2GroupmemberSync-[version]/
```

### 3. Configure the Extension

Use `dsconfig` interactive mode or batch configuration:

```bash
# Interactive mode
bin/dsconfig

# Navigate to:
# Sync Pipes > [Your Sync Pipe] > Sync Destination
# Select: Scim2GroupMemberDestination
```

See [Configuration](#configuration) section for detailed parameters.

### 4. Restart Sync Pipe

```bash
# Restart the specific sync pipe
bin/dsconfig set-sync-pipe-prop \
  --pipe-name "YourSyncPipe" \
  --set enabled:false

bin/dsconfig set-sync-pipe-prop \
  --pipe-name "YourSyncPipe" \
  --set enabled:true
```

## Configuration

### Destination Plugin Configuration

#### Scim2GroupMemberDestination

##### Required Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `base-url` | String | Base URL of SCIM2 endpoint | `https://api.okta.com/scim/v2` |
| `user-base-path` | String | Path to Users resource | `/Users` |
| `group-base-path` | String | Path to Groups resource | `/Groups` |
| `group-membership-attributes` | String[] | LDAP attributes containing group names | `memberOf`, `groupMembership` |
| `username-lookup-attribute` | String | LDAP attribute for username matching | `uid`, `sAMAccountName` |

##### Authentication Parameters

**Basic Authentication:**

```bash
--set auth-type:basic \
--set username:"service-account@company.com" \
--set password:"SecurePassword123"
```

**OAuth Bearer Token:**

```bash
--set auth-type:bearer \
--set bearer-token:"eyJhbGciOiJSUzI1NiIs..."
```

##### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `update-method` | String | `patch` | HTTP method: `patch` (recommended) or `put` |
| `disable-group-membership-lookups` | Boolean | `false` | Skip membership checks (performance optimization) |
| `max-retries` | Integer | `3` | Maximum retry attempts for failed operations |
| `retry-delay-ms` | Integer | `1000` | Initial retry delay (exponential backoff) |
| `connect-timeout-ms` | Integer | `30000` | HTTP connection timeout (30 seconds) |
| `read-timeout-ms` | Integer | `60000` | HTTP read timeout (60 seconds) |

##### SSL/TLS Parameters

```bash
# Custom truststore
--set trust-store-path:/path/to/truststore.jks \
--set trust-store-password:changeit \
--set trust-store-type:JKS

# Or allow untrusted (DEV/TEST ONLY - NOT PRODUCTION)
--set allow-untrusted-certificates:true
```

##### HTTP Proxy Parameters

```bash
--set proxy-host:proxy.company.com \
--set proxy-port:8080 \
--set proxy-username:proxyuser \
--set proxy-password:proxypass \
--set proxy-type:http
```

### Source Plugin Configuration

#### LDAPSyncSourcePluginScim2GroupMembers

This plugin is **only required for group resync operations** with dynamic groups.

##### Required Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `user-id-attribute` | String | LDAP attribute on users for unique ID | `uid`, `employeeNumber` |

##### Configuration Example

```bash
dsconfig create-ldap-sync-source-plugin \
  --plugin-name "SCIM2GroupMemberSourcePlugin" \
  --type ldap-sync-source-plugin-scim2-group-members \
  --set enabled:true \
  --set user-id-attribute:uid \
  --pipe-name "YourSyncPipe"
```

## Operating Modes

### Mode 1: User Membership Sync (Incremental)

**Use Case**: Real-time synchronization of user group membership changes.

**Configuration**:
- Sync Mode: **Standard** (recommended)
- Source Plugin: Not required
- Destination Plugin: Scim2GroupMemberDestination

**Example Sync Pipe Configuration**:

```bash
dsconfig create-sync-pipe \
  --pipe-name "UserGroupMembershipSync" \
  --set sync-mode:standard \
  --set started:true \
  --set source-base-dn:"ou=users,dc=example,dc=com" \
  --set destination-base-dn:"ou=users,dc=example,dc=com" \
  --set sync-class:"inetOrgPerson" \
  --set included-ldap-attribute:memberOf
```

**Behavior**:
1. Monitors changes to `memberOf` (or configured attribute) on user entries
2. Maps LDAP user to SCIM2 user by username
3. Fetches current SCIM2 group memberships
4. Compares source vs destination
5. Updates SCIM2 groups with PATCH/PUT operations

### Mode 2: Group Resync (Full)

**Use Case**: Full synchronization of dynamic group memberships.

**Configuration**:
- Sync Mode: **Standard** with `--useExistingEntry` on resync
- Source Plugin: **LDAPSyncSourcePluginScim2GroupMembers** (required)
- Destination Plugin: Scim2GroupMemberDestination

**Prerequisites**:
- Groups must exist in SCIM2 destination with matching `displayName`
- Dynamic groups must have `memberURL` attribute in LDAP

**Resync Command**:

```bash
# Full resync with existing entry lookup
realtime-sync resync \
  --pipe-name "UserGroupMembershipSync" \
  --useExistingEntry \
  --source-base-dn "ou=groups,dc=example,dc=com" \
  --filter "(objectClass=groupOfURLs)"
```

**Behavior**:
1. Source plugin expands `memberURL` into `members` attribute
2. Destination plugin maps LDAP group to SCIM2 group
3. Searches SCIM2 for each member user ID
4. Replaces entire SCIM2 group membership with PUT

## Usage Examples

### Example 1: Okta Integration

```bash
dsconfig set-sync-destination-prop \
  --pipe-name "OktaGroupSync" \
  --set base-url:"https://dev-123456.okta.com/api/v1/scim/v2" \
  --set user-base-path:"/Users" \
  --set group-base-path:"/Groups" \
  --set auth-type:bearer \
  --set bearer-token:"00abc123def456..." \
  --set group-membership-attributes:memberOf \
  --set username-lookup-attribute:uid \
  --set update-method:patch \
  --set max-retries:5
```

### Example 2: Azure AD Integration

```bash
dsconfig set-sync-destination-prop \
  --pipe-name "AzureADGroupSync" \
  --set base-url:"https://graph.microsoft.com/beta/scim" \
  --set user-base-path:"/Users" \
  --set group-base-path:"/Groups" \
  --set auth-type:bearer \
  --set bearer-token:"eyJ0eXAiOiJKV1QiLCJh..." \
  --set group-membership-attributes:memberOf \
  --set username-lookup-attribute:userPrincipalName \
  --set update-method:patch
```

### Example 3: Dynamic Group Resync

**LDAP Dynamic Group**:
```ldif
dn: cn=developers,ou=groups,dc=example,dc=com
objectClass: groupOfURLs
cn: developers
memberURL: ldap:///ou=users,dc=example,dc=com??sub?(department=engineering)
```

**Resync Command**:
```bash
realtime-sync resync \
  --pipe-name "GroupResyncPipe" \
  --useExistingEntry \
  --source-base-dn "cn=developers,ou=groups,dc=example,dc=com" \
  --filter "(objectClass=groupOfURLs)"
```

**Result**: All engineering department users added to SCIM2 "developers" group.

## Troubleshooting

### Common Issues

#### Issue 1: "No SCIM2 user found for username: jdoe"

**Cause**: Username attribute mismatch between LDAP and SCIM2.

**Solution**:
- Verify `username-lookup-attribute` matches LDAP attribute
- Verify SCIM2 `userName` field matches LDAP value
- Check case sensitivity

#### Issue 2: "Group does not exist in SCIM2"

**Cause**: Group hasn't been created in SCIM2 destination.

**Solution**:
- Create group in SCIM2 with exact `displayName` matching LDAP `cn`
- Verify case-sensitive match
- Use `--useExistingEntry` flag during resync

#### Issue 3: "PATCH request failed with status: 400"

**Cause**: SCIM2 endpoint doesn't support PATCH or has strict validation.

**Solution**:
- Switch to PUT method: `--set update-method:put`
- Check SCIM2 endpoint documentation for supported operations
- Review error response body in logs

#### Issue 4: Performance Degradation with Large Groups

**Cause**: Frequent group membership lookup queries.

**Solution**:
- Enable performance optimization: `--set disable-group-membership-lookups:true`
- This skips membership checks and always attempts operations
- Suitable when SCIM2 endpoint handles duplicate operations gracefully

### Debug Logging

Enable comprehensive debug logging:

```bash
# Enable debug mode in Ping Data Sync
bin/dsconfig set-log-publisher-prop \
  --publisher-name "File-Based Debug Logger" \
  --set enabled:true

# Set log level
bin/dsconfig set-log-publisher-prop \
  --publisher-name "File-Based Debug Logger" \
  --set default-debug-level:verbose
```

View logs:
```bash
tail -f logs/debug
```

### Validation Script

Use the included validation script:

```bash
./verify_config.sh
```

## Performance Optimization

### Best Practices

1. **Use PATCH Method** (default)
   - More efficient than PUT
   - RFC 7644 compliant
   - Reduces network traffic

2. **Enable Membership Lookup Optimization**
   - For SCIM2 endpoints with large groups
   - When duplicate operation handling is acceptable
   - Configuration: `--set disable-group-membership-lookups:true`

3. **Adjust Retry Settings**
   - Increase `max-retries` for unreliable networks
   - Adjust `retry-delay-ms` based on endpoint rate limits
   - Use exponential backoff (automatic)

4. **Configure Timeouts Appropriately**
   - Increase `read-timeout-ms` for slow endpoints
   - Balance between responsiveness and reliability

5. **Use Standard Sync Mode**
   - More accurate than notification mode
   - Fetches current state for comparison
   - Reduces unnecessary operations

### Performance Metrics

Expected throughput (varies by environment):

- **User Membership Updates**: 50-200 operations/second
- **Group Resync**: Depends on group size and member count
  - Small groups (<100 members): 1-5 seconds
  - Large groups (>1000 members): 10-60 seconds

## Security Considerations

### Production Deployment

1. **Never Use `allow-untrusted-certificates:true` in Production**
   - Only for development/testing
   - Use proper SSL/TLS with valid certificates
   - Configure custom truststore if needed

2. **Secure Credential Storage**
   - Use Ping Data Sync's password encryption
   - Rotate credentials regularly
   - Use service accounts with minimal privileges

3. **OAuth Token Management**
   - Use short-lived tokens when possible
   - Implement token refresh mechanism externally if needed
   - Monitor token expiration

4. **Network Security**
   - Use HTTPS for all SCIM2 communications
   - Configure firewall rules to restrict access
   - Use VPN or private networks when possible

5. **Audit Logging**
   - Enable comprehensive logging
   - Monitor for failed authentication attempts
   - Review logs regularly for anomalies

### SCIM2 Endpoint Permissions

Required permissions on SCIM2 service account:

- **Users**: Read access to search and retrieve user information
- **Groups**: Read and Write access to modify group memberships
- Typically: `User.Read.All` + `Group.ReadWrite.All` or equivalent

## Additional Documentation

- [Configuration Enhancement Guide](CONFIGURATION_ENHANCEMENT.md)
- [Group Resync Implementation Details](GROUP_RESYNC_IMPLEMENTATION.md)
- [Resync Troubleshooting Guide](RESYNC_TROUBLESHOOTING.md)
- [SCIM2 Sync Technical Details](README_SCIM2_SYNC.md)

## Support

### Commercial Support

This plugin is provided as-is without official support. For enterprise support options, contact:

- **Ping Identity**: https://www.pingidentity.com/support
- **Professional Services**: Available for custom implementations

### Community Support

- **GitHub Issues**: https://github.com/Jeremy-Heer/datasync-scim2-members/issues
- **Ping Identity Community**: https://support.pingidentity.com/s/

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with comprehensive tests
4. Follow existing code style and documentation standards

## License

This project is licensed under the Common Development and Distribution License (CDDL) Version 1.0.

See [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built on Ping Identity's UnboundID Server SDK and SCIM2 SDK
- Implements RFC 7644 (SCIM 2.0 Protocol) and RFC 7643 (SCIM 2.0 Core Schema)
- Portions Copyright 2010-2025 Ping Identity Corporation

---

**Version**: 1.18  
**Last Updated**: January 2025  
**Status**: ✅ Production Ready

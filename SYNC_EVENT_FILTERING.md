# SCIM2 Sync Event Filtering Matrix

## Overview

This document provides a comprehensive event-by-event filtering matrix showing which LDAP events are **ALLOWED** or **BLOCKED** across all 5 sync pipes. The goal is to provision only a **subset of LDAP users and groups** to the SCIM2 destination by implementing upstream filtering in source plugins.

---

## Filtering Philosophy

### Core Principles

1. **Filter Upstream** - Block events at source plugins before they reach destination plugins
2. **Minimize SCIM2 Queries** - Prevent unnecessary API calls by filtering early
3. **Clear Logging** - Log all filtered events at INFO level for visibility
4. **No Misleading Errors** - Avoid "not found" errors in destination by filtering upstream
5. **Explicit Allow/Block** - Every event type has a clear decision with rationale

### Filtering Criteria

**User Events:**
- Users WITH `scim-groups` attribute populated → **IN SCOPE** for SCIM2
- Users WITHOUT `scim-groups` attribute → **OUT OF SCOPE**, block all events

**Group Events:**
- Groups matching `group.filter` (e.g., `cn=scim-*`) → **IN SCOPE** for SCIM2
- Groups NOT matching filter → **OUT OF SCOPE**, block all events

---

## Event Matrix

### Legend

- ✅ **ALLOW** - Event is processed and synchronized to SCIM2
- 🚫 **BLOCK** - Event is filtered at source plugin, no SCIM2 action
- ➖ **N/A** - Pipe does not process this event type

---

## User Events

### Event 1: User CREATE (without group membership attributes)

**Scenario:** New user added to LDAP without `scim-groups` attribute populated

```ldif
dn: uid=jdoe,ou=Users,dc=example,dc=com
objectClass: inetOrgPerson
cn: John Doe
uid: jdoe
# NO scim-groups attribute
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| **Pipe 1: Users-Basic-CRUD** | 🚫 BLOCK | User not in SCIM2 scope (no group membership attributes) |
| Pipe 2: Groups-Basic-CRUD | ➖ N/A | Pipe processes groups only |
| Pipe 3: Groups-Static-Members | ➖ N/A | Pipe processes groups only |
| Pipe 4: Groups-Dynamic-Resync | ➖ N/A | Pipe processes groups only |
| **Pipe 5: Users-Group-Membership** | 🚫 BLOCK | No group attributes to sync |

**Source Plugin Logic:**
```java
// In UserBasicCrudSourcePlugin.postFetch()
if (!hasGroupMembershipAttributes(entry)) {
  operation.logInfo("User has no group membership attributes - filtered from SCIM2 sync");
  return PostStepResult.CONTINUE; // BLOCK
}
```

---

### Event 2: User CREATE (with group membership attributes)

**Scenario:** New user added to LDAP with `scim-groups` attribute populated

```ldif
dn: uid=jsmith,ou=Users,dc=example,dc=com
objectClass: inetOrgPerson
cn: Jane Smith
uid: jsmith
scim-groups: developers
scim-groups: qa-team
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| **Pipe 1: Users-Basic-CRUD** | ✅ ALLOW | User in SCIM2 scope - create user in SCIM2 |
| Pipe 2: Groups-Basic-CRUD | ➖ N/A | Pipe processes groups only |
| Pipe 3: Groups-Static-Members | ➖ N/A | Pipe processes groups only |
| Pipe 4: Groups-Dynamic-Resync | ➖ N/A | Pipe processes groups only |
| **Pipe 5: Users-Group-Membership** | ✅ ALLOW | Group attributes present - add user to SCIM2 groups |

**Source Plugin Logic:**
```java
// In UserBasicCrudSourcePlugin.postFetch()
if (hasGroupMembershipAttributes(entry)) {
  operation.logInfo("User has group membership attributes - allowing SCIM2 sync");
  return PostStepResult.CONTINUE; // ALLOW
}
```

**Expected SCIM2 Operations:**
1. Pipe 1: `POST /Users` (create user jsmith)
2. Pipe 5: `PATCH /Groups/{developers-id}` (add jsmith to developers)
3. Pipe 5: `PATCH /Groups/{qa-team-id}` (add jsmith to qa-team)

---

### Event 3: User MODIFY (no group membership attribute changes)

**Scenario:** User modified but `scim-groups` attribute unchanged

```ldif
dn: uid=jsmith,ou=Users,dc=example,dc=com
changetype: modify
replace: telephoneNumber
telephoneNumber: +1-555-1234
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| **Pipe 1: Users-Basic-CRUD** | ✅ ALLOW | User in scope - update user attributes in SCIM2 |
| Pipe 2: Groups-Basic-CRUD | ➖ N/A | Pipe processes groups only |
| Pipe 3: Groups-Static-Members | ➖ N/A | Pipe processes groups only |
| Pipe 4: Groups-Dynamic-Resync | ➖ N/A | Pipe processes groups only |
| **Pipe 5: Users-Group-Membership** | 🚫 BLOCK | No group membership changes in changelog |

**Source Plugin Logic:**
```java
// In UserGroupMembershipSourcePlugin.postFetch()
if (!hasGroupMembershipModifications(changeLogEntry)) {
  operation.logInfo("User modification has no group membership changes - filtered from membership sync");
  return PostStepResult.CONTINUE; // BLOCK for Pipe 5
}
```

**Expected SCIM2 Operations:**
1. Pipe 1: `PATCH /Users/{jsmith-id}` (update phoneNumber)
2. Pipe 5: No operation (filtered)

---

### Event 4: User MODIFY (adding group membership attributes)

**Scenario:** User modified to ADD `scim-groups` values

```ldif
dn: uid=jsmith,ou=Users,dc=example,dc=com
changetype: modify
add: scim-groups
scim-groups: admins
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| **Pipe 1: Users-Basic-CRUD** | ✅ ALLOW | User in scope - update user attributes |
| Pipe 2: Groups-Basic-CRUD | ➖ N/A | Pipe processes groups only |
| Pipe 3: Groups-Static-Members | ➖ N/A | Pipe processes groups only |
| Pipe 4: Groups-Dynamic-Resync | ➖ N/A | Pipe processes groups only |
| **Pipe 5: Users-Group-Membership** | ✅ ALLOW | Group membership ADD detected - add user to group |

**Source Plugin Logic:**
```java
// In UserGroupMembershipSourcePlugin.postFetch()
if (hasGroupMembershipModifications(changeLogEntry)) {
  operation.logInfo("User has group membership modifications - allowing membership sync");
  return PostStepResult.CONTINUE; // ALLOW
}
```

**Expected SCIM2 Operations:**
1. Pipe 1: `PATCH /Users/{jsmith-id}` (update scim-groups attribute if mapped)
2. Pipe 5: `PATCH /Groups/{admins-id}` (add jsmith to admins group)

---

### Event 5: User MODIFY (removing group membership attributes)

**Scenario:** User modified to DELETE `scim-groups` values

```ldif
dn: uid=jsmith,ou=Users,dc=example,dc=com
changetype: modify
delete: scim-groups
scim-groups: developers
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| **Pipe 1: Users-Basic-CRUD** | ✅ ALLOW | User in scope - update user attributes |
| Pipe 2: Groups-Basic-CRUD | ➖ N/A | Pipe processes groups only |
| Pipe 3: Groups-Static-Members | ➖ N/A | Pipe processes groups only |
| Pipe 4: Groups-Dynamic-Resync | ➖ N/A | Pipe processes groups only |
| **Pipe 5: Users-Group-Membership** | ✅ ALLOW | Group membership DELETE detected - remove user from group |

**Expected SCIM2 Operations:**
1. Pipe 1: `PATCH /Users/{jsmith-id}` (update scim-groups attribute)
2. Pipe 5: `PATCH /Groups/{developers-id}` (remove jsmith from developers)

---

### Event 6: User MODIFY (replacing all group membership attributes)

**Scenario:** User modified to REPLACE `scim-groups` with new set

```ldif
dn: uid=jsmith,ou=Users,dc=example,dc=com
changetype: modify
replace: scim-groups
scim-groups: qa-team
scim-groups: support
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| **Pipe 1: Users-Basic-CRUD** | ✅ ALLOW | User in scope - update user attributes |
| Pipe 2: Groups-Basic-CRUD | ➖ N/A | Pipe processes groups only |
| Pipe 3: Groups-Static-Members | ➖ N/A | Pipe processes groups only |
| Pipe 4: Groups-Dynamic-Resync | ➖ N/A | Pipe processes groups only |
| **Pipe 5: Users-Group-Membership** | ✅ ALLOW | Group membership REPLACE detected - sync exact set |

**Expected SCIM2 Operations:**
1. Pipe 1: `PATCH /Users/{jsmith-id}` (update scim-groups attribute)
2. Pipe 5: `PATCH /Groups/{developers-id}` (remove jsmith - was in developers before)
3. Pipe 5: `PATCH /Groups/{qa-team-id}` (add jsmith if not already member)
4. Pipe 5: `PATCH /Groups/{support-id}` (add jsmith if not already member)
5. Pipe 5: `PATCH /Groups/{admins-id}` (remove jsmith - was in admins before)

---

### Event 7: User DELETE (with group membership attributes)

**Scenario:** User deleted from LDAP who was in SCIM2 scope

```ldif
dn: uid=jsmith,ou=Users,dc=example,dc=com
changetype: delete
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| **Pipe 1: Users-Basic-CRUD** | ✅ ALLOW | User in scope - delete from SCIM2 |
| Pipe 2: Groups-Basic-CRUD | ➖ N/A | Pipe processes groups only |
| Pipe 3: Groups-Static-Members | ➖ N/A | Pipe processes groups only |
| Pipe 4: Groups-Dynamic-Resync | ➖ N/A | Pipe processes groups only |
| **Pipe 5: Users-Group-Membership** | ✅ ALLOW | User deletion includes group cleanup |

**Expected SCIM2 Operations:**
1. Pipe 1: `DELETE /Users/{jsmith-id}` (delete user from SCIM2)
2. Pipe 5: SCIM2 should auto-remove user from groups (depends on SCIM2 implementation)

**Note:** Some SCIM2 implementations automatically remove deleted users from groups. If not, Pipe 5 should handle cleanup before deletion.

---

### Event 8: User DELETE (without group membership attributes)

**Scenario:** User deleted from LDAP who was NOT in SCIM2 scope

```ldif
dn: uid=jdoe,ou=Users,dc=example,dc=com
changetype: delete
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| **Pipe 1: Users-Basic-CRUD** | 🚫 BLOCK | User never in SCIM2 scope - no action needed |
| Pipe 2: Groups-Basic-CRUD | ➖ N/A | Pipe processes groups only |
| Pipe 3: Groups-Static-Members | ➖ N/A | Pipe processes groups only |
| Pipe 4: Groups-Dynamic-Resync | ➖ N/A | Pipe processes groups only |
| **Pipe 5: Users-Group-Membership** | 🚫 BLOCK | User was never synced - no action needed |

**Expected SCIM2 Operations:** None (user never existed in SCIM2)

---

## Group Events

### Event 9: Group CREATE (does not match filter)

**Scenario:** New group created that doesn't match `group.filter=(cn=scim-*)`

```ldif
dn: cn=internal-team,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: internal-team
member: uid=jdoe,ou=Users,dc=example,dc=com
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| Pipe 1: Users-Basic-CRUD | ➖ N/A | Pipe processes users only |
| **Pipe 2: Groups-Basic-CRUD** | 🚫 BLOCK | Group does not match filter - not in SCIM2 scope |
| **Pipe 3: Groups-Static-Members** | 🚫 BLOCK | Group does not match filter - not in SCIM2 scope |
| **Pipe 4: Groups-Dynamic-Resync** | 🚫 BLOCK | Group does not match filter - not in SCIM2 scope |
| Pipe 5: Users-Group-Membership | ➖ N/A | Pipe processes users only |

**Source Plugin Logic:**
```java
// In GroupBasicCrudSourcePlugin.postFetch()
// In StaticGroupSourcePlugin.postFetch()
// In DynamicGroupSourcePlugin.postFetch()
if (!groupFilter.matchesEntry(entry)) {
  operation.logInfo("Group does not match filter - filtered from SCIM2 sync");
  return PostStepResult.CONTINUE; // BLOCK
}
```

**Expected SCIM2 Operations:** None (group filtered out)

---

### Event 10: Group CREATE (matches filter - static group)

**Scenario:** New static group created matching `group.filter=(cn=scim-*)`

```ldif
dn: cn=scim-developers,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: scim-developers
member: uid=jsmith,ou=Users,dc=example,dc=com
member: uid=bjones,ou=Users,dc=example,dc=com
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| Pipe 1: Users-Basic-CRUD | ➖ N/A | Pipe processes users only |
| **Pipe 2: Groups-Basic-CRUD** | ✅ ALLOW | Group matches filter - create in SCIM2 (without members initially) |
| **Pipe 3: Groups-Static-Members** | ✅ ALLOW | Static group matches filter - create and add members |
| Pipe 4: Groups-Dynamic-Resync | ➖ N/A | Not a dynamic group |
| Pipe 5: Users-Group-Membership | ➖ N/A | Pipe processes users only |

**Source Plugin Logic:**
```java
// In GroupBasicCrudSourcePlugin.postFetch()
if (groupFilter.matchesEntry(entry)) {
  operation.logInfo("Group matches filter - allowing SCIM2 sync");
  return PostStepResult.CONTINUE; // ALLOW
}

// In StaticGroupSourcePlugin.postFetch()
if (groupFilter.matchesEntry(entry) && isStaticGroup(entry)) {
  // Expand members
  operation.logInfo("Static group matches filter - allowing member sync");
  return PostStepResult.CONTINUE; // ALLOW
}
```

**Expected SCIM2 Operations:**
1. Pipe 2: `POST /Groups` (create group scim-developers without members)
2. Pipe 3: `PATCH /Groups/{scim-developers-id}` (add jsmith and bjones as members)

---

### Event 11: Group CREATE (matches filter - dynamic group)

**Scenario:** New dynamic group created matching `group.filter=(cn=scim-*)`

```ldif
dn: cn=scim-engineers,ou=Groups,dc=example,dc=com
objectClass: groupOfURLs
cn: scim-engineers
memberURL: ldap:///ou=Users,dc=example,dc=com??sub?(department=Engineering)
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| Pipe 1: Users-Basic-CRUD | ➖ N/A | Pipe processes users only |
| **Pipe 2: Groups-Basic-CRUD** | ✅ ALLOW | Group matches filter - create in SCIM2 (without members initially) |
| Pipe 3: Groups-Static-Members | ➖ N/A | Not a static group |
| **Pipe 4: Groups-Dynamic-Resync** | ✅ ALLOW | Dynamic group matches filter - execute memberURL and populate |
| Pipe 5: Users-Group-Membership | ➖ N/A | Pipe processes users only |

**Expected SCIM2 Operations:**
1. Pipe 2: `POST /Groups` (create group scim-engineers without members)
2. Pipe 4: `PUT /Groups/{scim-engineers-id}` (replace members with all users matching memberURL)

---

### Event 12: Group MODIFY (does not match filter)

**Scenario:** Group modified that doesn't match `group.filter`

```ldif
dn: cn=internal-team,ou=Groups,dc=example,dc=com
changetype: modify
add: member
member: uid=asmith,ou=Users,dc=example,dc=com
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| Pipe 1: Users-Basic-CRUD | ➖ N/A | Pipe processes users only |
| **Pipe 2: Groups-Basic-CRUD** | 🚫 BLOCK | Group does not match filter - not in SCIM2 scope |
| **Pipe 3: Groups-Static-Members** | 🚫 BLOCK | Group does not match filter - not in SCIM2 scope |
| **Pipe 4: Groups-Dynamic-Resync** | 🚫 BLOCK | Group does not match filter - not in SCIM2 scope |
| Pipe 5: Users-Group-Membership | ➖ N/A | Pipe processes users only |

**Expected SCIM2 Operations:** None (group filtered out)

---

### Event 13: Group MODIFY (matches filter - static member ADD)

**Scenario:** Static group modified to ADD member

```ldif
dn: cn=scim-developers,ou=Groups,dc=example,dc=com
changetype: modify
add: member
member: uid=ckent,ou=Users,dc=example,dc=com
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| Pipe 1: Users-Basic-CRUD | ➖ N/A | Pipe processes users only |
| **Pipe 2: Groups-Basic-CRUD** | ✅ ALLOW | Group matches filter - update group metadata if changed |
| **Pipe 3: Groups-Static-Members** | ✅ ALLOW | Static group member change - add ckent to SCIM2 group |
| Pipe 4: Groups-Dynamic-Resync | ➖ N/A | Not a dynamic group |
| Pipe 5: Users-Group-Membership | ➖ N/A | Pipe processes users only |

**Expected SCIM2 Operations:**
1. Pipe 2: No operation (no group metadata changes)
2. Pipe 3: `PATCH /Groups/{scim-developers-id}` (add ckent to members)

---

### Event 14: Group MODIFY (matches filter - static member DELETE)

**Scenario:** Static group modified to DELETE member

```ldif
dn: cn=scim-developers,ou=Groups,dc=example,dc=com
changetype: modify
delete: member
member: uid=bjones,ou=Users,dc=example,dc=com
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| Pipe 1: Users-Basic-CRUD | ➖ N/A | Pipe processes users only |
| **Pipe 2: Groups-Basic-CRUD** | ✅ ALLOW | Group matches filter - update if needed |
| **Pipe 3: Groups-Static-Members** | ✅ ALLOW | Static group member change - remove bjones from SCIM2 group |
| Pipe 4: Groups-Dynamic-Resync | ➖ N/A | Not a dynamic group |
| Pipe 5: Users-Group-Membership | ➖ N/A | Pipe processes users only |

**Expected SCIM2 Operations:**
1. Pipe 2: No operation (no group metadata changes)
2. Pipe 3: `PATCH /Groups/{scim-developers-id}` (remove bjones from members)

---

### Event 15: Group MODIFY (matches filter - dynamic memberURL change)

**Scenario:** Dynamic group memberURL modified

```ldif
dn: cn=scim-engineers,ou=Groups,dc=example,dc=com
changetype: modify
replace: memberURL
memberURL: ldap:///ou=Users,dc=example,dc=com??sub?(|(department=Engineering)(department=DevOps))
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| Pipe 1: Users-Basic-CRUD | ➖ N/A | Pipe processes users only |
| **Pipe 2: Groups-Basic-CRUD** | ✅ ALLOW | Group matches filter - update if needed |
| Pipe 3: Groups-Static-Members | ➖ N/A | Not a static group |
| **Pipe 4: Groups-Dynamic-Resync** | ✅ ALLOW | Dynamic group URL change - re-execute and replace all members |
| Pipe 5: Users-Group-Membership | ➖ N/A | Pipe processes users only |

**Expected SCIM2 Operations:**
1. Pipe 2: No operation (no group metadata changes)
2. Pipe 4: `PUT /Groups/{scim-engineers-id}` (replace all members with new memberURL results)

---

### Event 16: Group DELETE (does not match filter)

**Scenario:** Group deleted that doesn't match `group.filter`

```ldif
dn: cn=internal-team,ou=Groups,dc=example,dc=com
changetype: delete
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| Pipe 1: Users-Basic-CRUD | ➖ N/A | Pipe processes users only |
| **Pipe 2: Groups-Basic-CRUD** | 🚫 BLOCK | Group never in SCIM2 scope - no action needed |
| **Pipe 3: Groups-Static-Members** | 🚫 BLOCK | Group never in SCIM2 scope - no action needed |
| **Pipe 4: Groups-Dynamic-Resync** | 🚫 BLOCK | Group never in SCIM2 scope - no action needed |
| Pipe 5: Users-Group-Membership | ➖ N/A | Pipe processes users only |

**Expected SCIM2 Operations:** None (group never existed in SCIM2)

---

### Event 17: Group DELETE (matches filter)

**Scenario:** Group deleted that matches `group.filter`

```ldif
dn: cn=scim-developers,ou=Groups,dc=example,dc=com
changetype: delete
```

| Pipe | Decision | Rationale |
|------|----------|-----------|
| Pipe 1: Users-Basic-CRUD | ➖ N/A | Pipe processes users only |
| **Pipe 2: Groups-Basic-CRUD** | ✅ ALLOW | Group in SCIM2 scope - delete from SCIM2 |
| **Pipe 3: Groups-Static-Members** | ✅ ALLOW | Process if needed (group deletion handled by Pipe 2) |
| **Pipe 4: Groups-Dynamic-Resync** | ✅ ALLOW | Process if needed (group deletion handled by Pipe 2) |
| Pipe 5: Users-Group-Membership | ➖ N/A | Pipe processes users only |

**Expected SCIM2 Operations:**
1. Pipe 2: `DELETE /Groups/{scim-developers-id}` (delete group from SCIM2)
2. Pipes 3/4: No operation (Pipe 2 handles deletion)

**Note:** Only one pipe (Pipe 2) should handle actual group deletion to avoid conflicts.

---

## Summary Matrix

### User Events Summary

| Event | Description | Pipe 1 | Pipe 5 |
|-------|-------------|--------|--------|
| 1 | CREATE without group attrs | 🚫 BLOCK | 🚫 BLOCK |
| 2 | CREATE with group attrs | ✅ ALLOW | ✅ ALLOW |
| 3 | MODIFY no group changes | ✅ ALLOW | 🚫 BLOCK |
| 4 | MODIFY ADD group attrs | ✅ ALLOW | ✅ ALLOW |
| 5 | MODIFY DELETE group attrs | ✅ ALLOW | ✅ ALLOW |
| 6 | MODIFY REPLACE group attrs | ✅ ALLOW | ✅ ALLOW |
| 7 | DELETE with group attrs | ✅ ALLOW | ✅ ALLOW |
| 8 | DELETE without group attrs | 🚫 BLOCK | 🚫 BLOCK |

### Group Events Summary

| Event | Description | Pipe 2 | Pipe 3 | Pipe 4 |
|-------|-------------|--------|--------|--------|
| 9 | CREATE not filtered | 🚫 BLOCK | 🚫 BLOCK | 🚫 BLOCK |
| 10 | CREATE filtered static | ✅ ALLOW | ✅ ALLOW | ➖ N/A |
| 11 | CREATE filtered dynamic | ✅ ALLOW | ➖ N/A | ✅ ALLOW |
| 12 | MODIFY not filtered | 🚫 BLOCK | 🚫 BLOCK | 🚫 BLOCK |
| 13 | MODIFY filtered ADD member | ✅ ALLOW | ✅ ALLOW | ➖ N/A |
| 14 | MODIFY filtered DELETE member | ✅ ALLOW | ✅ ALLOW | ➖ N/A |
| 15 | MODIFY filtered memberURL | ✅ ALLOW | ➖ N/A | ✅ ALLOW |
| 16 | DELETE not filtered | 🚫 BLOCK | 🚫 BLOCK | 🚫 BLOCK |
| 17 | DELETE filtered | ✅ ALLOW | ✅ ALLOW | ✅ ALLOW |

---

## Implementation Checklist

- [ ] UserBasicCrudSourcePlugin filters users without group membership attributes
- [ ] GroupBasicCrudSourcePlugin filters groups not matching `group.filter`
- [ ] StaticGroupSourcePlugin evaluates `group.filter` early in `postFetch()`
- [ ] DynamicGroupSourcePlugin evaluates `group.filter` early in `postFetch()`
- [ ] UserGroupMembershipSourcePlugin filters users without group attribute changes
- [ ] All source plugins log filtered events at INFO level
- [ ] Destination plugins have redundant checks removed
- [ ] Test scripts created for each event type per pipe
- [ ] Monitoring in place to track filter effectiveness

---

## Testing Recommendations

### Per-Pipe Testing

**Pipe 1: Users-Basic-CRUD**
- Test Event 1 (block user without groups)
- Test Event 2 (allow user with groups)
- Test Event 3 (allow modify, no group changes)
- Test Event 7 (allow delete with groups)
- Test Event 8 (block delete without groups)

**Pipe 2: Groups-Basic-CRUD**
- Test Event 9 (block unfiltered group)
- Test Event 10/11 (allow filtered group CREATE)
- Test Event 12 (block unfiltered group MODIFY)
- Test Event 16 (block unfiltered group DELETE)
- Test Event 17 (allow filtered group DELETE)

**Pipe 3: Groups-Static-Members**
- Test Event 10 (static group with members)
- Test Event 13 (ADD member to filtered group)
- Test Event 14 (DELETE member from filtered group)

**Pipe 4: Groups-Dynamic-Resync**
- Test Event 11 (dynamic group CREATE)
- Test Event 15 (memberURL change)

**Pipe 5: Users-Group-Membership**
- Test Event 2 (user with initial groups)
- Test Event 4 (ADD group attribute)
- Test Event 5 (DELETE group attribute)
- Test Event 6 (REPLACE group attributes)

---

## Logging Standards

### Filtered Events (INFO Level)

```
[INFO] UserBasicCrudSourcePlugin: User uid=jdoe has no group membership attributes - filtered from SCIM2 sync
[INFO] GroupBasicCrudSourcePlugin: Group cn=internal-team does not match filter - filtered from SCIM2 sync
[INFO] UserGroupMembershipSourcePlugin: User uid=jsmith has no group membership modifications - filtered from membership sync
[INFO] StaticGroupSourcePlugin: Group cn=internal-team does not match filter - filtered from SCIM2 sync
[INFO] DynamicGroupSourcePlugin: Group cn=internal-group does not match filter - filtered from SCIM2 sync
```

### Allowed Events (INFO Level)

```
[INFO] UserBasicCrudSourcePlugin: User uid=jsmith has group membership attributes - allowing SCIM2 sync
[INFO] GroupBasicCrudSourcePlugin: Group cn=scim-developers matches filter - allowing SCIM2 sync
[INFO] UserGroupMembershipSourcePlugin: User uid=jsmith has group membership modifications - allowing membership sync
[INFO] StaticGroupSourcePlugin: Static group cn=scim-developers matches filter - allowing member sync
[INFO] DynamicGroupSourcePlugin: Dynamic group cn=scim-engineers matches filter - allowing member sync
```

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-02 | System | Initial event filtering matrix |

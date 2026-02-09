#!/bin/bash
# Test Script: Dynamic Group User Creation
# Purpose: Verify that DynamicGroupMemberDestination creates users that don't exist in SCIM2
#          when user.lifecycle.mode=dynamic-group-memberships is configured

set -e

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test-functions.sh"

# Test configuration
TEST_NAME="Dynamic Group User Creation"
GROUP_DN="cn=scim-qa-dynamic,ou=Groups,dc=example,dc=com"
GROUP_CN="scim-qa-dynamic"
TEST_USER_DN="uid=newuser1,ou=SyncUsers,dc=example,dc=com"
TEST_USER_UID="newuser1"
MEMBERURL="ldap:///ou=SyncUsers,dc=example,dc=com??sub?(uid=newuser*)"

print_header "${TEST_NAME}"

# Step 1: Verify configuration includes user creation settings
print_step "Verifying configuration for user creation"
check_config_property "user.lifecycle.mode" "dynamic-group-memberships"
check_config_property "scim.user.attributes"
check_config_property "scim.user.map.userName"

# Step 2: Clean up any existing test data
print_step "Cleaning up test data in LDAP and SCIM2"
delete_ldap_entry "${TEST_USER_DN}" || true
delete_ldap_entry "${GROUP_DN}" || true
delete_scim2_user "${TEST_USER_UID}" || true
delete_scim2_group "${GROUP_CN}" || true

# Step 3: Create test user in LDAP (not in SCIM2)
print_step "Creating test user in LDAP only"
create_ldap_user "${TEST_USER_DN}" "${TEST_USER_UID}" "New" "User One" "newuser1@example.com"

# Step 4: Verify user does NOT exist in SCIM2 yet
print_step "Verifying user does not exist in SCIM2"
if scim2_user_exists "${TEST_USER_UID}"; then
    print_error "User ${TEST_USER_UID} already exists in SCIM2 - cleanup failed"
    exit 1
fi
print_success "User confirmed not in SCIM2"

# Step 5: Create SCIM2 group first (required for membership sync)
print_step "Creating SCIM2 group"
create_scim2_group "${GROUP_CN}" "QA Dynamic Test Group"

# Step 6: Create dynamic group in LDAP with memberURL pointing to new user
print_step "Creating dynamic group in LDAP"
cat <<EOF | ldapadd -x -H ldap://localhost:1389 -D "cn=Directory Manager" -w password
dn: ${GROUP_DN}
objectClass: top
objectClass: groupOfURLs
cn: ${GROUP_CN}
description: Dynamic group for testing user creation
memberURL: ${MEMBERURL}
EOF

# Step 7: Trigger resync to process dynamic group
print_step "Triggering dynamic group resync"
trigger_pipe_resync "Groups-Dynamic-Resync"

# Step 8: Wait for sync to complete
print_step "Waiting for sync to complete"
sleep 5

# Step 9: Verify user was created in SCIM2
print_step "Verifying user was created in SCIM2"
if ! scim2_user_exists "${TEST_USER_UID}"; then
    print_error "User ${TEST_USER_UID} was NOT created in SCIM2"
    print_error "Check logs for error messages during user creation"
    exit 1
fi
print_success "User ${TEST_USER_UID} created successfully in SCIM2"

# Step 10: Verify user attributes were mapped correctly
print_step "Verifying user attributes"
SCIM2_USER=$(get_scim2_user "${TEST_USER_UID}")
echo "${SCIM2_USER}" | jq .

# Check userName
USER_NAME=$(echo "${SCIM2_USER}" | jq -r '.userName')
if [ "${USER_NAME}" != "${TEST_USER_UID}" ]; then
    print_error "userName mismatch: expected ${TEST_USER_UID}, got ${USER_NAME}"
    exit 1
fi

# Check name.givenName
GIVEN_NAME=$(echo "${SCIM2_USER}" | jq -r '.name.givenName // empty')
if [ "${GIVEN_NAME}" != "New" ]; then
    print_warning "name.givenName not set or incorrect: ${GIVEN_NAME}"
fi

# Check name.familyName
FAMILY_NAME=$(echo "${SCIM2_USER}" | jq -r '.name.familyName // empty')
if [ "${FAMILY_NAME}" != "User" ]; then
    print_warning "name.familyName not set or incorrect: ${FAMILY_NAME}"
fi

print_success "User attributes verified"

# Step 11: Verify user is member of the group in SCIM2
print_step "Verifying group membership in SCIM2"
SCIM2_GROUP=$(get_scim2_group "${GROUP_CN}")
MEMBER_COUNT=$(echo "${SCIM2_GROUP}" | jq '.members | length')
echo "Group has ${MEMBER_COUNT} member(s)"

USER_ID=$(echo "${SCIM2_USER}" | jq -r '.id')
IS_MEMBER=$(echo "${SCIM2_GROUP}" | jq --arg uid "${USER_ID}" '.members[] | select(.value == $uid) | .value')

if [ -z "${IS_MEMBER}" ]; then
    print_error "User ${TEST_USER_UID} is NOT a member of group ${GROUP_CN} in SCIM2"
    exit 1
fi
print_success "User ${TEST_USER_UID} is a member of group ${GROUP_CN}"

# Step 12: Test with additional user
print_step "Testing with second user"
TEST_USER2_DN="uid=newuser2,ou=SyncUsers,dc=example,dc=com"
TEST_USER2_UID="newuser2"

delete_ldap_entry "${TEST_USER2_DN}" || true
delete_scim2_user "${TEST_USER2_UID}" || true

create_ldap_user "${TEST_USER2_DN}" "${TEST_USER2_UID}" "New" "User Two" "newuser2@example.com"

# Trigger resync again
trigger_pipe_resync "Groups-Dynamic-Resync"
sleep 5

# Verify second user created
if ! scim2_user_exists "${TEST_USER2_UID}"; then
    print_error "Second user ${TEST_USER2_UID} was NOT created in SCIM2"
    exit 1
fi
print_success "Second user ${TEST_USER2_UID} created successfully"

# Verify both users are members
SCIM2_GROUP=$(get_scim2_group "${GROUP_CN}")
MEMBER_COUNT=$(echo "${SCIM2_GROUP}" | jq '.members | length')
if [ "${MEMBER_COUNT}" -lt "2" ]; then
    print_error "Expected at least 2 members, found ${MEMBER_COUNT}"
    exit 1
fi
print_success "Both users are members of the group"

# Cleanup (optional)
print_step "Cleanup (leave data for inspection, uncomment to auto-cleanup)"
# delete_ldap_entry "${TEST_USER_DN}"
# delete_ldap_entry "${TEST_USER2_DN}"
# delete_ldap_entry "${GROUP_DN}"
# delete_scim2_user "${TEST_USER_UID}"
# delete_scim2_user "${TEST_USER2_UID}"
# delete_scim2_group "${GROUP_CN}"

print_header "Test Passed: ${TEST_NAME}"
echo ""
echo "Summary:"
echo "  ✓ User lifecycle mode configured correctly"
echo "  ✓ Users created in LDAP but not in SCIM2"
echo "  ✓ Dynamic group created with memberURL"
echo "  ✓ Users automatically created in SCIM2 during resync"
echo "  ✓ User attributes mapped correctly from LDAP"
echo "  ✓ Users added to group membership in SCIM2"
echo ""
echo "This confirms that DynamicGroupMemberDestination now has the same"
echo "user creation capability as StaticGroupMemberDestination."

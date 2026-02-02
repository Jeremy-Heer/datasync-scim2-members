#!/bin/bash
#
# Test Event 2: User CREATE with group membership attributes
# Expected: User is ALLOWED and created in SCIM2
#

# Source common utilities
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "${SCRIPT_DIR}/../common/config.sh"
source "${SCRIPT_DIR}/../common/ldap-utils.sh"
source "${SCRIPT_DIR}/../common/scim2-utils.sh"
source "${SCRIPT_DIR}/../common/logger.sh"

# Test configuration
TEST_USER="jsmith-$(date +%s)"
TEST_DN="uid=${TEST_USER},ou=SyncUsers,${LDAP_BASE_DN}"

# Test execution
run_test() {
  log_info "Running: Test User CREATE with group membership attributes"
  
  # Create user with scim-groups attribute
  log_info "Creating user ${TEST_USER} with scim-groups attribute"
  
  cat <<EOF | ldapadd -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_BIND_DN}" -w "${LDAP_BIND_PW}"
dn: ${TEST_DN}
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Jane Smith
sn: Smith
uid: ${TEST_USER}
mail: ${TEST_USER}@example.com
scim-groups: developers
scim-groups: qa-team
EOF
  
  if [ $? -ne 0 ]; then
    log_error "Failed to create user in LDAP"
    return 1
  fi
  
  log_info "User created in LDAP successfully"
  
  # Wait for sync
  log_info "Waiting 10 seconds for sync to process..."
  sleep 10
  
  # Verify user exists in SCIM2
  log_info "Verifying user in SCIM2..."
  scim2_user=$(get_scim2_user "${TEST_USER}")
  
  if [ -z "$scim2_user" ]; then
    log_fail "User ${TEST_USER} NOT found in SCIM2 (should have been created)"
    cleanup
    return 1
  fi
  
  log_pass "User ${TEST_USER} found in SCIM2"
  
  # Verify attributes
  if echo "$scim2_user" | grep -q "\"userName\":\"${TEST_USER}\""; then
    log_pass "User has correct userName attribute"
  else
    log_fail "User missing or incorrect userName attribute"
    cleanup
    return 1
  fi
  
  log_pass "Test completed successfully"
  
  # Cleanup
  cleanup
  return 0
}

# Cleanup function
cleanup() {
  log_info "Cleaning up test data..."
  
  # Delete from LDAP
  ldapdelete -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_BIND_DN}" -w "${LDAP_BIND_PW}" "${TEST_DN}" 2>/dev/null
  
  # Wait for sync to process deletion
  sleep 5
  
  log_info "Cleanup completed"
}

# Run the test
run_test
exit $?

# Configuration for SCIM2 Sync Test Scripts

# LDAP Source Configuration
export LDAP_HOST="${LDAP_HOST:-localhost}"
export LDAP_PORT="${LDAP_PORT:-389}"
export LDAP_BIND_DN="${LDAP_BIND_DN:-cn=admin,dc=example,dc=com}"
export LDAP_BIND_PW="${LDAP_BIND_PW:-changeme}"
export LDAP_BASE_DN="${LDAP_BASE_DN:-dc=example,dc=com}"

# SCIM2 Destination Configuration
export SCIM2_BASE_URL="${SCIM2_BASE_URL:-https://localhost:8443/scim/v2}"
export SCIM2_AUTH_TOKEN="${SCIM2_AUTH_TOKEN:-your-token-here}"
export SCIM2_USER_ENDPOINT="${SCIM2_USER_ENDPOINT:-/Users}"
export SCIM2_GROUP_ENDPOINT="${SCIM2_GROUP_ENDPOINT:-/Groups}"

# Test Configuration
export SYNC_WAIT_TIME="${SYNC_WAIT_TIME:-10}"  # Seconds to wait for sync

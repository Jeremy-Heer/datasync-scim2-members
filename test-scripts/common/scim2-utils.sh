# SCIM2 API utility functions

# Get SCIM2 user by userName
get_scim2_user() {
  local username="$1"
  local url="${SCIM2_BASE_URL}${SCIM2_USER_ENDPOINT}?filter=userName eq \"${username}\""
  
  curl -s -X GET "$url" \
    -H "Authorization: Bearer ${SCIM2_AUTH_TOKEN}" \
    -H "Content-Type: application/scim+json"
}

# Get SCIM2 group by displayName
get_scim2_group() {
  local groupname="$1"
  local url="${SCIM2_BASE_URL}${SCIM2_GROUP_ENDPOINT}?filter=displayName eq \"${groupname}\""
  
  curl -s -X GET "$url" \
    -H "Authorization: Bearer ${SCIM2_AUTH_TOKEN}" \
    -H "Content-Type: application/scim+json"
}

# Check if user is member of group
check_scim2_membership() {
  local groupname="$1"
  local username="$2"
  
  local group=$(get_scim2_group "$groupname")
  echo "$group" | grep -q "\"value\":\"${username}\""
  return $?
}

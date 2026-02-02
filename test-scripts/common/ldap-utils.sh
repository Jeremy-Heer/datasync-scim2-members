# LDAP utility functions

# Add entry using ldapadd
ldap_add() {
  local ldif="$1"
  echo "$ldif" | ldapadd -H ldap://${LDAP_HOST}:${LDAP_PORT} \
    -D "${LDAP_BIND_DN}" -w "${LDAP_BIND_PW}"
}

# Modify entry using ldapmodify
ldap_modify() {
  local ldif="$1"
  echo "$ldif" | ldapmodify -H ldap://${LDAP_HOST}:${LDAP_PORT} \
    -D "${LDAP_BIND_DN}" -w "${LDAP_BIND_PW}"
}

# Delete entry using ldapdelete
ldap_delete() {
  local dn="$1"
  ldapdelete -H ldap://${LDAP_HOST}:${LDAP_PORT} \
    -D "${LDAP_BIND_DN}" -w "${LDAP_BIND_PW}" "$dn"
}

# Search for entry
ldap_search() {
  local base_dn="$1"
  local filter="$2"
  ldapsearch -H ldap://${LDAP_HOST}:${LDAP_PORT} \
    -D "${LDAP_BIND_DN}" -w "${LDAP_BIND_PW}" \
    -b "$base_dn" "$filter"
}

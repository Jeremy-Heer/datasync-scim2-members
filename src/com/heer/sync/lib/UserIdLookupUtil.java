/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at
 * docs/licenses/cddl.txt
 * or http://www.opensource.org/licenses/cddl1.php.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at
 * docs/licenses/cddl.txt.  If applicable,
 * add the following below this CDDL HEADER, with the fields enclosed
 * by brackets "[]" replaced with your own identifying information:
 *      Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 *
 *      Portions Copyright 2010-2025 Ping Identity Corporation
 */
package com.heer.sync.lib;

import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.SearchResultEntry;

/**
 * Utility class for looking up user ID attributes from LDAP entries.
 * Provides optimized lookup logic that first attempts to extract the user ID
 * from the DN's RDN before performing an LDAP lookup. This is a common pattern
 * used when resolving static group membership (member/uniqueMember DNs).
 * 
 * <p>This class is stateless and thread-safe. All methods are static.
 */
public final class UserIdLookupUtil
{
  /**
   * Private constructor to prevent instantiation.
   */
  private UserIdLookupUtil()
  {
    // Utility class
  }
  
  /**
   * Looks up a user by DN and retrieves their user ID attribute value.
   * This is used for static group membership where member/uniqueMember contain DNs.
   * 
   * <p>Optimization: First attempts to extract the user ID from the DN's RDN
   * (e.g., "uid=jdoe,ou=people,dc=example,dc=com" → "jdoe"). If the RDN
   * attribute name doesn't match the requested user ID attribute, performs
   * an LDAP lookup to retrieve the attribute value.
   * 
   * @param sourceConnection The LDAP connection to use for the lookup
   * @param memberDN The DN of the user to look up
   * @param userIdAttribute The attribute name containing the user ID (e.g., "uid")
   * @param operation The sync operation for logging (may be null)
   * @return The user ID value, or null if not found
   */
  public static String lookupUserIdFromDN(final LDAPInterface sourceConnection,
                                          final String memberDN,
                                          final String userIdAttribute,
                                          final SyncOperation operation)
  {
    try
    {
      // Parse the DN to ensure it's valid
      DN dn = new DN(memberDN);
      
      // First, try to extract the user ID from the DN itself (optimization)
      // This handles cases like "uid=jdoe,ou=people,dc=example,dc=com"
      String rdnValue = dn.getRDN().getAttributeValues()[0];
      String rdnAttrName = dn.getRDN().getAttributeNames()[0];
      
      if (rdnAttrName.equalsIgnoreCase(userIdAttribute))
      {
        if (operation != null)
        {
          operation.logInfo("Extracted user ID '" + rdnValue + 
                           "' directly from DN: " + memberDN);
        }
        return rdnValue;
      }
      
      // If not in the RDN, perform an LDAP lookup to get the attribute
      if (operation != null)
      {
        operation.logInfo("Looking up user ID attribute '" + userIdAttribute + 
                         "' for DN: " + memberDN);
      }
      
      SearchResultEntry userEntry = sourceConnection.getEntry(memberDN, userIdAttribute);
      
      if (userEntry == null)
      {
        if (operation != null)
        {
          operation.logInfo("Could not find user entry for DN: " + memberDN);
        }
        return null;
      }
      
      String userId = userEntry.getAttributeValue(userIdAttribute);
      if (userId == null)
      {
        if (operation != null)
        {
          operation.logInfo("User entry " + memberDN + 
                             " does not have attribute: " + userIdAttribute);
        }
        return null;
      }
      
      if (operation != null)
      {
        operation.logInfo("Found user ID '" + userId + "' for DN: " + memberDN);
      }
      return userId;
    }
    catch (LDAPException e)
    {
      if (operation != null)
      {
        operation.logError("Error looking up user ID for DN " + memberDN + ": " + 
                          e.getMessage());
      }
      return null;
    }
  }
}

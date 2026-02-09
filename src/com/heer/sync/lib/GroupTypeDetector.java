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

import com.unboundid.ldap.sdk.Entry;

/**
 * Utility class for detecting LDAP group types based on entry attributes.
 * Centralizes the logic for identifying dynamic groups (memberURL) and
 * static groups (member/uniqueMember) to avoid duplication across plugins.
 * 
 * <p>This class is stateless and thread-safe. All methods are static.
 */
public final class GroupTypeDetector
{
  /**
   * Private constructor to prevent instantiation.
   */
  private GroupTypeDetector()
  {
    // Utility class
  }
  
  /**
   * Checks if an entry is a dynamic group (has memberURL attribute or groupOfURLs objectClass).
   * 
   * @param entry The LDAP entry to check
   * @return true if the entry has groupOfURLs objectClass or at least one memberURL attribute value
   */
  public static boolean isDynamicGroup(final Entry entry)
  {
    if (entry == null)
    {
      return false;
    }
    
    // Check objectClass for groupOfURLs
    if (entry.hasObjectClass("groupOfURLs"))
    {
      return true;
    }
    
    // Fallback: check for memberURL attribute
    String[] memberUrls = entry.getAttributeValues("memberURL");
    return (memberUrls != null && memberUrls.length > 0);
  }
  
  /**
   * Checks if an entry is a static group (has groupOfNames or groupOfUniqueNames objectClass,
   * or has member/uniqueMember attributes).
   * 
   * @param entry The LDAP entry to check
   * @return true if the entry has groupOfNames/groupOfUniqueNames objectClass or
   *         at least one member or uniqueMember attribute value
   */
  public static boolean isStaticGroup(final Entry entry)
  {
    if (entry == null)
    {
      return false;
    }
    
    // Check objectClass for groupOfNames or groupOfUniqueNames
    if (entry.hasObjectClass("groupOfNames") || entry.hasObjectClass("groupOfUniqueNames"))
    {
      return true;
    }
    
    // Fallback: check for member/uniqueMember attributes
    String[] memberDNs = entry.getAttributeValues("member");
    String[] uniqueMemberDNs = entry.getAttributeValues("uniqueMember");
    
    return (memberDNs != null && memberDNs.length > 0) || 
           (uniqueMemberDNs != null && uniqueMemberDNs.length > 0);
  }
  
  /**
   * Checks if an entry is any type of group (dynamic or static).
   * 
   * @param entry The LDAP entry to check
   * @return true if the entry is a dynamic or static group
   */
  public static boolean isGroup(final Entry entry)
  {
    return isDynamicGroup(entry) || isStaticGroup(entry);
  }
  
  /**
   * Gets a human-readable description of the group type.
   * 
   * @param entry The LDAP entry to describe
   * @return "dynamic group", "static group", "dynamic and static group", or "not a group"
   */
  public static String getGroupTypeDescription(final Entry entry)
  {
    boolean isDynamic = isDynamicGroup(entry);
    boolean isStatic = isStaticGroup(entry);
    
    if (isDynamic && isStatic)
    {
      return "dynamic and static group";
    }
    else if (isDynamic)
    {
      return "dynamic group";
    }
    else if (isStatic)
    {
      return "static group";
    }
    else
    {
      return "not a group";
    }
  }
}

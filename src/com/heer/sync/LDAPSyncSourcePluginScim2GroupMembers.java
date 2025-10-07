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
package com.heer.sync;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import com.unboundid.directory.sdk.sync.api.LDAPSyncSourcePlugin;
import com.unboundid.directory.sdk.sync.config.LDAPSyncSourcePluginConfig;
import com.unboundid.directory.sdk.sync.types.PostStepResult;
import com.unboundid.directory.sdk.sync.types.PreStepResult;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;



/**
 * This LDAP sync source plugin handles group resync operations for dynamic LDAP groups,
 * constructing a members attribute containing user IDs for each group member.
 * 
 * <p>For group resync operations, this plugin:
 * <UL>
 *   <LI>Detects dynamic groups (entries with memberURL attribute)</LI>
 *   <LI>Parses the memberURL to determine membership criteria (LDAP URL format)</LI>
 *   <LI>Queries the LDAP server to find all users matching the membership criteria</LI>
 *   <LI>Extracts the uid value from each member user</LI>
 *   <LI>Constructs a multi-valued members attribute containing all member uids</LI>
 *   <LI>Sends the group with the constructed members attribute to the destination</LI>
 * </UL>
 * 
 * <p>The destination plugin (Scim2GroupMemberDestination) will then process the
 * members attribute and update the SCIM2 group membership accordingly.
 * 
 * <p>Configuration arguments:
 * <UL>
 *   <LI>user-id-attribute -- The LDAP attribute on user entries that contains the
 *                            unique user ID (e.g., uid, sAMAccountName). This value
 *                            will be extracted and added to the members attribute.</LI>
 * </UL>
 * 
 * <p>The base DN for user searches is extracted from the memberURL attribute in the
 * dynamic group entry, so no separate search-base-dn configuration is required.
 */
public class LDAPSyncSourcePluginScim2GroupMembers
     extends LDAPSyncSourcePlugin
{

  private static final String ARG_NAME_USER_ID_ATTRIBUTE = "user-id-attribute";

  // The server context for the server in which this extension is running.
  private SyncServerContext serverContext;

  // This lock ensures that the configuration is updated atomically and safely.
  private final ReadWriteLock configLock = new ReentrantReadWriteLock();
  private final Lock configReadLock = configLock.readLock();
  private final Lock configWriteLock = configLock.writeLock();

  // The LDAP attribute on user entries containing the unique user ID (e.g., uid)
  private String userIdAttribute;

  /**
   * Retrieves a human-readable name for this extension.
   *
   * @return  A human-readable name for this extension.
   */
  @Override()
  public String getExtensionName()
  {
    return "SCIM2 Group Member Sync Source Plugin";
  }



  /**
   * Retrieves a human-readable description for this extension.  Each element
   * of the array that is returned will be considered a separate paragraph in
   * generated documentation.
   *
   * @return  A human-readable description for this extension, or {@code null}
   *          or an empty array if no description should be available.
   */
  @Override()
  public String[] getExtensionDescription()
  {
    return new String[]
    {
      "This LDAP sync source plugin handles group resync operations for dynamic LDAP groups. " +
      "It constructs a members attribute containing user IDs for each group member by " +
      "parsing the memberURL attribute, querying matching users, and extracting their uid values.",
      
      "The plugin detects dynamic groups (entries with memberURL attribute), parses the " +
      "LDAP URL to determine membership criteria, and queries the LDAP server to find all " +
      "users matching the criteria. It then extracts the configured user ID attribute value " +
      "from each member and constructs a multi-valued members attribute.",
      
      "This members attribute is then sent to the Scim2GroupMemberDestination plugin, which " +
      "updates the SCIM2 group membership accordingly during resync operations."
    };
  }



  /**
   * Updates the provided argument parser to define any configuration arguments
   * which may be used by this sync pipe plugin.  The argument parser may
   * also be updated to define relationships between arguments (e.g., to specify
   * required, exclusive, or dependent argument sets).
   *
   * @param  parser  The argument parser to be updated with the configuration
   *                 arguments which may be used by this sync pipe plugin.
   *
   * @throws ArgumentException  If a problem is encountered while updating the
   *                            provided argument parser.
   */
  @Override()
  public void defineConfigArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    // Add an argument for the user ID attribute
    Character shortIdentifier = null;
    String    longIdentifier  = ARG_NAME_USER_ID_ATTRIBUTE;
    boolean   required        = true;
    int       maxOccurrences  = 1;
    String    placeholder     = "{attr}";
    String    description     = "The name of the LDAP attribute on user entries " +
         "that contains the unique user ID (e.g., uid, sAMAccountName). This value " +
         "will be extracted from each member user and added to the members attribute " +
         "during group resync operations.";

    StringArgument arg = new StringArgument(shortIdentifier, longIdentifier,
         required, maxOccurrences, placeholder, description);
    arg.setValueRegex(Pattern.compile("^[a-zA-Z][a-zA-Z0-9\\\\-]*$"),
                      "A valid attribute name is required.");
    parser.addArgument(arg);
  }



  /**
   * Initializes this LDAP sync source plugin.  This method will be called
   * before any other methods in the class.
   *
   * @param  serverContext  A handle to the server context for the
   *                        Data Sync Server in which this extension is
   *                        running.  Extensions should typically store this
   *                        in a class member.
   * @param  config         The general configuration for this proxy
   *                        transformation.
   * @param  parser         The argument parser which has been initialized from
   *                        the configuration for this LDAP sync source
   *                        plugin.
   *
   * @throws  LDAPException  If a problem occurs while initializing this ldap
   *                         sync source plugin.
   */
  @Override
  public void initializeLDAPSyncSourcePlugin(
       final SyncServerContext serverContext,
       final LDAPSyncSourcePluginConfig config,
       final ArgumentParser parser)
       throws LDAPException
  {
    this.serverContext = serverContext;
    setConfig(config, parser);
  }



  /**
    * Indicates whether the configuration contained in the provided argument
    * parser represents a valid configuration for this extension.
    *
    * @param  config               The general configuration for this LDAP sync
    *                              source plugin.
    * @param  parser               The argument parser which has been
    *                              initialized with the proposed configuration.
    * @param  unacceptableReasons  A list that can be updated with reasons that
    *                              the proposed configuration is not acceptable.
    *
    * @return  {@code true} if the proposed configuration is acceptable, or
    *          {@code false} if not.
    */
  @Override
  public boolean isConfigurationAcceptable(
       final LDAPSyncSourcePluginConfig config,
       final ArgumentParser parser,
       final List<String> unacceptableReasons)
  {
    // The built-in ArgumentParser validation does all of the validation that
    // we need.
    return true;
  }



  /**
   * Attempts to apply the configuration contained in the provided argument
   * parser.
   *
   * @param  config                The general configuration for this LDAP sync
   *                               source.
   * @param  parser                The argument parser which has been
   *                               initialized with the new configuration.
   * @param  adminActionsRequired  A list that can be updated with information
   *                               about any administrative actions that may be
   *                               required before one or more of the
   *                               configuration changes will be applied.
   * @param  messages              A list that can be updated with information
   *                               about the result of applying the new
   *                               configuration.
   *
   * @return  A result code that provides information about the result of
   *          attempting to apply the configuration change.
   */
  @Override()
  public ResultCode applyConfiguration(
       final LDAPSyncSourcePluginConfig config,
       final ArgumentParser parser,
       final List<String> adminActionsRequired,
       final List<String> messages)
  {
    setConfig(config, parser);
    return ResultCode.SUCCESS;
  }



  /**
   * Sets the configuration for this plugin.  This is a centralized place
   * where the configuration is initialized or updated.
   *
   * @param  config         The general configuration for this LDAP sync
   *                        source plugin.
   * @param  parser         The argument parser which has been initialized from
   *                        the configuration for this LDAP sync source
   *                        plugin.
   */
  private void setConfig(
                   final LDAPSyncSourcePluginConfig config,
                   final ArgumentParser parser)
  {
    configWriteLock.lock();
    try
    {
      this.userIdAttribute = ((StringArgument)parser.getNamedArgument(
            ARG_NAME_USER_ID_ATTRIBUTE)).getValue();
    }
    finally
    {
      configWriteLock.unlock();
    }
  }



  /**
   * Retrieves a map containing examples of configurations that may be used for
   * this extension.  The map key should be a list of sample arguments, and the
   * corresponding value should be a description of the behavior that will be
   * exhibited by the extension when used with that configuration.
   *
   * @return  A map containing examples of configurations that may be used for
   *          this extension.  It may be {@code null} or empty if there should
   *          not be any example argument sets.
   */
  @Override
  public Map<List<String>, String> getExamplesArgumentSets()
  {
    final LinkedHashMap<List<String>,String> exampleMap =
         new LinkedHashMap<List<String>,String>(1);

    exampleMap.put(
         Arrays.asList(
              ARG_NAME_USER_ID_ATTRIBUTE + "=uid"),
         "Expands dynamic group membership for groups with memberURL attributes, " +
         "extracting uid values from matching user entries and constructing a " +
         "members attribute for synchronization to SCIM2 destination. " +
         "The base DN for user searches is extracted from the memberURL in each group.");

    return exampleMap;
  }


  /**
   * {@inheritDoc}
   */
  @Override
  public PreStepResult preFetch(final LDAPInterface sourceConnection,
                                final SearchRequest searchRequest,
                                final List<SearchResultEntry> searchResults,
                                final SyncOperation operation)
    throws LDAPException
  {
    /*
    This example performs a search similarly to PingDataSync. It is possible
    to use preFetch to instead suppress a search based on variable criteria
    such as DN.
     */
    searchResults.addAll(
            sourceConnection.search(searchRequest).getSearchEntries());

    return PreStepResult.SKIP_CURRENT_STEP;
  }


  /**
   * This method is called after fetching a source entry. For group entries with
   * memberURL attributes (dynamic groups), this method expands the membership
   * by parsing the LDAP URL, querying for matching users, and constructing a
   * members attribute containing user IDs.
   *
   * @param  sourceConnection       A connection to the source server.
   * @param  fetchedEntryRef        A reference to the entry that was fetched.
   *                                This entry can be edited in place, or the
   *                                reference can be changed to point to a
   *                                different entry that the plugin constructs.
   * @param  operation              The synchronization operation for this
   *                                change.
   *
   * @return  The result of the plugin processing.
   *
   * @throws  LDAPException  In general subclasses should not catch
   *                         LDAPExceptions that are thrown when
   *                         using the LDAPInterface unless there
   *                         are specific exceptions that are
   *                         expected.  The Data Sync Server
   *                         will handle LDAPExceptions in an
   *                         appropriate way based on the specific
   *                         cause of the exception.  For example,
   *                         some errors will result in the
   *                         SyncOperation being retried, and others
   *                         will trigger fail over to a different
   *                         server.  Plugins should only throw
   *                         LDAPException for errors related to
   *                         communication with the LDAP server.
   *                         Use the return code to indicate other
   *                         types of errors, which might require
   *                         retry.
   */
  @Override
  public PostStepResult postFetch(final LDAPInterface sourceConnection,
                                  final AtomicReference<Entry> fetchedEntryRef,
                                  final SyncOperation operation)
       throws LDAPException
  {
    try
    {
      configReadLock.lock();

      Entry entry = fetchedEntryRef.get();
      if (entry == null)
      {
        return PostStepResult.CONTINUE;
      }

      // Check if this is a dynamic group (has memberURL attribute)
      String[] memberUrls = entry.getAttributeValues("memberURL");
      if (memberUrls == null || memberUrls.length == 0)
      {
        // Not a dynamic group - continue without modification
        serverContext.debugInfo("Entry " + entry.getDN() + " does not have " +
            "memberURL attribute - not a dynamic group");
        return PostStepResult.CONTINUE;
      }

      operation.logInfo("Processing dynamic group: " + entry.getDN() + 
                       " with " + memberUrls.length + " memberURL(s)");

      // Collect all member user IDs
      List<String> memberUserIds = new ArrayList<String>();
      
      for (String memberUrl : memberUrls)
      {
        if (memberUrl == null || memberUrl.trim().isEmpty())
        {
          continue;
        }
        
        operation.logInfo("Parsing memberURL: " + memberUrl);
        
        // Parse the LDAP URL using UnboundID LDAP SDK
        LDAPURL ldapURL = null;
        try
        {
          ldapURL = new LDAPURL(memberUrl);
        }
        catch (LDAPException e)
        {
          operation.logInfo("Could not parse memberURL: " + memberUrl + " - " + e.getMessage());
          continue;
        }
        
        // Extract search parameters from the LDAP URL
        DN baseDN = ldapURL.getBaseDN();
        SearchScope scope = ldapURL.getScope();
        Filter filter = ldapURL.getFilter();
        
        // Use default values if not specified in URL
        if (baseDN == null)
        {
          operation.logInfo("memberURL does not contain a base DN, skipping: " + memberUrl);
          continue;
        }
        
        if (scope == null)
        {
          scope = SearchScope.SUB; // Default to subtree scope
        }
        
        if (filter == null)
        {
          filter = Filter.createPresenceFilter("objectClass"); // Default to (objectClass=*)
        }
        
        // Perform search to find matching users
        try
        {
          SearchRequest searchRequest = new SearchRequest(
              baseDN.toString(),
              scope,
              filter,
              userIdAttribute);
          
          operation.logInfo("Searching for group members with base DN: " + 
                           baseDN + ", scope: " + scope + 
                           ", filter: " + filter);
          
          List<SearchResultEntry> searchResults = 
              sourceConnection.search(searchRequest).getSearchEntries();
          
          operation.logInfo("Found " + searchResults.size() + " matching users");
          
          // Extract user ID from each result
          for (SearchResultEntry userEntry : searchResults)
          {
            String userId = userEntry.getAttributeValue(userIdAttribute);
            if (userId != null && !userId.trim().isEmpty())
            {
              memberUserIds.add(userId);
            }
            else
            {
              operation.logInfo("Warning: User entry " + userEntry.getDN() + 
                               " does not have " + userIdAttribute + " attribute");
            }
          }
        }
        catch (LDAPException e)
        {
          operation.logError("Error searching for group members: " + e.getMessage());
          // Continue processing other memberURLs
        }
      }
      
      // Add the members attribute to the group entry
      if (memberUserIds.isEmpty())
      {
        operation.logInfo("No member user IDs found for group: " + entry.getDN());
        // Add empty members attribute to indicate no members
        entry.setAttribute(new Attribute("members", new String[0]));
      }
      else
      {
        operation.logInfo("Adding " + memberUserIds.size() + 
                         " member user IDs to group: " + entry.getDN());
        entry.setAttribute(new Attribute("members", memberUserIds));
      }

      return PostStepResult.CONTINUE;
    }
    finally
    {
      configReadLock.unlock();
    }
  }




  /**
   * Appends a string representation of this LDAP sync source plugin to
   * the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPSyncSourcePluginScim2GroupMembers(userIdAttribute='");
    buffer.append(userIdAttribute);
    buffer.append("')");
  }
}

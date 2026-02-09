# Group Filter Enhancement

## Overview
Added a new optional configuration parameter `group-filter` to the `LDAPSyncSourcePluginScim2GroupMembers` plugin to limit expensive group member lookups to only specific groups that need to be synchronized.

## Changes Made

### 1. New Configuration Parameter
- **Parameter Name**: `group-filter`
- **Type**: LDAP filter (optional)
- **Purpose**: Determines which dynamic groups should have their membership expanded
- **Default Behavior**: If not specified, all groups with `memberURL` attributes are processed (backward compatible)

### 2. Code Changes

#### Constants Added
```java
private static final String ARG_NAME_GROUP_FILTER = "group-filter";
```

#### Field Added
```java
// Optional LDAP filter to determine which groups should have membership expanded
private Filter groupFilter;
```

#### Configuration Argument Definition
Added new argument in `defineConfigArguments()` method:
- Optional parameter (not required)
- Accepts standard LDAP filter syntax
- Includes comprehensive description with usage examples

#### Configuration Parsing
Updated `setConfig()` method to:
- Parse the group filter string into a Filter object
- Handle parsing errors gracefully
- Store null if filter not specified

#### Runtime Filtering
Updated `postFetch()` method to:
- Check if group matches the configured filter before processing
- Skip member expansion for non-matching groups
- Log at debug level for filtered-out groups
- Continue processing if filter evaluation fails

#### Documentation Updates
- Updated class-level JavaDoc to document the new parameter
- Added configuration example showing filter usage
- Updated `getExamplesArgumentSets()` to include filter example
- Updated `toString()` method to include filter in debug output

## Configuration Examples

### Example 1: Process Only Groups Starting with "scim-"
```properties
user-id-attribute=uid
group-filter=(cn=scim-*)
```

### Example 2: Process Groups with "sync" in Description
```properties
user-id-attribute=uid
group-filter=(description=*sync*)
```

### Example 3: Process Groups in Specific OU
```properties
user-id-attribute=uid
group-filter=(ou=syncGroups)
```

### Example 4: Complex Filter with Multiple Criteria
```properties
user-id-attribute=uid
group-filter=(&(cn=scim-*)(objectClass=groupOfURLs))
```

## Benefits

1. **Performance Improvement**: Significantly reduces load by skipping unnecessary member lookups for groups that don't need SCIM2 synchronization

2. **Flexible Filtering**: Uses standard LDAP filter syntax, allowing for:
   - Simple prefix/suffix matching
   - Complex boolean logic with AND/OR/NOT operators
   - Attribute-based filtering
   - Multi-criteria filtering

3. **Backward Compatible**: Optional parameter ensures existing configurations continue to work without modification

4. **Clear Logging**: Provides visibility into which groups are being processed vs. filtered out

5. **Fail-Safe**: If filter evaluation fails, the plugin continues processing the group to avoid data loss

## Testing Recommendations

1. Test with no filter configured (should process all dynamic groups)
2. Test with simple CN-based filter
3. Test with complex multi-attribute filter
4. Test with invalid filter syntax (should log error and process all groups)
5. Test with filter that matches no groups
6. Test with filter that matches all groups

## Performance Impact

For organizations with many dynamic groups where only a subset need SCIM2 synchronization, this enhancement can provide dramatic performance improvements:

- **Before**: Every dynamic group triggers expensive LDAP searches for all members
- **After**: Only groups matching the filter trigger member lookups
- **Expected Improvement**: Proportional to the ratio of filtered vs. total dynamic groups

Example: If you have 1000 dynamic groups but only 10 need SCIM2 sync, using a filter can reduce member lookup operations by 99%.

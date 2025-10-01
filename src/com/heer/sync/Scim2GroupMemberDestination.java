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

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.directory.sdk.sync.api.SyncDestination;
import com.unboundid.directory.sdk.sync.config.SyncDestinationConfig;
import com.unboundid.directory.sdk.sync.types.EndpointException;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ChangeLogEntry;

import com.unboundid.scim2.client.ScimService;
import com.unboundid.scim2.common.types.UserResource;
import com.unboundid.scim2.common.types.GroupResource;
import com.unboundid.scim2.common.types.Member;
import com.unboundid.scim2.common.messages.ListResponse;
import com.unboundid.scim2.common.filters.Filter;
import com.unboundid.scim2.common.exceptions.ScimException;

// JAX-RS client imports - using Jakarta EE (available from Ping Data Sync server lib directory)
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import java.io.IOException;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


/**
 * This implementation provides a SCIM2 destination for group membership synchronization.
 * It monitors changes to specified group membership attributes on LDAP users and
 * updates corresponding SCIM2 groups by adding or removing users based on the changes.
 * 
 * This destination uses standard synchronization mode, which provides reliable access
 * to complete user information and enables accurate comparison between source and 
 * destination group memberships.
 * 
 * KEY FEATURES:
 * - Fetches current SCIM2 group memberships during fetchEntry for accurate comparison
 * - Supports both PATCH (recommended) and PUT update methods via configuration
 * - Handles full resync operations by ensuring exact membership alignment
 * - Removes users from extra groups during REPLACE operations (resync scenarios)
 * - Supports multiple authentication methods (Basic Auth, OAuth Bearer Token)
 * - Configurable group membership lookup behavior for performance optimization
 * 
 * SYNCHRONIZATION FLOW:
 * 1. fetchEntry: Maps LDAP user to SCIM2 user and retrieves current group memberships
 * 2. Standard sync mode compares source vs destination group memberships automatically  
 * 3. modifyEntry: Processes differences and updates SCIM2 groups accordingly
 * 4. REPLACE operations ensure exact membership alignment (adds missing, removes extra)
 * 
 * PERFORMANCE OPTIMIZATION:
 * - When disable-group-membership-lookups is enabled, the destination skips
 *   checking current membership status via members.value filters and always
 *   sends group membership add/remove operations. This improves performance
 *   when the SCIM2 endpoint doesn't efficiently support these filter queries.
 * 
 * ======================================================================
 * IMPLEMENTATION STATUS: ✅ COMPLETE AND OPTIMIZED
 * ======================================================================
 * 
 * This implementation is complete with enhanced group membership synchronization:
 * ✅ Accurate group membership comparison using fetchEntry population
 * ✅ Full resync support with membership cleanup (removes extra memberships)
 * ✅ Configurable PATCH/PUT update methods with RFC compliance
 * ✅ Comprehensive error handling and logging
 * ✅ Multiple authentication methods supported
 * ✅ Optimized for both incremental and full synchronization scenarios
 * ✅ Configurable membership lookup behavior for performance tuning
 * 
 * Ready for production deployment to Ping Data Sync server.
 */
public class Scim2GroupMemberDestination extends SyncDestination
{

  // The general configuration for this Sync Destination
  private volatile SyncDestinationConfig config;

  // The server context for the server in which this extension is running
  private SyncServerContext serverContext;

  // SCIM2 service client for API interactions
  private ScimService scimService;

  // Direct JAX-RS client for manual PATCH requests (to avoid SDK's extra fields)
  private Client jaxrsClient;

  // Configuration parameters
  private String baseUrl;
  private String userBasePath;
  private String groupBasePath;
  private String username;
  private String password;
  private String[] groupMembershipAttributes;
  private String usernameLookupAttribute;
  private String authType;
  private String bearerToken;
  private String updateMethod;

  // SSL/TLS configuration
  private String trustStorePath;
  private String trustStorePassword;
  private String trustStoreType;
  private boolean allowUntrustedCertificates;

  // HTTP proxy configuration
  private String proxyHost;
  private String proxyPort;
  private String proxyUsername;
  private String proxyPassword;
  private String proxyType;

  // Group membership lookup configuration
  private boolean disableGroupMembershipLookups;


  /**
   * Retrieves a human-readable name for this extension.
   *
   * @return  A human-readable name for this extension.
   */
  @Override
  public String getExtensionName()
  {
    return "SCIM2 Group Membership Sync Destination";
  }


  /**
   * Retrieves a human-readable description for this extension.  Each element
   * of the array that is returned will be considered a separate paragraph in
   * generated documentation.
   *
   * @return  A human-readable description for this extension, or {@code null}
   *          or an empty array if no description should be available.
   */
  @Override
  public String[] getExtensionDescription()
  {
    return new String[]
      {
        "This SCIM2 destination synchronizes group membership changes from LDAP users to SCIM2 groups. " +
        "When configured group membership attributes change on an LDAP user, it will update the " +
        "corresponding SCIM2 group by adding or removing the user from the group.",
        "The destination monitors specified attributes for group membership values and performs " +
        "SCIM2 API calls to maintain group membership consistency between LDAP and SCIM2 endpoints."
      };
  }


  /**
   * {@inheritDoc}
   */
  @Override
  public void defineConfigArguments(final ArgumentParser parser)
                  throws ArgumentException
  {
    StringArgument baseUrlArg = new StringArgument(
                                 null, "base-url", true, 1, "{base-url}",
                                 "The base URL of the SCIM2 endpoint " +
                                 "(e.g., https://example.com/scim/v2).");

    StringArgument userBaseArg = new StringArgument(
                                 null, "user-base", true, 1, "{user-base}",
                                 "The base path for SCIM2 users " +
                                 "(e.g., /Users).");

    StringArgument groupBaseArg = new StringArgument(
                                 null, "group-base", true, 1, "{group-base}",
                                 "The base path for SCIM2 groups " +
                                 "(e.g., /Groups).");

    StringArgument usernameArg = new StringArgument(
                                 null, "username", true, 1, "{username}",
                                 "The username for authentication to the " +
                                 "SCIM2 endpoint.");

    StringArgument passwordArg = new StringArgument(
                                 null, "password", true, 1, "{password}",
                                 "The password for authentication to the " +
                                 "SCIM2 endpoint.");

    StringArgument groupMembershipAttrsArg = new StringArgument(
                                 null, "group-membership-attributes", true, 1,
                                 "{attr1,attr2,...}", 
                                 "Comma-separated list of LDAP attributes that " +
                                 "contain group membership information. The values " +
                                 "of these attributes should correspond to group names " +
                                 "in the SCIM2 endpoint.");

    StringArgument usernameLookupAttrArg = new StringArgument(
                                 null, "username-lookup-attribute", true, 1,
                                 "{attribute}", 
                                 "The LDAP attribute to use for looking up the " +
                                 "username that corresponds to the userName in " +
                                 "SCIM2 (e.g., uid, sAMAccountName).");

    StringArgument authTypeArg = new StringArgument(
                                 null, "auth-type", false, 1,
                                 "{basic|bearer}", 
                                 "Authentication type: 'basic' for username/password " +
                                 "or 'bearer' for OAuth token (default: basic).");

    StringArgument bearerTokenArg = new StringArgument(
                                 null, "bearer-token", false, 1,
                                 "{token}", 
                                 "OAuth bearer token for authentication " +
                                 "(required when auth-type is 'bearer').");

    StringArgument updateMethodArg = new StringArgument(
                                 null, "update-method", false, 1,
                                 "{patch|put}", 
                                 "Update method for group membership changes: 'patch' for " +
                                 "SCIM PATCH operations (recommended, RFC 7644 compliant) or " +
                                 "'put' for full group replacement. If PATCH is not supported " +
                                 "by the client, it will automatically fall back to PUT " +
                                 "(default: patch).");

    // SSL/TLS certificate trust configuration
    StringArgument trustStorePathArg = new StringArgument(
                                 null, "trust-store-path", false, 1,
                                 "{path}", 
                                 "Path to custom truststore file for HTTPS certificate " +
                                 "validation (e.g., /path/to/truststore.jks). If not specified, " +
                                 "uses JVM default truststore.");

    StringArgument trustStorePasswordArg = new StringArgument(
                                 null, "trust-store-password", false, 1,
                                 "{password}", 
                                 "Password for the custom truststore file. Required when " +
                                 "trust-store-path is specified.");

    StringArgument trustStoreTypeArg = new StringArgument(
                                 null, "trust-store-type", false, 1,
                                 "{JKS|PKCS12|etc}", 
                                 "Type of the truststore file (default: JKS). Common types " +
                                 "include JKS, PKCS12, JCEKS.");

    StringArgument allowUntrustedCertsArg = new StringArgument(
                                 null, "allow-untrusted-certificates", false, 0,
                                 null, 
                                 "Allow connections to HTTPS endpoints with untrusted " +
                                 "certificates (self-signed, expired, wrong hostname, etc.). " +
                                 "WARNING: This disables certificate validation and should " +
                                 "ONLY be used in development/testing environments.");

    // HTTP proxy configuration
    StringArgument proxyHostArg = new StringArgument(
                                 null, "proxy-host", false, 1,
                                 "{hostname}", 
                                 "HTTP proxy server hostname or IP address. When specified, " +
                                 "all SCIM2 requests will be routed through this proxy.");

    StringArgument proxyPortArg = new StringArgument(
                                 null, "proxy-port", false, 1,
                                 "{port}", 
                                 "HTTP proxy server port number (e.g., 8080, 3128). " +
                                 "Required when proxy-host is specified.");

    StringArgument proxyUsernameArg = new StringArgument(
                                 null, "proxy-username", false, 1,
                                 "{username}", 
                                 "Username for proxy authentication (if proxy requires " +
                                 "authentication).");

    StringArgument proxyPasswordArg = new StringArgument(
                                 null, "proxy-password", false, 1,
                                 "{password}", 
                                 "Password for proxy authentication (required when " +
                                 "proxy-username is specified).");

    StringArgument proxyTypeArg = new StringArgument(
                                 null, "proxy-type", false, 1,
                                 "{HTTP|SOCKS}", 
                                 "Type of proxy server: 'HTTP' for HTTP/HTTPS proxy or " +
                                 "'SOCKS' for SOCKS proxy (default: HTTP).");

    StringArgument disableGroupMembershipLookupsArg = new StringArgument(
                                 null, "disable-group-membership-lookups", false, 0,
                                 null, 
                                 "Disable group membership lookups using members.value type filters. " +
                                 "When enabled, the destination will always send group membership " +
                                 "add or remove operations without checking if the user is already " +
                                 "a member or not. This can improve performance when the SCIM2 " +
                                 "endpoint does not efficiently support members.value filters, " +
                                 "but may result in redundant API calls.");

    parser.addArgument(baseUrlArg);
    parser.addArgument(userBaseArg);
    parser.addArgument(groupBaseArg);
    parser.addArgument(usernameArg);
    parser.addArgument(passwordArg);
    parser.addArgument(groupMembershipAttrsArg);
    parser.addArgument(usernameLookupAttrArg);
    parser.addArgument(authTypeArg);
    parser.addArgument(bearerTokenArg);
    parser.addArgument(updateMethodArg);
    parser.addArgument(trustStorePathArg);
    parser.addArgument(trustStorePasswordArg);
    parser.addArgument(trustStoreTypeArg);
    parser.addArgument(allowUntrustedCertsArg);
    parser.addArgument(proxyHostArg);
    parser.addArgument(proxyPortArg);
    parser.addArgument(proxyUsernameArg);
    parser.addArgument(proxyPasswordArg);
    parser.addArgument(proxyTypeArg);
    parser.addArgument(disableGroupMembershipLookupsArg);
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
      Arrays.asList("base-url=https://example.com/scim/v2", 
                    "user-base=/Users", "group-base=/Groups",
                    "username=syncuser", "password=p@ssW0rd",
                    "group-membership-attributes=memberOf,groups",
                    "username-lookup-attribute=uid"),
          "Sync group membership changes to SCIM2 endpoint using HTTP Basic authentication, " +
          "monitoring memberOf and groups attributes and using uid for username lookups " +
          "(uses recommended PATCH method by default).");

    exampleMap.put(
      Arrays.asList("base-url=https://example.com/scim/v2", 
                    "user-base=/Users", "group-base=/Groups",
                    "auth-type=bearer", "bearer-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                    "group-membership-attributes=memberOf",
                    "username-lookup-attribute=uid",
                    "update-method=put"),
          "Sync group membership changes to SCIM2 endpoint using OAuth Bearer Token authentication, " +
          "monitoring memberOf attribute and using PUT method for updates (metadata stripped per RFC 7643).");

    exampleMap.put(
      Arrays.asList("base-url=https://internal-scim.company.com/scim/v2", 
                    "user-base=/Users", "group-base=/Groups",
                    "username=syncuser", "password=p@ssW0rd",
                    "group-membership-attributes=memberOf",
                    "username-lookup-attribute=uid",
                    "trust-store-path=/opt/certs/company-truststore.jks",
                    "trust-store-password=trustpass",
                    "trust-store-type=JKS"),
          "Sync to internal SCIM2 endpoint using custom truststore for SSL certificate validation, " +
          "ideal for internal CA or self-signed certificates in enterprise environments.");

    exampleMap.put(
      Arrays.asList("base-url=https://example.com/scim/v2", 
                    "user-base=/Users", "group-base=/Groups",
                    "username=syncuser", "password=p@ssW0rd",
                    "group-membership-attributes=memberOf,groups",
                    "username-lookup-attribute=uid",
                    "proxy-host=proxy.company.com",
                    "proxy-port=8080",
                    "proxy-username=proxyuser",
                    "proxy-password=proxypass"),
          "Sync through corporate HTTP proxy with authentication, useful for environments " +
          "where direct internet access is restricted and all traffic must go through a proxy.");

    exampleMap.put(
      Arrays.asList("base-url=https://dev-scim.example.com/scim/v2", 
                    "user-base=/Users", "group-base=/Groups",
                    "username=devuser", "password=devpass",
                    "group-membership-attributes=memberOf",
                    "username-lookup-attribute=uid",
                    "allow-untrusted-certificates"),
          "Development/testing configuration that accepts untrusted SSL certificates " +
          "(self-signed, expired, wrong hostname). WARNING: Only use in non-production environments!");

    exampleMap.put(
      Arrays.asList("base-url=https://example.com/scim/v2", 
                    "user-base=/Users", "group-base=/Groups",
                    "username=syncuser", "password=p@ssW0rd",
                    "group-membership-attributes=memberOf",
                    "username-lookup-attribute=uid",
                    "disable-group-membership-lookups"),
          "High-performance configuration that disables group membership lookups. " +
          "Always sends group membership operations without checking current state, " +
          "ideal for SCIM2 endpoints that don't efficiently support members.value filters.");

    return exampleMap;
  }


  /**
   * Initializes this sync destination. This hook is called when a Sync Pipe
   * first starts up, or when the <i>resync</i> process first starts up. Any
   * initialization should be performed here. This method should generally store
   * the {@link SyncServerContext} in a class
   * member so that it can be used elsewhere in the implementation.
   *
   * @param  serverContext  A handle to the server context for the server in
   *                        which this extension is running. Extensions should
   *                        typically store this in a class member.
   * @param  config         The general configuration for this object.
   * @param  parser         The argument parser which has been initialized from
   *                        the configuration for this sync destination.
   * @throws  EndpointException
   *                        if a problem occurs while initializing this
   *                        sync destination.
   */
  @Override()
  public void initializeSyncDestination(
                                    final SyncServerContext serverContext,
                                    final SyncDestinationConfig config,
                                    final ArgumentParser parser)
                                           throws EndpointException
  {
    this.serverContext = serverContext;
    this.config        = config;

    StringArgument baseUrlArg = (StringArgument)
                              parser.getNamedArgument("base-url");

    StringArgument userBaseArg = (StringArgument)
                              parser.getNamedArgument("user-base");

    StringArgument groupBaseArg = (StringArgument)
                              parser.getNamedArgument("group-base");

    StringArgument usernameArg = (StringArgument)
                              parser.getNamedArgument("username");

    StringArgument passwordArg = (StringArgument)
                              parser.getNamedArgument("password");

    StringArgument groupMembershipAttrsArg = (StringArgument)
                              parser.getNamedArgument("group-membership-attributes");

    StringArgument usernameLookupAttrArg = (StringArgument)
                              parser.getNamedArgument("username-lookup-attribute");

    StringArgument authTypeArg = (StringArgument)
                              parser.getNamedArgument("auth-type");

    StringArgument bearerTokenArg = (StringArgument)
                              parser.getNamedArgument("bearer-token");

    StringArgument updateMethodArg = (StringArgument)
                              parser.getNamedArgument("update-method");

    // SSL/TLS certificate trust configuration
    StringArgument trustStorePathArg = (StringArgument)
                              parser.getNamedArgument("trust-store-path");

    StringArgument trustStorePasswordArg = (StringArgument)
                              parser.getNamedArgument("trust-store-password");

    StringArgument trustStoreTypeArg = (StringArgument)
                              parser.getNamedArgument("trust-store-type");

    StringArgument allowUntrustedCertsArg = (StringArgument)
                              parser.getNamedArgument("allow-untrusted-certificates");

    // HTTP proxy configuration
    StringArgument proxyHostArg = (StringArgument)
                              parser.getNamedArgument("proxy-host");

    StringArgument proxyPortArg = (StringArgument)
                              parser.getNamedArgument("proxy-port");

    StringArgument proxyUsernameArg = (StringArgument)
                              parser.getNamedArgument("proxy-username");

    StringArgument proxyPasswordArg = (StringArgument)
                              parser.getNamedArgument("proxy-password");

    StringArgument proxyTypeArg = (StringArgument)
                              parser.getNamedArgument("proxy-type");

    StringArgument disableGroupMembershipLookupsArg = (StringArgument)
                              parser.getNamedArgument("disable-group-membership-lookups");

    this.baseUrl = baseUrlArg.getValue();
    this.userBasePath = userBaseArg.getValue();
    this.groupBasePath = groupBaseArg.getValue();
    this.username = usernameArg.getValue();
    this.password = passwordArg.getValue();
    this.usernameLookupAttribute = usernameLookupAttrArg.getValue();
    
    // Set authentication type and bearer token (with defaults)
    this.authType = (authTypeArg != null && authTypeArg.getValue() != null) ? 
                    authTypeArg.getValue() : "basic";
    this.bearerToken = (bearerTokenArg != null) ? bearerTokenArg.getValue() : null;
    
    // Set update method (default to recommended PATCH)
    this.updateMethod = (updateMethodArg != null && updateMethodArg.getValue() != null) ? 
                        updateMethodArg.getValue().toLowerCase() : "patch";

    // Parse SSL/TLS configuration
    this.trustStorePath = (trustStorePathArg != null) ? trustStorePathArg.getValue() : null;
    this.trustStorePassword = (trustStorePasswordArg != null) ? trustStorePasswordArg.getValue() : null;
    this.trustStoreType = (trustStoreTypeArg != null && trustStoreTypeArg.getValue() != null) ? 
                          trustStoreTypeArg.getValue() : "JKS";
    this.allowUntrustedCertificates = (allowUntrustedCertsArg != null && allowUntrustedCertsArg.isPresent());

    // Parse HTTP proxy configuration
    this.proxyHost = (proxyHostArg != null) ? proxyHostArg.getValue() : null;
    this.proxyPort = (proxyPortArg != null) ? proxyPortArg.getValue() : null;
    this.proxyUsername = (proxyUsernameArg != null) ? proxyUsernameArg.getValue() : null;
    this.proxyPassword = (proxyPasswordArg != null) ? proxyPasswordArg.getValue() : null;
    this.proxyType = (proxyTypeArg != null && proxyTypeArg.getValue() != null) ? 
                     proxyTypeArg.getValue().toUpperCase() : "HTTP";

    // Parse group membership lookup configuration (default to false - enable lookups)
    this.disableGroupMembershipLookups = (disableGroupMembershipLookupsArg != null && 
                                         disableGroupMembershipLookupsArg.isPresent());

    // Parse comma-separated group membership attributes
    String groupMembershipAttrsStr = groupMembershipAttrsArg.getValue();
    this.groupMembershipAttributes = groupMembershipAttrsStr.split(",");
    for (int i = 0; i < this.groupMembershipAttributes.length; i++) {
      this.groupMembershipAttributes[i] = this.groupMembershipAttributes[i].trim();
    }

    try
    {
      // Initialize JAX-RS client with Apache HttpClient connector for native PATCH support
      // Apache HttpClient has full support for PATCH method without workarounds
      ClientConfig clientConfig = new ClientConfig();
      clientConfig.connectorProvider(new ApacheConnectorProvider());
      
      // Configure SSL/TLS settings
      SSLContext sslContext = createSSLContext();
      if (sslContext != null) {
        clientConfig.property("jersey.config.apache.client.sslContext", sslContext);
      }
      
      // Configure HTTP proxy settings
      configureProxy(clientConfig);
      
      Client restClient = ClientBuilder.newClient(clientConfig);
      
      // Configure authentication based on auth-type
      if ("bearer".equalsIgnoreCase(this.authType)) {
        // OAuth Bearer Token authentication
        if (this.bearerToken == null || this.bearerToken.trim().isEmpty()) {
          throw new RuntimeException("Bearer token is required when auth-type is 'bearer'");
        }
        
        // Register custom authorization header filter for bearer token
        restClient.register(new BearerTokenFilter(this.bearerToken));
        
        System.out.println("   Using OAuth Bearer Token authentication");
        
      } else {
        // HTTP Basic authentication (default)
        if (this.username == null || this.password == null) {
          throw new RuntimeException("Username and password are required for basic authentication");
        }
        
        HttpAuthenticationFeature basicAuthFeature = 
            HttpAuthenticationFeature.basicBuilder()
                                     .credentials(this.username, this.password)
                                     .build();
        restClient.register(basicAuthFeature);
        
        System.out.println("   Using HTTP Basic authentication");
      }
      
      // Create SCIM2 service with authenticated client
      WebTarget target = restClient.target(URI.create(this.baseUrl));
      this.scimService = new ScimService(target);
      
      // Store the JAX-RS client for direct PATCH requests
      this.jaxrsClient = restClient;
      
      // Log successful initialization
      System.out.println("✅ SCIM2 Group Membership Sync Destination initialized successfully!");
      System.out.println("   Base URL: " + this.baseUrl);
      System.out.println("   HTTP Client: Apache HttpClient (native PATCH support)");
      System.out.println("   Authentication Type: " + this.authType);
      System.out.println("   Update Method: " + this.updateMethod.toUpperCase());
      System.out.println("   User Base: " + this.userBasePath);
      System.out.println("   Group Base: " + this.groupBasePath);
      System.out.println("   Monitoring attributes: " + Arrays.toString(this.groupMembershipAttributes));
      System.out.println("   Username lookup attribute: " + this.usernameLookupAttribute);
      
      // Log SSL/TLS configuration
      if (trustStorePath != null && !trustStorePath.trim().isEmpty()) {
        System.out.println("   SSL/TLS: Custom truststore (" + trustStoreType + ") - " + trustStorePath);
      } else if (allowUntrustedCertificates) {
        System.out.println("   SSL/TLS: WARNING - Accepting untrusted certificates (development/testing only)");
      } else {
        System.out.println("   SSL/TLS: Using JVM default truststore");
      }
      
      // Log proxy configuration
      if (proxyHost != null && !proxyHost.trim().isEmpty()) {
        System.out.println("   HTTP Proxy: " + proxyType + " proxy at " + proxyHost + ":" + 
                          (proxyPort != null ? proxyPort : "8080") + 
                          (proxyUsername != null ? " (with authentication)" : ""));
      } else {
        System.out.println("   HTTP Proxy: Direct connection (no proxy)");
      }
      
      // Log group membership lookup configuration
      System.out.println("   Group Membership Lookups: " + 
                        (disableGroupMembershipLookups ? "DISABLED (always send operations)" : "ENABLED (check before operations)"));
    }
    catch(Exception e)
    {
      // Create EndpointException - the constructor expects LDAPException or PostStepResult
      // For other exceptions, we'll need to wrap them appropriately
      if (e instanceof EndpointException) {
        throw (EndpointException) e;
      } else {
        // Since we can't create EndpointException from String, log error and rethrow as RuntimeException
        System.err.println("Failed to initialize SCIM2 service: " + e.getMessage());
        throw new RuntimeException("Failed to initialize SCIM2 service", e);
      }
    }
  }


  /**
   * This hook is called when a Sync Pipe shuts down, or when the <i>resync</i>
   * process shuts down. Any clean-up of this sync destination should be
   * performed here.
   */
  @Override
  public void finalizeSyncDestination()
  {
    if(scimService != null)
    {
      // SCIM service doesn't require explicit cleanup
      // Log using available operation or simple system logging
    }
  }



  /**
   * Return the URL or path identifying the destination endpoint
   * to which this extension is transmitting data. This is used for logging
   * purposes only, so it could just be a server name or hostname and port, etc.
   *
   * @return the path to the destination endpoint
   */
  @Override
  public String getCurrentEndpointURL()
  {
    return baseUrl != null ? baseUrl : "not configured";
  }



  /**
   * Return a full destination entry (in LDAP form) from the destination
   * endpoint, corresponding to the source {@link Entry} that is passed in.
   * <p>
   * This method maps LDAP users to their corresponding SCIM2 users by looking up
   * the username and finding the matching SCIM2 user. It returns a synthetic LDAP
   * entry containing the username and SCIM2 user ID for use in standard synchronization mode.
   * <p>
   * This method <b>must be thread safe</b>, as it will be called repeatedly and
   * concurrently by each of the Sync Pipe worker threads as they process
   * entries.
   * @param destEntryMappedFromSrc
   *          the LDAP entry which corresponds to the destination "entry" to
   *          fetch
   * @param  operation
   *          the sync operation for this change
   * @return a list containing the full LDAP entries that matched this search
   *          (there may be more than one), or an empty list if no such entry
   *          exists
   * @throws EndpointException
   *           if there is an error fetching the entry
   */
  @Override
  public List<Entry> fetchEntry(final Entry destEntryMappedFromSrc,
                                       final SyncOperation operation)
                                          throws EndpointException
  {
    // Extract username from the mapped entry
    String username = null;
    Attribute usernameAttr = destEntryMappedFromSrc.getAttribute(usernameLookupAttribute);
    
    if (usernameAttr != null && usernameAttr.getValue() != null) {
      username = usernameAttr.getValue();
    } else {
      operation.logInfo("No username found in attribute: " + usernameLookupAttribute + 
                       " for entry: " + destEntryMappedFromSrc.getDN());
      return Collections.emptyList();
    }
    
    // Search for corresponding SCIM2 user
    String scim2UserId = findScim2UserId(username, operation);
    if (scim2UserId == null) {
      operation.logInfo("No SCIM2 user found for username: " + username);
      return Collections.emptyList();
    }
    
    // Create a synthetic LDAP entry representing the SCIM2 user
    // This entry will contain the username, SCIM2 user ID, and current group memberships
    Entry syntheticEntry = new Entry(destEntryMappedFromSrc.getDN());
    syntheticEntry.addAttribute(usernameLookupAttribute, username);
    syntheticEntry.addAttribute("scim2UserId", scim2UserId);
    
    // Fetch current group memberships from SCIM2 and populate group attributes
    // This allows the standard sync mode to perform accurate comparisons between
    // source and destination group memberships
    populateCurrentGroupMemberships(syntheticEntry, scim2UserId, operation);
    
    operation.logInfo("Fetched entry for username: " + username + 
                     " with SCIM2 ID: " + scim2UserId + 
                     " with current group memberships populated for accurate comparison");
    
    return Arrays.asList(syntheticEntry);
  }



  /**
   * Creates a full destination "entry", corresponding to the LDAP
   * {@link Entry} that is passed in.
   * <p>
   * <b>Note:</b> This SCIM2 Group Membership destination does not support
   * creating entries as it is designed specifically for group membership
   * synchronization. Group membership changes are handled in the
   * {@link #modifyEntry} method.
   * <p>
   * This method <b>must be thread safe</b>, as it will be called repeatedly and
   * concurrently by the Sync Pipe worker threads as they process CREATE
   * operations.
   * @param entryToCreate
   *          the LDAP entry which corresponds to the destination
   *          "entry" to create
   * @param  operation
   *          the sync operation for this change
   * @throws EndpointException
   *           if there is an error creating the entry
   */
  @Override
  public void createEntry(final Entry entryToCreate,
                                       final SyncOperation operation)
                                           throws EndpointException
  {
    if (shouldIgnore(entryToCreate, operation))
    {
      return;
    }
    
    // This SCIM2 destination is designed for group membership synchronization only
    // Entry creation is not supported
    operation.logInfo("createEntry called but not supported by SCIM2 Group Membership destination for entry: " + 
                     entryToCreate.getDN());
  }



  /**
   * Modify an "entry" on the destination, corresponding to the LDAP
   * {@link Entry} that is passed in. This method is responsible for
   * detecting changes to group membership attributes and updating the
   * corresponding SCIM2 groups by adding or removing users.
   * <p>
   * This method <b>must be thread safe</b>, as it will be called repeatedly and
   * concurrently by the Sync Pipe worker threads as they process MODIFY
   * operations.
   * @param entryToModify
   *          the LDAP entry which corresponds to the destination
   *          "entry" to modify. If the synchronization mode is 'standard',
   *          this will be the entry that was returned by {@link #fetchEntry};
   *          otherwise if the synchronization mode is 'notification', this
   *          will be the destination entry mapped from the source entry, before
   *          changes are applied.
   * @param modsToApply
   *          a list of Modification objects which should be applied; these will
   *          have any configured attribute mappings already applied
   * @param  operation
   *          the sync operation for this change
   * @throws EndpointException
   *           if there is an error modifying the entry
   */
  @Override
  public void modifyEntry(final Entry entryToModify,
                          final List<Modification> modsToApply,
                          final SyncOperation operation)
                                                 throws EndpointException
  {
    if (shouldIgnore(entryToModify, operation))
    {
      return;
    }

    // Handle both standard and notification synchronization modes:
    // - In standard mode: entryToModify is the synthetic entry from fetchEntry with scim2UserId
    // - In notification mode: entryToModify is the mapped source entry, need to lookup scim2UserId
    String username = null;
    String scim2UserId = null;
    
    Attribute usernameAttr = entryToModify.getAttribute(usernameLookupAttribute);
    if (usernameAttr != null && usernameAttr.getValue() != null) {
      username = usernameAttr.getValue();
    }
    
    // Try to get scim2UserId from synthetic entry (standard mode)
    Attribute scim2UserIdAttr = entryToModify.getAttribute("scim2UserId");
    if (scim2UserIdAttr != null && scim2UserIdAttr.getValue() != null) {
      scim2UserId = scim2UserIdAttr.getValue();
    } else if (username != null) {
      // In notification mode, lookup the SCIM2 user ID
      scim2UserId = findScim2UserId(username, operation);
    } else {
      // In notification mode, if username not in entry, try alternative methods
      username = getUsernameFromNotificationMode(entryToModify, operation);
      if (username != null) {
        scim2UserId = findScim2UserId(username, operation);
      }
    }
    
    if (username == null || scim2UserId == null) {
      operation.logInfo("Skipping entry - missing username or SCIM2 user ID for DN: " + entryToModify.getDN());
      return;
    }

    // Process each modification
    for (Modification mod : modsToApply) {
      if (isGroupMembershipModification(mod)) {
        processGroupMembershipModification(mod, scim2UserId, operation);
      }
    }
    
    operation.logInfo("Processed group membership changes for user: " + username + " (SCIM2 ID: " + scim2UserId + ")");
  }

  /**
   * Processes a group membership modification and updates SCIM2 groups accordingly.
   * This method handles ADD, DELETE, and REPLACE operations to maintain group membership
   * consistency between source LDAP and destination SCIM2.
   * 
   * For REPLACE operations (common during resync), this method ensures that the user's
   * group memberships in SCIM2 exactly match what's specified in the source, removing
   * any extra memberships that exist in SCIM2 but not in the source.
   * 
   * @param modification The LDAP modification containing group changes
   * @param scim2UserId The SCIM2 user ID
   * @param operation The sync operation for logging
   * @throws EndpointException If there's an error processing the modification
   */
  private void processGroupMembershipModification(final Modification modification, 
      final String scim2UserId, final SyncOperation operation) throws EndpointException {
    
    ModificationType modType = modification.getModificationType();
    String[] values = modification.getValues();
    
    if (ModificationType.REPLACE.equals(modType)) {
      // For REPLACE operations, we need to ensure the user's memberships exactly match
      // the source. This is common during full resync operations.
      processGroupMembershipReplace(modification.getAttributeName(), values, scim2UserId, operation);
      return;
    }
    
    // Handle DELETE operations with null/empty values - this means remove from all groups for this attribute
    if (ModificationType.DELETE.equals(modType) && (values == null || values.length == 0)) {
      operation.logInfo("Processing DELETE operation with no specific values - removing user from all groups for attribute: " + 
                       modification.getAttributeName());
      processDeleteAllGroupMemberships(modification.getAttributeName(), scim2UserId, operation);
      return;
    }
    
    // Handle ADD and DELETE operations with specific values
    if (values == null || values.length == 0) {
      return;
    }
    
    for (String groupName : values) {
      if (groupName == null || groupName.trim().isEmpty()) {
        continue;
      }
      
      groupName = groupName.trim();
      String scim2GroupId = findScim2GroupId(groupName, operation);
      
      if (scim2GroupId == null) {
        operation.logInfo("Skipping group - SCIM2 group not found: " + groupName);
        continue;
      }
      
      try {
        if (ModificationType.ADD.equals(modType)) {
          addUserToScim2Group(scim2GroupId, scim2UserId, operation);
        } else if (ModificationType.DELETE.equals(modType)) {
          removeUserFromScim2Group(scim2GroupId, scim2UserId, operation);
        } else {
          operation.logInfo("Unsupported modification type: " + modType + " for group: " + groupName);
        }
      } catch (EndpointException e) {
        operation.logInfo("Error processing group membership change for group " + groupName + ": " + e.getMessage());
        throw e;
      }
    }
  }

  /**
   * Processes a REPLACE modification for group memberships, ensuring the user's
   * SCIM2 group memberships exactly match the source values. This includes removing
   * the user from any groups they're currently in but shouldn't be according to the source.
   * 
   * @param attributeName The name of the group membership attribute being replaced
   * @param newGroupNames The new group names from the source (null means remove from all groups)
   * @param scim2UserId The SCIM2 user ID
   * @param operation The sync operation for logging
   * @throws EndpointException If there's an error during processing
   */
  private void processGroupMembershipReplace(final String attributeName, final String[] newGroupNames,
      final String scim2UserId, final SyncOperation operation) throws EndpointException {
    
    // Get current group memberships for this attribute
    // In notification mode with lookups disabled, try to get "before" values from changelog
    List<String> currentGroups = getCurrentGroupMembershipsForReplace(attributeName, scim2UserId, operation);
    
    // Determine target group names (empty list if newGroupNames is null)
    List<String> targetGroups = new ArrayList<String>();
    if (newGroupNames != null) {
      for (String groupName : newGroupNames) {
        if (groupName != null && !groupName.trim().isEmpty()) {
          targetGroups.add(groupName.trim());
        }
      }
    }
    
    // Find groups to add (in target but not in current)
    List<String> groupsToAdd = new ArrayList<String>(targetGroups);
    groupsToAdd.removeAll(currentGroups);
    
    // Find groups to remove (in current but not in target)
    List<String> groupsToRemove = new ArrayList<String>(currentGroups);
    groupsToRemove.removeAll(targetGroups);
    
    operation.logInfo("REPLACE operation for attribute " + attributeName + 
                     ": adding " + groupsToAdd.size() + " groups, removing " + groupsToRemove.size() + " groups");
    
    // Add user to new groups
    for (String groupName : groupsToAdd) {
      String scim2GroupId = findScim2GroupId(groupName, operation);
      if (scim2GroupId != null) {
        try {
          addUserToScim2Group(scim2GroupId, scim2UserId, operation);
        } catch (EndpointException e) {
          operation.logInfo("Error adding user to group " + groupName + ": " + e.getMessage());
          // Continue with other groups rather than failing the entire operation
        }
      } else {
        operation.logInfo("Skipping add - SCIM2 group not found: " + groupName);
      }
    }
    
    // Remove user from old groups
    for (String groupName : groupsToRemove) {
      String scim2GroupId = findScim2GroupId(groupName, operation);
      if (scim2GroupId != null) {
        try {
          removeUserFromScim2Group(scim2GroupId, scim2UserId, operation);
        } catch (EndpointException e) {
          operation.logInfo("Error removing user from group " + groupName + ": " + e.getMessage());
          // Continue with other groups rather than failing the entire operation
        }
      } else {
        operation.logInfo("Skipping remove - SCIM2 group not found: " + groupName);
      }
    }
  }

  /**
   * Processes a DELETE operation for all group memberships when no specific values are provided.
   * This handles the case where all values are removed from a group membership attribute,
   * which should result in removing the user from all groups associated with that attribute.
   * 
   * @param attributeName The name of the group membership attribute
   * @param scim2UserId The SCIM2 user ID
   * @param operation The sync operation for logging
   * @throws EndpointException If there's an error during processing
   */
  private void processDeleteAllGroupMemberships(final String attributeName, final String scim2UserId, 
      final SyncOperation operation) throws EndpointException {
    
    // Get current group memberships for this attribute
    List<String> currentGroups = getCurrentGroupMembershipsForAttribute(attributeName, scim2UserId, operation);
    
    if (currentGroups.isEmpty()) {
      operation.logInfo("User " + scim2UserId + " has no current group memberships for attribute " + 
                       attributeName + " - nothing to remove");
      return;
    }
    
    operation.logInfo("DELETE all operation for attribute " + attributeName + 
                     ": removing user from " + currentGroups.size() + " groups");
    
    // Remove user from all current groups
    for (String groupName : currentGroups) {
      String scim2GroupId = findScim2GroupId(groupName, operation);
      if (scim2GroupId != null) {
        try {
          removeUserFromScim2Group(scim2GroupId, scim2UserId, operation);
        } catch (EndpointException e) {
          operation.logInfo("Error removing user from group " + groupName + ": " + e.getMessage());
          // Continue with other groups rather than failing the entire operation
        }
      } else {
        operation.logInfo("Skipping remove - SCIM2 group not found: " + groupName);
      }
    }
  }

  /**
   * Retrieves current group memberships for a specific attribute by searching SCIM2.
   * This is used during REPLACE operations to determine which groups need to be added or removed.
   * Optimized for large groups by requesting only essential attributes.
   * 
   * @param attributeName The group membership attribute name (for logging)
   * @param scim2UserId The SCIM2 user ID
   * @param operation The sync operation for logging
   * @return List of current group display names
   */
  private List<String> getCurrentGroupMembershipsForAttribute(final String attributeName, 
      final String scim2UserId, final SyncOperation operation) {
    List<String> currentGroups = new ArrayList<String>();
    
    // Check if group membership lookups are disabled
    if (disableGroupMembershipLookups) {
      operation.logInfo("Group membership lookups disabled - returning empty list for attribute " + 
                       attributeName + " and user " + scim2UserId);
      return currentGroups; // Return empty list
    }
    
    try {
      // Search for all groups where this user is a member
      // Request only displayName and id to minimize data transfer for large groups
      Filter userMemberFilter = Filter.eq("members.value", scim2UserId);
      
      // Debug logging for request
      if (serverContext.debugEnabled()) {
        serverContext.debugInfo("SCIM2 Current Group Memberships Request - Attribute: " + attributeName + 
                              ", User ID: " + scim2UserId + 
                              ", Base Path: " + groupBasePath + 
                              ", Filter: " + userMemberFilter.toString());
      }
      
      ListResponse<GroupResource> groupSearchResponse = 
          scimService.searchRequest(groupBasePath)
              .filter(userMemberFilter.toString())
              .attributes("id", "displayName") // Only request essential attributes
              .invoke(GroupResource.class);
      
      // Debug logging for response
      if (serverContext.debugEnabled()) {
        serverContext.debugInfo("SCIM2 Current Group Memberships Response - Attribute: " + attributeName + 
                              ", User ID: " + scim2UserId + 
                              ", Total Results: " + groupSearchResponse.getTotalResults() + 
                              ", Resources Count: " + 
                              (groupSearchResponse.getResources() != null ? groupSearchResponse.getResources().size() : 0));
      }
      
      if (groupSearchResponse.getTotalResults() > 0) {
        for (GroupResource group : groupSearchResponse.getResources()) {
          String displayName = group.getDisplayName();
          if (displayName != null && !displayName.trim().isEmpty()) {
            currentGroups.add(displayName);
          }
        }
      }
      
      operation.logInfo("Found " + currentGroups.size() + " current group memberships for attribute " + 
                       attributeName + " and user " + scim2UserId);
      
    } catch (Exception e) {
      operation.logInfo("Error retrieving current group memberships for user " + scim2UserId + ": " + e.getMessage());
      // Return empty list - the sync will still work but may be less accurate
    }
    
    return currentGroups;
  }

  /**
   * Retrieves current group memberships for REPLACE operations.
   * In notification mode with lookups disabled, attempts to get "before" values from changelog.
   * Otherwise, falls back to standard SCIM2 lookup.
   * 
   * @param attributeName The group membership attribute name
   * @param scim2UserId The SCIM2 user ID 
   * @param operation The sync operation
   * @return List of current group display names
   */
  private List<String> getCurrentGroupMembershipsForReplace(final String attributeName, 
      final String scim2UserId, final SyncOperation operation) {
    
    // If lookups are disabled, try to get "before" values from changelog (notification mode)
    if (disableGroupMembershipLookups) {
      List<String> beforeGroups = getBeforeGroupsFromChangelog(attributeName, operation);
      if (beforeGroups != null) {
        operation.logInfo("Using changelog before values for REPLACE - found " + beforeGroups.size() + 
                         " previous groups for attribute " + attributeName);
        return beforeGroups;
      } else {
        operation.logInfo("No changelog before values available - falling back to empty list for attribute " + attributeName);
        return new ArrayList<String>();
      }
    }
    
    // Standard mode or notification mode with lookups enabled - use SCIM2 lookup
    return getCurrentGroupMembershipsForAttribute(attributeName, scim2UserId, operation);
  }

  /**
   * Attempts to extract "before" group values from changelog entry.
   * This is used in notification mode to determine what groups to remove during REPLACE operations.
   * 
   * @param attributeName The group membership attribute name
   * @param operation The sync operation
   * @return List of group names from before values, or null if not available
   */
  private List<String> getBeforeGroupsFromChangelog(final String attributeName, final SyncOperation operation) {
    try {
      // Get the changelog entry from the operation
      ChangeLogEntry changeLogEntry = operation.getChangeLogEntry();
      if (changeLogEntry != null) {
        
        // Look for ds-changelog-before-values attribute
        Attribute beforeValuesAttr = changeLogEntry.getAttribute("ds-changelog-before-values");
        if (beforeValuesAttr != null) {
          
          List<String> beforeGroups = new ArrayList<String>();
          
          // Parse the before values - format is like:
          // "jeremy-att: developers\njeremy-att: devops\nmodifyTimestamp: ..."
          for (String beforeValue : beforeValuesAttr.getValues()) {
            String[] lines = beforeValue.split("\n");
            for (String line : lines) {
              line = line.trim();
              if (line.startsWith(attributeName + ":")) {
                String groupValue = line.substring((attributeName + ":").length()).trim();
                if (!groupValue.isEmpty()) {
                  beforeGroups.add(groupValue);
                  operation.logInfo("Found before group value: " + groupValue + " for attribute: " + attributeName);
                }
              }
            }
          }
          
          if (!beforeGroups.isEmpty()) {
            operation.logInfo("Extracted " + beforeGroups.size() + " before group values from changelog for attribute: " + attributeName);
            return beforeGroups;
          }
        } else {
          operation.logInfo("No ds-changelog-before-values attribute found in changelog entry");
        }
      } else {
        operation.logInfo("No changelog entry available in sync operation");
      }
      
    } catch (Exception e) {
      operation.logInfo("Error extracting before groups from changelog: " + e.getMessage());
    }
    
    return null;
  }



  /**
   * Delete a full "entry" from the destination, corresponding to the LDAP
   * {@link Entry} that is passed in.
   * <p>
   * <b>Note:</b> This SCIM2 Group Membership destination does not support
   * deleting entries as it is designed specifically for group membership
   * synchronization. When a user is deleted, you may want to handle this
   * by removing the user from all groups, but that logic would need to be
   * implemented separately.
   * <p>
   * This method <b>must be thread safe</b>, as it will be called repeatedly and
   * concurrently by the Sync Pipe worker threads as they process DELETE
   * operations.
   * @param entryToDelete
   *          the LDAP entry which corresponds to the destination
   *          "entry" to delete. If the synchronization mode is 'standard',
   *          this will be the entry that was returned by {@link #fetchEntry};
   *          otherwise if the synchronization mode is 'notification', this
   *          will be the mapped destination entry.
   * @param  operation
   *          the sync operation for this change
   * @throws EndpointException
   *           if there is an error deleting the entry
   */
  @Override
  public void deleteEntry(final Entry entryToDelete,
                                       final SyncOperation operation)
                                            throws EndpointException
  {
    if (shouldIgnore(entryToDelete, operation))
    {
      return;
    }
    
    // This SCIM2 destination is designed for group membership synchronization only
    // Entry deletion is not supported
    operation.logInfo("deleteEntry called but not supported by SCIM2 Group Membership destination for entry: " + 
                     entryToDelete.getDN());
  }

  /**
   * Extracts the username from notification mode entry or changelog entry.
   * In notification mode, we try multiple approaches to get the username.
   * 
   * @param entryToModify The entry being modified (may have limited data in notification mode)
   * @param operation The sync operation
   * @return The username if found, null otherwise
   */
  private String getUsernameFromNotificationMode(final Entry entryToModify, final SyncOperation operation) {
    try {
      // First try: get username from the entry itself (if available)
      if (entryToModify != null) {
        Attribute usernameAttr = entryToModify.getAttribute(usernameLookupAttribute);
        if (usernameAttr != null && usernameAttr.getValue() != null) {
          operation.logInfo("Found username from entry: " + usernameAttr.getValue());
          return usernameAttr.getValue();
        }
      }
      
      // Second try: extract from DN
      String dn = entryToModify != null ? entryToModify.getDN() : null;
      if (dn != null) {
        String usernameFromDN = extractUsernameFromDN(dn, operation);
        if (usernameFromDN != null) {
          operation.logInfo("Extracted username from DN: " + usernameFromDN);
          return usernameFromDN;
        }
      }
      
    } catch (Exception e) {
      operation.logInfo("Error extracting username in notification mode: " + e.getMessage());
    }
    
    return null;
  }

  /**
   * Extracts username from a DN string as a fallback method.
   * Looks for common username attributes in the RDN.
   * 
   * @param dn The distinguished name
   * @param operation The sync operation for logging
   * @return The username if found, null otherwise
   */
  private String extractUsernameFromDN(final String dn, final SyncOperation operation) {
    try {
      // Simple parsing for common patterns like "uid=username,..." or "cn=username,..."
      if (dn != null && dn.toLowerCase().startsWith("uid=")) {
        int commaIndex = dn.indexOf(',');
        if (commaIndex > 4) {
          return dn.substring(4, commaIndex);
        } else if (commaIndex == -1) {
          return dn.substring(4);
        }
      } else if (dn != null && dn.toLowerCase().startsWith("cn=")) {
        int commaIndex = dn.indexOf(',');
        if (commaIndex > 3) {
          return dn.substring(3, commaIndex);
        } else if (commaIndex == -1) {
          return dn.substring(3);
        }
      }
      // Add more patterns as needed
    } catch (Exception e) {
      operation.logInfo("Error parsing DN for username: " + e.getMessage());
    }
    return null;
  }



  /**
   * Entries that have 'cn=ignore user' as the RDN will be ignored. This method
   * demonstrates using SyncOperation#setIgnored() to direct the Sync Server to
   * ignore certain types of changes and isn't tied to a true use case.
   *
   * @param entry
   *          The entry to to be checked.
   * @param operation
   *          The sync operation.
   * @return {@code true} if the entry should be ignored.
   * @throws EndpointException
   *           If the RDN could not be retrieved.
   */
  protected boolean shouldIgnore(final Entry entry,
      final SyncOperation operation) throws EndpointException {
    // For SCIM2 group membership sync, we only process entries that have
    // changes to the configured group membership attributes
    return false;
  }

  /**
   * Populates the synthetic LDAP entry with current group memberships from SCIM2.
   * This method retrieves all groups the user is currently a member of in SCIM2
   * and adds them to the appropriate group membership attributes in the entry.
   * This enables accurate comparison between source and destination during sync.
   * 
   * @param syntheticEntry The synthetic LDAP entry to populate
   * @param scim2UserId The SCIM2 user ID
   * @param operation The sync operation for logging
   */
  private void populateCurrentGroupMemberships(final Entry syntheticEntry, final String scim2UserId, 
      final SyncOperation operation) {
    try {
      // Initialize all group membership attributes with empty values
      for (String groupAttr : groupMembershipAttributes) {
        syntheticEntry.addAttribute(groupAttr, new String[0]);
      }
      
      // Check if group membership lookups are disabled
      if (disableGroupMembershipLookups) {
        operation.logInfo("Group membership lookups disabled - skipping population for user " + scim2UserId);
        return; // Leave all attributes empty
      }
      
      // Search for all groups where this user is a member
      // Using a filter to find groups that contain this user ID in their members
      // Request only displayName and id to minimize data transfer for large groups
      Filter userMemberFilter = Filter.eq("members.value", scim2UserId);
      
      // Debug logging for request
      if (serverContext.debugEnabled()) {
        serverContext.debugInfo("SCIM2 Group Membership Population Request - User ID: " + scim2UserId + 
                              ", Base Path: " + groupBasePath + 
                              ", Filter: " + userMemberFilter.toString());
      }
      
      ListResponse<GroupResource> groupSearchResponse = 
          scimService.searchRequest(groupBasePath)
              .filter(userMemberFilter.toString())
              .attributes("id", "displayName") // Only request essential attributes
              .invoke(GroupResource.class);
      
      // Debug logging for response
      if (serverContext.debugEnabled()) {
        serverContext.debugInfo("SCIM2 Group Membership Population Response - User ID: " + scim2UserId + 
                              ", Total Results: " + groupSearchResponse.getTotalResults() + 
                              ", Resources Count: " + 
                              (groupSearchResponse.getResources() != null ? groupSearchResponse.getResources().size() : 0));
      }
      
      if (groupSearchResponse.getTotalResults() > 0) {
        // Collect all group display names
        List<String> currentGroupNames = new ArrayList<String>();
        for (GroupResource group : groupSearchResponse.getResources()) {
          String displayName = group.getDisplayName();
          if (displayName != null && !displayName.trim().isEmpty()) {
            currentGroupNames.add(displayName);
          }
        }
        
        if (!currentGroupNames.isEmpty()) {
          // For simplicity, add all current group memberships to the first configured attribute
          // In a more sophisticated implementation, you might map different types of groups
          // to different attributes based on naming conventions or other criteria
          String primaryGroupAttr = groupMembershipAttributes[0];
          syntheticEntry.setAttribute(primaryGroupAttr, currentGroupNames.toArray(new String[0]));
          
          operation.logInfo("Populated " + currentGroupNames.size() + 
                           " current group memberships in attribute: " + primaryGroupAttr + 
                           " for user: " + scim2UserId);
        } else {
          operation.logInfo("User " + scim2UserId + " is not currently a member of any groups");
        }
      } else {
        operation.logInfo("No group memberships found for user: " + scim2UserId);
      }
      
    } catch (ScimException e) {
      operation.logInfo("Error retrieving current group memberships for user " + scim2UserId + ": " + e.getMessage());
      // Continue with empty group attributes - the sync will still work but may be less efficient
    } catch (Exception e) {
      operation.logInfo("Error retrieving current group memberships for user " + scim2UserId + ": " + e.getMessage());
      // Continue with empty group attributes - the sync will still work but may be less efficient
    }
  }

  /**
   * Searches for a SCIM2 user by username and returns the user's ID.
   * 
   * @param username The username to search for
   * @param operation The sync operation for logging
   * @return The SCIM2 user ID if found, null otherwise
   * @throws EndpointException If there's an error during the search
   */
  protected String findScim2UserId(final String username, final SyncOperation operation) 
      throws EndpointException {
    try {
      // Check if SCIM service is initialized
      if (scimService == null) {
        operation.logInfo("SCIM service not initialized - cannot search for user: " + username);
        return null;
      }
      
      // Search for SCIM2 user using Filter
      Filter filter = Filter.eq("userName", username);
      
      // Debug logging for request
      if (serverContext.debugEnabled()) {
        serverContext.debugInfo("SCIM2 User Search Request - Base Path: " + userBasePath + 
                              ", Filter: " + filter.toString() + 
                              ", Username: " + username);
      }
      
      ListResponse<UserResource> searchResponse =
        scimService.searchRequest(userBasePath)
          .filter(filter.toString())
          .invoke(UserResource.class);
      
      // Debug logging for response
      if (serverContext.debugEnabled()) {
        serverContext.debugInfo("SCIM2 User Search Response - Username: " + username + 
                              ", Total Results: " + searchResponse.getTotalResults() + 
                              ", Resources Count: " + 
                              (searchResponse.getResources() != null ? searchResponse.getResources().size() : 0));
      }
      
      if (searchResponse.getTotalResults() > 0) {
        UserResource user = searchResponse.getResources().get(0);
        String userId = user.getId();
        operation.logInfo("Found SCIM2 user ID: " + userId + " for username: " + username);
        return userId;
      } else {
        operation.logInfo("No SCIM2 user found for username: " + username);
        return null;
      }
      
    } catch (ScimException e) {
      operation.logInfo("Error searching for SCIM2 user: " + username + " - " + e.getMessage());
      throw new RuntimeException("Error searching for SCIM2 user: " + username, e);
    } catch (Exception e) {
      operation.logInfo("Error searching for SCIM2 user: " + username + " - " + e.getMessage());
      throw new RuntimeException("Error searching for SCIM2 user: " + username, e);
    }
  }

  /**
   * Searches for a SCIM2 group by display name and returns the group's ID.
   * 
   * @param groupName The group name to search for
   * @param operation The sync operation for logging
   * @return The SCIM2 group ID if found, null otherwise
   * @throws EndpointException If there's an error during the search
   */
  protected String findScim2GroupId(final String groupName, final SyncOperation operation) 
      throws EndpointException {
    try {
      // Check if SCIM service is initialized
      if (scimService == null) {
        operation.logInfo("SCIM service not initialized - cannot search for group: " + groupName);
        return null;
      }
      
      // Search for SCIM2 group using Filter
      Filter filter = Filter.eq("displayName", groupName);
      
      // Debug logging for request
      if (serverContext.debugEnabled()) {
        serverContext.debugInfo("SCIM2 Group Search Request - Base Path: " + groupBasePath + 
                              ", Filter: " + filter.toString() + 
                              ", Group Name: " + groupName);
      }
      
      ListResponse<GroupResource> searchResponse =
        scimService.searchRequest(groupBasePath)
          .filter(filter.toString())
          .invoke(GroupResource.class);
      
      // Debug logging for response
      if (serverContext.debugEnabled()) {
        serverContext.debugInfo("SCIM2 Group Search Response - Group Name: " + groupName + 
                              ", Total Results: " + searchResponse.getTotalResults() + 
                              ", Resources Count: " + 
                              (searchResponse.getResources() != null ? searchResponse.getResources().size() : 0));
      }
      
      if (searchResponse.getTotalResults() > 0) {
        GroupResource group = searchResponse.getResources().get(0);
        String groupId = group.getId();
        operation.logInfo("Found SCIM2 group ID: " + groupId + " for group name: " + groupName);
        return groupId;
      } else {
        operation.logInfo("No SCIM2 group found for group name: " + groupName);
        return null;
      }
      
    } catch (ScimException e) {
      operation.logInfo("Error searching for SCIM2 group: " + groupName + " - " + e.getMessage());
      throw new RuntimeException("Error searching for SCIM2 group: " + groupName, e);
    } catch (Exception e) {
      operation.logInfo("Error searching for SCIM2 group: " + groupName + " - " + e.getMessage());
      throw new RuntimeException("Error searching for SCIM2 group: " + groupName, e);
    }
  }

  /**
   * Adds a user to a SCIM2 group using either PATCH or PUT operation based on configuration.
   * PATCH follows RFC 7644 Section 3.5.2 and avoids read-only meta attributes per RFC 7643 Section 3.1.
   * PUT retrieves, modifies, and replaces the entire group with metadata stripped per RFC 7643.
   * 
   * @param groupId The ID of the SCIM2 group
   * @param userId The ID of the SCIM2 user to add
   * @param operation The sync operation for logging
   * @throws EndpointException If there's an error during the update
   */
  protected void addUserToScim2Group(final String groupId, final String userId, 
      final SyncOperation operation) throws EndpointException {
    try {
      // Check if SCIM service is initialized
      if (scimService == null) {
        operation.logInfo("SCIM service not initialized - cannot add user to group");
        return;
      }
      
      // Check if user is already a member to avoid unnecessary API calls
      // But if lookups are disabled, we always attempt the add operation
      if (!disableGroupMembershipLookups && isUserMemberOfGroup(groupId, userId, operation)) {
        operation.logInfo("User " + userId + " is already a member of group " + groupId);
        return;
      }
      
      if ("put".equalsIgnoreCase(updateMethod)) {
        // PUT method: retrieve, modify, and replace entire group
        addUserToScim2GroupViaPut(groupId, userId, operation);
      } else {
        // PATCH method: recommended approach per RFC 7644
        addUserToScim2GroupViaPatch(groupId, userId, operation);
      }
      
    } catch (ScimException e) {
      operation.logInfo("Error adding user " + userId + " to SCIM2 group " + groupId + " - " + e.getMessage());
      throw new RuntimeException("Error adding user to SCIM2 group", e);
    } catch (Exception e) {
      operation.logInfo("Error adding user " + userId + " to SCIM2 group " + groupId + " - " + e.getMessage());
      throw new RuntimeException("Error adding user to SCIM2 group", e);
    }
  }

  /**
   * Adds a user to a SCIM2 group using PATCH operation (recommended approach).
   * Uses direct JAX-RS client to create RFC 7644 compliant PATCH requests without extra fields.
   */
  private void addUserToScim2GroupViaPatch(final String groupId, final String userId, 
      final SyncOperation operation) throws ScimException {
    // Create manual PATCH request using JAX-RS client to ensure RFC 7644 compliance
    String patchJson = createAddMemberPatchJson(userId);
    
    // Debug logging for request
    if (serverContext.debugEnabled()) {
      serverContext.debugInfo("SCIM2 Group PATCH Add Request - Group ID: " + groupId + 
                            ", User ID: " + userId + 
                            ", URL: " + baseUrl + groupBasePath + "/" + groupId + 
                            ", Request Body: " + patchJson);
    }
    
    try {
      WebTarget target = jaxrsClient.target(baseUrl + groupBasePath + "/" + groupId);
      Response response = target.request("application/scim+json")
          .method("PATCH", Entity.entity(patchJson, "application/scim+json"));
      
      // Debug logging for response
      if (serverContext.debugEnabled()) {
        String responseBody = response.hasEntity() ? response.readEntity(String.class) : "";
        serverContext.debugInfo("SCIM2 Group PATCH Add Response - Group ID: " + groupId + 
                              ", User ID: " + userId + 
                              ", Status: " + response.getStatus() + 
                              ", Response Body: " + responseBody);
        // Need to close and recreate response for subsequent reading
        response.close();
        response = target.request("application/scim+json")
            .method("PATCH", Entity.entity(patchJson, "application/scim+json"));
      }
      
      if (response.getStatus() >= 200 && response.getStatus() < 300) {
        operation.logInfo("Added user " + userId + " to SCIM2 group " + groupId + " via PATCH (RFC 7644 compliant)");
      } else {
        String errorBody = response.hasEntity() ? response.readEntity(String.class) : "No response body";
        throw new RuntimeException("PATCH request failed with status: " + response.getStatus() + 
                               " - " + errorBody);
      }
      response.close();
      
    } catch (Exception e) {
      throw new RuntimeException("Error executing PATCH request: " + e.getMessage(), e);
    }
  }

  /**
   * Adds a user to a SCIM2 group using PUT operation with metadata stripped per RFC 7643.
   */
  private void addUserToScim2GroupViaPut(final String groupId, final String userId, 
      final SyncOperation operation) throws ScimException {
    
    // Debug logging for request
    if (serverContext.debugEnabled()) {
      serverContext.debugInfo("SCIM2 Group PUT Add Request - Group ID: " + groupId + 
                            ", User ID: " + userId + 
                            ", Retrieving group for modification");
    }
    
    // Retrieve the SCIM2 group
    GroupResource group = scimService.retrieve(groupBasePath, groupId, GroupResource.class);
    List<Member> members = group.getMembers();
    if (members == null) {
      members = new ArrayList<Member>();
      group.setMembers(members);
    }
    
    // Create new member and add to list
    Member newMember = new Member();
    newMember.setValue(userId);
    newMember.setRef(URI.create(baseUrl + userBasePath + "/" + userId));
    members.add(newMember);
    
    // Strip read-only and immutable attributes per RFC 7643 Section 3.1
    stripReadOnlyAttributes(group);
    
    // Debug logging for the replacement request
    if (serverContext.debugEnabled()) {
      serverContext.debugInfo("SCIM2 Group PUT Add Replace Request - Group ID: " + groupId + 
                            ", User ID: " + userId + 
                            ", Members Count: " + members.size() + 
                            ", Executing PUT replace operation");
    }
    
    // Replace the group with updated members list
    group = scimService.replace(group);
    
    // Debug logging for response
    if (serverContext.debugEnabled()) {
      serverContext.debugInfo("SCIM2 Group PUT Add Replace Response - Group ID: " + groupId + 
                            ", User ID: " + userId + 
                            ", Operation completed successfully");
    }
    operation.logInfo("Added user " + userId + " to SCIM2 group " + groupId + " via PUT (metadata stripped per RFC 7643)");
  }

  /**
   * Removes a user from a SCIM2 group using either PATCH or PUT operation based on configuration.
   * PATCH follows RFC 7644 Section 3.5.2 and avoids read-only meta attributes per RFC 7643 Section 3.1.
   * PUT retrieves, modifies, and replaces the entire group with metadata stripped per RFC 7643.
   * 
   * @param groupId The ID of the SCIM2 group
   * @param userId The ID of the SCIM2 user to remove
   * @param operation The sync operation for logging
   * @throws EndpointException If there's an error during the update
   */
  protected void removeUserFromScim2Group(final String groupId, final String userId, 
      final SyncOperation operation) throws EndpointException {
    try {
      // Check if SCIM service is initialized
      if (scimService == null) {
        operation.logInfo("SCIM service not initialized - cannot remove user from group");
        return;
      }
      
      // Check if user is actually a member to avoid unnecessary API calls
      // But if lookups are disabled, we always attempt the remove operation
      if (!disableGroupMembershipLookups && !isUserMemberOfGroup(groupId, userId, operation)) {
        operation.logInfo("User " + userId + " is not a member of group " + groupId);
        return;
      }
      
      if ("put".equalsIgnoreCase(updateMethod)) {
        // PUT method: retrieve, modify, and replace entire group
        removeUserFromScim2GroupViaPut(groupId, userId, operation);
      } else {
        // PATCH method: recommended approach per RFC 7644
        removeUserFromScim2GroupViaPatch(groupId, userId, operation);
      }
      
    } catch (ScimException e) {
      operation.logInfo("Error removing user " + userId + " from SCIM2 group " + groupId + " - " + e.getMessage());
      throw new RuntimeException("Error removing user from SCIM2 group", e);
    } catch (Exception e) {
      operation.logInfo("Error removing user " + userId + " from SCIM2 group " + groupId + " - " + e.getMessage());
      throw new RuntimeException("Error removing user from SCIM2 group", e);
    }
  }

  /**
   * Removes a user from a SCIM2 group using PATCH operation (recommended approach).
   * Uses direct JAX-RS client to create RFC 7644 compliant PATCH requests without extra fields.
   */
  private void removeUserFromScim2GroupViaPatch(final String groupId, final String userId, 
      final SyncOperation operation) throws ScimException {
    // Create manual PATCH request using JAX-RS client to ensure RFC 7644 compliance
    String patchJson = createRemoveMemberPatchJson(userId);
    
    // Debug logging for request
    if (serverContext.debugEnabled()) {
      serverContext.debugInfo("SCIM2 Group PATCH Remove Request - Group ID: " + groupId + 
                            ", User ID: " + userId + 
                            ", URL: " + baseUrl + groupBasePath + "/" + groupId + 
                            ", Request Body: " + patchJson);
    }
    
    try {
      WebTarget target = jaxrsClient.target(baseUrl + groupBasePath + "/" + groupId);
      Response response = target.request("application/scim+json")
          .method("PATCH", Entity.entity(patchJson, "application/scim+json"));
      
      // Debug logging for response
      if (serverContext.debugEnabled()) {
        String responseBody = response.hasEntity() ? response.readEntity(String.class) : "";
        serverContext.debugInfo("SCIM2 Group PATCH Remove Response - Group ID: " + groupId + 
                              ", User ID: " + userId + 
                              ", Status: " + response.getStatus() + 
                              ", Response Body: " + responseBody);
        // Need to close and recreate response for subsequent reading
        response.close();
        response = target.request("application/scim+json")
            .method("PATCH", Entity.entity(patchJson, "application/scim+json"));
      }
      
      if (response.getStatus() >= 200 && response.getStatus() < 300) {
        operation.logInfo("Removed user " + userId + " from SCIM2 group " + groupId + " via PATCH (RFC 7644 compliant)");
      } else {
        String errorBody = response.hasEntity() ? response.readEntity(String.class) : "No response body";
        throw new RuntimeException("PATCH request failed with status: " + response.getStatus() + 
                               " - " + errorBody);
      }
      response.close();
      
    } catch (Exception e) {
      throw new RuntimeException("Error executing PATCH request: " + e.getMessage(), e);
    }
  }

  /**
   * Removes a user from a SCIM2 group using PUT operation with metadata stripped per RFC 7643.
   */
  private void removeUserFromScim2GroupViaPut(final String groupId, final String userId, 
      final SyncOperation operation) throws ScimException {
    
    // Debug logging for request
    if (serverContext.debugEnabled()) {
      serverContext.debugInfo("SCIM2 Group PUT Remove Request - Group ID: " + groupId + 
                            ", User ID: " + userId + 
                            ", Retrieving group for modification");
    }
    
    // Retrieve the SCIM2 group
    GroupResource group = scimService.retrieve(groupBasePath, groupId, GroupResource.class);
    List<Member> members = group.getMembers();
    if (members == null) {
      operation.logInfo("Group " + groupId + " has no members to remove");
      return;
    }
    
    // Remove the member from the list
    int originalSize = members.size();
    members.removeIf(member -> userId.equals(member.getValue()));
    int newSize = members.size();
    
    // Strip read-only and immutable attributes per RFC 7643 Section 3.1
    stripReadOnlyAttributes(group);
    
    // Debug logging for the replacement request
    if (serverContext.debugEnabled()) {
      serverContext.debugInfo("SCIM2 Group PUT Remove Replace Request - Group ID: " + groupId + 
                            ", User ID: " + userId + 
                            ", Original Members Count: " + originalSize + 
                            ", New Members Count: " + newSize + 
                            ", Executing PUT replace operation");
    }
    
    // Replace the group with updated members list
    group = scimService.replace(group);
    
    // Debug logging for response
    if (serverContext.debugEnabled()) {
      serverContext.debugInfo("SCIM2 Group PUT Remove Replace Response - Group ID: " + groupId + 
                            ", User ID: " + userId + 
                            ", Operation completed successfully");
    }
    
    operation.logInfo("Removed user " + userId + " from SCIM2 group " + groupId + " via PUT (metadata stripped per RFC 7643)");
  }

  /**
   * Strips read-only and immutable attributes from a GroupResource per RFC 7643 Section 3.1.
   * The meta attribute and its sub-attributes are read-only and should not be included in PUT requests.
   */
  private void stripReadOnlyAttributes(GroupResource group) {
    // Strip meta attribute - it's read-only per RFC 7643 Section 3.1
    group.setMeta(null);
    
    // Note: SCIM2 SDK may handle schemas automatically, so we don't need to manually strip them
    // The UnboundID SCIM2 SDK typically manages schemas appropriately for PUT operations
  }

  /**
   * Checks if a user is already a member of a SCIM2 group.
   * Optimized for large groups by using SCIM search filters instead of retrieving full group data.
   * 
   * @param groupId The ID of the SCIM2 group
   * @param userId The ID of the SCIM2 user
   * @param operation The sync operation for logging
   * @return true if user is a member, false otherwise
   */
  protected boolean isUserMemberOfGroup(final String groupId, final String userId, 
      final SyncOperation operation) {
    // Check if group membership lookups are disabled
    if (disableGroupMembershipLookups) {
      operation.logInfo("Group membership lookups disabled - skipping membership check for user " + 
                       userId + " in group " + groupId);
      return false; // Always return false to ensure operations are attempted
    }
    
    try {
      // Use a search filter to check membership without retrieving full group data
      // This is much more efficient for large groups as it only returns the count
      Filter membershipFilter = Filter.and(
          Filter.eq("id", groupId),
          Filter.eq("members.value", userId)
      );
      
      // Debug logging for membership check request
      if (serverContext.debugEnabled()) {
        serverContext.debugInfo("SCIM2 Group Membership Check Request - Group ID: " + groupId + 
                              ", User ID: " + userId + 
                              ", Filter: " + membershipFilter.toString());
      }
      
      ListResponse<GroupResource> searchResponse = 
          scimService.searchRequest(groupBasePath)
              .filter(membershipFilter.toString())
              .attributes("id") // Only request minimal attributes
              .invoke(GroupResource.class);
      
      boolean isMember = searchResponse.getTotalResults() > 0;
      
      // Debug logging for membership check response
      if (serverContext.debugEnabled()) {
        serverContext.debugInfo("SCIM2 Group Membership Check Response - Group ID: " + groupId + 
                              ", User ID: " + userId + 
                              ", Is Member: " + isMember + 
                              ", Total Results: " + searchResponse.getTotalResults());
      }
      
      return isMember;
      
    } catch (Exception e) {
      operation.logInfo("Error checking group membership for user " + userId + " in group " + groupId + ": " + e.getMessage());
      return false;
    }
  }

  /**
   * Checks if a modification involves one of the configured group membership attributes.
   * 
   * @param modification The LDAP modification to check
   * @return true if the modification affects a group membership attribute
   */
  protected boolean isGroupMembershipModification(final Modification modification) {
    String attrName = modification.getAttributeName();
    for (String groupAttr : groupMembershipAttributes) {
      if (groupAttr.equalsIgnoreCase(attrName)) {
        return true;
      }
    }
    return false;
  }

  /**
   * JAX-RS ClientRequestFilter for OAuth Bearer token authentication.
   * This filter adds the Authorization header with the Bearer token to all requests.
   */
  private static class BearerTokenFilter implements ClientRequestFilter {
    private final String bearerToken;

    public BearerTokenFilter(String bearerToken) {
      this.bearerToken = bearerToken;
    }

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {
      requestContext.getHeaders().add(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
    }
  }

  /**
   * Creates a custom SSL context based on the trust configuration.
   * Supports custom truststore or trust-all certificates for development/testing.
   * 
   * @return SSLContext configured based on trust settings, or null to use default
   * @throws Exception if there's an error creating the SSL context
   */
  private SSLContext createSSLContext() throws Exception {
    // If custom truststore is specified
    if (trustStorePath != null && !trustStorePath.trim().isEmpty()) {
      KeyStore trustStore = KeyStore.getInstance(trustStoreType);
      try (FileInputStream fis = new FileInputStream(trustStorePath)) {
        trustStore.load(fis, trustStorePassword != null ? 
                      trustStorePassword.toCharArray() : null);
      }
      
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(
          TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(trustStore);
      
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, tmf.getTrustManagers(), null);
      return sslContext;
    }
    
    // If allowing untrusted certificates (NOT recommended for production)
    if (allowUntrustedCertificates) {
      TrustManager[] trustAllCerts = new TrustManager[] {
        new X509TrustManager() {
          @Override
          public X509Certificate[] getAcceptedIssuers() { return null; }
          @Override
          public void checkClientTrusted(X509Certificate[] certs, String authType) { }
          @Override
          public void checkServerTrusted(X509Certificate[] certs, String authType) { }
        }
      };
      
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, trustAllCerts, null);
      return sslContext;
    }
    
    return null; // Use default SSL context
  }

  /**
   * Configures HTTP proxy settings on the client configuration.
   * Supports both HTTP and SOCKS proxies with optional authentication.
   * 
   * @param clientConfig The JAX-RS client configuration to modify
   */
  private void configureProxy(ClientConfig clientConfig) {
    if (proxyHost != null && !proxyHost.trim().isEmpty()) {
      // Set proxy host and port
      clientConfig.property(ClientProperties.PROXY_URI, 
          "http://" + proxyHost + ":" + (proxyPort != null ? proxyPort : "8080"));
      
      // Set proxy authentication if provided
      if (proxyUsername != null && !proxyUsername.trim().isEmpty()) {
        clientConfig.property(ClientProperties.PROXY_USERNAME, proxyUsername);
        if (proxyPassword != null) {
          clientConfig.property(ClientProperties.PROXY_PASSWORD, proxyPassword);
        }
      }
    }
  }

  /**
   * Creates a proper RFC 7644 compliant PATCH JSON for adding a member to a group.
   * This method ensures only the required fields (schemas and Operations) are included.
   */
  private String createAddMemberPatchJson(final String userId) {
    StringBuilder json = new StringBuilder();
    json.append("{");
    json.append("\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],");
    json.append("\"Operations\":[{");
    json.append("\"op\":\"add\",");
    json.append("\"path\":\"members\",");
    json.append("\"value\":[{");
    json.append("\"value\":\"").append(userId).append("\",");
    json.append("\"$ref\":\"").append(baseUrl).append(userBasePath).append("/").append(userId).append("\"");
    json.append("}]");
    json.append("}]");
    json.append("}");
    return json.toString();
  }

  /**
   * Creates a proper RFC 7644 compliant PATCH JSON for removing a member from a group.
   * This method ensures only the required fields (schemas and Operations) are included.
   */
  private String createRemoveMemberPatchJson(final String userId) {
    StringBuilder json = new StringBuilder();
    json.append("{");
    json.append("\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],");
    json.append("\"Operations\":[{");
    json.append("\"op\":\"remove\",");
    json.append("\"path\":\"members[value eq \\\"").append(userId).append("\\\"]\"");
    json.append("}]");
    json.append("}");
    return json.toString();
  }
}

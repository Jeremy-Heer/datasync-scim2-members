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
package com.heer.sync.lib.scim2;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.HttpHeaders;

import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;

import com.unboundid.scim2.client.ScimService;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;

import com.heer.sync.lib.ConfigFileLoader;

/**
 * Factory for creating configured SCIM2 clients with authentication, SSL/TLS, and proxy support.
 * Supports both inline configuration arguments and shared configuration files.
 */
public class Scim2ClientFactory
{
  private final SyncServerContext serverContext;
  private final ConfigFileLoader configLoader;
  
  // SCIM2 endpoint configuration
  private final String baseUrl;
  private final String userBasePath;
  private final String groupBasePath;
  
  // Authentication configuration
  private final String authType;
  private final String username;
  private final String password;
  private final String bearerToken;
  
  // SSL/TLS configuration
  private final String trustStorePath;
  private final String trustStorePassword;
  private final String trustStoreType;
  private final boolean allowUntrustedCertificates;
  
  // HTTP proxy configuration
  private final String proxyHost;
  private final String proxyPort;
  private final String proxyUsername;
  private final String proxyPassword;
  private final String proxyType;
  
  // Timeout configuration
  private final int connectTimeoutMs;
  private final int readTimeoutMs;
  
  /**
   * Creates a new SCIM2 client factory with the specified configuration.
   * 
   * @param serverContext The sync server context for logging
   * @param configLoader Optional configuration file loader (can be null)
   * @param baseUrl SCIM2 base URL (required)
   * @param userBasePath User resource path (required)
   * @param groupBasePath Group resource path (required)
   * @param authType Authentication type: "basic" or "bearer"
   * @param username Username for basic auth
   * @param password Password for basic auth
   * @param bearerToken Bearer token for OAuth auth
   * @param trustStorePath Path to custom truststore
   * @param trustStorePassword Truststore password
   * @param trustStoreType Truststore type (JKS, PKCS12, etc.)
   * @param allowUntrustedCertificates Allow untrusted SSL certificates
   * @param proxyHost HTTP proxy hostname
   * @param proxyPort HTTP proxy port
   * @param proxyUsername Proxy authentication username
   * @param proxyPassword Proxy authentication password
   * @param proxyType Proxy type (HTTP or SOCKS)
   * @param connectTimeoutMs Connection timeout in milliseconds
   * @param readTimeoutMs Read timeout in milliseconds
   */
  public Scim2ClientFactory(
      final SyncServerContext serverContext,
      final ConfigFileLoader configLoader,
      final String baseUrl,
      final String userBasePath,
      final String groupBasePath,
      final String authType,
      final String username,
      final String password,
      final String bearerToken,
      final String trustStorePath,
      final String trustStorePassword,
      final String trustStoreType,
      final boolean allowUntrustedCertificates,
      final String proxyHost,
      final String proxyPort,
      final String proxyUsername,
      final String proxyPassword,
      final String proxyType,
      final int connectTimeoutMs,
      final int readTimeoutMs)
  {
    this.serverContext = serverContext;
    this.configLoader = configLoader;
    this.baseUrl = baseUrl;
    this.userBasePath = userBasePath;
    this.groupBasePath = groupBasePath;
    this.authType = authType;
    this.username = username;
    this.password = password;
    this.bearerToken = bearerToken;
    this.trustStorePath = trustStorePath;
    this.trustStorePassword = trustStorePassword;
    this.trustStoreType = trustStoreType;
    this.allowUntrustedCertificates = allowUntrustedCertificates;
    this.proxyHost = proxyHost;
    this.proxyPort = proxyPort;
    this.proxyUsername = proxyUsername;
    this.proxyPassword = proxyPassword;
    this.proxyType = proxyType;
    this.connectTimeoutMs = connectTimeoutMs;
    this.readTimeoutMs = readTimeoutMs;
  }
  
  /**
   * Creates and configures a SCIM2 service client.
   * 
   * @return Configured ScimService instance
   * @throws RuntimeException if client creation fails
   */
  public ScimService createScimService()
  {
    try
    {
      // Initialize JAX-RS client with Apache HttpClient connector for native PATCH support
      ClientConfig clientConfig = new ClientConfig();
      clientConfig.connectorProvider(new ApacheConnectorProvider());
      
      // Configure connection and read timeouts
      clientConfig.property(ClientProperties.CONNECT_TIMEOUT, connectTimeoutMs);
      clientConfig.property(ClientProperties.READ_TIMEOUT, readTimeoutMs);
      
      // Configure SSL/TLS settings
      SSLContext sslContext = createSSLContext();
      if (sslContext != null)
      {
        clientConfig.property("jersey.config.apache.client.sslContext", sslContext);
      }
      
      // Configure HTTP proxy settings
      configureProxy(clientConfig);
      
      Client restClient = ClientBuilder.newClient(clientConfig);
      
      // Configure authentication
      configureAuthentication(restClient);
      
      // Create SCIM2 service with authenticated client
      WebTarget target = restClient.target(URI.create(baseUrl));
      return new ScimService(target);
    }
    catch (Exception e)
    {
      throw new RuntimeException("Failed to create SCIM2 service: " + e.getMessage(), e);
    }
  }
  
  /**
   * Creates and configures a JAX-RS client for direct HTTP operations.
   * 
   * @return Configured JAX-RS Client instance
   * @throws RuntimeException if client creation fails
   */
  public Client createJaxrsClient()
  {
    try
    {
      ClientConfig clientConfig = new ClientConfig();
      clientConfig.connectorProvider(new ApacheConnectorProvider());
      
      clientConfig.property(ClientProperties.CONNECT_TIMEOUT, connectTimeoutMs);
      clientConfig.property(ClientProperties.READ_TIMEOUT, readTimeoutMs);
      
      SSLContext sslContext = createSSLContext();
      if (sslContext != null)
      {
        clientConfig.property("jersey.config.apache.client.sslContext", sslContext);
      }
      
      configureProxy(clientConfig);
      
      Client restClient = ClientBuilder.newClient(clientConfig);
      
      configureAuthentication(restClient);
      
      return restClient;
    }
    catch (Exception e)
    {
      throw new RuntimeException("Failed to create JAX-RS client: " + e.getMessage(), e);
    }
  }
  
  /**
   * Configures authentication on the provided client.
   */
  private void configureAuthentication(final Client client)
  {
    if ("bearer".equalsIgnoreCase(authType))
    {
      // OAuth Bearer Token authentication
      if (bearerToken == null || bearerToken.trim().isEmpty())
      {
        throw new RuntimeException("Bearer token is required when auth-type is 'bearer'");
      }
      
      client.register(new BearerTokenFilter(bearerToken));
      
      if (serverContext != null)
      {
        serverContext.debugInfo("Using OAuth Bearer Token authentication");
      }
    }
    else
    {
      // HTTP Basic authentication (default)
      if (username == null || password == null)
      {
        throw new RuntimeException("Username and password are required for basic authentication");
      }
      
      HttpAuthenticationFeature basicAuthFeature = 
          HttpAuthenticationFeature.basicBuilder()
                                   .credentials(username, password)
                                   .build();
      client.register(basicAuthFeature);
      
      if (serverContext != null)
      {
        serverContext.debugInfo("Using HTTP Basic authentication");
      }
    }
  }
  
  /**
   * Creates an SSL context based on configuration.
   */
  private SSLContext createSSLContext() throws Exception
  {
    if (allowUntrustedCertificates)
    {
      // Create a trust manager that accepts all certificates
      TrustManager[] trustAllCerts = new TrustManager[]
      {
        new X509TrustManager()
        {
          public X509Certificate[] getAcceptedIssuers() { return null; }
          public void checkClientTrusted(X509Certificate[] certs, String authType) {}
          public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }
      };
      
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
      
      if (serverContext != null)
      {
        serverContext.debugWarning("SSL/TLS: Accepting untrusted certificates - USE ONLY FOR DEVELOPMENT/TESTING!");
      }
      
      return sslContext;
    }
    else if (trustStorePath != null && !trustStorePath.trim().isEmpty())
    {
      // Load custom truststore
      KeyStore trustStore = KeyStore.getInstance(trustStoreType);
      
      try (FileInputStream fis = new FileInputStream(trustStorePath))
      {
        trustStore.load(fis, trustStorePassword != null ? trustStorePassword.toCharArray() : null);
      }
      
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(trustStore);
      
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());
      
      if (serverContext != null)
      {
        serverContext.debugInfo("SSL/TLS: Using custom truststore (" + trustStoreType + "): " + trustStorePath);
      }
      
      return sslContext;
    }
    
    // Use JVM default
    if (serverContext != null)
    {
      serverContext.debugInfo("SSL/TLS: Using JVM default truststore");
    }
    return null;
  }
  
  /**
   * Configures HTTP proxy settings on the client configuration.
   */
  private void configureProxy(final ClientConfig clientConfig)
  {
    if (proxyHost != null && !proxyHost.trim().isEmpty())
    {
      String proxyUri = proxyHost + ":" + (proxyPort != null ? proxyPort : "8080");
      
      clientConfig.property(ClientProperties.PROXY_URI, proxyUri);
      
      if (proxyUsername != null && !proxyUsername.trim().isEmpty())
      {
        clientConfig.property(ClientProperties.PROXY_USERNAME, proxyUsername);
        clientConfig.property(ClientProperties.PROXY_PASSWORD, proxyPassword);
        
        if (serverContext != null)
        {
          serverContext.debugInfo("HTTP Proxy: " + proxyType + " proxy at " + proxyUri + " (with authentication)");
        }
      }
      else
      {
        if (serverContext != null)
        {
          serverContext.debugInfo("HTTP Proxy: " + proxyType + " proxy at " + proxyUri);
        }
      }
    }
  }
  
  /**
   * Gets the base URL.
   */
  public String getBaseUrl()
  {
    return baseUrl;
  }
  
  /**
   * Gets the user base path.
   */
  public String getUserBasePath()
  {
    return userBasePath;
  }
  
  /**
   * Gets the group base path.
   */
  public String getGroupBasePath()
  {
    return groupBasePath;
  }
  
  /**
   * JAX-RS filter for adding Bearer token authentication.
   */
  private static class BearerTokenFilter implements ClientRequestFilter
  {
    private final String token;
    
    public BearerTokenFilter(final String token)
    {
      this.token = token;
    }
    
    @Override
    public void filter(ClientRequestContext requestContext) throws IOException
    {
      requestContext.getHeaders().add(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }
  }
}

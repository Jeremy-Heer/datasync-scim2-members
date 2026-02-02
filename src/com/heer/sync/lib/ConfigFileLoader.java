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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.FileTime;
import java.util.Properties;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import com.unboundid.directory.sdk.sync.types.SyncServerContext;

/**
 * Thread-safe configuration file loader that reads Java Properties files
 * and supports automatic reload when the file is modified. This utility
 * enables sharing configuration across multiple plugins while supporting
 * credential updates without restart.
 * 
 * <p>Features:
 * <ul>
 *   <li>Thread-safe concurrent access using read-write locks</li>
 *   <li>Automatic reload detection via file modification time</li>
 *   <li>Cached properties for performance</li>
 *   <li>Fallback to default values when keys are missing</li>
 *   <li>Graceful error handling with logging</li>
 * </ul>
 * 
 * <p>Usage example:
 * <pre>
 * ConfigFileLoader config = new ConfigFileLoader(
 *     "/path/to/scim-sync.properties", 
 *     serverContext);
 * 
 * String userId = config.getProperty("user.id.attribute", "uid");
 * String baseUrl = config.getProperty("scim2.base.url");
 * 
 * // Force reload to pick up credential changes
 * config.reload();
 * </pre>
 */
public class ConfigFileLoader
{
  // The file path to the properties file
  private final String configFilePath;
  
  // Server context for logging
  private final SyncServerContext serverContext;
  
  // Lock for thread-safe access to configuration
  private final ReadWriteLock configLock = new ReentrantReadWriteLock();
  private final Lock readLock = configLock.readLock();
  private final Lock writeLock = configLock.writeLock();
  
  // Cached properties
  private Properties properties;
  
  // Last modified time of the configuration file
  private FileTime lastModifiedTime;
  
  /**
   * Creates a new configuration file loader.
   * 
   * @param configFilePath The absolute path to the properties file
   * @param serverContext The sync server context for logging
   * @throws IOException If the file cannot be read initially
   */
  public ConfigFileLoader(final String configFilePath, 
                          final SyncServerContext serverContext)
      throws IOException
  {
    this.configFilePath = configFilePath;
    this.serverContext = serverContext;
    this.properties = new Properties();
    this.lastModifiedTime = null;
    
    // Load properties initially
    reload();
  }
  
  /**
   * Gets a property value from the configuration file.
   * If the file has been modified since last load, it will be reloaded automatically.
   * 
   * @param key The property key
   * @return The property value, or null if not found
   */
  public String getProperty(final String key)
  {
    return getProperty(key, null);
  }
  
  /**
   * Gets a property value from the configuration file with a default fallback.
   * If the file has been modified since last load, it will be reloaded automatically.
   * 
   * @param key The property key
   * @param defaultValue The default value to return if key is not found
   * @return The property value, or defaultValue if not found
   */
  public String getProperty(final String key, final String defaultValue)
  {
    // Check if file has been modified and reload if needed
    checkAndReloadIfModified();
    
    readLock.lock();
    try
    {
      return properties.getProperty(key, defaultValue);
    }
    finally
    {
      readLock.unlock();
    }
  }
  
  /**
   * Gets a boolean property value from the configuration file.
   * 
   * @param key The property key
   * @param defaultValue The default value to return if key is not found
   * @return The boolean property value, or defaultValue if not found or invalid
   */
  public boolean getBooleanProperty(final String key, final boolean defaultValue)
  {
    String value = getProperty(key);
    if (value == null)
    {
      return defaultValue;
    }
    
    return Boolean.parseBoolean(value.trim());
  }
  
  /**
   * Gets an integer property value from the configuration file.
   * 
   * @param key The property key
   * @param defaultValue The default value to return if key is not found
   * @return The integer property value, or defaultValue if not found or invalid
   */
  public int getIntProperty(final String key, final int defaultValue)
  {
    String value = getProperty(key);
    if (value == null)
    {
      return defaultValue;
    }
    
    try
    {
      return Integer.parseInt(value.trim());
    }
    catch (NumberFormatException e)
    {
      if (serverContext != null)
      {
        serverContext.debugWarning("Invalid integer value for property '" + key + 
                                  "': " + value + ", using default: " + defaultValue);
      }
      return defaultValue;
    }
  }
  
  /**
   * Checks if the configuration file has been modified since last load,
   * and reloads it if necessary.
   */
  private void checkAndReloadIfModified()
  {
    try
    {
      File configFile = new File(configFilePath);
      if (!configFile.exists())
      {
        if (serverContext != null)
        {
          serverContext.debugWarning("Configuration file does not exist: " + configFilePath);
        }
        return;
      }
      
      FileTime currentModTime = Files.getLastModifiedTime(configFile.toPath());
      
      // Check if file has been modified
      if (lastModifiedTime == null || currentModTime.compareTo(lastModifiedTime) > 0)
      {
        if (serverContext != null)
        {
          serverContext.debugInfo("Configuration file has been modified, reloading: " + 
                                 configFilePath);
        }
        reload();
      }
    }
    catch (IOException e)
    {
      if (serverContext != null)
      {
        serverContext.debugWarning("Error checking configuration file modification time: " + 
                                  e.getMessage());
      }
    }
  }
  
  /**
   * Forces a reload of the configuration file from disk.
   * This method is thread-safe and can be called concurrently.
   * 
   * @throws IOException If the file cannot be read
   */
  public void reload() throws IOException
  {
    writeLock.lock();
    try
    {
      File configFile = new File(configFilePath);
      
      if (!configFile.exists())
      {
        throw new IOException("Configuration file does not exist: " + configFilePath);
      }
      
      if (!configFile.canRead())
      {
        throw new IOException("Configuration file is not readable: " + configFilePath);
      }
      
      Properties newProperties = new Properties();
      try (FileInputStream fis = new FileInputStream(configFile))
      {
        newProperties.load(fis);
      }
      
      // Update cached properties and modification time
      this.properties = newProperties;
      this.lastModifiedTime = Files.getLastModifiedTime(configFile.toPath());
      
      if (serverContext != null)
      {
        serverContext.debugInfo("Successfully loaded configuration from: " + configFilePath + 
                               " (" + properties.size() + " properties)");
      }
    }
    finally
    {
      writeLock.unlock();
    }
  }
  
  /**
   * Gets the path to the configuration file.
   * 
   * @return The configuration file path
   */
  public String getConfigFilePath()
  {
    return configFilePath;
  }
  
  /**
   * Gets the number of properties loaded from the configuration file.
   * 
   * @return The number of properties
   */
  public int getPropertyCount()
  {
    readLock.lock();
    try
    {
      return properties.size();
    }
    finally
    {
      readLock.unlock();
    }
  }
  
  /**
   * Checks if a property key exists in the configuration.
   * 
   * @param key The property key to check
   * @return true if the key exists, false otherwise
   */
  public boolean hasProperty(final String key)
  {
    checkAndReloadIfModified();
    
    readLock.lock();
    try
    {
      return properties.containsKey(key);
    }
    finally
    {
      readLock.unlock();
    }
  }
}

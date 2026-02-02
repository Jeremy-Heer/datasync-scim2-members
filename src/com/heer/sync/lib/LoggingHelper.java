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
import com.unboundid.directory.sdk.sync.types.SyncServerContext;

/**
 * Helper utility for common logging patterns used across SCIM sync plugins.
 * Provides consistent formatting and level-appropriate logging methods.
 * 
 * <p>This class is stateless and thread-safe. All methods are static.
 */
public final class LoggingHelper
{
  /**
   * Private constructor to prevent instantiation.
   */
  private LoggingHelper()
  {
    // Utility class
  }
  
  /**
   * Logs a debug message if debug logging is enabled.
   * 
   * @param serverContext The server context
   * @param message The message to log
   */
  public static void logDebug(final SyncServerContext serverContext, 
                              final String message)
  {
    if (serverContext != null && serverContext.debugEnabled())
    {
      serverContext.debugInfo(message);
    }
  }
  
  /**
   * Logs an info-level message through the sync operation.
   * 
   * @param operation The sync operation
   * @param message The message to log
   */
  public static void logInfo(final SyncOperation operation, 
                             final String message)
  {
    if (operation != null)
    {
      operation.logInfo(message);
    }
  }
  
  /**
   * Logs an error message through the sync operation.
   * 
   * @param operation The sync operation
   * @param message The error message to log
   */
  public static void logError(final SyncOperation operation, 
                              final String message)
  {
    if (operation != null)
    {
      operation.logError(message);
    }
  }
  
  /**
   * Logs a warning through the server context debug system.
   * 
   * @param serverContext The server context
   * @param message The warning message to log
   */
  public static void logWarning(final SyncServerContext serverContext, 
                                final String message)
  {
    if (serverContext != null)
    {
      serverContext.debugWarning(message);
    }
  }
  
  /**
   * Formats a configuration loading message.
   * 
   * @param pluginName The name of the plugin
   * @param configFile The path to the config file (may be null)
   * @return A formatted message string
   */
  public static String formatConfigLoadMessage(final String pluginName, 
                                                final String configFile)
  {
    if (configFile != null)
    {
      return pluginName + " loaded configuration from file: " + configFile;
    }
    else
    {
      return pluginName + " loaded configuration from inline arguments";
    }
  }
}

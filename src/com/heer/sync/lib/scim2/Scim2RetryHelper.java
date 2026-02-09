/*
 * Copyright 2025 Corp Heer
 */

package com.heer.sync.lib.scim2;

import com.unboundid.directory.sdk.sync.types.SyncOperation;

/**
 * Utility class for executing SCIM2 operations with retry logic and exponential backoff.
 * This helper provides resilience against transient network failures and temporary
 * service unavailability.
 */
public class Scim2RetryHelper
{
  /**
   * Functional interface for operations that can be retried.
   *
   * @param <T> The return type of the operation
   */
  @FunctionalInterface
  public interface RetryableOperation<T>
  {
    /**
     * Executes the operation.
     *
     * @return The result of the operation
     * @throws Exception If the operation fails
     */
    T execute() throws Exception;
  }

  /**
   * Executes an operation with retry logic and exponential backoff.
   * 
   * @param <T> The return type of the operation
   * @param operation The operation to execute
   * @param maxRetries Maximum number of retry attempts (0 means no retries)
   * @param initialDelayMs Initial delay in milliseconds before first retry
   * @param operation The sync operation for logging (may be null)
   * @return The result of the successful operation
   * @throws Exception If all retry attempts fail
   */
  public static <T> T executeWithRetry(
      final RetryableOperation<T> operation,
      final int maxRetries,
      final int initialDelayMs,
      final SyncOperation syncOperation) throws Exception
  {
    Exception lastException = null;
    
    for (int attempt = 0; attempt <= maxRetries; attempt++)
    {
      try
      {
        return operation.execute();
      }
      catch (Exception e)
      {
        lastException = e;
        
        if (attempt < maxRetries)
        {
          // Calculate exponential backoff delay: initialDelay * 2^attempt
          long delayMs = initialDelayMs * (1L << attempt);
          
          if (syncOperation != null)
          {
            syncOperation.logInfo(
              "Operation failed (attempt " + (attempt + 1) + "/" + (maxRetries + 1) + 
              "), retrying in " + delayMs + "ms: " + e.getMessage());
          }
          
          try
          {
            Thread.sleep(delayMs);
          }
          catch (InterruptedException ie)
          {
            Thread.currentThread().interrupt();
            throw new Exception("Retry interrupted", ie);
          }
        }
        else
        {
          if (syncOperation != null)
          {
            syncOperation.logInfo(
              "Operation failed after " + (maxRetries + 1) + " attempts: " + e.getMessage());
          }
        }
      }
    }
    
    // All retries exhausted
    throw new Exception("Operation failed after " + (maxRetries + 1) + " attempts", lastException);
  }
  
  /**
   * Executes an operation with retry logic and exponential backoff (without sync operation logging).
   * 
   * @param <T> The return type of the operation
   * @param operation The operation to execute
   * @param maxRetries Maximum number of retry attempts (0 means no retries)
   * @param initialDelayMs Initial delay in milliseconds before first retry
   * @return The result of the successful operation
   * @throws Exception If all retry attempts fail
   */
  public static <T> T executeWithRetry(
      final RetryableOperation<T> operation,
      final int maxRetries,
      final int initialDelayMs) throws Exception
  {
    return executeWithRetry(operation, maxRetries, initialDelayMs, null);
  }
}

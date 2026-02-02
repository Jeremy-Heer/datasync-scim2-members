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

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Reusable read-write lock manager for thread-safe configuration updates.
 * Provides a consistent pattern for protecting configuration state that is
 * frequently read but infrequently updated.
 * 
 * <p>The read-write lock pattern allows multiple concurrent readers or a
 * single writer, optimizing for the common case where configuration is read
 * much more often than it is updated.
 * 
 * <p>Usage example:
 * <pre>
 * private final ConfigLockManager lockManager = new ConfigLockManager();
 * private String configValue;
 * 
 * // Reading configuration
 * lockManager.readLock().lock();
 * try {
 *   return configValue;
 * } finally {
 *   lockManager.readLock().unlock();
 * }
 * 
 * // Writing configuration
 * lockManager.writeLock().lock();
 * try {
 *   configValue = newValue;
 * } finally {
 *   lockManager.writeLock().unlock();
 * }
 * </pre>
 */
public class ConfigLockManager
{
  private final ReadWriteLock lock = new ReentrantReadWriteLock();
  private final Lock readLock = lock.readLock();
  private final Lock writeLock = lock.writeLock();
  
  /**
   * Gets the read lock for accessing configuration.
   * Multiple threads can hold the read lock simultaneously.
   * 
   * @return The read lock
   */
  public Lock readLock()
  {
    return readLock;
  }
  
  /**
   * Gets the write lock for updating configuration.
   * Only one thread can hold the write lock, and no read locks can be held.
   * 
   * @return The write lock
   */
  public Lock writeLock()
  {
    return writeLock;
  }
}

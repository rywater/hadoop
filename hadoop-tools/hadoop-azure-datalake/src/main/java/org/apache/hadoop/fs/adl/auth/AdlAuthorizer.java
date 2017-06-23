/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.fs.adl.auth;


import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;

/**
 * Interface to support authorization in Azure Data Lake Storage. This interface's intended functionality is similar to
 * the WasbAuthorizationInterface used by the WASB driver.
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public interface AdlAuthorizer {

  /**
   * @param conf File system configuration
   * @throws AdlAuthorizationException if unable to initialize the authorizer
   */
  void init(Configuration conf) throws AdlAuthorizationException;

  /**
   *
   * @param accessType the {@link AdlAccessType} being requested for authorization
   * @param paths The absolute paths of the storage being accessed. Some operations may request operation access
   *              to multiple directories. For example: {@link AdlAccessType#RENAME} will ask for access to two
   *              directories, a source and destination.
   * @return true if access is authorized for all requested directories, otherwise false.
   * @throws AdlAuthorizationException on authorization failure
   */
  boolean isAuthorized(AdlAccessType accessType, Path... paths) throws AdlAuthorizationException;
}

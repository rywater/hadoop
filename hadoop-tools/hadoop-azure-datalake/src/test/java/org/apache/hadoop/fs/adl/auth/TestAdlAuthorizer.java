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

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.adl.AdlConfKeys;
import org.junit.Test;

import java.io.IOException;
import java.util.Optional;

import static org.junit.Assert.*;

public class TestAdlAuthorizer {

  @Test
  public void testCreateClassInstanceSucceeds() throws Exception {
    Configuration configuration = new Configuration();
    configuration.set(AdlConfKeys.ADL_EXTERNAL_AUTHORIZATION_CLASS, "org.apache.hadoop.fs.adl.auth.MockAdlAuthorizer");
    AdlAuthorizer authorizer = AdlAuthorizerFactory.create(configuration);
    assertTrue("Create method should have returned an instance", authorizer != null);
  }

  @Test
  public void testCreateWithoutConfigurationReturnsEmpty() throws Exception {
    AdlAuthorizer authorizer = AdlAuthorizerFactory.create(new Configuration());
    assertTrue("Create method should have returned an empty optional", authorizer == null);
  }

  @Test(expected = IOException.class)
  public void testClassNotFoundIsPropagatedAsIOException() throws Exception {
    Configuration configuration = new Configuration();
    configuration.set(AdlConfKeys.ADL_EXTERNAL_AUTHORIZATION_CLASS, "class.does.not.exist");
    AdlAuthorizerFactory.create(configuration);
    fail("Creation of the authorizer should have failed");
  }

}
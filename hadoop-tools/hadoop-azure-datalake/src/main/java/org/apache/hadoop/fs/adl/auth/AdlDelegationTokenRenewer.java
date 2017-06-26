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
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenRenewer;
import org.apache.hadoop.security.token.delegation.AbstractDelegationTokenIdentifier;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenAuthenticatedURL;
import org.apache.hadoop.security.token.delegation.web.KerberosDelegationTokenAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.PrivilegedExceptionAction;

/**
 * Handles renewal of Token for ADL delegation tokens
 */
public class AdlDelegationTokenRenewer extends TokenRenewer {

  private static final Logger LOGGER = LoggerFactory.getLogger(AdlDelegationTokenRenewer.class);

  @Override
  public boolean handleKind(Text kind) {
    return AdlDelegationTokenIdentifier.TOKEN_KIND.equals(kind);
  }

  @Override
  public boolean isManaged(Token<?> token) throws IOException {
    return true;
  }

  @Override
  public long renew(Token<?> token, Configuration conf) throws IOException, InterruptedException {
    LOGGER.debug("Renewing the delegation token");
    return DelegationTokenHandler.renew(token, conf);
  }

  @Override
  public void cancel(Token<?> token, Configuration conf) throws IOException, InterruptedException {
    LOGGER.debug("Cancelling the delegation token");
    DelegationTokenHandler.cancel(token, conf);
  }
}

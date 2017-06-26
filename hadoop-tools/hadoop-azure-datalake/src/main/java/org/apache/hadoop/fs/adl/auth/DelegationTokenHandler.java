package org.apache.hadoop.fs.adl.auth;

import com.google.common.base.Supplier;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.adl.AdlConfKeys;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.delegation.AbstractDelegationTokenIdentifier;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenAuthenticatedURL;
import org.apache.hadoop.security.token.delegation.web.KerberosDelegationTokenAuthenticator;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.PrivilegedExceptionAction;

public final class DelegationTokenHandler {

  private static final String DEFAULT_DELEGATION_MANAGER_ENDPOINT = "/tokenmanager/v1";
  private static final int DEFAULT_CRED_SERVICE_PORT = 50911;

  private DelegationTokenHandler() {

  }

  public static Token<?> retrieve(final String renewer, Configuration conf) throws IOException, InterruptedException {
    return doConnected(conf, new Supplier<DelegationTokenAuthenticatedURL.Token>() {
      @Override
      public DelegationTokenAuthenticatedURL.Token get() {
        return new DelegationTokenAuthenticatedURL.Token();
      }
    }, new AuthenticatedAction<Token<?>>() {
      @Override
      public Token<?> handle(UserGroupInformation ugi, final DelegationTokenAuthenticatedURL.Token authToken,
                             final String serviceUrl, final String proxyUser) throws IOException, InterruptedException {
        return ugi.doAs(new PrivilegedExceptionAction<Token<?>>() {
          @Override
          public Token<?> run() throws Exception {
            return getAuthenticatedUrl().getDelegationToken(new URL(serviceUrl), authToken, renewer, proxyUser);
          }
        });
      }
    });
  }

  static Long renew(final Token<?> token, Configuration conf) throws IOException, InterruptedException {
    return doConnected(conf, new Supplier<DelegationTokenAuthenticatedURL.Token>() {
      @Override
      public DelegationTokenAuthenticatedURL.Token get() {
        return createAuthUrlToken(token);
      }
    }, new AuthenticatedAction<Long>() {
      @Override
      public Long handle(UserGroupInformation ugi, final DelegationTokenAuthenticatedURL.Token authToken,
                         final String serviceUrl, final String proxyUser) throws IOException, InterruptedException {
        return ugi.doAs(new PrivilegedExceptionAction<Long>() {
          @Override
          public Long run() throws Exception {
            return getAuthenticatedUrl().renewDelegationToken(new URL(serviceUrl), authToken, proxyUser);
          }
        });
      }
    });
  }

  static void cancel(final Token<?> token, Configuration conf) throws IOException, InterruptedException {
    doConnected(conf, new Supplier<DelegationTokenAuthenticatedURL.Token>() {
      @Override
      public DelegationTokenAuthenticatedURL.Token get() {
        return createAuthUrlToken(token);
      }
    }, new AuthenticatedAction<Void>() {
      @Override
      public Void handle(UserGroupInformation ugi, final DelegationTokenAuthenticatedURL.Token authToken,
                         final String serviceUrl, final String proxyUser) throws IOException, InterruptedException {
        ugi.doAs(new PrivilegedExceptionAction<Void>() {
          @Override
          public Void run() throws Exception {
            getAuthenticatedUrl().cancelDelegationToken(new URL(serviceUrl), authToken, proxyUser);
            return null;
          }
        });
        return null;
      }
    });
  }

  private static <T> T doConnected(Configuration conf, Supplier<DelegationTokenAuthenticatedURL.Token> tokenSupplier, AuthenticatedAction<T> action) throws IOException, InterruptedException {
    UserGroupInformation ugi = UserGroupInformation.getCurrentUser();
    UserGroupInformation connectUgi = ugi.getRealUser();
    String proxyUser = connectUgi == null ? null : connectUgi.getShortUserName();
    if (connectUgi == null) {
      connectUgi = ugi;
    }

    connectUgi.checkTGTAndReloginFromKeytab();
    String credServiceUrl = getCredServiceUrl(conf);
    DelegationTokenAuthenticatedURL.Token authToken = tokenSupplier.get();

    return action.handle(connectUgi, authToken, credServiceUrl, proxyUser);
  }

  private interface AuthenticatedAction<T> {
    T handle(UserGroupInformation ugi, DelegationTokenAuthenticatedURL.Token authToken,
             String serviceUrl, String proxyUser) throws IOException, InterruptedException;
  }

  @SuppressWarnings("unchecked")
  private static DelegationTokenAuthenticatedURL.Token createAuthUrlToken(Token<?> token) {
    DelegationTokenAuthenticatedURL.Token authToken = new DelegationTokenAuthenticatedURL.Token();
    authToken.setDelegationToken((Token<AbstractDelegationTokenIdentifier>) token);
    return authToken;
  }

  private static DelegationTokenAuthenticatedURL getAuthenticatedUrl() {
    return new DelegationTokenAuthenticatedURL(new KerberosDelegationTokenAuthenticator());
  }

  private static String getCredServiceUrl(Configuration conf) throws UnknownHostException {
    String baseUrl = conf.get(AdlConfKeys.KEY_CRED_SERVICE_URL, String.format("http://%s:%s", InetAddress.getLocalHost().
            getCanonicalHostName(), DEFAULT_CRED_SERVICE_PORT));
    return baseUrl + DEFAULT_DELEGATION_MANAGER_ENDPOINT;
  }
}

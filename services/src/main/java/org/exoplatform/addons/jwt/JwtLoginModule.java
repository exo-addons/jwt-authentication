/*
 * Copyright (C) 2024 eXo Platform SAS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package org.exoplatform.addons.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.commons.io.IOUtils;
import org.exoplatform.commons.utils.PropertyManager;
import org.exoplatform.container.component.ComponentRequestLifecycle;
import org.exoplatform.container.component.RequestLifeCycle;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.organization.User;
import org.exoplatform.services.organization.UserHandler;
import org.exoplatform.services.organization.UserStatus;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.UsernameCredential;
import org.exoplatform.services.security.j2ee.TomcatLoginModule;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class JwtLoginModule extends TomcatLoginModule {

  protected final Log log = ExoLogger.getLogger(JwtLoginModule.class);

  private String jwtIssuer;
  private String jwtAudience;
  private String jwtPublicKeyUrl;
  private String jwtPublicKeyContent;

  public JwtLoginModule() {
    this.jwtIssuer = PropertyManager.getProperty("exo.jwt.issuer");
    this.jwtAudience = PropertyManager.getProperty("exo.jwt.audience");
    this.jwtPublicKeyUrl = PropertyManager.getProperty("exo.jwt.publicKeyUrl");
    if (this.jwtIssuer == null) {
      this.jwtIssuer = PropertyManager.getProperty("exo.base.url");
    }
    if (this.jwtAudience == null) {
      this.jwtAudience = PropertyManager.getProperty("exo.base.url");
    }

    loadPublicKeyContent();

  }

  private void loadPublicKeyContent() {
    try (InputStream is = new URI(this.jwtPublicKeyUrl).toURL().openStream()) {
      jwtPublicKeyContent = IOUtils.toString(is, StandardCharsets.UTF_8);
      jwtPublicKeyContent = jwtPublicKeyContent.replace("\n", "")
                                               .replace("-----BEGIN PUBLIC KEY-----", "")
                                               .replace("-----END PUBLIC KEY-----", "");
      LOG.info("Public key founded : {}", jwtPublicKeyContent);
    } catch (Exception e) {
      log.error("Unable to load keystore {}", jwtPublicKeyUrl, e);
      jwtPublicKeyContent="";
    }
  }

  @Override
  protected Log getLogger() {
    return log;
  }

  @Override
  public boolean login() throws LoginException {
    try {
      if (sharedState.containsKey("exo.security.identity")) {
        if (log.isDebugEnabled())
          log.debug("Use Identity from previous LoginModule");
        identity = (Identity)sharedState.get("exo.security.identity");
      } else {
        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("Username");
        callbacks[1] = new PasswordCallback("Password",false);

        callbackHandler.handle(callbacks);
        String jwtToken = new String(((PasswordCallback) callbacks[1]).getPassword());
        ((PasswordCallback)callbacks[1]).clearPassword();

        if (jwtToken.startsWith("Bearer ")) {
          long startTime = System.currentTimeMillis();
          String username = validateToken(jwtToken);
          log.debug("Time to validate token in jwtLoginModule : {} ms", System.currentTimeMillis() - startTime);

          if (username != null) {
            searchUser(username);

            Authenticator authenticator = getContainer().getComponentInstanceOfType(Authenticator.class);
            identity = authenticator.createIdentity(username);

            sharedState.put("javax.security.auth.login.name", username);
            sharedState.put("exo.security.identity", identity);
            subject.getPublicCredentials().add(new UsernameCredential(username));
          }
        }
      }
      return true;

    } catch (final Exception e) {
      if (log.isDebugEnabled()) {
        log.debug(e.getMessage(), e);
      } else if (log.isWarnEnabled()) {
        log.warn(e.getMessage());
      }
      throw new LoginException(e.getMessage());
    }
  }

  private void searchUser(String username) throws Exception {
    OrganizationService organizationService = getContainer().getComponentInstanceOfType(OrganizationService.class);
    begin(organizationService);
    try {
      UserHandler uHandler = organizationService.getUserHandler();
      User user = uHandler.findUserByName(username, UserStatus.ANY);
      if (user == null) {
        log.debug("user {0} doesn't exists. JwtLoginModule will be ignored.", username);
        throw new LoginException("Can't authenticate. user " + username + " does not exist");
      } else if (!user.isEnabled()) {
        throw new LoginException("Can't authenticate. user " + username + " is disabled");
      }
    } finally {
      end(organizationService);
    }
  }

  @Override
  public boolean commit() throws LoginException {
    if (identity != null) {
      super.commit();
    }
    return true;
  }

  private String validateToken(String authorization) throws LoginException {
    try {
      authorization = authorization.substring("Bearer ".length()).trim();

      if (this.jwtPublicKeyContent.isEmpty()) {
        loadPublicKeyContent();
      }

      KeyFactory kf = KeyFactory.getInstance("RSA");
      X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(this.jwtPublicKeyContent));
      RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

      Claims claims = Jwts.parserBuilder()
                          .setSigningKey(pubKey)
                          .requireIssuer(this.jwtIssuer)
                          .requireAudience(this.jwtAudience)
                          .setAllowedClockSkewSeconds(10)
                          .build()
                          .parseClaimsJws(authorization)
                          .getBody();

      return claims.getSubject();
    } catch (Exception e) {
      log.error("Unable to validate jwt token {}", authorization, e);
      throw new LoginException("Unable to validate jwt token");
    }
  }

  private void begin(OrganizationService orgService) {
    if (orgService instanceof ComponentRequestLifecycle componentRequestLifecycle) {
      RequestLifeCycle.begin(componentRequestLifecycle);
    }
  }

  private void end(OrganizationService orgService) {
    if (orgService instanceof ComponentRequestLifecycle) {
      RequestLifeCycle.end();
    }
  }
}

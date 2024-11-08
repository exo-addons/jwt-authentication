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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.exoplatform.commons.utils.PropertyManager;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.exoplatform.web.filter.Filter;
import org.gatein.wci.ServletContainer;
import org.gatein.wci.ServletContainerFactory;
import org.gatein.wci.authentication.AuthenticationException;
import org.gatein.wci.security.Credentials;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Base64;

public class JwtFilter implements Filter {

  private static final String DEFAULT_AUTHORIZATION_HEADER = "Authorization";

  protected final Log LOG = ExoLogger.getLogger(JwtFilter.class);

  private String jwtHeaderName;

  private String jwtParameterName;
  private boolean jwtRedirectIfAnonym;
  private String jwtRedirectUrl;

  public JwtFilter() {
    this.jwtHeaderName = PropertyManager.getProperty("exo.jwt.header");
    this.jwtParameterName = PropertyManager.getProperty("exo.jwt.parameter");
    this.jwtRedirectUrl = PropertyManager.getProperty("exo.jwt.redirectUrl");
    this.jwtRedirectIfAnonym = Boolean.parseBoolean(PropertyManager.getProperty("exo.jwt.redirectIfAnonym"));

    if (this.jwtHeaderName == null && this.jwtParameterName == null) {
      this.jwtHeaderName = DEFAULT_AUTHORIZATION_HEADER;
    }
  }

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest)servletRequest;
    String userId = httpRequest.getRemoteUser();

    if (userId == null) {

      String authorizationToken = "";
      if (this.jwtHeaderName != null) {
        authorizationToken = httpRequest.getHeader(jwtHeaderName);
      } else if (jwtParameterName != null) {
        authorizationToken = httpRequest.getParameter(jwtParameterName);
      }

      if (authorizationToken!=null) {
        if (!authorizationToken.startsWith("Bearer ")) {
          authorizationToken = "Bearer " + authorizationToken;
        }
        String username = extractUsername(authorizationToken);
        if (username != null) {
          ServletContainer servletContainer = ServletContainerFactory.getServletContainer();
          Credentials credentials = new Credentials(username, authorizationToken);
          try {
            servletContainer.login(httpRequest, (HttpServletResponse) servletResponse, credentials);
          } catch (AuthenticationException ae) {
            LOG.error("Unable to authenticate user with jwt token {}", authorizationToken);
          }
        }
      }
      if (this.jwtRedirectIfAnonym) {
        String authenticatedUser = httpRequest.getRemoteUser();
        LOG.info("user found after authentication = {}", authenticatedUser);
        if (authenticatedUser == null) {
          HttpServletResponse httpResponse = (HttpServletResponse)servletResponse;
          httpResponse.sendRedirect(this.jwtRedirectUrl);
          return;
        }
      }
    }
    filterChain.doFilter(servletRequest, servletResponse);


  }

  private String extractUsername(String jwtToken) {
    //we do not validate the token here, only extract sub value
    //validation is done in JwtLoginModule

    try {
      String[] split = jwtToken.split("\\.");
      String payload = new String(Base64.getUrlDecoder().decode(split[1]));
      JSONObject jsonPayload = new JSONObject(payload);
      return jsonPayload.getString("sub");
    } catch (Exception e) {
      LOG.warn("Unable to decode JWT Token {}", jwtToken);
    }
    return null;

  }
}

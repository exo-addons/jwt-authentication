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

  public JwtFilter() {
    this.jwtHeaderName = PropertyManager.getProperty("exo.jwt.header");
    this.jwtParameterName = PropertyManager.getProperty("exo.jwt.parameter");

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
        if (username!=null) {
          ServletContainer servletContainer = ServletContainerFactory.getServletContainer();
          Credentials credentials = new Credentials(username, authorizationToken);
          try {
            servletContainer.login(httpRequest, (HttpServletResponse) servletResponse, credentials);
          } catch (AuthenticationException ae) {
            LOG.error("Unable to authenticate user with jwt token {}", authorizationToken);
          }
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

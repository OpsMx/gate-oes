/*
 * Copyright 2023 OpsMx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.gate.security.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class BearerTokenExtractor {
  private static final Log logger =
      LogFactory.getLog(
          org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor.class);

  public BearerTokenExtractor() {}

  public Authentication extract(HttpServletRequest request) {
    String tokenValue = this.extractToken(request);
    if (tokenValue != null) {
      PreAuthenticatedAuthenticationToken authentication =
          new PreAuthenticatedAuthenticationToken(tokenValue, "");
      return authentication;
    } else {
      return null;
    }
  }

  protected String extractToken(HttpServletRequest request) {
    String token = this.extractHeaderToken(request);
    if (token == null) {
      logger.debug("Token not found in headers. Trying request parameters.");
      token = request.getParameter("access_token");
      if (token == null) {
        logger.debug("Token not found in request parameters.  Not an OAuth2 request.");
      } else {
        request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, "Bearer");
      }
    }

    return token;
  }

  protected String extractHeaderToken(HttpServletRequest request) {
    Enumeration<String> headers = request.getHeaders("Authorization");

    String value;
    do {
      if (!headers.hasMoreElements()) {
        return null;
      }

      value = (String) headers.nextElement();
    } while (!value.toLowerCase().startsWith("Bearer".toLowerCase()));

    String authHeaderValue = value.substring("Bearer".length()).trim();
    request.setAttribute(
        OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE,
        value.substring(0, "Bearer".length()).trim());
    int commaIndex = authHeaderValue.indexOf(44);
    if (commaIndex > 0) {
      authHeaderValue = authHeaderValue.substring(0, commaIndex);
    }

    return authHeaderValue;
  }
}

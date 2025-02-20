/*
 * Copyright 2016 Google, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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

package com.netflix.spinnaker.gate.security.oauth2

import com.netflix.spinnaker.gate.config.AuthConfig
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2SsoProperties
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter
import org.springframework.session.web.http.DefaultCookieSerializer
import org.springframework.stereotype.Component
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

@Configuration

@EnableWebSecurity
@EnableOAuth2Sso
@EnableConfigurationProperties
// Note the 4 single-quotes below - this is a raw groovy string, because SpEL and groovy
// string syntax overlap!
@ConditionalOnExpression(''''${security.oauth2.client.client-id:}'!=""''')
class OAuth2SsoConfig {

  @Autowired
  AuthConfig authConfig

  @Autowired
  ExternalAuthTokenFilter externalAuthTokenFilter

  @Autowired
  ExternalSslAwareEntryPoint entryPoint

  @Autowired
  DefaultCookieSerializer defaultCookieSerializer

  @Primary
  @Bean
  @ConditionalOnProperty(
    prefix = 'security.oauth2.resource.spinnaker-user-info-token-services',
    name = 'enabled',
    havingValue = 'true',
    matchIfMissing = true)
  ResourceServerTokenServices spinnakerUserInfoTokenServices() {
    new SpinnakerUserInfoTokenServices()
  }

  @Bean
  SecurityFilterChain configure(HttpSecurity http) throws Exception {
    defaultCookieSerializer.setSameSite(null)
    authConfig.configure(http)

    http.exceptionHandling().authenticationEntryPoint(entryPoint)
    http.addFilterBefore(new BasicAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter)
    http.addFilterBefore(externalAuthTokenFilter, AbstractPreAuthenticatedProcessingFilter.class) as SecurityFilterChain
  }

  /**
   * Use this class to specify how to map fields from the userInfoUri response to what's expected to be in the User.
   */
  @Component
  @ConfigurationProperties("security.oauth2.user-info-mapping")
  static class UserInfoMapping {
    String email = "email"
    String firstName = "given_name"
    String lastName = "family_name"
    String username = "email"
    String serviceAccountEmail = "client_email"
    String roles = null
  }

  @Component
  @ConfigurationProperties("security.oauth2.user-info-requirements")
  static class UserInfoRequirements extends HashMap<String, String> {
  }

  /**
   * This class exists to change the login redirect (to /login) to the same URL as the
   * preEstablishedRedirectUri, if set, where the SSL is terminated outside of this server.
   */
  @Component
  @ConditionalOnExpression(''''${security.oauth2.client.client-id:}'!=""''')
  static class ExternalSslAwareEntryPoint extends LoginUrlAuthenticationEntryPoint {

    @Autowired
    private AuthorizationCodeResourceDetails details

    @Autowired
    ExternalSslAwareEntryPoint(OAuth2SsoProperties sso) {
      super(sso.loginPath)
    }

    @Override
    protected String determineUrlToUseForThisRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
      return details.preEstablishedRedirectUri ?: super.determineUrlToUseForThisRequest(request, response, exception)
    }
  }
}

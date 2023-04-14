/*
 * Copyright 2016 Netflix, Inc.
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

package com.netflix.spinnaker.gate.config

import com.netflix.spinnaker.fiat.shared.FiatClientConfigurationProperties
import com.netflix.spinnaker.fiat.shared.FiatPermissionEvaluator
import com.netflix.spinnaker.fiat.shared.FiatStatus
import com.netflix.spinnaker.gate.filters.FiatSessionFilter
import com.netflix.spinnaker.gate.services.PermissionService
import com.netflix.spinnaker.gate.services.ServiceAccountFilterConfigProps
import com.netflix.spinnaker.security.User
import groovy.util.logging.Slf4j
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.stereotype.Component

import jakarta.servlet.Filter
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

@Slf4j
@Configuration
@EnableConfigurationProperties([ServiceConfiguration, ServiceAccountFilterConfigProps])
class AuthConfig {

  @Autowired
  PermissionRevokingLogoutSuccessHandler permissionRevokingLogoutSuccessHandler

  @Autowired
  SecurityProperties securityProperties

  @Autowired
  FiatClientConfigurationProperties configProps

  @Autowired
  FiatStatus fiatStatus

  @Autowired
  FiatPermissionEvaluator permissionEvaluator

  @Autowired
  RequestMatcherProvider requestMatcherProvider

  @Value('${security.debug:false}')
  boolean securityDebug

  @Value('${fiat.session-filter.enabled:true}')
  boolean fiatSessionFilterEnabled

  @Value('${security.webhooks.default-auth-enabled:false}')
  boolean webhookDefaultAuthEnabled

  void configure(HttpSecurity http) throws Exception {
    // @formatter:off
    http
      .authorizeHttpRequests((authz) ->
        authz
          .requestMatchers(new AntPathRequestMatcher("/error")).permitAll()
          .requestMatchers(new AntPathRequestMatcher('/favicon.ico')).permitAll()
          .requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.OPTIONS, "/**")).permitAll()
          .requestMatchers(new AntPathRequestMatcher(PermissionRevokingLogoutSuccessHandler.LOGGED_OUT_URL)).permitAll()
          .requestMatchers(new AntPathRequestMatcher('/auth/user')).permitAll()
          .requestMatchers(new AntPathRequestMatcher('/plugins/deck/**')).permitAll()
          .requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.POST, '/webhooks/**')).permitAll()
          .requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.POST, '/notifications/callbacks/**')).permitAll()
          .requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.POST, '/managed/notifications/callbacks/**')).permitAll()
          .requestMatchers(new AntPathRequestMatcher('/health')).permitAll()
          .requestMatchers(new AntPathRequestMatcher('/**')).authenticated()
      )

    if (fiatSessionFilterEnabled) {
      Filter fiatSessionFilter = new FiatSessionFilter(
        fiatSessionFilterEnabled,
        fiatStatus,
        permissionEvaluator)

      http.addFilterBefore(fiatSessionFilter, AnonymousAuthenticationFilter.class)
    }

    if (webhookDefaultAuthEnabled) {
      http.authorizeHttpRequests(
        (requests) ->
          requests
            .requestMatchers(new AntPathRequestMatcher(HttpMethod.POST, "/webhooks/**")).authenticated());
    }

    http.logout()
        .logoutUrl("/auth/logout")
        .logoutSuccessHandler(permissionRevokingLogoutSuccessHandler)
        .permitAll()
        .and()
      .csrf()
        .disable()
    // @formatter:on
  }

  void configure(WebSecurity web) throws Exception {
    web.debug(securityDebug)
  }

  @Component
  static class PermissionRevokingLogoutSuccessHandler implements LogoutSuccessHandler, InitializingBean {

    static final String LOGGED_OUT_URL = "/auth/loggedOut"

    @Autowired
    PermissionService permissionService

    SimpleUrlLogoutSuccessHandler delegate = new SimpleUrlLogoutSuccessHandler();

    @Override
    void afterPropertiesSet() throws Exception {
      delegate.setDefaultTargetUrl(LOGGED_OUT_URL)
    }

    @Override
    void onLogoutSuccess(HttpServletRequest request,
                         HttpServletResponse response,
                         Authentication authentication) throws IOException, ServletException {
      def username = (authentication?.getPrincipal() as User)?.username
      if (username) {
        permissionService.logout(username)
      }
      delegate.onLogoutSuccess(request, response, authentication)
    }
  }
}

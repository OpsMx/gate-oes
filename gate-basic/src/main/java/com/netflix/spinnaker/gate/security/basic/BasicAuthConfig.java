/*
 * Copyright 2018 Google, Inc.
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

package com.netflix.spinnaker.gate.security.basic;

import com.netflix.spinnaker.gate.config.AuthConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.session.web.http.DefaultCookieSerializer;

@ConditionalOnExpression("${security.basicform.enabled:false}")
@Configuration
@EnableWebSecurity
public class BasicAuthConfig {

  private final AuthConfig authConfig;

  private final BasicAuthProvider authProvider;

  @Autowired DefaultCookieSerializer defaultCookieSerializer;

  @Autowired
  public BasicAuthConfig(AuthConfig authConfig, SecurityProperties securityProperties) {
    this.authConfig = authConfig;
    this.authProvider = new BasicAuthProvider(securityProperties);
  }

  @Bean
  public SecurityFilterChain configure(HttpSecurity http) throws Exception {
    defaultCookieSerializer.setSameSite(null);
    http.formLogin()
        .and()
        .httpBasic()
        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
    authConfig.configure(http);
    return http.build();
  }
}

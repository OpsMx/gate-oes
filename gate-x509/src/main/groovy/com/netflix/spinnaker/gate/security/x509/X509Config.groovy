/*
 * Copyright 2015 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//file:noinspection GroovyAssignabilityCheck
//file:noinspection GroovyAccessibility

package com.netflix.spinnaker.gate.security.x509

import com.netflix.spinnaker.gate.config.AuthConfig
import com.netflix.spinnaker.gate.security.SpinnakerAuthConfig
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.context.NullSecurityContextRepository

@ConditionalOnExpression('${x509.enabled:false}')
@Configuration
@SpinnakerAuthConfig
@EnableWebSecurity
//ensure this configures after a standard WebSecurityConfigurerAdapter (1000) so
// it becomes the fallthrough for a mixed mode of some SSO + x509 for API calls
// and otherwise will just work(tm) if it is the only WebSecurityConfigurerAdapter
// present as well
@Order(2000)
class X509Config {

  @Value('${x509.subject-principal-regex:}')
  String subjectPrincipalRegex

  @Autowired
  AuthConfig authConfig

  @Autowired
  X509AuthenticationUserDetailsService x509AuthenticationUserDetailsService

  @Bean
  public SecurityFilterChain x509FilterChain(HttpSecurity http) throws Exception {
    authConfig.configure(http)
    http.securityContext().securityContextRepository(new NullSecurityContextRepository())
    http.x509().authenticationUserDetailsService(x509AuthenticationUserDetailsService)

    if (subjectPrincipalRegex) {
      http.x509().subjectPrincipalRegex(subjectPrincipalRegex)
    }
    //x509 is the catch-all if configured, this will auth apiPort connections and
    // any additional ports that get installed and removes the requestMatcher
    // installed by authConfig
    return http.build()
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> authConfig.configure(web)
  }

  @Bean
  X509IdentityExtractor x509IdentityExtractor() {
    return new X509IdentityExtractor(x509AuthenticationUserDetailsService)
  }
}

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

package com.opsmx.spinnaker.gate.security.saml;

import com.netflix.spinnaker.gate.config.AuthConfig;
import com.netflix.spinnaker.gate.security.SpinnakerAuthConfig;
import com.netflix.spinnaker.gate.services.PermissionService;
import com.netflix.spinnaker.security.User;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.session.DefaultCookieSerializerCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
@SpinnakerAuthConfig
@ConditionalOnExpression("${spring.security.saml2.enabled:false}")
public class SamlSecurityConfiguration {

  @Autowired private AuthConfig authConfig;

  @Value("${spring.security.saml2.groupAttribute:memberOf}")
  private String groupAttribute;

  @Autowired private PermissionService permissionService;

  @Bean
  public SecurityFilterChain samlFilterChain(HttpSecurity http) throws Exception {

    log.info("Configuring SAML Security");

    OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
    authenticationProvider.setResponseAuthenticationConverter(groupsConverter());

    authConfig.configure(http);

    http.saml2Login(
            saml2 -> saml2.authenticationManager(new ProviderManager(authenticationProvider)))
        .saml2Logout(Customizer.withDefaults());

    return http.build();
  }

  private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2UserDetails>
      groupsConverter() {

    Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> delegate =
        OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

    return responseToken -> {
      Saml2Authentication authentication = delegate.convert(responseToken);
      Saml2AuthenticatedPrincipal principal =
          (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
      log.info(
          "********************SAML attributes **************************************** : {}",
          principal.getAttributes());
      List<String> groups = principal.getAttribute(groupAttribute);
      Set<GrantedAuthority> authorities = new HashSet<>();
      if (groups != null) {
        groups.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
      } else {
        authorities.addAll(authentication.getAuthorities());
      }

      Assertion assertion = responseToken.getResponse().getAssertions().get(0);
      String username = assertion.getSubject().getNameID().getValue();

      User user = new User();
      user.setRoles(groups);
      user.setUsername(username);
      user.setFirstName("First Name");
      user.setLastName("Last name");

      permissionService.loginWithRoles(username, groups);

      return new Saml2UserDetails(authentication, user);
    };
  }

  @Bean
  public DefaultCookieSerializerCustomizer cookieSerializerCustomizer() {
    return cookieSerializer -> cookieSerializer.setSameSite(null);
  }
}

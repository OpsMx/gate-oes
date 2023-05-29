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

import com.netflix.spectator.api.Registry;
import com.netflix.spinnaker.fiat.shared.FiatClientConfigurationProperties;
import com.netflix.spinnaker.gate.config.AuthConfig;
import com.netflix.spinnaker.gate.security.AllowedAccountsSupport;
import com.netflix.spinnaker.gate.security.SpinnakerAuthConfig;
import com.netflix.spinnaker.gate.services.PermissionService;
import com.netflix.spinnaker.kork.core.RetrySupport;
import com.netflix.spinnaker.security.User;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.beans.factory.annotation.Autowired;
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

  @Autowired private Saml2UserAttributeMapping saml2UserAttributeMapping;

  @Autowired private PermissionService permissionService;

  @Autowired private Registry registry;

  private RetrySupport retrySupport = new RetrySupport();

  @Autowired private AllowedAccountsSupport allowedAccountsSupport;

  @Autowired private FiatClientConfigurationProperties fiatClientConfigurationProperties;

  @Bean
  public SecurityFilterChain samlFilterChain(HttpSecurity http) throws Exception {

    log.info("Configuring SAML Security");

    OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
    authenticationProvider.setResponseAuthenticationConverter(extractUserDetails());

    authConfig.configure(http);

    http.saml2Login(
            saml2 -> saml2.authenticationManager(new ProviderManager(authenticationProvider)))
        .saml2Logout(Customizer.withDefaults());

    return http.build();
  }

  private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2UserDetails>
      extractUserDetails() {

    log.debug("**Extracting user details**");

    Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> delegate =
        OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

    return responseToken -> {
      Saml2Authentication authentication = delegate.convert(responseToken);
      Saml2AuthenticatedPrincipal principal =
          (Saml2AuthenticatedPrincipal) authentication.getPrincipal();

      List<String> roles = principal.getAttribute(saml2UserAttributeMapping.getRoles());
      String firstName = principal.getFirstAttribute(saml2UserAttributeMapping.getFirstName());
      String lastName = principal.getFirstAttribute(saml2UserAttributeMapping.getLastName());
      String email = principal.getFirstAttribute(saml2UserAttributeMapping.getEmail());

      Set<GrantedAuthority> authorities = new HashSet<>();
      if (roles != null) {
        roles.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
      } else {
        authorities.addAll(authentication.getAuthorities());
      }
      Assertion assertion = responseToken.getResponse().getAssertions().get(0);
      String username = assertion.getSubject().getNameID().getValue();

      User user = new User();
      user.setRoles(roles);
      user.setUsername(username);
      user.setFirstName(firstName);
      user.setLastName(lastName);
      user.setEmail(email);
      user.setAllowedAccounts(allowedAccountsSupport.filterAllowedAccounts(username, roles));

      loginWithRoles(username, roles);

      return new Saml2UserDetails(authentication, user);
    };
  }

  private void loginWithRoles(String username, List<String> roles) {

    var id = registry.createId("fiat.login").withTag("type", "saml");

    try {
      retrySupport.retry(
          () -> {
            permissionService.loginWithRoles(username, roles);
            return null;
          },
          5,
          2000,
          Boolean.FALSE);

      log.debug(
          "Successful SAML authentication (user: {}, roleCount: {}, roles: {})",
          username,
          roles.size(),
          roles);
      id = id.withTag("success", true).withTag("fallback", "none");
    } catch (Exception e) {
      log.debug(
          "Unsuccessful SAML authentication (user: {}, roleCount: {}, roles: {}, legacyFallback: {})",
          username,
          roles.size(),
          roles,
          fiatClientConfigurationProperties.isLegacyFallback(),
          e);
      id =
          id.withTag("success", false)
              .withTag("fallback", fiatClientConfigurationProperties.isLegacyFallback());

      if (!fiatClientConfigurationProperties.isLegacyFallback()) {
        throw e;
      }
    } finally {
      registry.counter(id).increment();
    }
  }

  @Bean
  public DefaultCookieSerializerCustomizer cookieSerializerCustomizer() {
    return cookieSerializer -> cookieSerializer.setSameSite(null);
  }
}

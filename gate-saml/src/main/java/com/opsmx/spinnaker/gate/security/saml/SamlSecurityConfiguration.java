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
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties;
import org.springframework.boot.autoconfigure.session.DefaultCookieSerializerCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

@Slf4j
@Configuration
@EnableWebSecurity
@SpinnakerAuthConfig
@ConditionalOnExpression("${spring.security.saml2.enabled:false}")
public class SamlSecurityConfiguration {

  @Value("${spring.security.saml2.registration-id}")
  private String registrationId;

  @Autowired private AuthConfig authConfig;

  @Autowired private Saml2UserAttributeMapping saml2UserAttributeMapping;

  @Autowired private PermissionService permissionService;

  @Autowired private Registry registry;

  private RetrySupport retrySupport = new RetrySupport();

  @Autowired private AllowedAccountsSupport allowedAccountsSupport;

  @Autowired private FiatClientConfigurationProperties fiatClientConfigurationProperties;

  @Autowired private Saml2RelyingPartyProperties relyingPartyProperties;

  private URI acsLocation;

  private String loginProcessingUrl;

  public static final String defaultFilterUrl =
      "{baseUrl}" + Saml2WebSsoAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI;

  @Bean
  public UserDetailsService userDetailsService() {
    return username -> {
      User user = new User();
      user.setUsername(username);
      return user;
    };
  }

  @Bean
  public RememberMeServices rememberMeServices(UserDetailsService userDetailsService) {
    TokenBasedRememberMeServices rememberMeServices =
        new TokenBasedRememberMeServices("password", userDetailsService);
    rememberMeServices.setCookieName("cookieName");
    rememberMeServices.setParameter("rememberMe");
    return rememberMeServices;
  }

  @Bean
  public OpenSaml4AuthenticationProvider authenticationProvider() {
    var authProvider = new OpenSaml4AuthenticationProvider();
    authProvider.setResponseAuthenticationConverter(extractUserDetails());
    return authProvider;
  }

  @Bean
  public ProviderManager authenticationManager(
      OpenSaml4AuthenticationProvider authenticationProvider) {
    return new ProviderManager(authenticationProvider);
  }

  @Bean
  public Saml2WebSsoAuthenticationFilter saml2WebSsoAuthenticationFilter(
      RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
      AuthenticationManager authenticationManager) {
    log.info(
        "ACS endpoint configured : {}",
        relyingPartyProperties.getRegistration().get(registrationId).getAcs().getLocation());
    Saml2WebSsoAuthenticationFilter saml2WebSsoAuthenticationFilter;
    if (!relyingPartyProperties
        .getRegistration()
        .get(registrationId)
        .getAcs()
        .getLocation()
        .equalsIgnoreCase(defaultFilterUrl)) {
      initAcsUri();
      saml2WebSsoAuthenticationFilter =
          new Saml2WebSsoAuthenticationFilter(
              relyingPartyRegistrationRepository, loginProcessingUrl);
    } else {
      saml2WebSsoAuthenticationFilter =
          new Saml2WebSsoAuthenticationFilter(relyingPartyRegistrationRepository);
    }

    saml2WebSsoAuthenticationFilter.setAuthenticationManager(authenticationManager);
    saml2WebSsoAuthenticationFilter.setSecurityContextRepository(
        new HttpSessionSecurityContextRepository());
    saml2WebSsoAuthenticationFilter.setSessionAuthenticationStrategy(
        new ChangeSessionIdAuthenticationStrategy());

    return saml2WebSsoAuthenticationFilter;
  }

  private void initAcsUri() {
    try {
      acsLocation =
          new URI(
              relyingPartyProperties.getRegistration().get(registrationId).getAcs().getLocation());
      loginProcessingUrl = acsLocation.getPath().replace(registrationId, "{registrationId}");
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    } catch (Exception e) {
      log.error("Exception occurred while reading the ACS endpoint : ", e);
      throw e;
    }
  }

  @Bean
  public SecurityFilterChain samlFilterChain(
      HttpSecurity http,
      RememberMeServices rememberMeServices,
      Saml2WebSsoAuthenticationFilter webSsoAuthenticationFilter,
      ProviderManager authenticationManager)
      throws Exception {

    log.info("Configuring SAML Security");

    authConfig.configure(http);

    http.saml2Login(
            saml2 -> {
              saml2.authenticationManager(authenticationManager);
              if (!relyingPartyProperties
                  .getRegistration()
                  .get(registrationId)
                  .getAcs()
                  .getLocation()
                  .equalsIgnoreCase(defaultFilterUrl)) {
                saml2.loginProcessingUrl(loginProcessingUrl);
              }
            })
        .rememberMe(remember -> remember.rememberMeServices(rememberMeServices))
        .addFilter(webSsoAuthenticationFilter)
        .saml2Logout(Customizer.withDefaults());

    return http.build();
  }

  private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2UserDetails>
      extractUserDetails() {

    log.debug("**Extracting user details**");

    Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> delegate =
        OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

    return responseToken -> {
      List<String> roles = new ArrayList<>();
      log.debug("responseToken : {}", responseToken);
      Saml2Authentication authentication = delegate.convert(responseToken);
      Saml2AuthenticatedPrincipal principal =
          (Saml2AuthenticatedPrincipal) authentication.getPrincipal();

      log.debug("role attribute in config : {}", saml2UserAttributeMapping.getRoles());
      log.debug("firstName attribute in config : {}", saml2UserAttributeMapping.getFirstName());
      log.debug("lastName attribute in config : {}", saml2UserAttributeMapping.getLastName());
      log.debug("email attribute in config : {}", saml2UserAttributeMapping.getEmail());
      log.debug(
          "rolesDelimiter in config : {}",
          saml2UserAttributeMapping.getRoles().getRolesDelimiter());

      List<String> rolesExtractedFromIDP =
          principal.getAttribute(saml2UserAttributeMapping.getRoles().getAttributeName());
      String firstName = principal.getFirstAttribute(saml2UserAttributeMapping.getFirstName());
      String lastName = principal.getFirstAttribute(saml2UserAttributeMapping.getLastName());
      String email = principal.getFirstAttribute(saml2UserAttributeMapping.getEmail());
      Assertion assertion = responseToken.getResponse().getAssertions().get(0);
      log.info("assertion : {}", assertion);
      log.info("encrypted assertion : {}", responseToken.getResponse().getEncryptedAssertions());
      String username = assertion.getSubject().getNameID().getValue();

      if (rolesExtractedFromIDP != null) {
        if (saml2UserAttributeMapping.getRoles().getRolesDelimiter() != null) {
          for (String role : rolesExtractedFromIDP) {
            roles.addAll(
                Arrays.stream(role.split(saml2UserAttributeMapping.getRoles().getRolesDelimiter()))
                    .toList());
          }
        } else {
          roles = rolesExtractedFromIDP;
        }
        if (saml2UserAttributeMapping.getRoles().isForceLowercaseRoles()) {
          roles = roles.stream().map(String::toLowerCase).toList();
        }

        if (saml2UserAttributeMapping.getRoles().isSortRoles()) {
          roles = roles.stream().sorted().toList();
        }
        if (saml2UserAttributeMapping.getRoles().getRequiredRoles() != null) {
          if (!roles.containsAll(saml2UserAttributeMapping.getRoles().getRequiredRoles())) {
            throw new BadCredentialsException(
                String.format(
                    "User %s does not have all roles %s",
                    username, saml2UserAttributeMapping.getRoles().getRequiredRoles()));
          }
        }
      }

      User user = new User();
      user.setRoles(roles);
      user.setUsername(username);
      user.setFirstName(firstName);
      user.setLastName(lastName);
      user.setEmail(email);
      user.setAllowedAccounts(allowedAccountsSupport.filterAllowedAccounts(username, roles));

      log.debug("username extracted from responseToken : {}", username);
      log.debug("firstName extracted from responseToken : {}", firstName);
      log.debug("lastName extracted from responseToken : {}", lastName);
      log.debug("email extracted from responseToken : {}", email);
      log.debug("roles extracted from responseToken : {}", roles);

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

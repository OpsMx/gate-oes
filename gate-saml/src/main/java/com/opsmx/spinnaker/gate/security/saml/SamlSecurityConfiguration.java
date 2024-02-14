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
import java.util.*;
import javax.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.session.DefaultCookieSerializerCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;

@Slf4j
@Configuration
@EnableWebSecurity
@SpinnakerAuthConfig
@ConditionalOnExpression("${spring.security.saml2.enabled:false}")
public class SamlSecurityConfiguration {

  @Autowired private AuthConfig authConfig;

  @Autowired private Saml2UserAttributeMapping saml2UserAttributeMapping;

  @Autowired private Saml2Config saml2Config;

  @Autowired private PermissionService permissionService;

  @Autowired private Registry registry;

  private RetrySupport retrySupport = new RetrySupport();

  @Autowired private AllowedAccountsSupport allowedAccountsSupport;

  @Autowired private FiatClientConfigurationProperties fiatClientConfigurationProperties;

  @Autowired private UserDetailsService userDetailsService;

  @PostConstruct
  public void validate() {
    // Validate signature digest algorithm
    SignatureAlgorithms.fromName(saml2Config.getSignatureDigest());
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
  public SecurityFilterChain samlFilterChain(
      HttpSecurity http, RememberMeServices rememberMeServices) throws Exception {

    log.info("Configuring SAML Security");

    OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
    authenticationProvider.setResponseAuthenticationConverter(extractUserDetails());

    authConfig.configure(http);

    http.saml2Login(
            saml2 -> {
              saml2.authenticationManager(new ProviderManager(authenticationProvider));
              saml2.loginProcessingUrl("/saml/sso");
            })
        .rememberMe(remember -> remember.rememberMeServices(rememberMeServices))
        .saml2Logout(Customizer.withDefaults());

    initSignatureDigest();

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
      log.debug("rolesDelimiter in config : {}", saml2UserAttributeMapping.getRolesDelimiter());

      List<String> rolesExtractedFromIDP =
          principal.getAttribute(saml2UserAttributeMapping.getRoles().getAttributeName());
      String firstName = principal.getFirstAttribute(saml2UserAttributeMapping.getFirstName());
      String lastName = principal.getFirstAttribute(saml2UserAttributeMapping.getLastName());
      String email = principal.getFirstAttribute(saml2UserAttributeMapping.getEmail());
      Assertion assertion = responseToken.getResponse().getAssertions().get(0);
      String username = assertion.getSubject().getNameID().getValue();

      Set<GrantedAuthority> authorities = new HashSet<>();
      if (rolesExtractedFromIDP != null) {
        if (saml2UserAttributeMapping.getRolesDelimiter() != null) {
          for (String role : rolesExtractedFromIDP) {
            roles.addAll(
                Arrays.stream(role.split(saml2UserAttributeMapping.getRolesDelimiter())).toList());
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
        roles.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
      } else {
        authorities.addAll(authentication.getAuthorities());
      }

      UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

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

      return new Saml2UserDetails(authentication, userDetails);
    };
  }

  private void initSignatureDigest() {
    var secConfig = org.opensaml.Configuration.getGlobalSecurityConfiguration();
    if (secConfig instanceof BasicSecurityConfiguration basicSecConfig) {
      var algo = SignatureAlgorithms.fromName(saml2Config.getSignatureDigest());
      log.info("Using " + algo + " digest for signing SAML messages");
      basicSecConfig.registerSignatureAlgorithmURI("RSA", algo.rsaSignatureMethod);
      basicSecConfig.setSignatureReferenceDigestMethod(algo.digestMethod);
    } else {
      log.warn(
          "Unable to find global BasicSecurityConfiguration (found "
              + secConfig
              + "). Ignoring signatureDigest configuration value.");
    }
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

  // Available digests taken from org.opensaml.xml.signature.SignatureConstants (RSA signatures)
  private enum SignatureAlgorithms {
    SHA1(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, SignatureConstants.ALGO_ID_DIGEST_SHA1),
    SHA256(
        SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, SignatureConstants.ALGO_ID_DIGEST_SHA256),
    SHA384(
        SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384, SignatureConstants.ALGO_ID_DIGEST_SHA384),
    SHA512(
        SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512, SignatureConstants.ALGO_ID_DIGEST_SHA512),
    RIPEMD160(
        SignatureConstants.ALGO_ID_SIGNATURE_RSA_RIPEMD160,
        SignatureConstants.ALGO_ID_DIGEST_RIPEMD160),
    MD5(
        SignatureConstants.ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5,
        SignatureConstants.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5);

    String rsaSignatureMethod;
    String digestMethod;

    SignatureAlgorithms(String rsaSignatureMethod, String digestMethod) {
      this.rsaSignatureMethod = rsaSignatureMethod;
      this.digestMethod = digestMethod;
    }

    static SignatureAlgorithms fromName(String digestName) {
      try {
        return SignatureAlgorithms.valueOf(digestName.toUpperCase());
      } catch (IllegalArgumentException e) {
        throw new IllegalStateException(
            "Invalid saml.signatureDigest value "
                + digestName
                + ". Valid values are "
                + Arrays.toString(SignatureAlgorithms.values()));
      }
    }
  }
}

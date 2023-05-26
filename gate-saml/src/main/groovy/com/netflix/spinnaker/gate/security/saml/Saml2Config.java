/*
 * Copyright 2023 Netflix, Inc.
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

package com.netflix.spinnaker.gate.security.saml;

import com.netflix.spinnaker.gate.config.AuthConfig;
import com.netflix.spinnaker.gate.security.SpinnakerAuthConfig;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.session.DefaultCookieSerializerCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
@SpinnakerAuthConfig
@ConditionalOnExpression("${saml.java.enabled:false}")
public class Saml2Config {

  @Bean
  public SecurityFilterChain saml2FilterChain(HttpSecurity http) throws Exception {

    OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();

    authenticationProvider.setResponseAuthenticationConverter(groupsConverter());

    // @formatter:off
    http.authorizeHttpRequests(
            authorize ->
                authorize
                    .requestMatchers("/error", "/favicon.ico", "/auth/user", "/health")
                    .permitAll()
                    .requestMatchers(HttpMethod.OPTIONS, "/**")
                    .permitAll()
                    .requestMatchers(
                        AuthConfig.PermissionRevokingLogoutSuccessHandler.getLOGGED_OUT_URL())
                    .permitAll()
                    .requestMatchers("/plugins/deck/**")
                    .permitAll()
                    .requestMatchers(HttpMethod.POST, "/webhooks/**")
                    .permitAll()
                    .requestMatchers(HttpMethod.POST, "/notifications/callbacks/**")
                    .permitAll()
                    .requestMatchers(HttpMethod.POST, "/managed/notifications/callbacks/**")
                    .permitAll()
                    .requestMatchers("/**")
                    .authenticated())
        .saml2Login(
            saml2 -> saml2.authenticationManager(new ProviderManager(authenticationProvider)))
        .saml2Logout(Customizer.withDefaults())
        .csrf()
        .disable();
    // @formatter:on

    return http.build();
  }

  @Bean
  public RelyingPartyRegistrationResolver relyingPartyRegistrationResolver(
      RelyingPartyRegistrationRepository registrations) {
    return new DefaultRelyingPartyRegistrationResolver(
        (id) -> registrations.findByRegistrationId("two"));
  }

  @Bean
  public Saml2AuthenticationTokenConverter authentication(
      RelyingPartyRegistrationResolver registrations) {
    return new Saml2AuthenticationTokenConverter(registrations);
  }

  @Bean
  public FilterRegistrationBean<Saml2MetadataFilter> metadata(
      RelyingPartyRegistrationResolver registrations) {
    Saml2MetadataFilter metadata =
        new Saml2MetadataFilter(registrations, new OpenSamlMetadataResolver());
    FilterRegistrationBean<Saml2MetadataFilter> filter = new FilterRegistrationBean<>(metadata);
    filter.setOrder(-101);
    return filter;
  }

  @Bean
  public RelyingPartyRegistrationRepository repository() {

    Saml2X509Credential signing =
        Saml2X509Credential.signing(getRSAPrivateKey(), relyingPartyCertificate());
    RelyingPartyRegistration two =
        RelyingPartyRegistrations.fromMetadataLocation(
                /*"https://dev-67279665.okta.com/app/exk8r4izcvIcvjMSc5d7/sso/saml/metadata"*/
                "https://dev-67279665.okta.com/app/exk8r4izcvIcvjMSc5d7/sso/saml/metadata")
            .registrationId("two")
            .signingX509Credentials((c) -> c.add(signing))
            //              .singleLogoutServiceLocation("http://localhost:8084/logout/saml2/slo")
            .entityId("http://www.okta.com/exk8r4izcvIcvjMSc5d7")
            .build();
    return new InMemoryRelyingPartyRegistrationRepository(two);
  }

  @Bean
  public DefaultCookieSerializerCustomizer cookieSerializerCustomizer() {
    return cookieSerializer -> cookieSerializer.setSameSite(null);
  }

  //  @Bean
  //  public WebSSOProfileConsumer webSSOprofileConsumerImpl() {
  //    WebSSOProfileConsumerImpl profileConsumer = new WebSSOProfileConsumerImpl();
  //    profileConsumer.setMaxAuthenticationAge(7200);
  //    return profileConsumer;
  //  }

  private RSAPrivateKey getRSAPrivateKey() {
    Resource resource =
        new FileSystemResource("/home/pranav/isd-releases/ConfigureAuthProvider/newSaml/local.key");
    try (InputStream is = resource.getInputStream()) {
      return RsaKeyConverters.pkcs8().convert(is);
    } catch (Exception e) {
      log.error("Exception while getting the private key : {}", e);
      throw new RuntimeException();
    }
  }

  private X509Certificate relyingPartyCertificate() {
    Resource resource =
        new FileSystemResource("/home/pranav/isd-releases/ConfigureAuthProvider/newSaml/local.crt");
    try (InputStream is = resource.getInputStream()) {
      return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
    } catch (Exception ex) {
      throw new UnsupportedOperationException(ex);
    }
  }

  private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication>
      groupsConverter() {

    Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> delegate =
        OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

    return responseToken -> {
      Saml2Authentication authentication = delegate.convert(responseToken);
      Saml2AuthenticatedPrincipal principal =
          (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
      List<String> groups = principal.getAttribute("memberOf");
      Set<GrantedAuthority> authorities = new HashSet<>();
      if (groups != null) {
        groups.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
      } else {
        authorities.addAll(authentication.getAuthorities());
      }
      return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
    };
  }
}

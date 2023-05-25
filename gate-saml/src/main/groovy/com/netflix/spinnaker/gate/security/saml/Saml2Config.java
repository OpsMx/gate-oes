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

import com.netflix.spinnaker.gate.security.SpinnakerAuthConfig;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.core.Saml2X509Credential;
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
@ConditionalOnExpression("${saml.enabled:false}")
public class Saml2Config {

  @Bean
  public SecurityFilterChain saml2FilterChain(HttpSecurity http) throws Exception {
    // @formatter:off
    http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
        .saml2Login(Customizer.withDefaults())
        .saml2Logout(Customizer.withDefaults());
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
                "https://dev-67279665.okta.com/app/exk8r4izcvIcvjMSc5d7/sso/saml/metadata")
            .registrationId("two")
            .signingX509Credentials((c) -> c.add(signing))
            .singleLogoutServiceLocation("http://localhost:8084/logout/saml2/slo")
            .build();
    return new InMemoryRelyingPartyRegistrationRepository(two);
  }

  private RSAPrivateKey getRSAPrivateKey() {
    Resource resource =
        new FileSystemResource(
            "/home/pranav/isd-releases/ConfigureAuthProvider/samlNewprivate.key");
    try (InputStream is = resource.getInputStream()) {
      return RsaKeyConverters.pkcs8().convert(is);
    } catch (Exception e) {
      log.error("Exception while getting the private key : {}", e);
      throw new RuntimeException();
    }
  }

  private X509Certificate relyingPartyCertificate() {
    Resource resource =
        new FileSystemResource("/home/pranav/isd-releases/ConfigureAuthProvider/spinSaml.crt");
    try (InputStream is = resource.getInputStream()) {
      return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
    } catch (Exception ex) {
      throw new UnsupportedOperationException(ex);
    }
  }
}

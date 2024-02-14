/*
 * Copyright 2024 OpsMx, Inc.
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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;

public class SamlSecurityConfigurationTest {

  @Test
  public void testUserDetailsExtractionFromSamlResponseToken()
      throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
    HttpSecurity httpSecurity = new HttpSecurity();

    Method extractUserDetails =
        SamlSecurityConfiguration.class.getDeclaredMethod("extractUserDetails");
    extractUserDetails.setAccessible(true);
    Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2UserDetails> userDetails =
        (Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2UserDetails>)
            extractUserDetails.invoke(SamlSecurityConfiguration.class);
  }
}

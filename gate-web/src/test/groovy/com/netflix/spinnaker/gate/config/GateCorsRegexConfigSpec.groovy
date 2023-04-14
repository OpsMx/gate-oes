/*
 * Copyright 2019 Netflix, Inc.
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

package com.netflix.spinnaker.gate.config

import com.netflix.spinnaker.fiat.shared.FiatService
import com.netflix.spinnaker.gate.Main
import com.netflix.spinnaker.gate.services.internal.ClouddriverService
import com.netflix.spinnaker.gate.services.internal.ClouddriverServiceSelector
import com.netflix.spinnaker.gate.services.internal.ExtendedFiatService
import com.netflix.spinnaker.gate.services.internal.Front50Service
import com.netflix.spinnaker.gate.services.internal.OrcaServiceSelector
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import spock.lang.Specification

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@SpringBootTest(classes = Main)
@ActiveProfiles('regexcors')
@TestPropertySource(properties = ["spring.config.location=classpath:gate-test.yml", "retrofit.enabled=true"])
class GateCorsRegexConfigSpec { /*extends Specification

  @Autowired
  private MockMvc mvc

  @MockBean ClouddriverService clouddriverService;

  @MockBean
  ClouddriverServiceSelector clouddriverServiceSelector;

  @MockBean
  private Front50Service front50Service

  @MockBean
  private OrcaServiceSelector orcaServiceSelector

  @MockBean
  private FiatService fiatService

  @MockBean
  private ExtendedFiatService extendedFiatService

  def "cors filter should set the allowed origin header to localhost"() {
    expect:
    mvc.perform(get("/version").header('Origin', 'https://localhost'))
      .andExpect(status().isOk())
      .andExpect(header().stringValues('Access-Control-Allow-Origin', 'https://localhost'))
      .andReturn()
      .response
      .contentAsString.length() > 0 // Got some content.
  }

  def "cors filter should set the allowed origin header to *(allow all)"() {
    expect:
    mvc.perform(get("/version").header('Origin', 'https://test.blah.com'))
      .andExpect(status().isOk())
      .andExpect(header().stringValues('Access-Control-Allow-Origin', '*'))
      .andReturn()
      .response
      .contentAsString.length() > 0 // Got some content.
  }

  def "cors filter should set the allowed origin header to testblah.somewhere.net"() {
    expect:
    mvc.perform(get("/version").header('Origin', 'https://testblah.somewhere.net'))
      .andExpect(status().isOk())
      .andExpect(header().stringValues('Access-Control-Allow-Origin', 'https://testblah.somewhere.net'))
      .andReturn()
      .response
      .contentAsString.length() > 0 // Got some content.
  }*/

}

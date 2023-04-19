/*
 * Copyright 2017 Google, Inc.
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
package com.netflix.spinnaker.gate.security.basic

import com.netflix.spinnaker.fiat.shared.FiatService
import com.netflix.spinnaker.gate.Main
import com.netflix.spinnaker.gate.config.GateConfig
import com.netflix.spinnaker.gate.config.RedisTestConfig
import com.netflix.spinnaker.gate.health.DownstreamServicesHealthIndicator
import com.netflix.spinnaker.gate.security.FormLoginRequestBuilder
import com.netflix.spinnaker.gate.security.GateSystemTest
import com.netflix.spinnaker.gate.security.YamlFileApplicationContextInitializer
import com.netflix.spinnaker.gate.services.AccountLookupService
import com.netflix.spinnaker.gate.services.internal.ClouddriverService
import com.netflix.spinnaker.gate.services.internal.ClouddriverServiceSelector
import com.netflix.spinnaker.gate.services.internal.EchoService
import com.netflix.spinnaker.gate.services.internal.ExtendedFiatService
import com.netflix.spinnaker.gate.services.internal.Front50Service
import com.netflix.spinnaker.gate.services.internal.OrcaServiceSelector
import com.netflix.spinnaker.gate.services.internal.RoscoService
import com.netflix.spinnaker.gate.services.internal.RoscoServiceSelector
import groovy.util.logging.Slf4j
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.http.HttpHeaders
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.MvcResult
import org.springframework.util.Base64Utils
import spock.lang.Specification

import jakarta.servlet.http.Cookie

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*

@Slf4j
@GateSystemTest
@SpringBootTest(properties = ["retrofit.enabled=true","fiat.enabled=false"])
@ContextConfiguration(
  classes = [Main, GateConfig, BasicAuthConfig, BasicTestConfig, RedisTestConfig],
  initializers = YamlFileApplicationContextInitializer
)
@AutoConfigureMockMvc
@TestPropertySource("/basic-auth.properties")
class BasicAuthSpec extends Specification {

  @Autowired
  MockMvc mockMvc

  @MockBean
  private FiatService fiatService

  @MockBean
  private ExtendedFiatService extendedFiatService

  @MockBean
  private ClouddriverService clouddriverService

  @MockBean
  ClouddriverServiceSelector clouddriverServiceSelector

  @MockBean
  private Front50Service front50Service

  @MockBean
  private OrcaServiceSelector orcaServiceSelector

  @MockBean
  private EchoService echoService;

  @MockBean
  private RoscoService roscoService;

  @MockBean
  RoscoServiceSelector roscoServiceSelector

  @MockBean
  private DownstreamServicesHealthIndicator downstreamServicesHealthIndicator;



  static class BasicTestConfig {

    @Bean
    RedisTestConfig redisTestConfig() {
      new RedisTestConfig()
    }

    @Bean
    @Primary
    AccountLookupService accountLookupService() {
      return new AccountLookupService() {
        @Override
        List<ClouddriverService.AccountDetails> getAccounts() {
          return [
            new ClouddriverService.AccountDetails(name: "foo")
          ]
        }
      }
    }

  }
}

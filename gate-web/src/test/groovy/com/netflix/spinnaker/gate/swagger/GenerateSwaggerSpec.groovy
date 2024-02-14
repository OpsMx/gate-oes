package com.netflix.spinnaker.gate.swagger

import com.netflix.spinnaker.fiat.shared.FiatService
import com.netflix.spinnaker.gate.Main
import com.netflix.spinnaker.gate.health.DownstreamServicesHealthIndicator
import com.netflix.spinnaker.gate.security.GateSystemTest
import com.netflix.spinnaker.gate.security.YamlFileApplicationContextInitializer
import com.netflix.spinnaker.gate.services.internal.ClouddriverService
import com.netflix.spinnaker.gate.services.internal.ClouddriverServiceSelector
import com.netflix.spinnaker.gate.services.internal.EchoService
import com.netflix.spinnaker.gate.services.internal.ExtendedFiatService
import com.netflix.spinnaker.gate.services.internal.Front50Service
import com.netflix.spinnaker.gate.services.internal.IgorService
import com.netflix.spinnaker.gate.services.internal.KayentaService
import com.netflix.spinnaker.gate.services.internal.KeelService
import com.netflix.spinnaker.gate.services.internal.OrcaServiceSelector
import com.netflix.spinnaker.gate.services.internal.RoscoService
import com.netflix.spinnaker.gate.services.internal.RoscoServiceSelector
import groovy.util.logging.Slf4j
import org.apache.commons.io.FileUtils
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.http.MediaType
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import spock.lang.Specification

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get

@Slf4j
@GateSystemTest
@ContextConfiguration(
  classes = [Main],
  initializers = YamlFileApplicationContextInitializer
)
@TestPropertySource(
  // Enable Controllers we want to document in the spec here.
  properties = [ "retrofit.enabled=true","services.kayenta.enabled=true","services.kayenta.canary-config-store=true",
    "services.keel.enabled=true", "spring.application.name=gate", 'services.fiat.baseUrl=https://localhost', 'services.keel.baseUrl=https://localhost' ])
class GenerateSwaggerSpec extends Specification {

  @Autowired
  WebApplicationContext wac

  @MockBean
  private IgorService igorService

  @MockBean
  private ClouddriverServiceSelector clouddriverServiceSelector

  @MockBean
  private ClouddriverService clouddriverService

  @MockBean
  private Front50Service front50Service

  @MockBean
  private OrcaServiceSelector orcaServiceSelector

  @MockBean
  private EchoService echoService

  @MockBean
  private FiatService fiatService

  @MockBean
  private ExtendedFiatService extendedFiatService

  @MockBean
  private RoscoService roscoService

  @MockBean
  private RoscoServiceSelector roscoServiceSelector

  @MockBean
  private KeelService keelService

  @MockBean
  private KayentaService kayentaService

  @MockBean
  private DownstreamServicesHealthIndicator downstreamServicesHealthIndicator


  MockMvc mockMvc

  def setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build()
  }

  def "generate and write swagger spec to file"() {
    given:
    Boolean written = false

    when:
    mockMvc.perform(get("/v3/api-docs").accept(MediaType.APPLICATION_JSON))
      .andDo({ result ->
      log.info('Generating swagger spec and writing to "swagger.json".')
      FileUtils.writeStringToFile(new File('swagger.json'), result.getResponse().getContentAsString())
      written = true
    })

    then:
    written
  }
}

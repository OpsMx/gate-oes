package com.netflix.spinnaker.gate;

import com.netflix.spinnaker.fiat.shared.FiatService;
import com.netflix.spinnaker.gate.health.DownstreamServicesHealthIndicator;
import com.netflix.spinnaker.gate.services.internal.*;
import com.netflix.spinnaker.kork.client.ServiceClientProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(classes = {Main.class})
@ActiveProfiles("test")
@TestPropertySource(properties = {"spring.config.location=classpath:gate-test.yml"})
public class MainSpec {

  @Autowired ServiceClientProvider serviceClientProvider;

  @MockBean private ClouddriverService clouddriverService;

  @MockBean private ClouddriverServiceSelector clouddriverServiceSelector;

  @MockBean private Front50Service front50Service;

  @MockBean private OrcaServiceSelector orcaServiceSelector;

  @MockBean private EchoService echoService;

  @MockBean private FiatService fiatService;

  @MockBean private ExtendedFiatService extendedFiatService;

  @MockBean private RoscoService roscoService;

  @MockBean private RoscoServiceSelector roscoServiceSelector;

  @MockBean private KeelService keelService;

  @MockBean private DownstreamServicesHealthIndicator downstreamServicesHealthIndicator;

  @Test
  public void startupTest() {
    assert serviceClientProvider != null;
  }
}

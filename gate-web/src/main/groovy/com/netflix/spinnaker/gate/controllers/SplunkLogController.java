package com.netflix.spinnaker.gate.controllers;

import io.swagger.v3.oas.annotations.Operation;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/splunk")
@ConditionalOnProperty("splunk.log.enabled")
public class SplunkLogController {

  private static final Logger log = LoggerFactory.getLogger(SplunkLogController.class);

  // Sample baseURL = https://hostURL?paramsKey=paramsValue&index=CLUSTER_NAME%20pod=POD_NAME
  @Value("${splunk.log.baseURL}")
  private String baseURL;

  @Value("${splunk.log.clusterName}")
  private String clusterName;

  @Operation(summary = "Retrieve splunk logs")
  @GetMapping("/logs/{podName}")
  public ResponseEntity<byte[]> getSplunkLogs(@PathVariable("podName") String podName)
      throws IOException {
    String logUrl = baseURL.replace("CLUSTER_NAME", clusterName).replace("POD_NAME", podName);
    log.info("Inside SplunkLogController - getSplunkLogs(), splunk Log URL : " + logUrl);

    String logFileName = podName + "-log";
    String headerValue = "attachment; filename=" + logFileName;
    try (InputStream in = new URL(logUrl).openStream()) {
      byte[] fileContents = in.readAllBytes();
      return ResponseEntity.ok().header("Content-Disposition", headerValue).body(fileContents);
    }
  }
}

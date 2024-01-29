package com.netflix.spinnaker.gate.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.ConfigureRedisAction;

@Configuration
public class RedisSecureConfig {

  /**
   * Always disable the ConfigureRedisAction that Spring Boot uses internally. Instead, we use one
   * qualified with @ConnectionPostProcessor. See
   * {@link PostConnectionConfiguringJedisConnectionFactory, GateConfig}.
   * */
  @Bean
  @PostConnectionConfiguringJedisConnectionFactory.ConnectionPostProcessor
  @ConditionalOnProperty("redis.configuration.secure")
  ConfigureRedisAction connectionPostProcessorConfigureRedisAction() {
    return ConfigureRedisAction.NO_OP;
  }
}

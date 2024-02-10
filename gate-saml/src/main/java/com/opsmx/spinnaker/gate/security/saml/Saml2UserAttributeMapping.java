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

import java.util.List;
import lombok.Data;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConditionalOnExpression("${spring.security.saml2.enabled:false}")
@ConfigurationProperties(prefix = "spring.security.saml2.user-attribute-mapping")
public class Saml2UserAttributeMapping {

  private String firstName = "user.firstName";
  private String lastName = "user.lastName";
  private Roles roles = new Roles();
  private String email = "user.email";

  @Data
  public static class Roles {
    private String attributeName = "memberOf";
    private List<String> requiredRoles;
    private boolean sortRoles = false;
    private boolean forceLowercaseRoles = true;
    private String rolesDelimiter;
  }
}

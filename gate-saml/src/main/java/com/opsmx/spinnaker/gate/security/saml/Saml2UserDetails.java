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

import com.netflix.spinnaker.security.User;
import java.util.Collection;
import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;

public class Saml2UserDetails extends AbstractAuthenticationToken {

  private User user = null;
  private Saml2Authentication saml2Authentication = null;

  public Saml2UserDetails(Saml2Authentication saml2Authentication, User user) {
    super(user.getAuthorities());
    this.saml2Authentication = saml2Authentication;
    this.user = user;
  }

  @Override
  public String getName() {
    return this.user.getUsername();
  }

  @Override
  public Collection<GrantedAuthority> getAuthorities() {
    List<GrantedAuthority> authorities = (List<GrantedAuthority>) this.user.getAuthorities();
    return authorities;
  }

  @Override
  public Object getCredentials() {
    return this.saml2Authentication;
  }

  @Override
  public Object getDetails() {
    return this.user;
  }

  @Override
  public Object getPrincipal() {
    return this.user;
  }

  @Override
  public boolean isAuthenticated() {
    return true;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {}
}

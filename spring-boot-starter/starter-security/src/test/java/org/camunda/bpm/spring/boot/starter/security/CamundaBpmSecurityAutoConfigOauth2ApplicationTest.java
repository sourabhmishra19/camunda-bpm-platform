/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH
 * under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership. Camunda licenses this file to you under the Apache License,
 * Version 2.0; you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.camunda.bpm.spring.boot.starter.security;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.camunda.bpm.spring.boot.starter.security.oauth2.CamundaBpmSpringSecurityDisableAutoConfiguration;
import org.camunda.bpm.spring.boot.starter.security.oauth2.CamundaSpringSecurityOAuth2AutoConfiguration;
import org.camunda.bpm.spring.boot.starter.security.oauth2.impl.AuthorizeTokenFilter;
import org.camunda.commons.testing.ProcessEngineLoggingRule;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;

@AutoConfigureMockMvc
@TestPropertySource("/oauth2-mock.properties")
public class CamundaBpmSecurityAutoConfigOauth2ApplicationTest extends AbstractSpringSecurityTest {

  private static final String PROVIDER = "mock-provider";
  public static final String AUTHORIZED_USER = "bob";
  public static final String UNAUTHORIZED_USER = "mary";

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private ClientRegistrationRepository registrations;

  @MockBean
  private OAuth2AuthorizedClientService authorizedClientService;

  @Rule
  public ProcessEngineLoggingRule loggingRule = new ProcessEngineLoggingRule().watch(AuthorizeTokenFilter.class.getCanonicalName());

  @Test
  public void SpringSecurityAutoConfigurationCorrectlySet() {
    assertThat(getBeanForClass(CamundaSpringSecurityOAuth2AutoConfiguration.class, mockMvc.getDispatcherServlet().getWebApplicationContext())).isNotNull();
    assertThat(getBeanForClass(CamundaBpmSpringSecurityDisableAutoConfiguration.class, mockMvc.getDispatcherServlet().getWebApplicationContext())).isNull();
  }

  @Test
  public void webappWithoutAuthentication() throws Exception {
    // given no authentication

    // when
    mockMvc.perform(MockMvcRequestBuilders.get(baseUrl + "/camunda/api/engine/engine/default/user")
            .accept(MediaType.APPLICATION_JSON))
        .andDo(MockMvcResultHandlers.print())
        // then
        .andExpect(MockMvcResultMatchers.status().isFound())
        .andExpect(MockMvcResultMatchers.header().exists("Location"))
        .andExpect(MockMvcResultMatchers.header().string("Location", baseUrl + "/oauth2/authorization/" + PROVIDER));
  }

  @Test
  public void webappApiWithAuthorizedUser() throws Exception {
    OAuth2AuthenticationToken authenticationToken = createToken(AUTHORIZED_USER);
    createAuthorizedClient(authenticationToken);

    // when
    mockMvc.perform(MockMvcRequestBuilders.get(baseUrl + "/camunda/api/engine/engine/default/user")
            .accept(MediaType.APPLICATION_JSON)
            .with(authentication(authenticationToken)))
        // then
        .andDo(MockMvcResultHandlers.print())
        .andExpect(MockMvcResultMatchers.status().isOk())
        .andExpect(MockMvcResultMatchers.content().json(EXPECTED_NAME_DEFAULT));
  }

  @Test
  public void webappWithUnauthorizedUser() throws Exception {
    OAuth2AuthenticationToken authenticationToken = createToken(UNAUTHORIZED_USER);
    createAuthorizedClient(authenticationToken);

    // when
    mockMvc.perform(MockMvcRequestBuilders.get(baseUrl + "/camunda/api/engine/engine/default/user")
            .accept(MediaType.APPLICATION_JSON)
            .with(authentication(authenticationToken)))
        // then
        .andExpect(MockMvcResultMatchers.status().isFound())
        .andExpect(MockMvcResultMatchers.header().exists("Location"))
        .andExpect(MockMvcResultMatchers.header().string("Location", baseUrl + "/oauth2/authorization/" + PROVIDER));

    String expectedWarn = "Authorize failed for '" + UNAUTHORIZED_USER + "'";
    assertThat(loggingRule.getFilteredLog(expectedWarn)).hasSize(1);
  }

  private OAuth2AuthenticationToken createToken(String user) {
    List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("USER");
    OAuth2User oAuth2User = new DefaultOAuth2User(authorities, Map.of("name", user), "name");
    return new OAuth2AuthenticationToken(oAuth2User, authorities, PROVIDER);
  }

  private void createAuthorizedClient(OAuth2AuthenticationToken authenticationToken) {
    OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "value", Instant.now(), Instant.now().plus(Duration.ofDays(1)));
    ClientRegistration clientRegistration = this.registrations.findByRegistrationId(authenticationToken.getAuthorizedClientRegistrationId());
    OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, authenticationToken.getName(), accessToken);
    when(this.authorizedClientService.loadAuthorizedClient(PROVIDER, AUTHORIZED_USER)).thenReturn(authorizedClient);
  }

}

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
package org.camunda.bpm.qa.upgrade.scenarios7190.variables;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.Map;

import org.camunda.bpm.engine.ManagementService;
import org.camunda.bpm.engine.RuntimeService;
import org.camunda.bpm.qa.upgrade.Origin;
import org.camunda.bpm.qa.upgrade.ScenarioUnderTest;
import org.camunda.bpm.qa.upgrade.UpgradeTestRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ScenarioUnderTest("JpaEntitiesScenario")
@Origin("7.19.0")
public class JpaEntitiesTest {

  Logger LOG = LoggerFactory.getLogger(JpaEntitiesTest.class);
  @Rule
  public UpgradeTestRule engineRule = new UpgradeTestRule();

  ManagementService managementService;
  RuntimeService runtimeService;

  @Before
  public void assignServices() {
    managementService = engineRule.getManagementService();
    runtimeService = engineRule.getRuntimeService();
  }

  @Test
  @ScenarioUnderTest("createJpaVariables.1")
  public void shouldHandleJpaVariables() {
    // given
    Map<String, String> properties = managementService.getProperties();
    String processInstanceId = properties.get("JpaEntitiesScenario.processInstanceId");

    // when
    Object singleResult = runtimeService.getVariable(processInstanceId, "simpleEntityFieldAccess");

    // then value is empty due to empty JPA test serializer
    assertThat(singleResult).isNull();
  }

}

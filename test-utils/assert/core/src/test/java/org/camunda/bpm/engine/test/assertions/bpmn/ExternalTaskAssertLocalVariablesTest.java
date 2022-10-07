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
package org.camunda.bpm.engine.test.assertions.bpmn;

import org.camunda.bpm.engine.runtime.ProcessInstance;
import static org.camunda.bpm.engine.test.assertions.bpmn.BpmnAwareTests.assertThat;
import static org.camunda.bpm.engine.test.assertions.bpmn.BpmnAwareTests.complete;
import static org.camunda.bpm.engine.test.assertions.bpmn.BpmnAwareTests.externalTaskQuery;
import static org.camunda.bpm.engine.test.assertions.bpmn.BpmnAwareTests.runtimeService;
import static org.camunda.bpm.engine.test.assertions.bpmn.BpmnAwareTests.withVariables;

import org.camunda.bpm.engine.ProcessEngineException;
import org.camunda.bpm.engine.test.ProcessEngineRule;
import org.camunda.bpm.engine.test.Deployment;
import org.camunda.bpm.engine.test.assertions.helpers.Failure;
import org.camunda.bpm.engine.test.assertions.helpers.ProcessAssertTestCase;
import org.junit.Rule;
import org.junit.Test;
import java.util.Collections;

public class ExternalTaskAssertLocalVariablesTest extends ProcessAssertTestCase {

  @Rule
  public ProcessEngineRule processEngineRule = new ProcessEngineRule();

  @Test
  @Deployment(resources = { "bpmn/ExternalTaskAssert-localVariables.bpmn" })
  public void testHasToprocessInstancecName_Success() {
    // When
    ProcessInstance pi = runtimeService().startProcessInstanceByKey("ExternalTaskAssert-localVariables");
    // Then
    assertThat(externalTaskQuery().singleResult()).isNotNull();
    // Then
    assertThat(externalTaskQuery().singleResult()).hasTopicName("External_1");

    // When
    complete(
      externalTaskQuery().singleResult(),
        Collections.EMPTY_MAP,
        withVariables(
          "local_variable_1", "value_1"));

    // Then
    assertThat(externalTaskQuery().singleResult()).isNotNull();
    // Then
    assertThat(externalTaskQuery().singleResult()).hasTopicName("Noop");
    // Then
    assertThat(pi).variables().containsKey("variable_1");
  }

  @Test
  @Deployment(resources = { "bpmn/ExternalTaskAssert-localVariables.bpmn" })
  public void testHasToprocessInstancecName_Error_Null() {
    // When
    runtimeService().startProcessInstanceByKey("ExternalTaskAssert-localVariables");
    // Then
    assertThat(externalTaskQuery().singleResult()).isNotNull();
    // Then

    expect(new Failure() {
      @Override
      public void when() {
        complete(externalTaskQuery().singleResult());
      }
    }, ProcessEngineException.class);
  }
}

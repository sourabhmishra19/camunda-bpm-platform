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
package org.camunda.bpm.engine.test.jobexecutor;

import static org.assertj.core.api.Assertions.fail;

import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.JavaDelegate;
import org.camunda.bpm.engine.test.util.PluggableProcessEngineTest;
import org.camunda.bpm.model.bpmn.Bpmn;
import org.junit.Test;

public class SlowTest extends PluggableProcessEngineTest {

  @Test
  public void shouldTakeTooLongInJobExecution() {
    // given
    testRule.deploy(Bpmn.createExecutableProcess("process")
        .startEvent()
          .camundaAsyncAfter()
        .serviceTask()
          .camundaClass(SlowExecutionDelegate.class)
        .endEvent()
        .done());
    runtimeService.startProcessInstanceByKey("process");

    // when
    testRule.waitForJobExecutorToProcessAllJobs();

    // then
    fail("should have failed already because it took too long!");
  }

  public static class SlowExecutionDelegate implements JavaDelegate {

    @Override
    public void execute(DelegateExecution execution) throws Exception {
      Thread.sleep(13_000L);
    }

  }

}

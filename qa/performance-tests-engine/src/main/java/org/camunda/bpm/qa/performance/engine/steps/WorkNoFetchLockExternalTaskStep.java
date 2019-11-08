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
package org.camunda.bpm.qa.performance.engine.steps;

import java.util.Map;

import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.qa.performance.engine.framework.PerfTestRunContext;
import org.camunda.bpm.qa.performance.engine.junit.ExternalTaskRecorder;

/**
 * @author Paul Lungu
 *
 */
public class WorkNoFetchLockExternalTaskStep extends ProcessEngineAwareStep {
	
	
	  protected String taskIdKey;
	  private Map<String, Object> processVariables;

	  public WorkNoFetchLockExternalTaskStep(ProcessEngine processEngine, String taskIdKey) {
	    this(processEngine, taskIdKey, null);
	  }

	  public WorkNoFetchLockExternalTaskStep(ProcessEngine processEngine, String taskIdKey, Map<String, Object> processVariables) {
	    super(processEngine);
	    this.taskIdKey = taskIdKey;
	    this.processVariables = processVariables;
	  }

	  public void execute(PerfTestRunContext context) {
	    String taskId = context.getVariable(taskIdKey);
	    processEngine.getExternalTaskService().complete(taskId, ExternalTaskRecorder.WORKER_ID, processVariables);
	  }

}

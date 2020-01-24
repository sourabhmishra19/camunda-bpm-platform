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

package org.camunda.bpm.engine.impl.cmd;

import org.camunda.bpm.engine.externaltask.ExternalTaskQuery;
import org.camunda.bpm.engine.impl.ExternalTaskQueryImpl;
import org.camunda.bpm.engine.impl.interceptor.Command;
import org.camunda.bpm.engine.impl.interceptor.CommandContext;

import java.io.Serializable;
import java.util.List;

public class GetTopicNamesCmd implements Command<List<String>>, Serializable {

  protected ExternalTaskQueryImpl externalTaskQuery = new ExternalTaskQueryImpl();

  public GetTopicNamesCmd(boolean withLockedTasks, boolean withUnlockedTasks, boolean withRetriesLeft){
    if (withLockedTasks) {
      externalTaskQuery.locked();
    }
    if (withUnlockedTasks) {
      externalTaskQuery.notLocked();
    }
    if (withRetriesLeft) {
      externalTaskQuery.withRetriesLeft();
    }
  }

  @Override public List<String> execute(CommandContext commandContext) {
    return commandContext
        .getExternalTaskManager()
        .selectTopicNamesByQuery(externalTaskQuery);
  }

}

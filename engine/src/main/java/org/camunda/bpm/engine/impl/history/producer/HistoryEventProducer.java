/* Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.camunda.bpm.engine.impl.history.producer;

import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.camunda.bpm.engine.delegate.DelegateTask;
import org.camunda.bpm.engine.impl.history.event.HistoryEvent;
import org.camunda.bpm.engine.impl.persistence.entity.VariableInstanceEntity;

/**
 * <p>The producer for history events. The history event producer is 
 * responsible for extracting data from the runtime structures 
 * (Executions, Tasks, ...) and adding the data to a {@link HistoryEvent}.
 *  
 * @author Daniel Meyer
 * @author Marcel Wieczorek
 * 
 */
public interface HistoryEventProducer {
  
  // Process instances //////////////////////////////////////
  
  /** 
   * Creates the history event fired when an activity instances is <strong>created</strong>.
   *  
   * @param execution the current execution.
   * @return the history event
   */
  public HistoryEvent createProcessInstanceStartEvt(DelegateExecution execution);
  
  /** 
   * Creates the history event fired when a process instances is <strong>ended</strong>.
   *  
   * @param execution the current execution.
   * @return the history event
   */
  public HistoryEvent createProcessInstanceEndEvt(DelegateExecution execution);
    
  
  // Activity instances /////////////////////////////////////
  
  /** 
   * Creates the history event fired when an activity instances is <strong>started</strong>.
   *  
   * @param execution the current execution.
   * @return the history event
   */
  public HistoryEvent createActivityInstanceStartEvt(DelegateExecution execution);
  
  /** 
   * Creates the history event fired when an activity instances is <strong>updated</strong>.
   *  
   * @param execution the current execution.
   * @param task the task association that is currently updated. (May be null in case there is not task associated.)
   * @return the history event
   */
  public HistoryEvent createActivityInstanceUpdateEvt(DelegateExecution execution, DelegateTask task);
  
  /** 
   * Creates the history event fired when an activity instances is <strong>ended</strong>.
   *  
   * @param execution the current execution.
   * @return the history event
   */
  public HistoryEvent createActivityInstanceEndEvt(DelegateExecution execution);
  
  
  // Task Instances /////////////////////////////////////////
  
  /** 
   * Creates the history event fired when a task instances is <strong>created</strong>.
   *  
   * @param task the task
   * @return the history event
   */
  public HistoryEvent createTaskInstanceCreateEvt(DelegateTask task);
  
  /** 
   * Creates the history event fired when a task instances is <strong>updated</strong>.
   *  
   * @param task the task
   * @return the history event
   */
  public HistoryEvent createTaskInstanceUpdateEvt(DelegateTask task);
  
  /** 
   * Creates the history event fired when a task instances is <strong>completed</strong>.
   *  
   * @param task the task
   * @param deleteReason 
   * @return the history event
   */
  public HistoryEvent createTaskInstanceCompleteEvt(DelegateTask task, String deleteReason);
  
  
  // HistoricVariableUpdateEventEntity //////////////////////
  
  /** 
   * Creates the history event fired when an execution variable is updated.
   *  
   * @param variableInstance the runtime variable instance
   * @param execution the execution to which the variable is linked
   * @return the history event
   */
  public HistoryEvent createHistoricVariableUpdateEvt(VariableInstanceEntity variableInstance, DelegateExecution execution);
  
  /** 
   * Creates the history event fired when a task local variable is updated.
   *  
   * @param variableInstance the runtime variable instance
   * @param task the task to which the execution is linked
   * @return the history event
   */
  public HistoryEvent createHistoricVariableUpdateEvt(VariableInstanceEntity variableInstance, DelegateTask task);

}

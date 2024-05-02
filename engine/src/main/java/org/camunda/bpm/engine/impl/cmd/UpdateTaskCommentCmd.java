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

import static org.camunda.bpm.engine.impl.util.EnsureUtil.ensureNotNull;

import java.io.Serializable;
import org.camunda.bpm.engine.history.UserOperationLogEntry;
import org.camunda.bpm.engine.impl.cfg.CommandChecker;
import org.camunda.bpm.engine.impl.interceptor.Command;
import org.camunda.bpm.engine.impl.interceptor.CommandContext;
import org.camunda.bpm.engine.impl.persistence.entity.CommentEntity;
import org.camunda.bpm.engine.impl.persistence.entity.PropertyChange;
import org.camunda.bpm.engine.impl.persistence.entity.TaskEntity;
import org.camunda.bpm.engine.impl.util.ClockUtil;

/**
 * Command to update a comment by a given task ID.
 */
public class UpdateTaskCommentCmd implements Command<Object>, Serializable {

  private static final long serialVersionUID = 1L;
  protected String taskId;
  protected String commentId;
  protected String message;

  public UpdateTaskCommentCmd(String taskId, String commentId, String message) {
    this.taskId = taskId;
    this.commentId = commentId;
    this.message = message;
  }

  public Object execute(CommandContext commandContext) {
    ensureNotNull("commentId", commentId);
    ensureNotNull("taskId", taskId);
    ensureNotNull("message", message);

    CommentEntity comment = commandContext.getCommentManager().findCommentByTaskIdAndCommentId(taskId, commentId);
    ensureNotNull("No comment exists with commentId: " + commentId + " and taskId: " + taskId, "comment", comment);
    TaskEntity task = commandContext.getTaskManager().findTaskById(taskId);
    ensureNotNull("No task exists with taskId: " + taskId, "task", task);

    checkUpdateTask(task, commandContext);
    updateComment(commandContext, comment);
    PropertyChange propertyChange = new PropertyChange("comment", comment.getMessage(), message);
    commandContext.getOperationLogManager()
        .logCommentOperation(UserOperationLogEntry.OPERATION_TYPE_UPDATE_COMMENT, task, propertyChange);
    task.triggerUpdateEvent();

    return null;
  }

  private void updateComment(CommandContext commandContext, CommentEntity comment) {
    String eventMessage = comment.toEventMessage(message);

    String userId = commandContext.getAuthenticatedUserId();

    comment.setMessage(eventMessage);
    comment.setFullMessage(message);
    comment.setTime(ClockUtil.getCurrentTime());
    comment.setAction(UserOperationLogEntry.OPERATION_TYPE_UPDATE_COMMENT);
    comment.setUserId(userId);

    commandContext.getCommentManager().updateCommentMessage(comment);
  }

  protected void checkUpdateTask(TaskEntity task, CommandContext commandContext) {
    for (CommandChecker checker : commandContext.getProcessEngineConfiguration().getCommandCheckers()) {
      checker.checkUpdateTask(task);
    }
  }
}
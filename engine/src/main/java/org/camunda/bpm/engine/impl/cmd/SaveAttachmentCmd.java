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

import java.io.Serializable;

import org.camunda.bpm.engine.impl.interceptor.Command;
import org.camunda.bpm.engine.impl.interceptor.CommandContext;
import org.camunda.bpm.engine.impl.persistence.entity.AttachmentEntity;
import org.camunda.bpm.engine.task.Attachment;


/**
 * @author Tom Baeyens
 */
public class SaveAttachmentCmd implements Command<Object>, Serializable {

  private static final long serialVersionUID = 1L;
  protected Attachment attachment;
  
  public SaveAttachmentCmd(Attachment attachment) {
    this.attachment = attachment;
  }

  public Object execute(CommandContext commandContext) {
    AttachmentEntity updateAttachment = commandContext
      .getDbEntityManager()
      .selectById(AttachmentEntity.class, attachment.getId());
    
    updateAttachment.setName(attachment.getName());
    updateAttachment.setDescription(attachment.getDescription());
    
    return null;
  }
}

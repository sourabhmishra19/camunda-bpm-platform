/*
 * Copyright 2016 camunda services GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
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
package org.camunda.bpm.engine.impl.cmd;

import org.camunda.bpm.engine.impl.persistence.entity.ExternalTaskEntity;
import java.util.Date;

/**
 * Represents the command to set the expiration of an existing external task.
 *
 * @author Michael Irigoyen <mirigoyen@accusoft.com>
 */
public class SetExternalTaskExpirationCmd extends ExternalTaskCmd {

  /**
   * The expiration length in milliseconds that should added
   * to the current time and set on the external task.
   */
  protected Date expiration;

  public SetExternalTaskExpirationCmd(String externalTaskId, Date expiration) {
    super(externalTaskId);
    this.expiration = new Date(System.currentTimeMillis() + 60000);
  }

  @Override
  protected void execute(ExternalTaskEntity externalTask) {
    externalTask.setExpiration(expiration);
  }

  @Override
  protected void validateInput() {
  }
}

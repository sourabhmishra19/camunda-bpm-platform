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

package org.camunda.bpm.engine.impl.persistence.entity;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.camunda.bpm.engine.history.HistoricVariableInstance;
import org.camunda.bpm.engine.impl.context.Context;
import org.camunda.bpm.engine.impl.db.PersistentObject;
import org.camunda.bpm.engine.impl.variable.ValueFields;
import org.camunda.bpm.engine.impl.variable.VariableType;

/**
 * @author Christian Lipphardt (camunda)
 */
public class HistoricVariableInstanceEntity implements ValueFields, HistoricVariableInstance, PersistentObject, Serializable {

  private static final long serialVersionUID = 1L;

  protected String id;
  protected String processInstanceId;
  
  protected String taskId;
  protected String executionId;
  
  protected String name;
  protected int revision;
  protected VariableType variableType;

  protected Long longValue;
  protected Double doubleValue;
  protected String textValue;
  protected String textValue2;

  protected ByteArrayEntity byteArrayValue;
  protected String byteArrayId;

  protected Object cachedValue;

  public HistoricVariableInstanceEntity() {
  }

  public Object getPersistentState() {
    // immutable
    return HistoricVariableInstanceEntity.class;
  }
  
  public Object getValue() {
    if (!variableType.isCachable() || cachedValue == null) {
      cachedValue = variableType.getValue(this);
    }
    return cachedValue;
  }
  
  // byte array value /////////////////////////////////////////////////////////
  
  // i couldn't find a easy readable way to extract the common byte array value logic
  // into a common class.  therefor it's duplicated in VariableInstanceEntity, 
  // HistoricVariableInstance and HistoricDetailVariableInstanceUpdateEntity 
  
  public String getByteArrayValueId() {
    return byteArrayId;
  }

  public void setByteArrayValueId(String byteArrayValueId) {
    this.byteArrayId = byteArrayValueId;
    this.byteArrayValue = null;
  }

  public ByteArrayEntity getByteArrayValue() {
    if ((byteArrayValue == null) && (byteArrayId != null)) {
      byteArrayValue = Context
        .getCommandContext()
        .getDbSqlSession()
        .selectById(ByteArrayEntity.class, byteArrayId);
    }
    return byteArrayValue;
  }
  
  public void setByteArrayValue(byte[] bytes) {
    ByteArrayEntity byteArrayValue = null;
    if (this.byteArrayId!=null) {
      getByteArrayValue();
      Context
        .getCommandContext()
        .getByteArrayManager()
        .deleteByteArrayById(this.byteArrayId);
    }
    if (bytes!=null) {
      byteArrayValue = new ByteArrayEntity(bytes);
      Context
        .getCommandContext()
        .getDbSqlSession()
        .insert(byteArrayValue);
    }
    this.byteArrayValue = byteArrayValue;
    if (byteArrayValue != null) {
      this.byteArrayId = byteArrayValue.getId();
    } else {
      this.byteArrayId = null;
    }
  }

  // getters and setters //////////////////////////////////////////////////////

  public String getVariableTypeName() {
    return (variableType != null ? variableType.getTypeName() : null);
  }

  public String getVariableName() {
    return name;
  }

  public VariableType getVariableType() {
    return variableType;
  }

  public int getRevision() {
    return revision;
  }

  public void setRevision(int revision) {
    this.revision = revision;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public Long getLongValue() {
    return longValue;
  }

  public void setLongValue(Long longValue) {
    this.longValue = longValue;
  }

  public Double getDoubleValue() {
    return doubleValue;
  }

  public void setDoubleValue(Double doubleValue) {
    this.doubleValue = doubleValue;
  }

  public String getTextValue() {
    return textValue;
  }

  public void setTextValue(String textValue) {
    this.textValue = textValue;
  }

  public String getTextValue2() {
    return textValue2;
  }

  public void setTextValue2(String textValue2) {
    this.textValue2 = textValue2;
  }

  public void setByteArrayValue(ByteArrayEntity byteArrayValue) {
    this.byteArrayValue = byteArrayValue;
  }

  public Object getCachedValue() {
    return cachedValue;
  }

  public void setCachedValue(Object cachedValue) {
    this.cachedValue = cachedValue;
  }

  public void setVariableType(VariableType variableType) {
    this.variableType = variableType;
  }

  public void setProcessInstanceId(String processInstanceId) {
    this.processInstanceId = processInstanceId;
  }

  public String getId() {
    return id;
  }
  
  public void setId(String id) {
    this.id = id;
  }

  public String getProcessInstanceId() {
    return processInstanceId;
  }

  public String getTaskId() {
    return taskId;
  }

  public void setTaskId(String taskId) {
    this.taskId = taskId;
  }
  
  public String getExecutionId() {
    return executionId;
  }
  
  public void setExecutionId(String executionId) {
    this.executionId = executionId;
  }
}

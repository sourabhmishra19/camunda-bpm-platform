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
package org.camunda.bpm.engine.cdi.impl;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;

import org.camunda.bpm.engine.cdi.BusinessProcess;
import org.camunda.bpm.engine.variable.VariableMap;
import org.camunda.bpm.engine.variable.value.TypedValue;

/**
 * Allows to expose the process variables of the current business process as a
 * java.util.Map<String,Object>
 * <p/>
 * The map delegates changes to
 * {@link BusinessProcess#setVariable(String, Object)} and
 * {@link BusinessProcess#getVariable(String)}, so that they are not flushed
 * prematurely.
 * 
 * @author Daniel Meyer
 */
public class ProcessVariableMap implements VariableMap {
  
  @Inject private BusinessProcess businessProcess;
  
  @Override
  public Object get(Object key) {
    if(key == null) {
      throw new IllegalArgumentException("This map does not support 'null' keys.");
    }
    return businessProcess.getVariable(key.toString());
  }

  @Override
  public <T> T getValue(String name, Class<T> type) {
    Object object = get(name);
    if (object == null) {
      return null;
    } else if (type.isAssignableFrom(object.getClass())) {
      return (T) object;
    } else {
      throw new ClassCastException("Cannot cast variable named '" + name + "' with value '" + object + "' to type '" + type + "'.");
    }
  }

  @Override
  public <T extends TypedValue> T getValueTyped(String name) {
    if (name == null) {
      throw new IllegalArgumentException("This map does not support 'null' keys.");
    }
    return businessProcess.getVariableTyped(name);
  }

  @Override
  public Object put(String key, Object value) {
    if(key == null) {
      throw new IllegalArgumentException("This map does not support 'null' keys.");
    }
    Object variableBefore = businessProcess.getVariable(key);
    businessProcess.setVariable(key, value);
    return variableBefore;
  }
  
  @Override
  public void putAll(Map< ? extends String, ? extends Object> m) {
    for (java.util.Map.Entry< ? extends String, ? extends Object> newEntry : m.entrySet()) {
      businessProcess.setVariable(newEntry.getKey(), newEntry.getValue());      
    }
  }

  @Override
  public VariableMap putValue(String name, Object value) {
    throw new UnsupportedOperationException(ProcessVariableMap.class.getName() + ".putValue() is not supported.");
  }

  @Override
  public VariableMap putValueTyped(String name, TypedValue value) {
    throw new UnsupportedOperationException(ProcessVariableMap.class.getName() + ".putValueTyped() is not supported.");
  }

  @Override
  public int size() {
    throw new UnsupportedOperationException(ProcessVariableMap.class.getName()+".size() is not supported.");
  }

  @Override
  public boolean isEmpty() {
    throw new UnsupportedOperationException(ProcessVariableMap.class.getName()+".isEmpty() is not supported.");
  }

  @Override
  public boolean containsKey(Object key) {
    throw new UnsupportedOperationException(ProcessVariableMap.class.getName()+".containsKey() is not supported.");
  }

  @Override
  public boolean containsValue(Object value) {
    throw new UnsupportedOperationException(ProcessVariableMap.class.getName()+".containsValue() is not supported.");
  }

  @Override
  public Object remove(Object key) {
    throw new UnsupportedOperationException("ProcessVariableMap.remove is unsupported. Use ProcessVariableMap.put(key, null)");    
  }

  @Override
  public void clear() {
    throw new UnsupportedOperationException(ProcessVariableMap.class.getName()+".clear() is not supported.");
  }

  @Override
  public Set<String> keySet() {
    throw new UnsupportedOperationException(ProcessVariableMap.class.getName()+".keySet() is not supported.");
  }

  @Override
  public Collection<Object> values() {
    throw new UnsupportedOperationException(ProcessVariableMap.class.getName()+".values() is not supported.");
  }

  @Override
  public Set<java.util.Map.Entry<String, Object>> entrySet() {
    throw new UnsupportedOperationException(ProcessVariableMap.class.getName()+".entrySet() is not supported.");
  }

}

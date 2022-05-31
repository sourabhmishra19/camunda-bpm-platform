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
package org.camunda.spin.plugin.impl;

/**
 * A FunctionMapper which resolves the Spin functions for Expression Language.
 *
 * <p>Lazy loading: This implementation supports lazy loading: the Java Methods
 * are loaded upon the first request.</p>
 *
 * <p>Caching: once the methods are loaded, they are cached in a Map for efficient
 * retrieval.</p>
 *
 * @author Daniel Meyer
 *
 */
public final class SpinFunctions {
  public final static String S = "S";
  public final static String XML = "XML";
  public final static String JSON = "JSON";
}

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
package org.camunda.bpm.engine.test.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.ThrowableAssert.catchThrowable;
import static org.camunda.bpm.engine.impl.util.ExceptionUtil.PERSISTENCE_CONNECTION_ERROR_CLASS;

import java.sql.SQLException;
import java.util.Properties;
import org.apache.ibatis.datasource.pooled.PooledDataSource;
import org.apache.ibatis.exceptions.PersistenceException;
import org.camunda.bpm.engine.IdentityService;
import org.camunda.bpm.engine.ProcessEngineException;
import org.camunda.bpm.engine.identity.User;
import org.camunda.bpm.engine.impl.cfg.ProcessEngineConfigurationImpl;
import org.camunda.bpm.engine.impl.db.sql.DbSqlSessionFactory;
import org.camunda.bpm.engine.impl.test.RequiredDatabase;
import org.camunda.bpm.engine.impl.util.PropertiesUtil;
import org.camunda.bpm.engine.test.ProcessEngineRule;
import org.camunda.bpm.engine.test.util.ProvidedProcessEngineRule;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

// This test is excluded on Oracle 23ai since the SQL State changed.
@RequiredDatabase(excludes = { DbSqlSessionFactory.H2 })
public class ConnectionPersistenceExceptionTest {

  @Rule
  public ProcessEngineRule engineRule = new ProvidedProcessEngineRule();

  protected IdentityService identityService;

  protected ProcessEngineConfigurationImpl engineConfig;

  protected String resetUrl;

  @Before
  public void assignServices() {
    identityService = engineRule.getIdentityService();

    engineConfig = engineRule.getProcessEngineConfiguration();

    resetUrl = ((PooledDataSource) engineConfig.getDataSource()).getUrl();
  }

  @After
  public void resetEngine() {
    ((PooledDataSource) engineConfig.getDataSource()).setUrl(resetUrl);
    engineRule.getIdentityService().deleteUser("foo");
  }

  @Test
  public void shouldFailWithConnectionError() {
    // given
    User user = identityService.newUser("foo");
    identityService.saveUser(user);

    // when
    SQLException sqlException = provokePersistenceConnectionError();

    // then
    assertThat(sqlException.getSQLState()).startsWith(PERSISTENCE_CONNECTION_ERROR_CLASS);
  }

  // helper ////////////////////////////////////////////////////////////////////////////////////////

  protected SQLException provokePersistenceConnectionError() {
    Properties properties = PropertiesUtil.getProperties("/database.properties");
    String host = (String) properties.get("database.host");
    String port = (String) properties.get("database.port");

    String jdbcUrl = resetUrl.replace(host + ":" + port, "not-existing-server:123");
    ((PooledDataSource) engineConfig.getDataSource()).setUrl(jdbcUrl);

    Throwable result = catchThrowable(() -> identityService.deleteUser("foo"));

    assertThat(result).isInstanceOf(ProcessEngineException.class);
    assertThat(result.getCause())
        .isInstanceOf(PersistenceException.class) // 1st cause
        .hasCauseInstanceOf(SQLException.class); // 2nd cause

    return (SQLException) result.getCause().getCause();
  }

}

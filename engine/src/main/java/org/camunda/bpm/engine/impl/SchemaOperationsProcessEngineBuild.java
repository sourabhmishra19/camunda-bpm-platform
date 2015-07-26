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
package org.camunda.bpm.engine.impl;

import org.camunda.bpm.engine.ProcessEngineConfiguration;
import org.camunda.bpm.engine.ProcessEngineException;
import org.camunda.bpm.engine.impl.cfg.ProcessEngineConfigurationImpl;
import org.camunda.bpm.engine.impl.cmd.DetermineHistoryLevelCmd;
import org.camunda.bpm.engine.impl.context.Context;
import org.camunda.bpm.engine.impl.db.PersistenceSession;
import org.camunda.bpm.engine.impl.db.entitymanager.DbEntityManager;
import org.camunda.bpm.engine.impl.history.HistoryLevel;
import org.camunda.bpm.engine.impl.interceptor.Command;
import org.camunda.bpm.engine.impl.interceptor.CommandContext;
import org.camunda.bpm.engine.impl.persistence.entity.PropertyEntity;

import java.util.logging.Logger;

/**
 * @author Tom Baeyens
 * @author Roman Smirnov
 * @author Sebastian Menski
 * @author Daniel Meyer
 */
public final class SchemaOperationsProcessEngineBuild implements Command<Void> {

  private final static Logger log = Logger.getLogger(SchemaOperationsProcessEngineBuild.class.getName());

  public Void execute(final CommandContext commandContext) {
    String databaseSchemaUpdate = Context.getProcessEngineConfiguration().getDatabaseSchemaUpdate();
    PersistenceSession persistenceSession = commandContext.getSession(PersistenceSession.class);
    if (ProcessEngineConfigurationImpl.DB_SCHEMA_UPDATE_DROP_CREATE.equals(databaseSchemaUpdate)) {
      try {
        persistenceSession.dbSchemaDrop();
      } catch (RuntimeException e) {
        // ignore
      }
    }
    if ( ProcessEngineConfiguration.DB_SCHEMA_UPDATE_CREATE_DROP.equals(databaseSchemaUpdate)
      || ProcessEngineConfigurationImpl.DB_SCHEMA_UPDATE_DROP_CREATE.equals(databaseSchemaUpdate)
      || ProcessEngineConfigurationImpl.DB_SCHEMA_UPDATE_CREATE.equals(databaseSchemaUpdate)
      ) {
      persistenceSession.dbSchemaCreate();
    } else if (ProcessEngineConfiguration.DB_SCHEMA_UPDATE_FALSE.equals(databaseSchemaUpdate)) {
      persistenceSession.dbSchemaCheckVersion();
    } else if (ProcessEngineConfiguration.DB_SCHEMA_UPDATE_TRUE.equals(databaseSchemaUpdate)) {
      persistenceSession.dbSchemaUpdate();
    }


    DbEntityManager entityManager = commandContext.getSession(DbEntityManager.class);
    checkHistoryLevel(entityManager);
    checkDeploymentLockExists(entityManager);

    return null;
  }

  public static void dbCreateHistoryLevel(DbEntityManager entityManager) {
    ProcessEngineConfigurationImpl processEngineConfiguration = Context.getProcessEngineConfiguration();
    HistoryLevel configuredHistoryLevel = processEngineConfiguration.getHistoryLevel();
    PropertyEntity property = new PropertyEntity("historyLevel", Integer.toString(configuredHistoryLevel.getId()));
    entityManager.insert(property);
    log.info("Creating historyLevel property in database with value: " + processEngineConfiguration.getHistory());
  }

  /**
   *
   * @param entityManager entoty manager for db query
   * @return Integer value representing the history level or <code>null</code> if none found
   */
  public static Integer databaseHistoryLevel(DbEntityManager entityManager) {

    try {
      PropertyEntity historyLevelProperty = entityManager.selectById(PropertyEntity.class, "historyLevel");
      return historyLevelProperty != null ? new Integer(historyLevelProperty.getValue()) : null;
    } catch (Exception e) {
      log.warning("could not select property historyLevel: " + e.getMessage());
      return null;
    }

  }

  public void checkHistoryLevel(final DbEntityManager entityManager) {
    final ProcessEngineConfigurationImpl processEngineConfiguration = Context.getProcessEngineConfiguration();

    if (ProcessEngineConfiguration.HISTORY_AUTO.equals(processEngineConfiguration.getHistory())) {
      final HistoryLevel historyLevel = processEngineConfiguration.getCommandExecutorSchemaOperations().execute(new DetermineHistoryLevelCmd(processEngineConfiguration.getHistoryLevels()));
      processEngineConfiguration.setHistory(historyLevel.getName());
      processEngineConfiguration.setHistoryLevel(historyLevel);
    }

    HistoryLevel configuredHistoryLevel = processEngineConfiguration.getHistoryLevel();

    Integer databaseHistoryLevel = databaseHistoryLevel(entityManager);
    if (databaseHistoryLevel == null) {
      log.info("No historyLevel property found in database.");
      dbCreateHistoryLevel(entityManager);
    } else {
      if (!((Integer) configuredHistoryLevel.getId()).equals(databaseHistoryLevel)) {
        throw new ProcessEngineException("historyLevel mismatch: configuration says " + configuredHistoryLevel + " and database says " + databaseHistoryLevel);
      }
    }
  }

  public void checkDeploymentLockExists(DbEntityManager entityManager) {
    PropertyEntity deploymentLockProperty = entityManager.selectById(PropertyEntity.class, "deployment.lock");
    if (deploymentLockProperty == null) {
      log.warning("No deployment lock property found in database.");
    }
  }
}

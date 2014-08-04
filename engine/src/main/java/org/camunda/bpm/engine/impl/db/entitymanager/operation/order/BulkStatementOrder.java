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
package org.camunda.bpm.engine.impl.db.entitymanager.operation.order;

import org.camunda.bpm.engine.impl.db.entitymanager.operation.DbBulkOperation;
import org.camunda.bpm.engine.impl.db.entitymanager.operation.DbOperation;

/**
 * Orders bulk operations according to the lexicographical ordering of their statement names
 *
 * @author Daniel Meyer
 *
 */
public class BulkStatementOrder implements DbOperationComparator<DbBulkOperation> {

  public int compare(DbBulkOperation firstOperation, DbBulkOperation secondOperation) {

    // order by statement
    int statementOrder = firstOperation.getStatement().compareTo(secondOperation.getStatement());

    if(statementOrder == 0) {
      return firstOperation.hashCode() < secondOperation.hashCode() ? -1 : 1;
    } else {
      return statementOrder;
    }

  }

  public boolean isApplicableTo(DbOperation dbOperation) {
    return dbOperation instanceof DbBulkOperation;
  }

}

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
package org.camunda.bpm.integrationtest.functional.cdi;

import org.camunda.bpm.integrationtest.functional.cdi.beans.DependentScopedBean;
import org.camunda.bpm.integrationtest.util.AbstractFoxPlatformIntegrationTest;
import org.camunda.bpm.integrationtest.util.DeploymentHelper;
import org.camunda.bpm.integrationtest.util.TestContainer;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;

/**
 * @author Tassilo Weidner
 */
@RunWith(Arquillian.class)
public class CdiBeanDependentScopedSyncTest extends AbstractFoxPlatformIntegrationTest {

  @Deployment
  public static WebArchive processArchive() {
    return initWebArchiveDeployment()
      .addClass(DependentScopedBean.class)
      .addAsResource("org/camunda/bpm/integrationtest/functional/cdi/CdiBeanDependentScoped.testResolveBean.bpmn20.xml");
  }

  @Deployment(name="clientDeployment")
  public static WebArchive clientDeployment() {
    WebArchive deployment = ShrinkWrap.create(WebArchive.class, "client.war")
            .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")
            .addClass(AbstractFoxPlatformIntegrationTest.class)
            .addClass(DependentScopedBean.class)
            .addAsLibraries(DeploymentHelper.getEngineCdi());

    TestContainer.addContainerSpecificResourcesForNonPa(deployment);

    return deployment;
  }

  @Before
  @OperateOnDeployment("clientDeployment")
  public void setup() {
    DependentScopedBean.reset();

    Assert.assertEquals(0, runtimeService.createProcessInstanceQuery().processDefinitionKey("testResolveBean").count());

    runtimeService.startProcessInstanceByKey("testResolveBean");

    Assert.assertEquals(0,runtimeService.createProcessInstanceQuery().processDefinitionKey("testResolveBean").count());
  }

  @Test
  public void testResolveBean() {
    Assert.assertEquals(Arrays.asList("post-construct-invoked", "bean-invoked", "pre-destroy-invoked"), DependentScopedBean.lifecycle);
  }

}

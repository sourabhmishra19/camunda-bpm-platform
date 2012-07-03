package com.camunda.fox.platform.test.functional.ejb.remote;

import org.activiti.engine.runtime.ProcessInstance;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.camunda.fox.platform.test.functional.ejb.remote.bean.BusinessInterface;
import com.camunda.fox.platform.test.functional.ejb.remote.bean.RemoteSFSBClientDelegateBean;
import com.camunda.fox.platform.test.functional.ejb.remote.bean.RemoteSFSBean;
import com.camunda.fox.platform.test.util.AbstractFoxPlatformIntegrationTest;



/**
 * This test verifies that a CDI Java Bean Delegate is able to inject and invoke the 
 * remote business interface of a SFSB from a different application
 * 
 * Note:
 * - Fails on Jboss 
 * - works on Glassfish
 * 
 * @author Daniel Meyer
 *
 */
@Ignore
@RunWith(Arquillian.class)
public class RemoteSFSBInvocationTest extends AbstractFoxPlatformIntegrationTest {
 
  @Deployment(name="pa", order=2)
  public static WebArchive processArchive() {    
    return initWebArchiveDeployment()
      .addClass(RemoteSFSBClientDelegateBean.class)
      .addClass(BusinessInterface.class) // the business interface
      .addAsResource("com/camunda/fox/platform/test/functional/ejb/remote/RemoteSFSBInvocationTest.testInvokeBean.bpmn20.xml");      
  }
  
  @Deployment(order=1)
  public static WebArchive delegateDeployment() {    
    return ShrinkWrap.create(WebArchive.class, "service.war")
      .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")
      .addClass(AbstractFoxPlatformIntegrationTest.class)
      .addClass(RemoteSFSBean.class) // the EJB 
      .addClass(BusinessInterface.class); // the business interface
  }
    
  @Test
  @OperateOnDeployment("pa")
  public void testInvokeBean() throws Exception{
    
    // this testcase first resolves the Bean synchronously and then from the JobExecutor
    
    ProcessInstance pi = runtimeService.startProcessInstanceByKey("testInvokeBean");
    
    Assert.assertEquals(runtimeService.getVariable(pi.getId(), "result"), true);
    
    runtimeService.setVariable(pi.getId(), "result", false);
    
    taskService.complete(taskService.createTaskQuery().processInstanceId(pi.getId()).singleResult().getId());
    
    waitForJobExecutorToProcessAllJobs(6000, 300);
    
    Assert.assertEquals(runtimeService.getVariable(pi.getId(), "result"), true);
    
    taskService.complete(taskService.createTaskQuery().processInstanceId(pi.getId()).singleResult().getId());
  }
  
  @Test
  public void testMultipleInvocations() {
    
    // this is greater than any Datasource / EJB / Thread Pool size -> make sure all resources are released properly.
    int instances = 100;    
    String[] ids = new String[instances];
    
    for(int i=0; i<instances; i++) {    
      ids[i] = runtimeService.startProcessInstanceByKey("testInvokeBean").getId();    
      Assert.assertEquals(runtimeService.getVariable(ids[i], "result"), true);      
      runtimeService.setVariable(ids[i], "result", false);
      taskService.complete(taskService.createTaskQuery().processInstanceId(ids[i]).singleResult().getId());
    }
        
    waitForJobExecutorToProcessAllJobs(60*1000, 300);
    
    for(int i=0; i<instances; i++) {    
      Assert.assertEquals(runtimeService.getVariable(ids[i], "result"), true);    
      taskService.complete(taskService.createTaskQuery().processInstanceId(ids[i]).singleResult().getId());
    }
    
  }

}

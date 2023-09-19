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
package org.camunda.bpm.container.impl.jboss.service;

import java.util.List;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.camunda.bpm.application.ProcessApplicationInterface;
import org.camunda.bpm.container.impl.plugin.BpmPlatformPlugin;
import org.camunda.bpm.container.impl.plugin.BpmPlatformPlugins;
import org.jboss.as.ee.component.ComponentView;
import org.jboss.as.naming.ManagedReference;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;

/**
 * Responsible for invoking {@link BpmPlatformPlugin#postProcessApplicationUndeploy(ProcessApplicationInterface)}
 *
 * @author Daniel Meyer
 *
 */
public class ProcessApplicationStopService implements Service<ProcessApplicationStopService> {


  private final static Logger LOGGER = Logger.getLogger(ProcessApplicationStopService.class.getName());

  // for view-exposing ProcessApplicationComponents
  protected final Supplier<ComponentView> paComponentViewSupplier;
  protected final Supplier<ProcessApplicationInterface> noViewApplicationSupplier;
  protected final Supplier<BpmPlatformPlugins> platformPluginsSupplier;
  protected InjectedValue<ComponentView> paComponentViewInjector = new InjectedValue<ComponentView>();
  protected InjectedValue<ProcessApplicationInterface> noViewProcessApplication = new InjectedValue<ProcessApplicationInterface>();

  protected InjectedValue<BpmPlatformPlugins> platformPluginsInjector = new InjectedValue<BpmPlatformPlugins>();

  public ProcessApplicationStopService(Supplier<ComponentView> paComponentViewSupplier,
      Supplier<ProcessApplicationInterface> noViewApplicationSupplier,
      Supplier<BpmPlatformPlugins> platformPluginsSupplier
      ) {
    this.paComponentViewSupplier = paComponentViewSupplier;
    this.noViewApplicationSupplier = noViewApplicationSupplier;
    this.platformPluginsSupplier = platformPluginsSupplier;
  }

  @Override
  public ProcessApplicationStopService getValue() throws IllegalStateException, IllegalArgumentException {
    return this;
  }

  @Override
  public void start(StartContext arg0) throws StartException {
  }

  @Override
  public void stop(StopContext arg0) {


    ManagedReference reference = null;
    ProcessApplicationInterface processApplication = null;
    try {

      // get the process application component
      if(paComponentViewSupplier != null) {
        ComponentView componentView = paComponentViewSupplier.get();
        reference = componentView.createInstance();
        processApplication = (ProcessApplicationInterface) reference.getInstance();
      }
      else {
        processApplication = noViewApplicationSupplier.get();
      }

      BpmPlatformPlugins bpmPlatformPlugins = platformPluginsSupplier.get();
      List<BpmPlatformPlugin> plugins = bpmPlatformPlugins.getPlugins();

      for (BpmPlatformPlugin bpmPlatformPlugin : plugins) {
        bpmPlatformPlugin.postProcessApplicationUndeploy(processApplication);
      }

    }
    catch (Exception e) {
      LOGGER.log(Level.WARNING, "Exception while invoking BpmPlatformPlugin.postProcessApplicationUndeploy", e);

    }
    finally {
      if(reference != null) {
        reference.release();
      }
      if (processApplication != null ) {
        processApplication = null;
      }
    }
  }

}

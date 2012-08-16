/**
 * Copyright (C) 2011, 2012 camunda services GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.camunda.fox.platform.impl.deployment;

import static com.camunda.fox.platform.impl.deployment.spi.ProcessArchiveScanner.ScanningUtil.isDeployable;
import static com.camunda.fox.platform.impl.deployment.spi.ProcessArchiveScanner.ScanningUtil.isDiagramForProcess;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.activiti.engine.impl.util.IoUtil;
import org.jboss.vfs.VFS;
import org.jboss.vfs.VirtualFile;
import org.jboss.vfs.VirtualFileFilter;

import com.camunda.fox.platform.FoxPlatformException;
import com.camunda.fox.platform.impl.deployment.spi.ProcessArchiveScanner;
import com.camunda.fox.platform.spi.ProcessArchive;

/**
 * <p>A {@link ProcessArchiveScanner} which uses Jboss VFS for
 * scanning the process archive for processes.</p>
 * 
 * <p>This implementation should be used on Jboss AS 7</p>
 * 
 * @author Daniel Meyer
 * @author Falko Menge
 */
public class VfsProcessArchiveScanner implements ProcessArchiveScanner {

  private static Logger log = Logger.getLogger(VfsProcessArchiveScanner.class.getName());

  public Map<String, byte[]> findResources(ProcessArchive processArchive) {
    
    Map<String, byte[]> resources = new HashMap<String, byte[]>();

    final URL metaFileUrl = (URL) processArchive.getProperties().get(ProcessArchive.PROP_META_FILE_URL);
    final String resourceRootPath = (String) processArchive.getProperties().get(ProcessArchive.PROP_RESOURCE_ROOT_PATH);
    final ClassLoader classLoader = processArchive.getClassLoader();

    if(resourceRootPath != null && !resourceRootPath.startsWith("pa:")) {
      
        //  1. CASE: paResourceRootPath specified AND it is a "classpath:" resource root
      
        String strippedPath = resourceRootPath.replace("classpath:", "");
        Enumeration<URL> resourceRoots = loadClasspathResourceRoots(classLoader, strippedPath);
        
        if(!resourceRoots.hasMoreElements()) {
          log.warning("Could not find any resources for process archive resource root path '"+resourceRootPath+"' using classloader '"+classLoader+"'");
        }
        
        while (resourceRoots.hasMoreElements()) {
          URL resourceRoot = (URL) resourceRoots.nextElement();
          VirtualFile virtualRoot = getVirtualFileForUrl(resourceRoot);
          scanRoot(virtualRoot, resources);          
        }
        
          
    } else {
      
      // 2nd. CASE: no paResourceRootPath specified OR paResourceRootPath is PA-local

      VirtualFile metaFile = null;
      if (metaFileUrl != null) {
        metaFile = getVirtualFileForUrl(metaFileUrl);

        // use the parent resource of the META-INF folder
        VirtualFile resourceRoot = metaFile.getParent().getParent();

        if (resourceRootPath != null) { // pa-local path provided
          String strippedPath = resourceRootPath.replace("pa:", "");
          resourceRoot = resourceRoot.getChild(strippedPath);
        }
        
        // perform the scanning
        scanRoot(resourceRoot, resources);
        
      } else {
        throw new FoxPlatformException(ProcessArchive.PROP_META_FILE_URL + "-property must be set in order to scan a PA-local path.");
      }
    }

    return resources;

  }

  private VirtualFile getVirtualFileForUrl(final URL url) {
    try {
      return  VFS.getChild(url.toURI());
    } catch (URISyntaxException e) {
      throw new FoxPlatformException("Could not load virtual filefor url "+url, e);
    }
  }

  protected void scanRoot(VirtualFile processArchiveRoot, Map<String, byte[]> resources) {
    try {
      List<VirtualFile> processes = processArchiveRoot.getChildrenRecursively(new VirtualFileFilter() {
        public boolean accepts(VirtualFile file) {
          return isDeployable(file.getName());
        }
      });
      for (final VirtualFile process : processes) {
        addResource(process, processArchiveRoot, resources);
        // find diagram(s) for process
        List<VirtualFile> diagrams = process.getParent().getChildren(new VirtualFileFilter() {
          public boolean accepts(VirtualFile file) {
            return isDiagramForProcess(file.getName(), process.getName());
          }
        });
        for (VirtualFile diagram : diagrams) {
          addResource(diagram, processArchiveRoot, resources);
        }
      }
    } catch (IOException e) {
      log.log(Level.WARNING, "Could not scan VFS root: "+processArchiveRoot, e);
    }
  }

  private void addResource(VirtualFile virtualFile, VirtualFile processArchiveRoot, Map<String, byte[]> resources) {
    String resourceName = virtualFile.getPathNameRelativeTo(processArchiveRoot);
    try {
      InputStream inputStream = virtualFile.openStream();
      byte[] bytes = IoUtil.readInputStream(inputStream, resourceName);
      IoUtil.closeSilently(inputStream);
      resources.put(resourceName, bytes);
    } catch (IOException e) {
      log.log(Level.WARNING, "Could not read input stream of file '" + resourceName + "' from process archive '" + processArchiveRoot + "'.", e);
    }
  }
  
  protected Enumeration<URL> loadClasspathResourceRoots(final ClassLoader classLoader, String strippedPaResourceRootPath) {
    Enumeration<URL> resourceRoots;
    try {
      resourceRoots = classLoader.getResources(strippedPaResourceRootPath);
    } catch (IOException e) {
      throw new FoxPlatformException("Could not load resources at '"+strippedPaResourceRootPath+"' using classloaded '"+classLoader+"'", e);
    }
    return resourceRoots;
  }
  
}

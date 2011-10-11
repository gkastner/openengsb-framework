/**
 * Licensed to the Austrian Association for Software Tool Integration (AASTI)
 * under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership. The AASTI licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.openengsb.core.security.internal;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.security.Key;
import java.util.Hashtable;
import java.util.List;

import javax.crypto.SecretKey;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openengsb.core.api.OsgiUtilsService;
import org.openengsb.core.api.security.ConnectorKeyProvider;
import org.openengsb.core.api.security.ConnectorKeyRegistry;
import org.openengsb.core.api.security.model.KeyBean;
import org.openengsb.core.common.OpenEngSBCoreServices;
import org.openengsb.core.common.util.CipherUtils;
import org.openengsb.core.common.util.DefaultOsgiUtilsService;
import org.openengsb.core.security.internal.model.KeyBeanData;
import org.osgi.framework.BundleContext;

public class ConnectorKeyRegistryIT extends AbstractPersistenceTest {

    private ConnectorKeyRegistry registryService;

    private ConnectorKeyProvider providerService;

    @Before
    public void setUp() throws Exception {
        setupPersistence();

        ConnectorKeyRegistryImpl registry = new ConnectorKeyRegistryImpl();
        registry.setEntityManager(entityManager);
        registryService = getProxiedService(registry, ConnectorKeyRegistry.class);
        providerService = registry;
    }

    @After
    public void tearDown() throws Exception {
        @SuppressWarnings("unchecked")
        List<KeyBeanData> resultList = entityManager.createQuery("SELECT p FROM KeyBeanData p").getResultList();
        for (KeyBeanData item : resultList) {
            entityManager.remove(item);
        }
    }

    @Override
    protected String[] getEntityNames() {
        return new String[]{ "KeyBeanData" };
    }

    @Test
    public void testRegisterConnector() throws Exception {
        SecretKey key = CipherUtils.generateKey("AES", 128);
        registryService.registerInstanceKey("test", new KeyBean("AES", key.getEncoded()));
        Key connectorKey = providerService.getConnectorKey("test");
        assertThat(key, is(connectorKey));
    }

    @Test
    public void registerConnectorTwice_shouldFail() throws Exception {
        SecretKey key = CipherUtils.generateKey("AES", 128);
        registryService.registerInstanceKey("test", new KeyBean("AES", key.getEncoded()));
        try {
            registryService.registerInstanceKey("test", new KeyBean("AES", key.getEncoded()));
            fail("expected Exception");
        } catch (IllegalArgumentException e) {
            // expected
        }
    }

    @Override
    protected void setBundleContext(BundleContext bundleContext) {
        DefaultOsgiUtilsService osgiServiceUtils = new DefaultOsgiUtilsService();
        osgiServiceUtils.setBundleContext(bundleContext);
        registerService(osgiServiceUtils, new Hashtable<String, Object>(), OsgiUtilsService.class);
        OpenEngSBCoreServices.setOsgiServiceUtils(osgiServiceUtils);
    }
}

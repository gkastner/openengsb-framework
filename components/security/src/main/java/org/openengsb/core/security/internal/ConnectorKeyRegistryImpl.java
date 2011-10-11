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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.persistence.EntityManager;

import org.openengsb.core.api.security.ConnectorKeyProvider;
import org.openengsb.core.api.security.ConnectorKeyRegistry;
import org.openengsb.core.api.security.model.KeyBean;
import org.openengsb.core.security.internal.model.KeyBeanData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;

public class ConnectorKeyRegistryImpl implements ConnectorKeyRegistry, ConnectorKeyProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConnectorKeyRegistryImpl.class);

    private EntityManager em;

    @Override
    public void registerInstanceKey(String instanceId, KeyBean key) {
        KeyBeanData existing = em.find(KeyBeanData.class, instanceId);
        if (existing != null) {
            throw new IllegalArgumentException("instance already registered");
        }

        KeyBeanData keyBeanData = new KeyBeanData();
        keyBeanData.setInstanceId(instanceId);
        keyBeanData.setAlgorithm(key.getAlgorithm());
        keyBeanData.setEncodedKey(key.getEncodedKey());
        em.persist(keyBeanData);
        LOGGER.info("registered connector ", instanceId);
    }

    @Override
    public SecretKey getConnectorKey(String instanceid) {
        Preconditions.checkNotNull(instanceid);
        KeyBeanData entry = em.find(KeyBeanData.class, instanceid);
        if (entry == null) {
            throw new IllegalArgumentException("No such connector registered");
        }
        return new SecretKeySpec(entry.getEncodedKey(), entry.getAlgorithm());
    }

    public void setEntityManager(EntityManager em) {
        this.em = em;
    }

}

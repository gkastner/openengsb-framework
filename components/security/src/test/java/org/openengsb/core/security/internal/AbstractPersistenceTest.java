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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

import org.junit.Before;
import org.junit.BeforeClass;
import org.openengsb.core.test.AbstractOsgiMockServiceTest;

public abstract class AbstractPersistenceTest extends AbstractOsgiMockServiceTest {

    protected static EntityManager entityManager;
    protected static EntityManagerFactory emf;

    @BeforeClass
    public static void setupPersistenceFactory() throws Exception {
        emf = Persistence.createEntityManagerFactory("security-test");
        entityManager = emf.createEntityManager();
    }

    @Before
    public void setupPersistence() throws Exception {
        executeDelete(getEntityNames());
    }

    protected abstract String[] getEntityNames();

    protected void executeDelete(String... query) {
        if (entityManager.getTransaction().isActive()) {
            entityManager.getTransaction().commit();
        }
        entityManager.getTransaction().begin();
        for (String q : query) {
            entityManager.createQuery(String.format("DELETE FROM %s", q)).executeUpdate();
        }
        entityManager.getTransaction().commit();
    }

    @SuppressWarnings("unchecked")
    protected <T> T getProxiedService(final T service, Class<T> targetClass) {
        InvocationHandler invocationHandler = new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                entityManager.getTransaction().begin();
                Object result;
                try {
                    result = method.invoke(service, args);
                } catch (InvocationTargetException e) {
                    entityManager.getTransaction().rollback();
                    throw e.getCause();
                }
                entityManager.getTransaction().commit();
                return result;
            }
        };
        return (T) Proxy.newProxyInstance(this.getClass().getClassLoader(),
            new Class<?>[]{ targetClass }, invocationHandler);
    }
}

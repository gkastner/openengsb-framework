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

package test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.jms.JMSException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.openengsb.connector.usernamepassword.Password;
import org.openengsb.core.api.remote.MethodCall;
import org.openengsb.core.api.security.model.KeyBean;
import org.openengsb.core.common.util.CipherUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;

/**
 * Setup to run this app: + Start OpenEngSB + install the jms-feature: features:install openengsb-ports-jms + copy
 * example+example+testlog.connector to the openengsb/config-directory + copy openengsb/etc/keys/public.key.data to
 * src/main/resources
 */
public final class SecureSampleConnector {

    static final Logger LOGGER = LoggerFactory.getLogger(SecureSampleConnector.class);
    private static final String URL = "tcp://127.0.0.1:6549";
    private static OutgoingMessageHandler outgoingMessageHandler;
    private static JmsConfig jmsConfig;

    private static void init() throws Exception {
        jmsConfig = new JmsConfig(URL);
        jmsConfig.init();
        outgoingMessageHandler =
            new OutgoingMessageHandler(jmsConfig, "admin", new Password("password"), readPublicKey());

        SecretKey sessionKey = getConnectorSessionKeyFromFile();
        if (sessionKey == null) {
            sessionKey = generateNewConnectorKey();
            KeyBean keyBean = new KeyBean("AES", sessionKey.getEncoded());
            MethodCall call =
                new MethodCall("registerInstanceKey", new Object[]{ "example-remote", keyBean }, ImmutableMap.of(
                    "serviceFilter", "(objectClass=org.openengsb.core.api.security.ConnectorKeyRegistry)"));
            outgoingMessageHandler.callMethodAndReturnResult(call);
        }

        jmsConfig.createConsumerForQueue("example-remote", new ConnectorMessageListener(sessionKey, jmsConfig));
    }

    private static SecretKey generateNewConnectorKey() {
        File file = new File("secret.key");
        if (file.exists()) {
            throw new IllegalStateException("found file, but shouldn't be there when generating new key");
        }
        SecretKey key = CipherUtils.generateKey("AES", 128);
        try {
            FileUtils.writeByteArrayToFile(file, key.getEncoded());
        } catch (IOException e) {
            Throwables.propagate(e);
        }
        return key;
    }

    private static SecretKey getConnectorSessionKeyFromFile() {
        File file = new File("secret.key");
        if (!file.exists()) {
            return null;
        }
        byte[] encodedKey;
        try {
            encodedKey = FileUtils.readFileToByteArray(file);
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
        return new SecretKeySpec(encodedKey, "AES");
    }

    private static PublicKey readPublicKey() throws IOException {
        InputStream publicKeyResource = ClassLoader.getSystemResourceAsStream("public.key.data");
        byte[] publicKeyData = IOUtils.toByteArray(publicKeyResource);
        PublicKey publicKey = CipherUtils.deserializePublicKey(publicKeyData, "RSA");
        return publicKey;
    }

    private static void stop() throws JMSException {
        jmsConfig.stop();
    }

    /**
     * Small-test client that can be used for sending jms-messages to a running openengsb
     */
    public static void main(String[] args) throws Exception {
        LOGGER.info("initializing");
        init();
        LOGGER.info("initialized");
        System.in.read();
        LOGGER.info("stopping");
        stop();
        LOGGER.info("done");
    }

    private SecureSampleConnector() {
    }
}

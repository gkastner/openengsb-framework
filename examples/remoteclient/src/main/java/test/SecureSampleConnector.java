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

import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.SecretKey;
import javax.jms.Connection;
import javax.jms.Destination;
import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageListener;
import javax.jms.MessageProducer;
import javax.jms.Session;
import javax.jms.TextMessage;

import org.apache.activemq.ActiveMQConnectionFactory;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.codehaus.jackson.map.ObjectMapper;
import org.openengsb.connector.usernamepassword.Password;
import org.openengsb.core.api.model.BeanDescription;
import org.openengsb.core.api.remote.MethodCall;
import org.openengsb.core.api.remote.MethodCallRequest;
import org.openengsb.core.api.remote.MethodResult;
import org.openengsb.core.api.remote.MethodResult.ReturnType;
import org.openengsb.core.api.remote.MethodResultMessage;
import org.openengsb.core.api.security.DecryptionException;
import org.openengsb.core.api.security.EncryptionException;
import org.openengsb.core.api.security.model.EncryptedMessage;
import org.openengsb.core.api.security.model.KeyBean;
import org.openengsb.core.api.security.model.SecureRequest;
import org.openengsb.core.api.security.model.SecureResponse;
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
    private static final Logger LOGGER = LoggerFactory.getLogger(SecureSampleConnector.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String URL = "tcp://127.0.0.1:6549";

    private static Connection connection;
    private static Session session;
    private static MessageProducer producer;

    private static void init() throws JMSException, EncryptionException, DecryptionException, IOException,
        InterruptedException, ClassNotFoundException {
        ActiveMQConnectionFactory connectionFactory = new ActiveMQConnectionFactory(URL);
        connection = connectionFactory.createConnection();
        connection.start();

        session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
        Destination destination = session.createQueue("receive");
        producer = session.createProducer(destination);

        final SecretKey sessionKey = CipherUtils.generateKey("AES", 256);
        KeyBean keyBean = new KeyBean("AES", sessionKey.getEncoded());

        MethodCall call =
            new MethodCall("registerInstanceKey", new Object[]{ "example-remote", keyBean }, ImmutableMap.of(
                "serviceFilter",
                "(objectClass=org.openengsb.core.api.security.ConnectorKeyRegistry)"));

        call(call, "admin", new Password("password"));

        Destination adminQueue = session.createQueue("example-remote");

        // Set up a consumer to consume messages off of the admin queue
        MessageConsumer consumer = session.createConsumer(adminQueue);
        consumer.setMessageListener(new MessageListener() {
            @Override
            public void onMessage(Message message) {
                LOGGER.info("recieved JMS-message");
                LOGGER.info(message.toString());
                TextMessage content = (TextMessage) message;
                try {
                    String text = content.getText();
                    LOGGER.info(text);
                    byte[] decodeBase64 = Base64.decodeBase64(text);
                    byte[] decrypted = CipherUtils.decrypt(decodeBase64, sessionKey);
                    SecureRequest secureMessage = MAPPER.readValue(decrypted, SecureRequest.class);
                    MethodCallRequest readValue = secureMessage.getMessage();
                    Destination callIdQueue = session.createQueue(readValue.getCallId());
                    MessageProducer resultProducer = session.createProducer(callIdQueue);
                    MethodResult methodResult =
                        new MethodResult(readValue.getMethodCall().getArgs()[0], ReturnType.Object);
                    MethodResultMessage methodResultMessage =
                        new MethodResultMessage(methodResult, readValue.getCallId());
                    SecureResponse secureResponse = SecureResponse.create(methodResultMessage);

                    byte[] value = MAPPER.writeValueAsBytes(secureResponse);
                    byte[] encryptedResponse = CipherUtils.encrypt(value, sessionKey);
                    String base64String = Base64.encodeBase64String(encryptedResponse);
                    TextMessage message2 = session.createTextMessage(base64String);
                    resultProducer.send(message2);
                } catch (JMSException e) {
                    throw Throwables.propagate(e);
                } catch (IOException e) {
                    throw Throwables.propagate(e);
                } catch (DecryptionException e) {
                    throw Throwables.propagate(e);
                } catch (EncryptionException e) {
                    throw Throwables.propagate(e);
                }
            }
        });
    }

    private static MethodResult call(MethodCall call, String username, Object credentials) throws IOException,
        JMSException, InterruptedException, ClassNotFoundException, EncryptionException, DecryptionException {
        MethodCallRequest methodCallRequest = new MethodCallRequest(call);
        SecretKey sessionKey = CipherUtils.generateKey("AES", 128);
        String requestString = marshalRequest(methodCallRequest, sessionKey, username, credentials);
        sendMessage(requestString);
        String resultString = getResultFromQueue(methodCallRequest.getCallId());
        return convertStringToResult(resultString, sessionKey);
    }

    private static String marshalRequest(MethodCallRequest methodCallRequest, SecretKey sessionKey,
            String username, Object credentials) throws IOException, EncryptionException {
        byte[] requestString = marshalSecureRequest(methodCallRequest, username, credentials);
        EncryptedMessage encryptedMessage = encryptMessage(sessionKey, requestString);
        return MAPPER.writeValueAsString(encryptedMessage);
    }

    private static EncryptedMessage encryptMessage(SecretKey sessionKey, byte[] requestString) throws IOException,
        EncryptionException {
        PublicKey publicKey = readPublicKey();
        byte[] encryptedContent = CipherUtils.encrypt(requestString, sessionKey);
        byte[] encryptedKey = CipherUtils.encrypt(sessionKey.getEncoded(), publicKey);
        EncryptedMessage encryptedMessage = new EncryptedMessage(encryptedContent, encryptedKey);
        return encryptedMessage;
    }

    private static PublicKey readPublicKey() throws IOException {
        InputStream publicKeyResource = ClassLoader.getSystemResourceAsStream("public.key.data");
        byte[] publicKeyData = IOUtils.toByteArray(publicKeyResource);
        PublicKey publicKey = CipherUtils.deserializePublicKey(publicKeyData, "RSA");
        return publicKey;
    }

    private static byte[] marshalSecureRequest(MethodCallRequest methodCallRequest,
            String username, Object credentials) throws IOException {
        BeanDescription auth = BeanDescription.fromObject(credentials);
        SecureRequest secureRequest = SecureRequest.create(methodCallRequest, username, auth);
        return MAPPER.writeValueAsBytes(secureRequest);
    }

    private static MethodResult convertStringToResult(String resultString, SecretKey sessionKey) throws IOException,
        ClassNotFoundException, DecryptionException {
        SecureResponse resultMessage = decryptResponse(resultString, sessionKey);
        return convertResult(resultMessage);
    }

    private static MethodResult convertResult(SecureResponse resultMessage) throws ClassNotFoundException {
        MethodResult result = resultMessage.getMessage().getResult();
        if (result.getType() != ReturnType.Void) {
            Class<?> clazz = Class.forName(result.getClassName());
            Object resultValue = MAPPER.convertValue(result.getArg(), clazz);
            result.setArg(resultValue);
        }
        return result;
    }

    private static SecureResponse decryptResponse(String resultString, SecretKey sessionKey)
        throws DecryptionException, IOException {
        byte[] decryptedContent;
        try {
            decryptedContent = CipherUtils.decrypt(Base64.decodeBase64(resultString), sessionKey);
        } catch (DecryptionException e) {
            System.err.println(resultString);
            throw e;
        }
        SecureResponse resultMessage = MAPPER.readValue(decryptedContent, SecureResponse.class);
        return resultMessage;
    }

    private static void sendMessage(String requestString) throws JMSException {
        TextMessage message = session.createTextMessage(requestString);
        producer.send(message);
    }

    private static String getResultFromQueue(String callId) throws JMSException, InterruptedException {
        Destination resultDest = session.createQueue(callId);
        MessageConsumer consumer = session.createConsumer(resultDest);
        final Semaphore messageSem = new Semaphore(0);
        final AtomicReference<String> resultReference = new AtomicReference<String>();
        consumer.setMessageListener(new MessageListener() {
            @Override
            public void onMessage(Message message) {
                try {
                    String text = ((TextMessage) message).getText();
                    resultReference.set(text);
                } catch (JMSException e) {
                    throw new RuntimeException(e);
                } finally {
                    messageSem.release();
                }
            }
        });
        LOGGER.info("waiting for response");
        if (!messageSem.tryAcquire(10, TimeUnit.SECONDS)) {
            throw new RuntimeException("no response");
        }
        LOGGER.info("response received");
        return resultReference.get();
    }

    private static void stop() throws JMSException {
        session.close();
        connection.stop();
        connection.close();
    }

    /**
     * Small-test client that can be used for sending jms-messages to a running openengsb
     */
    public static void main(String[] args) throws Exception {
        LOGGER.info("initializing");
        init();
        LOGGER.info("initialized");
        MethodCall methodCall =
            new MethodCall("doSomething", new Object[]{ "Hello World!" }, ImmutableMap.of("serviceId",
                "example+example+testlog", "contextId", "foo"));
        LOGGER.info("calling method");
        // MethodResult methodResult = call(methodCall, new Authentication("admin", "password"));
        // System.out.println(methodResult);
        LOGGER.info("running");
        System.in.read();
        LOGGER.info("stopping");
        stop();
        LOGGER.info("done");
    }

    private SecureSampleConnector() {
    }
}

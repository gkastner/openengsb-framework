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
import java.security.PublicKey;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.SecretKey;
import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageListener;
import javax.jms.TextMessage;

import org.apache.commons.codec.binary.Base64;
import org.codehaus.jackson.map.ObjectMapper;
import org.openengsb.core.api.model.BeanDescription;
import org.openengsb.core.api.remote.MethodCall;
import org.openengsb.core.api.remote.MethodCallRequest;
import org.openengsb.core.api.remote.MethodResult;
import org.openengsb.core.api.security.Credentials;
import org.openengsb.core.api.security.DecryptionException;
import org.openengsb.core.api.security.EncryptionException;
import org.openengsb.core.api.security.model.EncryptedMessage;
import org.openengsb.core.api.security.model.SecureRequest;
import org.openengsb.core.api.security.model.SecureResponse;
import org.openengsb.core.common.util.CipherUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Throwables;

public class OutgoingMessageHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(OutgoingMessageHandler.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JmsConfig config;
    private String username;
    private Credentials credentials;
    private PublicKey hostPublicKey;

    protected OutgoingMessageHandler(JmsConfig config, String username, Credentials credentials, PublicKey publicKey)
        throws JMSException {
        this.config = config;
        this.username = username;
        this.credentials = credentials;
        hostPublicKey = publicKey;
    }

    public MethodResult callMethodAndReturnResult(MethodCall call) {
        MethodCallRequest methodCallRequest = new MethodCallRequest(call);
        BeanDescription credentials = BeanDescription.fromObject(this.credentials);
        SecureRequest secureRequest = SecureRequest.create(methodCallRequest, username, credentials);
        SecretKey sessionKey = CipherUtils.generateKey("AES", 128);
        String encryptedText;
        try {
            byte[] serializedSecureRequest = MAPPER.defaultPrettyPrintingWriter().writeValueAsBytes(secureRequest);
            encryptedText = encryptMessage(sessionKey, serializedSecureRequest);
        } catch (IOException e1) {
            throw Throwables.propagate(e1);
        } catch (EncryptionException e) {
            throw Throwables.propagate(e);
        }

        String resultString;
        try {
            config.sendMessage("receive", encryptedText);
            resultString = getResultFromQueue(methodCallRequest.getCallId());
        } catch (JMSException e) {
            throw Throwables.propagate(e);
        }

        byte[] encryptedResult = Base64.decodeBase64(resultString);
        byte[] decryptedResult;
        try {
            decryptedResult = CipherUtils.decrypt(encryptedResult, sessionKey);
        } catch (DecryptionException e) {
            throw Throwables.propagate(e);
        }
        SecureResponse secureResponse;
        try {
            secureResponse = MAPPER.readValue(decryptedResult, SecureResponse.class);
        } catch (IOException e1) {
            throw Throwables.propagate(e1);
        }
        return secureResponse.getMessage().getResult();
    }

    private String getResultFromQueue(String callId) throws JMSException {
        MessageConsumer resultConsumer = config.createConsumerForQueue(callId);
        final Semaphore messageSem = new Semaphore(0);
        final AtomicReference<String> resultReference = new AtomicReference<String>();
        resultConsumer.setMessageListener(new MessageListener() {
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
        LOGGER.info("waiting for response on queue {}", callId);
        try {
            if (!messageSem.tryAcquire(10, TimeUnit.SECONDS)) {
                throw new RuntimeException("no response");
            }
        } catch (InterruptedException e) {
            Throwables.propagate(e);
        }
        LOGGER.info("response received");
        return resultReference.get();
    }

    private String encryptMessage(SecretKey sessionKey, byte[] requestString) throws EncryptionException, IOException {
        byte[] encryptedContent = CipherUtils.encrypt(requestString, sessionKey);
        byte[] encryptedKey = CipherUtils.encrypt(sessionKey.getEncoded(), hostPublicKey);
        EncryptedMessage encryptedMessage = new EncryptedMessage(encryptedContent, encryptedKey);
        return MAPPER.writeValueAsString(encryptedMessage);
    }

}

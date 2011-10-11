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

import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;
import org.codehaus.jackson.map.ObjectMapper;
import org.openengsb.core.api.remote.MethodCallRequest;
import org.openengsb.core.api.remote.MethodResultMessage;
import org.openengsb.core.api.security.DecryptionException;
import org.openengsb.core.api.security.EncryptionException;
import org.openengsb.core.api.security.model.SecureRequest;
import org.openengsb.core.api.security.model.SecureResponse;
import org.openengsb.core.common.util.CipherUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Throwables;

class MessageHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(MessageHandler.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SecretKey sessionKey;

    protected MessageHandler(SecretKey sessionKey) {
        this.sessionKey = sessionKey;
    }

    private byte[] decryptData(String text) {
        byte[] encryptedData = Base64.decodeBase64(text);
        LOGGER.debug("decrypting {}", text);
        try {
            return CipherUtils.decrypt(encryptedData, sessionKey);
        } catch (DecryptionException e) {
            throw Throwables.propagate(e);
        }
    }

    private String encryptData(String text) {
        byte[] encryptData;
        try {
            encryptData = CipherUtils.encrypt(text.getBytes(), sessionKey);
        } catch (EncryptionException e) {
            throw Throwables.propagate(e);
        }
        return Base64.encodeBase64String(encryptData);
    }

    public MethodCallRequest unmarshal(String text) {
        byte[] data = decryptData(text);
        SecureRequest secureMessage;
        try {
            secureMessage = MAPPER.readValue(data, SecureRequest.class);
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
        return secureMessage.getMessage();
    }

    public String marshal(MethodResultMessage methodResultMessage) {
        SecureResponse secureResponse = SecureResponse.create(methodResultMessage);
        String plainResult;
        try {
            plainResult = MAPPER.defaultPrettyPrintingWriter().writeValueAsString(secureResponse);
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
        return encryptData(plainResult);
    }
}

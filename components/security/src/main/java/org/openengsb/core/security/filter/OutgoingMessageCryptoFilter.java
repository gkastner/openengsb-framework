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

package org.openengsb.core.security.filter;

import java.security.Key;
import java.util.Map;

import org.openengsb.core.api.remote.FilterAction;
import org.openengsb.core.api.remote.FilterConfigurationException;
import org.openengsb.core.api.remote.FilterException;
import org.openengsb.core.api.security.ConnectorKeyProvider;
import org.openengsb.core.api.security.DecryptionException;
import org.openengsb.core.api.security.EncryptionException;
import org.openengsb.core.common.remote.AbstractFilterChainElement;
import org.openengsb.core.common.util.CipherUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * This filter is intended for outgoing ports.
 * 
 * <code>
 * <pre>
 *      [byte[] with decrypted content]  > Filter > [byte[]]    > ...
 *                                                                                      |
 *                                                                                      v
 *      [byte[] with decrypted  result]  < Filter < [byte[]]    < ...
 * </pre>
 * </code>
 */
public class OutgoingMessageCryptoFilter extends AbstractFilterChainElement<byte[], byte[]> {

    private static final Logger LOGGER = LoggerFactory.getLogger(OutgoingMessageCryptoFilter.class);

    private FilterAction next;

    private ConnectorKeyProvider keySource;

    public OutgoingMessageCryptoFilter(ConnectorKeyProvider keySource, String secretKeyAlgorithm) {
        super(byte[].class, byte[].class);
        this.keySource = keySource;
    }

    @Override
    protected byte[] doFilter(byte[] input, Map<String, Object> metaData) {
        Key connectorKey = keySource.getConnectorKey((String) metaData.get("serviceId"));
        byte[] encryptedMessage;
        try {
            LOGGER.trace("encrypting message with key from registry");
            encryptedMessage = CipherUtils.encrypt(input, connectorKey);
        } catch (EncryptionException e1) {
            throw new FilterException(e1);
        }
        byte[] encryptedResult = (byte[]) next.filter(encryptedMessage, metaData);
        byte[] decryptedMessage;
        try {
            LOGGER.debug("decrypting encryptedMessage");
            decryptedMessage = CipherUtils.decrypt(encryptedResult, connectorKey);
        } catch (DecryptionException e1) {
            throw new FilterException(e1);
        }
        return decryptedMessage;
    }

    @Override
    public void setNext(FilterAction next) throws FilterConfigurationException {
        checkNextInputAndOutputTypes(next, byte[].class, byte[].class);
        this.next = next;
    }

}

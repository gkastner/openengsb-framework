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

import org.openengsb.core.api.remote.FilterChainElement;
import org.openengsb.core.api.remote.FilterChainElementFactory;
import org.openengsb.core.api.remote.FilterConfigurationException;
import org.openengsb.core.api.security.ConnectorKeyProvider;

public class OutgoingMessageCryptoFilterFactory implements FilterChainElementFactory {

    private ConnectorKeyProvider keySource;
    private String secretKeyAlgorithm;

    public OutgoingMessageCryptoFilterFactory() {
    }

    public OutgoingMessageCryptoFilterFactory(ConnectorKeyProvider keySource, String secretKeyAlgorithm) {
        this.keySource = keySource;
        this.secretKeyAlgorithm = secretKeyAlgorithm;
    }

    @Override
    public FilterChainElement newInstance() throws FilterConfigurationException {
        return new OutgoingMessageCryptoFilter(keySource, secretKeyAlgorithm);
    }

    public void setKeySource(ConnectorKeyProvider keySource) {
        this.keySource = keySource;
    }

    public void setSecretKeyAlgorithm(String secretKeyAlgorithm) {
        this.secretKeyAlgorithm = secretKeyAlgorithm;
    }

}

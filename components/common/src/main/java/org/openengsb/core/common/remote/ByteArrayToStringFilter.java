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

package org.openengsb.core.common.remote;

import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.openengsb.core.api.remote.FilterAction;
import org.openengsb.core.api.remote.FilterConfigurationException;

public class ByteArrayToStringFilter extends AbstractFilterChainElement<byte[], byte[]> {
    private FilterAction next;

    protected ByteArrayToStringFilter() {
        super(byte[].class, byte[].class);
    }

    @Override
    protected byte[] doFilter(byte[] input, Map<String, Object> metaData) {
        String encodedInput = Base64.encodeBase64String(input);
        String result = (String) next.filter(encodedInput, metaData);
        return Base64.decodeBase64(result);
    }

    @Override
    public void setNext(FilterAction next) throws FilterConfigurationException {
        checkNextInputAndOutputTypes(next, String.class, String.class);
        this.next = next;
    }
}

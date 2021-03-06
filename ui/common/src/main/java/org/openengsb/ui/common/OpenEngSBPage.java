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

package org.openengsb.ui.common;

import java.util.ArrayList;
import java.util.List;

import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.apache.wicket.util.string.StringValue;
import org.openengsb.core.api.context.ContextCurrentService;
import org.openengsb.core.api.context.ContextHolder;
import org.ops4j.pax.wicket.api.PaxWicketBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Baseclass for any page in the OpenEngSB and for client Projects. It initializes a context when started the first
 * time. In order for this page to work, a spring-bean of the class
 *
 * @link{org.openengsb.core.common.context.ContextCurrentService must be available
 */
public abstract class OpenEngSBPage extends WebPage {

    private static final long serialVersionUID = -9066059315599403517L;

    public static final String CONTEXT_PARAM = "context";

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenEngSBPage.class);

    @PaxWicketBean(name = "contextCurrentService")
    private ContextCurrentService contextService;

    public OpenEngSBPage() {
        initContextForCurrentThread();
    }

    public OpenEngSBPage(PageParameters parameters) {
        super(parameters);
        LOGGER.debug("creating new page using parameters: {}", parameters);
        StringValue context = parameters.get(CONTEXT_PARAM);
        if (context != null && context.toOptionalString() != null) {
            final String contextId = context.toOptionalString();
            LOGGER.debug("setting context-id from pageparameter: {}", contextId);
            ContextHolder.get().setCurrentContextId(contextId);
        }
    }

    protected List<String> getAvailableContexts() {
        if (contextService == null) {
            return new ArrayList<String>();
        }
        return contextService.getAvailableContexts();
    }

    protected final void initContextForCurrentThread() {
        String sessionContextId = ContextHolder.get().getCurrentContextId();
        if (sessionContextId == null) {
            sessionContextId = "foo";
        }
        if (getAvailableContexts().contains(sessionContextId)) {
            ContextHolder.get().setCurrentContextId(sessionContextId);
        } else {
            LOGGER.debug("initialize default-values in contexts");
            contextService.createContext(sessionContextId);
            contextService.createContext(sessionContextId + "2");
            ContextHolder.get().setCurrentContextId(sessionContextId);
        }
    }

    /**
     * @return the class name, which should be the index in navigation bar
     *
     */
    public String getHeaderMenuItem() {
        return this.getClass().getSimpleName();
    }
}

/**
 * Copyright 2010 OpenEngSB Division, Vienna University of Technology
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.openengsb.ui.web;

import java.util.ArrayList;
import java.util.List;

import org.apache.wicket.Component;
import org.apache.wicket.authentication.AuthenticatedWebSession;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.form.DropDownChoice;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.link.Link;
import org.apache.wicket.model.IModel;
import org.apache.wicket.protocol.http.WebSession;
import org.apache.wicket.spring.injection.annot.SpringBean;
import org.openengsb.core.common.context.ContextCurrentService;
import org.openengsb.ui.common.wicket.OpenEngSBPage;
import org.openengsb.ui.common.wicket.OpenEngSBWebSession;
import org.openengsb.ui.web.global.footer.FooterTemplate;
import org.openengsb.ui.web.global.header.HeaderTemplate;

@SuppressWarnings("serial")
public class BasePage extends OpenEngSBPage {
    @SpringBean
    private ContextCurrentService contextService;

    public BasePage() {
        initializeHeader();
        initializeLoginLogoutTemplate();
        initializeFooter();
    }

    private void initializeFooter() {
        add(new FooterTemplate("footer"));
    }

    private void initializeLoginLogoutTemplate() {
        Form<?> form = new Form<Object>("projectChoiceForm");
        form.add(createProjectChoice());
        add(form);
        try {
            form.setVisible(((OpenEngSBWebSession) WebSession.get()).isSignedIn());
        } catch (ClassCastException e) {
        }

        Link<Object> link = new Link<Object>("logout") {
            @Override
            public void onClick() {
                boolean signedIn = ((OpenEngSBWebSession) WebSession.get()).isSignedIn();
                if (signedIn) {
                    ((AuthenticatedWebSession) this.getSession()).signOut();
                }
                setResponsePage(signedIn ? Index.class : LoginPage.class);
            }
        };
        add(link);

        WebMarkupContainer container = new WebMarkupContainer("logintext");
        link.add(container);
        try {
            container.setVisible(!((OpenEngSBWebSession) WebSession.get()).isSignedIn());
        } catch (ClassCastException e) {
        }
        container = new WebMarkupContainer("logouttext");
        link.add(container);
        try {
            container.setVisible(((OpenEngSBWebSession) WebSession.get()).isSignedIn());
        } catch (ClassCastException e) {
        }
    }

    private void initializeHeader() {
        add(new HeaderTemplate("header", getHeaderMenuItem()));
    }

    private Component createProjectChoice() {
        DropDownChoice<String> dropDownChoice = new DropDownChoice<String>("projectChoice", new IModel<String>() {
            @Override
            public String getObject() {
                return getSessionContextId();
            }

            @Override
            public void setObject(String object) {
                setThreadLocalContext(object);
            }

            @Override
            public void detach() {
            }
        }, getAvailableContexts()) {
            @Override
            protected boolean wantOnSelectionChangedNotifications() {
                return true;
            }

            @Override
            protected void onModelChanged() {
                setResponsePage(BasePage.class);
            }

        };
        return dropDownChoice;
    }

    /**
     * @return the class name, which should be the index in navigation bar
     *
     */
    @Override
    public String getHeaderMenuItem() {
        return this.getClass().getSimpleName();
    }

    @Override
    public String getSessionContextId() {
        OpenEngSBWebSession session = OpenEngSBWebSession.get();
        if (session == null) {
            return "foo";
        }
        if (session.getThreadContextId() == null) {
            setThreadLocalContext("foo");
        }
        return session.getThreadContextId();
    }

    @Override
    public void setThreadLocalContext(String threadLocalContext) {
        OpenEngSBWebSession session = OpenEngSBWebSession.get();
        if (session != null) {
            session.setThreadContextId(threadLocalContext);
        }
    }

    @Override
    public List<String> getAvailableContexts() {
        if (contextService == null) {
            return new ArrayList<String>();
        }
        return contextService.getAvailableContexts();
    }
}
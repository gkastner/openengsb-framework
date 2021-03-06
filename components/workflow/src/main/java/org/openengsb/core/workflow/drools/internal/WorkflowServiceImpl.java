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

package org.openengsb.core.workflow.drools.internal;

import java.beans.BeanInfo;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.drools.KnowledgeBase;
import org.drools.event.process.DefaultProcessEventListener;
import org.drools.event.process.ProcessCompletedEvent;
import org.drools.event.process.ProcessNodeLeftEvent;
import org.drools.event.process.ProcessNodeTriggeredEvent;
import org.drools.event.process.ProcessStartedEvent;
import org.drools.event.rule.BeforeActivationFiredEvent;
import org.drools.event.rule.DefaultAgendaEventListener;
import org.drools.impl.KnowledgeBaseImpl;
import org.drools.runtime.StatefulKnowledgeSession;
import org.drools.runtime.process.NodeInstance;
import org.drools.runtime.process.ProcessInstance;
import org.drools.runtime.process.WorkflowProcessInstance;
import org.drools.runtime.rule.ConsequenceException;
import org.drools.runtime.rule.FactHandle;
import org.jbpm.workflow.instance.node.SubProcessNodeInstance;
import org.openengsb.core.api.Event;
import org.openengsb.core.api.context.ContextHolder;
import org.openengsb.core.common.AbstractOpenEngSBService;
import org.openengsb.core.util.DefaultOsgiUtilsService;
import org.openengsb.core.util.OsgiUtils;
import org.openengsb.core.util.ThreadLocalUtil;
import org.openengsb.core.workflow.api.RemoteEventProcessor;
import org.openengsb.core.workflow.api.RuleBaseException;
import org.openengsb.core.workflow.api.TaskboxService;
import org.openengsb.core.workflow.api.WorkflowException;
import org.openengsb.core.workflow.api.WorkflowService;
import org.openengsb.core.workflow.api.model.InternalWorkflowEvent;
import org.openengsb.core.workflow.api.model.ProcessBag;
import org.openengsb.core.workflow.api.model.RemoteEvent;
import org.openengsb.core.workflow.api.model.RuleBaseElementId;
import org.openengsb.core.workflow.api.model.RuleBaseElementType;
import org.openengsb.core.workflow.api.model.Task;
import org.openengsb.core.workflow.drools.WorkflowHelper;
import org.openengsb.domain.auditing.AuditingDomain;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Filter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WorkflowServiceImpl extends AbstractOpenEngSBService implements WorkflowService, RemoteEventProcessor {

    private static final String START_FLOW_CONSEQUENCE_LINE =
        " )\nthen\n  WorkflowHelper.startFlow(kcontext.getKnowledgeRuntime(), \"%s\");\n";

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowServiceImpl.class);

    private static final String FLOW_TRIGGER_RULE_TEMPLATE_START =
        "## This rule has been autogenerated by the WorkflowService\n" + "when\n" + "  %s ( name == \"%s\"";

    private static final String FLOW_TRIGGER_RULE_TEMPLATE_EVENT_FIELD = ", %s == \"%s\"";

    private DroolsRuleManager rulemanager;
    private BundleContext bundleContext;
    private TaskboxService taskbox;

    private Map<String, StatefulKnowledgeSession> sessions = new HashMap<String, StatefulKnowledgeSession>();
    private ExecutorService executor = ThreadLocalUtil.contextAwareExecutor(Executors.newCachedThreadPool());

    private Lock workflowLock = new ReentrantLock();

    private DefaultOsgiUtilsService utilsService;

    private Collection<AuditingDomain> auditingConnectors;

    @Override
    public void processEvent(Event event) throws WorkflowException {
        LOGGER.info("processing Event {} of type {}", event, event.getClass());
        for (AuditingDomain connector : auditingConnectors) {
            connector.onEvent(event);
        }
        StatefulKnowledgeSession session = getSessionForCurrentContext();
        FactHandle factHandle = null;
        try {
            factHandle = session.insert(event);
            workflowLock.lock();
            try {
                session.fireAllRules();
            } catch (ConsequenceException e) {
                throw new WorkflowException("ConsequenceException occured while processing event", e.getCause());
            } finally {
                workflowLock.unlock();
            }

            Set<Long> processIds = retrieveRelevantProcessInstanceIds(event, session);
            if (processIds.isEmpty()) {
                for (ProcessInstance p : session.getProcessInstances()) {
                    p.signalEvent(event.getClass().getSimpleName(), event);
                }
            } else {
                signalEventToProcesses(event, session, processIds);
            }
        } finally {
            session.retract(factHandle);
        }
    }

    @Override
    public void processRemoteEvent(RemoteEvent event) throws WorkflowException {
        processEvent(event);
    }

    private void signalEventToProcesses(Event event, StatefulKnowledgeSession session, Set<Long> processIds) {
        for (Long pid : processIds) {
            ProcessInstance processInstance = session.getProcessInstance(pid);
            if (processInstance == null) {
                LOGGER.warn("processInstance with ID {} not found, maybe it already terminated", pid);
            } else {
                processInstance.signalEvent(event.getClass().getSimpleName(), event);
            }
        }
    }

    private Set<Long> retrieveRelevantProcessInstanceIds(Event event, StatefulKnowledgeSession session) {
        Set<Long> processIds = new HashSet<Long>();
        Long processIdFromEvent = event.getProcessId();
        if (processIdFromEvent != null) {
            processIds.add(processIdFromEvent);
            processIds.addAll(getSubFlows(session.getProcessInstance(processIdFromEvent)));
        }
        if (event instanceof InternalWorkflowEvent) {
            ProcessBag bag = ((InternalWorkflowEvent) event).getProcessBag();
            Long processIdFromBag = Long.parseLong(bag.getProcessId());
            processIds.add(processIdFromBag);
            processIds.addAll(getSubFlows(session.getProcessInstance(processIdFromBag)));
        }

        return processIds;
    }

    private Collection<Long> getSubFlows(ProcessInstance processInstance) {
        Collection<Long> result = new HashSet<Long>();
        if (processInstance == null) {
            return result;
        }
        WorkflowProcessInstance wp = (WorkflowProcessInstance) processInstance;
        for (NodeInstance n : wp.getNodeInstances()) {
            if (n instanceof SubProcessNodeInstance) {
                SubProcessNodeInstance spn = (SubProcessNodeInstance) n;
                result.add(spn.getProcessInstanceId());
            }
        }
        return result;
    }

    @Override
    public long startFlow(String processId) throws WorkflowException {
        return startFlowWithParameters(processId, new HashMap<String, Object>());
    }

    @Override
    public ProcessBag executeWorkflow(String processId, ProcessBag parameters) throws WorkflowException {
        Map<String, Object> parameterMap = new HashMap<String, Object>();
        parameterMap.put("processBag", parameters);
        long id = startFlowWithParameters(processId, parameterMap);
        try {
            waitForFlowToFinishIndefinitely(id);
        } catch (InterruptedException e) {
            throw new WorkflowException(e);
        }
        return parameters;
    }

    @Override
    public long startFlowWithParameters(String processId, Map<String, Object> parameterMap) throws WorkflowException {
        try {
            return startFlowInBackground(processId, parameterMap).get();
        } catch (InterruptedException e) {
            throw new WorkflowException(e);
        } catch (ExecutionException e) {
            throw new WorkflowException("unable to start workflow " + processId, e.getCause());
        }
    }

    private Future<Long> startFlowInBackground(String processId, Map<String, Object> paramterMap)
        throws WorkflowException {
        Callable<Long> call = WorkflowHelper.getCallable(getSessionForCurrentContext(), processId, paramterMap);
        return executor.submit(call);
    }

    @Override
    public void registerFlowTriggerEvent(Event event, String... flowIds) throws WorkflowException {
        String eventName = event.getName();
        String ruleName = String.format("_generated_ trigger %s on %s", Arrays.asList(flowIds), eventName);
        StringBuffer ruleCode = generateFlowTriggerRule(event, flowIds);
        LOGGER.info("adding new rule with id: {}", ruleName);
        try {
            rulemanager.add(new RuleBaseElementId(RuleBaseElementType.Rule, ruleName), ruleCode.toString());
        } catch (RuleBaseException e) {
            throw new WorkflowException(e);
        }
    }

    private StringBuffer generateFlowTriggerRule(Event event, String... flowIds) throws WorkflowException {
        StringBuffer ruleCode = new StringBuffer();
        ruleCode.append(String.format(FLOW_TRIGGER_RULE_TEMPLATE_START, event.getClass().getName(), event.getName()));
        addOtherPropertyChecks(event, ruleCode);
        for (String flowId : flowIds) {
            ruleCode.append(String.format(START_FLOW_CONSEQUENCE_LINE, flowId));
        }
        return ruleCode;
    }

    private void addOtherPropertyChecks(Event event, StringBuffer ruleCode) throws WorkflowException {
        Class<? extends Event> eventClass = event.getClass();
        List<PropertyDescriptor> properties = reflectPropertiesFromEventClass(eventClass);
        for (PropertyDescriptor property : properties) {
            Method getter = property.getReadMethod();
            if (Modifier.PUBLIC != getter.getModifiers()) {
                continue;
            }
            Object propertyValue = getPropertyValue(event, getter);
            if (propertyValue == null) {
                continue;
            }
            ruleCode.append(String.format(FLOW_TRIGGER_RULE_TEMPLATE_EVENT_FIELD, property.getName(), propertyValue));
        }
    }

    private Object getPropertyValue(Event event, Method getter) throws WorkflowException {
        try {
            return getter.invoke(event);
        } catch (Exception e) {
            throw new WorkflowException("Cannot invoke getter '" + getter + "' of event class '" + event.getClass()
                    + "'.", e);
        }
    }

    private List<PropertyDescriptor> reflectPropertiesFromEventClass(Class<? extends Event> clazz)
        throws WorkflowException {
        if (clazz.equals(Event.class)) {
            return new ArrayList<PropertyDescriptor>();
        }
        try {
            List<PropertyDescriptor> result = new ArrayList<PropertyDescriptor>();
            BeanInfo info = Introspector.getBeanInfo(clazz);
            result.addAll(Arrays.asList(info.getPropertyDescriptors()));

            BeanInfo eventInfo = Introspector.getBeanInfo(Event.class);
            result.removeAll(Arrays.asList(eventInfo.getPropertyDescriptors()));

            return result;
        } catch (IntrospectionException ie) {
            throw new WorkflowException("Cannot introspect event class " + clazz, ie);
        }
    }

    @Override
    public void waitForFlowToFinishIndefinitely(long id) throws InterruptedException, WorkflowException {
        StatefulKnowledgeSession session = getSessionForCurrentContext();
        synchronized (session) {
            while (session.getProcessInstance(id) != null) {
                session.wait();
            }
        }
    }

    @Override
    public boolean waitForFlowToFinish(long id, long timeout) throws InterruptedException, WorkflowException {
        StatefulKnowledgeSession session = getSessionForCurrentContext();
        long endTime = System.currentTimeMillis() + timeout;
        synchronized (session) {
            while (session.getProcessInstance(id) != null && timeout > 0) {
                session.wait(timeout);
                timeout = endTime - System.currentTimeMillis();
            }
        }
        return !getRunningFlows().contains(id);
    }

    @Override
    public ProcessBag getProcessBagForInstance(long instanceId) {
        StatefulKnowledgeSession session = getSessionForCurrentContext();
        ProcessInstance instance = session.getProcessInstance(instanceId);
        if (instance == null || !(instance instanceof WorkflowProcessInstance)) {
            throw new IllegalArgumentException("Process instance with id " + instanceId + " not found");
        }
        return (ProcessBag) ((WorkflowProcessInstance) instance).getVariable("processBag");
    }

    public Collection<Long> getRunningFlows() throws WorkflowException {
        Collection<ProcessInstance> processInstances = getSessionForCurrentContext().getProcessInstances();
        Collection<Long> result = new HashSet<Long>();
        for (ProcessInstance p : processInstances) {
            result.add(p.getId());

        }
        return result;
    }

    private StatefulKnowledgeSession getSessionForCurrentContext() throws WorkflowException {
        String currentContextId = ContextHolder.get().getCurrentContextId();
        if (currentContextId == null) {
            throw new IllegalStateException("contextID must not be null");
        }
        if (sessions.containsKey(currentContextId)) {
            return sessions.get(currentContextId);
        }
        StatefulKnowledgeSession session;
        try {
            session = createSession();
        } catch (RuleBaseException e) {
            throw new WorkflowException(e);
        }
        sessions.put(currentContextId, session);
        return session;
    }

    protected StatefulKnowledgeSession createSession() throws RuleBaseException, WorkflowException {
        KnowledgeBase rb = rulemanager.getRulebase();
        ((KnowledgeBaseImpl) rb).ruleBase.lock();
        LOGGER.debug("retrieved rulebase: {} from source {}", rb, rulemanager);
        final StatefulKnowledgeSession session = rb.newStatefulKnowledgeSession();
        LOGGER.debug("session started");
        populateGlobals(session);
        LOGGER.debug("globals have been set");
        session.addEventListener(new DefaultProcessEventListener() {
            @Override
            public void beforeNodeTriggered(ProcessNodeTriggeredEvent event) {
                for (AuditingDomain ac : auditingConnectors) {
                    ProcessInstance instance = event.getProcessInstance();
                    ac.onNodeStart(instance.getProcessName(), instance.getId(), event.getNodeInstance().getNodeName());
                }
            }

            @Override
            public void afterNodeLeft(ProcessNodeLeftEvent event) {
                for (AuditingDomain ac : auditingConnectors) {
                    ProcessInstance instance = event.getProcessInstance();
                    ac.onNodeFinish(instance.getProcessName(), instance.getId(), event.getNodeInstance().getNodeName());
                }
            }

            @Override
            public void afterProcessCompleted(ProcessCompletedEvent event) {
                synchronized (session) {
                    session.notifyAll();
                }
            }
        });
        session.addEventListener(new DefaultProcessEventListener() {
            @Override
            public void afterProcessStarted(ProcessStartedEvent event) {
                String processId2 = event.getProcessInstance().getProcessId();
                long id = event.getProcessInstance().getId();
                LOGGER.info("started process \"{}\". instance-ID: {}", processId2, id);
            }

            @Override
            public void beforeNodeTriggered(ProcessNodeTriggeredEvent event) {
                long nodeId = event.getNodeInstance().getNodeId();
                String nodeName = event.getNodeInstance().getNodeName();
                LOGGER.info("Now triggering node \"{}\" (\"{}\").", nodeName, nodeId);
            }

            @Override
            public void afterProcessCompleted(ProcessCompletedEvent event) {
                String processId2 = event.getProcessInstance().getProcessId();
                long id = event.getProcessInstance().getId();
                LOGGER.info("process completed \"{}\". instance-ID: {}", processId2, id);
            }
        });

        session.addEventListener(new DefaultAgendaEventListener() {
            @Override
            public void beforeActivationFired(BeforeActivationFiredEvent event) {
                String ruleName = event.getActivation().getRule().getName();
                LOGGER.info("rule \"{}\" fired.", ruleName);
            }
        });
        ((KnowledgeBaseImpl) rb).ruleBase.unlock();
        return session;
    }

    private void populateGlobals(StatefulKnowledgeSession session) throws WorkflowException {
        Map<String, String> globals = rulemanager.listGlobals();
        for (Map.Entry<String, String> global : globals.entrySet()) {
            Class<?> globalClass;
            try {
                globalClass = bundleContext.getBundle().loadClass(global.getValue());
            } catch (ClassNotFoundException e) {
                throw new WorkflowException(String.format("Could not load class for global (%s)", global), e);
            }
            Filter filter =
                OsgiUtils.getFilterForLocation(globalClass, global.getKey(),
                    ContextHolder.get().getCurrentContextId());
            Object osgiServiceProxy = utilsService.getOsgiServiceProxy(filter, globalClass);
            session.setGlobal(global.getKey(), osgiServiceProxy);
        }
    }

    public void setBundleContext(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
        utilsService = new DefaultOsgiUtilsService(bundleContext);
    }

    public void setRulemanager(DroolsRuleManager rulemanager) {
        this.rulemanager = rulemanager;
    }

    @Override
    public void cancelFlow(Long processInstanceId) throws WorkflowException {
        getSessionForCurrentContext().abortProcessInstance(processInstanceId);
        List<Task> tasksForProcessId = taskbox.getTasksForProcessId(Long.toString(processInstanceId));
        for (Task t : tasksForProcessId) {
            taskbox.finishTask(t);
        }
    }

    public void setTaskbox(TaskboxService taskbox) {
        this.taskbox = taskbox;
    }

    public void setAuditingConnectors(Collection<AuditingDomain> auditingConnectors) {
        this.auditingConnectors = auditingConnectors;
    }

}

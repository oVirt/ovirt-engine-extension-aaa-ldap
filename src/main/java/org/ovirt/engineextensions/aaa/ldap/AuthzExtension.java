/*
 * Copyright 2012-2014 Red Hat Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */
package org.ovirt.engineextensions.aaa.ldap;

import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.*;
import java.util.*;

import com.unboundid.asn1.*;
import com.unboundid.ldap.sdk.*;
import org.slf4j.*;

import org.ovirt.engine.api.extensions.*;
import org.ovirt.engine.api.extensions.aaa.*;

public class AuthzExtension implements Extension {

    private class SearchOpaque {
        ExtUUID entity;
        boolean resolveGroups;
        boolean resolveGroupsRecursive;

        Framework.SearchInstance instance;
        String namespace;

        ExtKey groupsKey;
        ExtKey namespaceKey;
        String varPrefix;
        String completeSequence;
        Map<String, ExtKey> toKeys;
        Map<ExtKey, String> fromKeys;
    }

    public static final ExtKey DN_KEY = new ExtKey("AAA_LDAP_UNBOUNDID_DN", String.class, "95ca004b-6fe5-4552-988a-f3542171f713");
    public static final ExtKey RAW_GROUPS_KEY = new ExtKey("AAA_LDAP_UNBOUNDID_RAW_GROUPS", Collection/*<String>*/.class, "c51860df-9998-48a5-998f-843c2f88998a");

    private static final String PREFIX_CONFIG_AUTHZ = "config.authz.";

    private static final Logger log = LoggerFactory.getLogger(AuthzExtension.class);

    public static final Map<ExtKey, String> principalFromRecordKeys = getRecordKeys(Authz.PrincipalRecord.class);
    public static final Map<ExtKey, String> groupFromRecordKeys = getRecordKeys(Authz.GroupRecord.class);
    public static final Map<String, ExtKey> principalToRecordKeys = invertKeyValue(principalFromRecordKeys);
    public static final Map<String, ExtKey> groupToRecordKeys = invertKeyValue(groupFromRecordKeys);

    private Framework framework;
    private volatile boolean frameworkInitialized = false;
    private Collection<String> namespaces = new ArrayList<>();

    private String attrmapGroupRecord;
    private String attrmapPrincipalRecord;
    private String attrNamespace;
    private String sequenceNamespace;
    private String sequenceQueryGroups;
    private String sequenceQueryPrincipals;
    private String sequenceResolveGroup;
    private String sequenceResolvePrincipal;
    private String sequenceCompletePrincipal;
    private String sequenceCompleteGroup;

    private static Map<ExtKey, String>  getRecordKeys(Class<?> clz) {
        Map<ExtKey, String> ret  = new HashMap<ExtKey, String>();
        try {
            for (Field field : clz.getFields()) {
                if (ExtKey.class.isAssignableFrom(field.getType())) {
                    ret.put(
                        (ExtKey)field.get(null),
                        field.getName()
                    );
                }
            }
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
        return ret;
    }

    private static <K, V> Map<V, K> invertKeyValue(Map<K, V> m) {
        Map<V, K> ret = new HashMap<>();
        for (Map.Entry<K, V> entry : m.entrySet()) {
            ret.put(entry.getValue(), entry.getKey());
        }
        return ret;
    }

    private void ensureFramework(ExtMap input) throws Exception {
        if (!frameworkInitialized) {
            synchronized(this) {
                if (!frameworkInitialized) {
                    framework.open();

                    ExtMap context = input.<ExtMap>get(Base.InvokeKeys.CONTEXT);

                    String maxFilterSize = (String)framework.getGlobals().get(ExtensionUtil.VARS_MAX_FILTER_SIZE);
                    if (maxFilterSize != null) {
                        context.put(
                            Authz.ContextKeys.QUERY_MAX_FILTER_SIZE,
                            Integer.valueOf(maxFilterSize)
                        );
                    }

                    Object availableNamespace = framework.getGlobals().get(ExtensionUtil.VARS_AVAILABLE_NAMESPACE);
                    if (availableNamespace != null) {
                        namespaces.add(availableNamespace.toString());
                    } else {
                        namespaces = new ArrayList<>();
                        Map<String, Object> vars = framework.createSequenceVars();
                        framework.runSequence(sequenceNamespace, vars);
                        Framework.SearchInstance instance = (Framework.SearchInstance)vars.get(ExtensionUtil.VARS_QUERY);
                        if (instance == null) {
                            namespaces.add("*");
                        } else {
                            try {
                                while (true) {
                                    List<Map<String, List<String>>> result = framework.searchExecute(instance, 0);
                                    if (result == null) {
                                        break;
                                    }
                                    for (Map<String, List<String>> entry : result) {
                                        List<String> namespace = entry.get(attrNamespace);
                                        if (namespace != null) {
                                            namespaces.addAll(namespace);
                                        }
                                    }
                                }
                            } finally {
                                framework.searchClose(instance);
                            }
                        }
                    }

                    log.debug("Namespaces: '{}'", namespaces);
                    context.put(
                        Authz.ContextKeys.AVAILABLE_NAMESPACES,
                        namespaces
                    );
                    frameworkInitialized = true;
                }
            }
        }
    }

    private Filter transformFilter(
        ExtMap filter,
        List<Framework.AttrMapInfo> attrmap,
        Map<ExtKey, String> fromKeys,
        String prefix
    ) {
        Filter ret = null;

        log.debug("transformFilter entry");
        log.trace("filter {}", filter);

        ExtKey key = filter.<ExtKey>get(Authz.QueryFilterRecord.KEY);
        if (key == null) {
            log.trace("no key");
            List<Filter> filters = new ArrayList<>();
            for (ExtMap subfilter : filter.<Collection<ExtMap>>get(Authz.QueryFilterRecord.FILTER)) {
                Filter f = transformFilter(subfilter, attrmap, fromKeys, prefix);
                if (f != null) {
                    filters.add(f);
                }
            }
            switch (filter.<Integer>get(Authz.QueryFilterRecord.OPERATOR)) {
            default:
                throw new IllegalArgumentException("Invalid search operator");
            case Authz.QueryFilterOperator.NOT:
                if (filters.size() != 1) {
                    throw new IllegalArgumentException("Invalid search filter, not operator must have exactly one element");
                }
                ret = Filter.createNOTFilter(filters.get(0));
                break;
            case Authz.QueryFilterOperator.AND:
                ret = Filter.createANDFilter(filters);
                break;
            case Authz.QueryFilterOperator.OR:
                ret = Filter.createORFilter(filters);
                break;
            }
        } else {
            String field = fromKeys.get(key);
            if (field != null) {
                Framework.AttrMapInfo attrInfo = null;
                for (Framework.AttrMapInfo entry : attrmap) {
                    if (entry.getName().equals(prefix + field)) {
                        attrInfo = entry;
                    }
                }
                if (attrInfo != null) {
                    String fieldValue = filter.<String>get(key);
                    boolean prefixEquals = false;

                    if (AttrConversion.STRING.equals(attrInfo.getConversion())) {
                        if (fieldValue.endsWith("*")) {
                            fieldValue = fieldValue.substring(0, fieldValue.length()-1);
                            prefixEquals = true;
                        }
                    }

                    ASN1OctetString value = attrInfo.decode(fieldValue);
                    switch (filter.<Integer>get(Authz.QueryFilterRecord.OPERATOR)) {
                    default:
                        throw new IllegalArgumentException("Invalid search operator");
                    case Authz.QueryFilterOperator.EQ:
                        if (prefixEquals) {
                            ret = Filter.createSubstringFilter(attrInfo.getMap(), value.stringValue(), null, null);
                        } else {
                            ret = Filter.createEqualityFilter(attrInfo.getMap(), value.getValue());
                        }
                        break;
                    case Authz.QueryFilterOperator.LE:
                        ret = Filter.createLessOrEqualFilter(attrInfo.getMap(), value.getValue());
                        break;
                    case Authz.QueryFilterOperator.GE:
                        ret = Filter.createGreaterOrEqualFilter(attrInfo.getMap(), value.getValue());
                        break;
                    }
                }
            }
        }

        log.debug("transformFilter Return {}", ret);
        return ret;
    }

    private ExtMap transformVarsToRecord(
        Map<String, Object> vars,
        Map<String, ExtKey> toKeys,
        String varPrefix,
        ExtKey namespaceKey,
        String namespace
    ) {
        ExtMap record = new ExtMap();
        for (Map.Entry<String, Object> var : vars.entrySet()) {
            if (var.getKey().startsWith(varPrefix)) {
                ExtKey key = toKeys.get(var.getKey().substring(varPrefix.length()));
                if (key != null) {
                    record.put(key, vars.get(var.getKey()).toString());
                }
            }
        }
        return record.mput(
            namespaceKey,
            record.get(namespaceKey, namespace)
        ).mput(
            DN_KEY,
            vars.get(varPrefix + "DN")
        ).mput(
            RAW_GROUPS_KEY,
            vars.get(varPrefix + "GROUPS_RAW")
        );
    }

    private String resolveNamespace(String dn) {
        String candidate = "";
        for (String namespace : namespaces) {
            if (dn.endsWith("," + namespace) && namespace.length() > candidate.length()) {
                candidate = namespace;
            }
        }
        if (candidate.isEmpty()) {
            candidate = null;
        }
        return candidate;
    }

    private void _resolveGroups(ExtMap record, ExtKey groupsKey, boolean recursive, Map<String, ExtMap> cache)
    throws Exception {
        log.debug("_resolveGroups Entry");

        Collection<String> groups = record.<List<String>>get(RAW_GROUPS_KEY);
        if (groups != null) {
            record.remove(RAW_GROUPS_KEY);

            for (String group : groups) {
                log.debug("Resolving: '{}'", group);
                Collection<ExtMap> groupRecords = record.<Collection<ExtMap>>get(groupsKey, new LinkedList<ExtMap>());
                record.put(groupsKey, groupRecords);
                ExtMap groupRecord = cache.get(group);
                if (groupRecord == null) {
                    log.debug("Cache miss");
                    Map<String, Object> vars = framework.createSequenceVars();
                    vars.put(
                        ExtensionUtil.VARS_DN,
                        group
                    );
                    framework.runSequence(sequenceResolveGroup, vars);
                    if (vars.get(ExtensionUtil.GROUP_RECORD_PREFIX + "ID") == null) {
                        log.debug("WARNING: Cannot resolve group '{}'", group);
                    } else {
                        framework.runSequence(sequenceCompleteGroup, vars);
                        groupRecord = transformVarsToRecord(
                            vars, groupToRecordKeys,
                            ExtensionUtil.GROUP_RECORD_PREFIX,
                            Authz.GroupRecord.NAMESPACE,
                            resolveNamespace(group)
                        );
                    }
                }
                if (groupRecord != null) {
                    groupRecords.add(groupRecord);
                }

                if (recursive) {
                    for (ExtMap entry : groupRecords) {
                        _resolveGroups(entry, groupsKey, recursive, cache);
                    }
                }
            }
        }

        log.debug("_resolveGroups Return");
    }

    private void resolveGroups(Collection<ExtMap> records, ExtKey groupsKey, boolean recursive)
    throws Exception {
        log.debug("resolveGroups Entry");

        Map<String, ExtMap> cache = new HashMap<>();
        for (ExtMap record : records) {
            _resolveGroups(record, groupsKey, false, cache);
            if (recursive) {
                for (ExtMap groupRecord : record.<Collection<ExtMap>>get(groupsKey, Collections.<ExtMap>emptyList())) {
                    _resolveGroups(groupRecord, Authz.GroupRecord.GROUPS, true, cache);
                }
            }
        }

        log.debug("resolveGroups Return");
    }

    @Override
    public void invoke(ExtMap input, ExtMap output) {
        try {
            if (input.get(Base.InvokeKeys.COMMAND).equals(Base.InvokeCommands.LOAD)) {
                doLoad(input, output);
            } else if (input.get(Base.InvokeKeys.COMMAND).equals(Base.InvokeCommands.INITIALIZE)) {
                doInit(input, output);
            } else if (input.get(Base.InvokeKeys.COMMAND).equals(Base.InvokeCommands.TERMINATE)) {
                doTerminate(input, output);
            } else if (input.get(Base.InvokeKeys.COMMAND).equals(Authz.InvokeCommands.FETCH_PRINCIPAL_RECORD)) {
                doFetchPrincipalRecord(input, output);
            } else if (input.get(Base.InvokeKeys.COMMAND).equals(Authz.InvokeCommands.QUERY_OPEN)) {
                doQueryOpen(input, output);
            } else if (input.get(Base.InvokeKeys.COMMAND).equals(Authz.InvokeCommands.QUERY_EXECUTE)) {
                doQueryExecute(input, output);
            } else if (input.get(Base.InvokeKeys.COMMAND).equals(Authz.InvokeCommands.QUERY_CLOSE)) {
                doQueryClose(input, output);
            } else {
                output.put(Base.InvokeKeys.RESULT, Base.InvokeResult.UNSUPPORTED);
            }
            output.putIfAbsent(Base.InvokeKeys.RESULT, Base.InvokeResult.SUCCESS);
        } catch (Exception e) {
            log.debug("Exception", e);
            output.mput(
                Base.InvokeKeys.RESULT, Base.InvokeResult.FAILED
            ).mput(
                Base.InvokeKeys.MESSAGE, e.getMessage()
            );
        }
    }

    private void doLoad(ExtMap input, ExtMap output) throws Exception {
        ExtMap context = input.<ExtMap> get(
            Base.InvokeKeys.CONTEXT
        );
        Properties configuration = context.<Properties> get(
            Base.ContextKeys.CONFIGURATION
        );
        context.mput(
            ExtensionUtil.EXTENSION_INFO
        ).mput(
            Base.ContextKeys.EXTENSION_NAME,
            "aaa.ldap.authz"
        ).mput(
            Authz.ContextKeys.QUERY_MAX_FILTER_SIZE,
            Integer.valueOf(configuration.getProperty(PREFIX_CONFIG_AUTHZ + "query.max_filter_size", "50"))
        );

        framework = ExtensionUtil.frameworkCreate(context, "authz_enable");

        attrmapGroupRecord = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "attrmap.map-group-record.name", "map-group-record");
        attrmapPrincipalRecord = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "attrmap.map-principal-record.name", "map-principal-record");
        attrNamespace = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.namespace.attribute.namespace", "namespace");
        sequenceNamespace = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.namespace.name", "namespace");
        sequenceQueryGroups = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.query-groups.name", "query-groups");
        sequenceQueryPrincipals = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.query-principals.name", "query-principals");
        sequenceResolveGroup = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.resolve-group.name", "resolve-group");
        sequenceResolvePrincipal = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.resolve-principal.name", "resolve-principal");
        sequenceCompletePrincipal = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.complete-principal.name", "complete-principal");
        sequenceCompleteGroup = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.complete-group.name", "complete-group");

        if (Boolean.valueOf(framework.getGlobals().get(ExtensionUtil.VARS_CAPABILITY_RECUSRIVE_GROUP_RESOLUTION).toString())) {
            context.put(
                Authz.ContextKeys.CAPABILITIES,
                context.<Long>get(
                    Authz.ContextKeys.CAPABILITIES,
                    0l
                ) | Authz.Capabilities.RECURSIVE_GROUP_RESOLUTION
            );
        }
    }

    private void doInit(ExtMap input, ExtMap output) throws Exception {
        try {
            ensureFramework(input);
        } catch(Exception e) {
            log.error("Cannot initialize LDAP framework, deferring initialization. Error: {}", e.getMessage());
            log.debug("Exception", e);
        }
    }

    private void doTerminate(ExtMap input, ExtMap output) throws IOException {
        if (framework != null) {
            framework.close();
            framework = null;
        }
    }

    private void doFetchPrincipalRecord(ExtMap input, ExtMap output) throws Exception {

        log.debug("doFetchPrincipalRecord Enter");

        ensureFramework(input);

        Map<String, Object> vars = framework.createSequenceVars();
        vars.put(
            ExtensionUtil.PRINCIPAL_RECORD_PREFIX + "PRINCIPAL",
            input.<String>get(
                Authn.InvokeKeys.PRINCIPAL,
                input.<ExtMap>get(Authn.InvokeKeys.AUTH_RECORD).<String>get(
                    Authn.AuthRecord.PRINCIPAL
                )
            )
        );
        framework.runSequence(sequenceResolvePrincipal, vars);

        if (vars.get(ExtensionUtil.PRINCIPAL_RECORD_PREFIX + "ID") != null) {

            framework.runSequence(sequenceCompletePrincipal, vars);

            ExtMap principalRecord = transformVarsToRecord(
                vars,
                principalToRecordKeys,
                ExtensionUtil.PRINCIPAL_RECORD_PREFIX,
                Authz.PrincipalRecord.NAMESPACE,
                null
            );

            resolveGroups(
                Arrays.asList(principalRecord),
                Authz.PrincipalRecord.GROUPS,
                true
            );

            output.mput(
                Authz.InvokeKeys.PRINCIPAL_RECORD,
                principalRecord
            );
        }

        output.mput(
            Authz.InvokeKeys.STATUS,
            Authz.Status.SUCCESS
        );

        log.trace("Output {}", output);
        log.debug("doFetchPrincipalRecord Return");
    }

    private void doQueryOpen(ExtMap input, ExtMap output) throws Exception {

        log.debug("doQueryOpen Enter");

        ensureFramework(input);

        ExtMap context = input.<ExtMap> get(
            Base.InvokeKeys.CONTEXT
        );

        int flags = input.<Integer>get(Authz.InvokeKeys.QUERY_FLAGS, 0);
        log.debug("Flags={}", flags);
        SearchOpaque opaque = new SearchOpaque();
        opaque.entity = input.<ExtUUID>get(Authz.InvokeKeys.QUERY_ENTITY);
        opaque.resolveGroups = (flags & Authz.QueryFlags.RESOLVE_GROUPS) != 0;
        opaque.resolveGroupsRecursive = (flags & Authz.QueryFlags.RESOLVE_GROUPS_RECURSIVE) != 0;

        String sequence = null;
        String attrmapName = null;
        if (opaque.entity.equals(Authz.QueryEntity.PRINCIPAL)) {
            opaque.groupsKey = Authz.PrincipalRecord.GROUPS;
            opaque.namespaceKey = Authz.PrincipalRecord.NAMESPACE;
            opaque.varPrefix = ExtensionUtil.PRINCIPAL_RECORD_PREFIX;
            opaque.completeSequence = sequenceCompletePrincipal;
            opaque.toKeys = principalToRecordKeys;
            opaque.fromKeys = principalFromRecordKeys;
            sequence = sequenceQueryPrincipals;
            attrmapName = attrmapPrincipalRecord;
        } else if (opaque.entity.equals(Authz.QueryEntity.GROUP)) {
            opaque.groupsKey = Authz.GroupRecord.GROUPS;
            opaque.namespaceKey = Authz.GroupRecord.NAMESPACE;
            opaque.varPrefix = ExtensionUtil.GROUP_RECORD_PREFIX;
            opaque.completeSequence = sequenceCompleteGroup;
            opaque.toKeys = groupToRecordKeys;
            opaque.fromKeys = groupFromRecordKeys;
            sequence = sequenceQueryGroups;
            attrmapName = attrmapGroupRecord;
        }

        if (sequence != null) {
            Map<String, Object> vars = framework.createSequenceVars();
            vars.put(ExtensionUtil.VARS_NAMESPACE, input.<String>get(Authz.InvokeKeys.NAMESPACE));
            vars.put(
                ExtensionUtil.VARS_FILTER,
                transformFilter(
                    input.<ExtMap>get(Authz.InvokeKeys.QUERY_FILTER),
                    framework.getAttrMap(attrmapName, vars),
                    opaque.fromKeys,
                    opaque.varPrefix
                )
            );
            framework.runSequence(sequence, vars);
            opaque.namespace = (String)vars.get(ExtensionUtil.VARS_NAMESPACE);
            opaque.instance = (Framework.SearchInstance)vars.get(ExtensionUtil.VARS_QUERY);
            opaque.resolveGroupsRecursive = (
                opaque.resolveGroupsRecursive &&
                !Boolean.valueOf(vars.get(ExtensionUtil.VARS_CAPABILITY_RECUSRIVE_GROUP_RESOLUTION).toString())
            );

            if (opaque.instance != null) {
                output.mput(
                    Authz.InvokeKeys.QUERY_OPAQUE,
                    opaque
                );
            }
        }

        log.debug("doQueryOpen Return");
    }

    private void doQueryExecute(ExtMap input, ExtMap output) throws Exception {

        log.debug("doQueryExecute Enter");

        SearchOpaque opaque = input.<SearchOpaque>get(Authz.InvokeKeys.QUERY_OPAQUE);
        if (opaque != null) {
            List<Map<String, List<String>>> entries = framework.searchExecute(
                opaque.instance,
                input.<Integer>get(Authz.InvokeKeys.PAGE_SIZE, 0)
            );
            if (entries != null) {
                List<ExtMap> records = new LinkedList<>();

                for (Map<String, List<String>> entry : entries) {

                    Map<String, Object> vars = framework.createSequenceVars();
                    for (Map.Entry<String, List<String>> var : entry.entrySet()) {
                        Object value = var.getValue();
                        if (var.getKey().equals(opaque.varPrefix + "DN")) {
                            value = var.getValue().get(0);
                        } else if (var.getKey().startsWith(opaque.varPrefix)) {
                            ExtKey key = opaque.toKeys.get(var.getKey().substring(opaque.varPrefix.length()));
                            if (key != null) {
                                value = var.getValue().get(0);
                            }
                        }
                        vars.put(var.getKey(), value);
                    }
                    framework.runSequence(opaque.completeSequence, vars);

                    records.add(
                        transformVarsToRecord(
                            vars,
                            opaque.toKeys,
                            opaque.varPrefix,
                            opaque.namespaceKey,
                            opaque.namespace
                        )
                    );
                }

                if (opaque.resolveGroups) {
                    resolveGroups(
                        records,
                        opaque.groupsKey,
                        opaque.resolveGroupsRecursive
                    );
                }

                log.debug("doQueryExecute records#={}", records.size());
                log.trace("Records: {}", records);

                output.mput(
                    Authz.InvokeKeys.QUERY_RESULT,
                    records
                );
            }
        }

        log.debug("doQueryExecute Return");
    }

    private void doQueryClose(ExtMap input, ExtMap output) throws Exception {

        log.debug("doQueryClose Enter");

        SearchOpaque opaque = input.<SearchOpaque>get(Authz.InvokeKeys.QUERY_OPAQUE);
        if (opaque != null) {
            framework.searchClose(opaque.instance);
        }

        log.debug("doQueryClose Return");
    }
}

// vim: expandtab tabstop=4 shiftwidth=4

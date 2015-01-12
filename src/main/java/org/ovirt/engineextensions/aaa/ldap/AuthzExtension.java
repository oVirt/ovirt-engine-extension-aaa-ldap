/*
 * Copyright 2012-2015 Red Hat Inc.
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

    private static final String PREFIX_CONFIG_AUTHZ = "config.authz.";

    private static final Logger log = LoggerFactory.getLogger(AuthzExtension.class);

    public static final Map<ExtKey, String> principalFromRecordKeys = getRecordKeys(Authz.PrincipalRecord.class);
    public static final Map<ExtKey, String> groupFromRecordKeys = getRecordKeys(Authz.GroupRecord.class);
    public static final Map<String, ExtKey> principalToRecordKeys = invertKeyValue(principalFromRecordKeys);
    public static final Map<String, ExtKey> groupToRecordKeys = invertKeyValue(groupFromRecordKeys);

    private Framework framework;
    private volatile boolean frameworkInitialized = false;
    private Collection<String> namespaces = new ArrayList<>();

    private String logPrefix;
    private String attrmapGroupRecord;
    private String attrmapPrincipalRecord;
    private String attrNamespace;
    private String sequenceNamespace;
    private String sequenceQueryGroups;
    private String sequenceQueryPrincipals;
    private String sequenceResolveGroups;
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

    private List<Map<String, List<String>>> executeVarQuery(Map<String, Object> vars, String varName) throws LDAPException {
        List<Map<String, List<String>>> ret = new ArrayList<>();

        List<String> queryVars = new ArrayList<>();
        for (String var : vars.keySet()) {
            if (var.startsWith(varName)) {
                queryVars.add(var);
            }
        }

        try {
            for (String var : queryVars) {
                log.debug("Resolving query var '{}'", var);
                Framework.SearchInstance instance = (Framework.SearchInstance)vars.get(var);
                if (instance != null) {
                    List<Map<String, List<String>>> entries;
                    while (
                        (entries = framework.searchExecute(
                            instance,
                            0
                        )) != null
                    ) {
                        ret.addAll(entries);
                    }
                }
            }
        } finally {
            for (String var : queryVars) {
                Framework.SearchInstance instance = (Framework.SearchInstance)vars.get(var);
                if (instance != null) {
                    vars.remove(var);
                    try {
                        framework.searchClose(instance);
                    } catch(Exception e) {
                        log.error("Cannot close search of var '{}'", var);
                        log.debug("Cannot close search of var '{}', search: {}", var, instance);
                        log.debug("Exception", e);
                    }
                }
            }
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

                    namespaces = new ArrayList<>();
                    Map<String, Object> vars = framework.createSequenceVars();
                    framework.runSequence(sequenceNamespace, vars);
                    Collection<? extends Object> c = (Collection<? extends Object>)vars.get(ExtensionUtil.VARS_NAMESPACES);
                    if (c != null) {
                        for (Object o : c) {
                            namespaces.add(o.toString());
                        }
                    }
                    for (Map<String, List<String>> entry : executeVarQuery(vars, ExtensionUtil.VARS_QUERY)) {
                        List<String> namespace = entry.get(attrNamespace);
                        if (namespace != null) {
                            namespaces.addAll(namespace);
                        }
                    }

                    log.info("{} Available Namespaces: {}",
                        logPrefix,
                        namespaces
                    );
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

    private ExtMap transformSearchToRecord(
        Map<String, List<String>> attrs,
        Map<String, ExtKey> toKeys,
        String varPrefix,
        ExtKey namespaceKey
    ) {
        ExtMap record = new ExtMap();
        for (Map.Entry<String, List<String>> attr : attrs.entrySet()) {
            if (attr.getKey().startsWith(varPrefix)) {
                ExtKey key = toKeys.get(attr.getKey().substring(varPrefix.length()));
                if (key != null) {
                    record.put(key, attr.getValue().get(0));
                }
            }
        }
        String namespace = resolveNamespace(attrs.get(varPrefix + "DN").get(0).toString());
        if (namespace == null) {
            record = null;
            log.warn(
                "{} Cannot determine namespace for '{}', ignoring entry.",
                logPrefix,
                attrs.get(varPrefix + "DN").get(0)
            );
        } else {
            record.mput(
                namespaceKey,
                record.get(namespaceKey, namespace)
            ).mput(
                DN_KEY,
                attrs.get(varPrefix + "DN").get(0)
            );
        }
        return record;
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

    private void _resolveGroups(
        ExtMap record,
        ExtKey groupsKey,
        boolean recursive,
        Map<String, Collection<ExtMap>> cache,
        Deque<String> loopPrevention
    ) throws Exception {
        loopPrevention.push(record.<String>get(DN_KEY));
        log.debug("_resolveGroups Entry loopPrevention={}", loopPrevention);
        log.trace("_resolveGroups {}", record);

        Collection<ExtMap> groupRecords = cache.get(record.get(DN_KEY));
        if (groupRecords == null) {
            groupRecords = record.<Collection<ExtMap>>get(groupsKey, new LinkedList<ExtMap>());
            record.put(groupsKey, groupRecords);
            Map<String, Object> vars = framework.createSequenceVars();
            vars.put(
                ExtensionUtil.VARS_DN,
                record.get(DN_KEY)
            );
            vars.put(
                ExtensionUtil.VARS_DN_TYPE,
                groupsKey.equals(Authz.PrincipalRecord.GROUPS) ? "principal" : "group"
            );
            framework.runSequence(sequenceResolveGroups, vars);

            Set<String> addedGroups = new HashSet<>();
            for (Map<String, List<String>> entry : executeVarQuery(vars, ExtensionUtil.VARS_QUERY)) {
                String dn = entry.get(ExtensionUtil.GROUP_RECORD_PREFIX + "DN").get(0);
                if (!addedGroups.contains(dn)) {
                    addedGroups.add(dn);
                    ExtMap groupRecord = transformSearchToRecord(
                        entry,
                        groupToRecordKeys,
                        ExtensionUtil.GROUP_RECORD_PREFIX,
                        Authz.GroupRecord.NAMESPACE
                    );
                    if (groupRecord != null) {
                        groupRecords.add(groupRecord);
                    }
                }
            }
            cache.put(record.get(DN_KEY).toString(), groupRecords);
        }

        record.put(groupsKey, groupRecords);

        if (recursive) {
            for (ExtMap entry : groupRecords) {
                if (loopPrevention.contains(entry.get(DN_KEY))) {
                    log.error(
                        "{} Group recursion detected for group '{}' stack is {}",
                        logPrefix,
                        entry.get(DN_KEY),
                        loopPrevention
                    );
                } else {
                    _resolveGroups(entry, groupsKey, recursive, cache, loopPrevention);
                }
            }
        }

        loopPrevention.pop();
        log.debug("_resolveGroups Return");
    }

    private void resolveGroups(Collection<ExtMap> records, ExtKey groupsKey, boolean recursive)
    throws Exception {
        log.debug("resolveGroups Entry records={}, recursive={}", records, recursive);

        Deque<String> loopPrevention = new ArrayDeque<>();
        Map<String, Collection<ExtMap>> cache = new HashMap<>();
        for (ExtMap record : records) {
            _resolveGroups(record, groupsKey, false, cache, loopPrevention);
            if (recursive) {
                for (ExtMap groupRecord : record.<Collection<ExtMap>>get(groupsKey, Collections.<ExtMap>emptyList())) {
                    _resolveGroups(groupRecord, Authz.GroupRecord.GROUPS, true, cache, loopPrevention);
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
            ExtensionUtil.EXTENSION_NAME_PREFIX + "authz"
        ).mput(
            Authz.ContextKeys.QUERY_MAX_FILTER_SIZE,
            Integer.valueOf(configuration.getProperty(PREFIX_CONFIG_AUTHZ + "query.max_filter_size", "50"))
        );

        logPrefix = ExtensionUtil.getLogPrefix(context);

        framework = ExtensionUtil.frameworkCreate(context, logPrefix, "authz_enable");

        attrmapGroupRecord = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "attrmap.map-group-record.name", "map-group-record");
        attrmapPrincipalRecord = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "attrmap.map-principal-record.name", "map-principal-record");
        attrNamespace = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.namespace.attribute.namespace", "namespace");
        sequenceNamespace = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.namespace.name", "namespace");
        sequenceQueryGroups = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.query-groups.name", "query-groups");
        sequenceQueryPrincipals = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.query-principals.name", "query-principals");
        sequenceResolvePrincipal = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.resolve-principal.name", "resolve-principal");
        sequenceResolveGroups = configuration.getProperty(PREFIX_CONFIG_AUTHZ + "sequence.resolve-groups.name", "resolve-groups");
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
            log.error("{} Cannot initialize LDAP framework, deferring initialization. Error: {}", logPrefix, e.getMessage());
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

        String principal = (
            input.containsKey(Authn.InvokeKeys.AUTH_RECORD) ?
            input.<ExtMap>get(Authn.InvokeKeys.AUTH_RECORD).<String>get(
                Authn.AuthRecord.PRINCIPAL
            ) :
            input.<String>get(Authz.InvokeKeys.PRINCIPAL)
        );

        Map<String, Object> vars = framework.createSequenceVars();
        vars.put(
            ExtensionUtil.PRINCIPAL_RECORD_PREFIX + "PRINCIPAL",
            principal
        );
        framework.runSequence(sequenceResolvePrincipal, vars);
        Framework.SearchInstance instance = (Framework.SearchInstance)vars.get(ExtensionUtil.VARS_QUERY);
        if (instance == null) {
            throw new RuntimeException(String.format("No search for principal '%s'", principal));
        }

        ExtMap principalRecord = null;
        try {
            List<Map<String, List<String>>> entries;

            do {
                entries = framework.searchExecute(
                    instance,
                    0
                );
            } while (entries != null && entries.size() == 0);
            if (entries == null) {
                throw new RuntimeException(String.format("Cannot locate principal '%s'", principal));
            } else if (entries.size() != 1) {
                throw new RuntimeException(String.format("Expected signle result (%s) while searching principal '%s'", entries.size(), principal));
            }
            principalRecord = transformSearchToRecord(
                entries.get(0),
                principalToRecordKeys,
                ExtensionUtil.PRINCIPAL_RECORD_PREFIX,
                Authz.PrincipalRecord.NAMESPACE
            );
            if (principalRecord == null) {
                throw new RuntimeException(String.format("Cannot locate principal '%s'", principal));
            }
        } finally {
            framework.searchClose(instance);
        }
        if ((input.<Integer>get(Authz.InvokeKeys.QUERY_FLAGS) & Authz.QueryFlags.RESOLVE_GROUPS) != 0) {
            resolveGroups(
                Arrays.asList(principalRecord),
                Authz.PrincipalRecord.GROUPS,
                (
                    (input.<Integer>get(Authz.InvokeKeys.QUERY_FLAGS) & Authz.QueryFlags.RESOLVE_GROUPS_RECURSIVE) != 0 &&
                    !Boolean.valueOf(vars.get(ExtensionUtil.VARS_CAPABILITY_RECUSRIVE_GROUP_RESOLUTION).toString())
                )
            );
        }

        output.mput(
            Authz.InvokeKeys.PRINCIPAL_RECORD,
            principalRecord
        );

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
                    ExtMap record = transformSearchToRecord(
                        entry,
                        opaque.toKeys,
                        opaque.varPrefix,
                        opaque.namespaceKey
                    );
                    if (record != null) {
                        records.add(record);
                    }
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

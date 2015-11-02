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
import java.net.*;
import java.nio.charset.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import javax.naming.*;
import javax.net.*;
import javax.net.ssl.*;

import com.unboundid.asn1.*;
import com.unboundid.ldap.sdk.*;
import com.unboundid.ldap.sdk.controls.*;
import com.unboundid.ldap.sdk.extensions.*;
import com.unboundid.util.*;
import com.unboundid.util.ssl.*;
import org.slf4j.*;

public class Framework implements Closeable {

    public static class AttrMapInfo {

        private final String name;
        private final MapProperties props;
        private final AttrConversion conversion;
        private final MapProperties conversionProps;

        private AttrMapInfo(String name, MapProperties props) {
            this.name = name;
            this.props = props;
            this.conversion = AttrConversion.valueOf(props.getString(AttrConversion.STRING.toString(), "conversion"));
            this.conversionProps = props.getOrEmpty("conversion", conversion.toString());
        }
        @Override
        public String toString() {
            return String.format(
                "AttrMapInfo(%s, %s)",
                name,
                conversion
            );
        }
        public String getName() {
            return name;
        }
        public String getMap() {
            return props.getMandatoryString("map");
        }
        public String encode(ASN1OctetString value) {
            return conversion.encode(value, conversionProps);
        }
        public ASN1OctetString decode(String value) {
            return conversion.decode(value, conversionProps);
        }
        public boolean isString() {
            return conversion.isString();
        }
    }

    private static class ConnectionPoolEntry implements Closeable {
        public String name;
        public MapProperties props;
        public LDAPConnectionPool connectionPool;
        public boolean supportPaging;
        public boolean supportPasswordModify;
        public boolean supportWhoAmI;

        @Override
        public void close() throws IOException {
            if (connectionPool != null) {
                connectionPool.close();
            }
        }

        public String toString() {
            return String.format(
                "ConnectionPoolEntry(name='%s', connectionPool=%s, supportPaging=%s, supportPasswordModify=%s, supportWhoAmI=%s)",
                name,
                connectionPool,
                supportPaging,
                supportPasswordModify,
                supportWhoAmI
            );
        }
    }

    public static class SearchInstance {
        private ConnectionPoolEntry connectionPoolEntry;
        private LDAPConnection connection;
        private List<AttrMapInfo> attrMap;
        private SearchRequest searchRequest;
        private boolean doPaging;
        private ASN1OctetString resumeCookie;
        private int pageSize;
        private int limitLeft;
        private boolean done;

        public String toString() {
            return String.format(
                "SearchInstance(searchRequest='%s', doPaging=%s, resumeCookie='%s', pageSize=%s, limitLeft=%s, done=%s)",
                searchRequest,
                doPaging,
                resumeCookie,
                pageSize,
                limitLeft,
                done
            );
        }
    }

    private static final Logger log = LoggerFactory.getLogger(Framework.class);

    public static final String VARS_AUTH_TRANSLATED_MESSAGE = "authTranslatedMessage";
    public static final String VARS_AUTH_WHO_AM_I = "authWhoAmI";
    public static final String VARS_DIAGNOSTIC_MESSAGE = "diagnosticMessage";
    public static final String VARS_MESSAGE = "message";
    public static final String VARS_RESULT_CODE = "resultCode";
    public static final String VARS_SENSITIVE = "sensitiveKeys";
    public static final String VARS_STOP = "stop";
    public static final String VARS_DN = "_dn";

    private static final Map<ResultCode, String> resultCodeNameMap;
    static {
        try {
            resultCodeNameMap = new HashMap<ResultCode, String>();
            List<ResultCode> codes = Arrays.asList(ResultCode.values());
            for (java.lang.reflect.Field field : ResultCode.class.getFields()) {
                Object o = field.get(null);
                if (codes.contains(o)) {
                    resultCodeNameMap.put(
                        (ResultCode)o,
                        field.getName()
                    );
                }
            }
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private final String logPrefix;
    private final MapProperties props;
    private final int statsTTL;

    private final Map<String, ConnectionPoolEntry> connectionPools = new ConcurrentHashMap<>();
    private final Map<String, Object> initglobals = new ConcurrentHashMap<>();;
    private final Map<String, Object> globals = new ConcurrentHashMap<>();
    private volatile long nextStats = 0;

    public static String getDNDomainComponent(String dn) throws LDAPException {
        StringBuilder ret = new StringBuilder();
        for (RDN rdn : new DN(DN.normalize(dn)).getRDNs()) {
            for (String name : rdn.getAttributeNames()) {
                if ("dc".equals(name)) {
                    for (String value : rdn.getAttributeValues()) {
                        if (ret.length() > 0) {
                            ret.append('.');
                        }
                        ret.append(value);
                    }
                }
            }
        }
        return ret.toString();
    }

    private MapProperties applyDefault(MapProperties props) throws IOException {
        MapProperties ret = new MapProperties();

        try (
            InputStream is = this.getClass().getResourceAsStream("profile-defaults.properties");
            Reader reader = new InputStreamReader(is, StandardCharsets.UTF_8);
        ) {
            Properties p = new Properties();
            p.load(reader);
            ret.load(new MapProperties(p));
        }

        ret.load(props);

        return ret;
    }

    public void dumpVariables(Map<String, Object> vars) {
        if (log.isTraceEnabled()) {
            List<String> keys = new ArrayList<>(vars.keySet());
            List<String> sensitiveKeys = Arrays.asList(Util.toString(vars.get(VARS_SENSITIVE), "").trim().split(" *, *"));
            Collections.sort(keys);
            log.trace("VARS-BEGIN");
            for (String k : keys) {
                log.trace(
                    "{} = {}",
                    k,
                    sensitiveKeys.contains(k) ? "***" : vars.get(k)
                );
            }
            log.trace("VARS-END");
        }
    }

    private void dumpProperties(MapProperties props) {
        if (log.isDebugEnabled()) {
            log.debug("PROPERTIES-BEGIN");

            Set<String> sensitiveKeys = new HashSet<>();
            for (MapProperties entry : props.getOrEmpty("sensitive-keys").getMap().values()) {
                sensitiveKeys.add(entry.getValue());
            }

            log.debug(props.toString(sensitiveKeys));
            log.debug("PROPERTIES-END");
        }
    }

    private String applyPattern(MapProperties props, String s) {
        if (s == null) {
            return null;
        } else {
            return s.replaceFirst(
                props.getMandatoryString("pattern"),
                props.getMandatoryString("replace")
            );
        }
    }

    private String translateDiagnosticMessage(MapProperties diagProps, Map<String, Object> vars) {

        diagProps = diagProps.get("mapping");

        String resultCode = Util.toString(vars.get(VARS_RESULT_CODE));
        String diagnosticMessage = Util.toString(vars.get(VARS_DIAGNOSTIC_MESSAGE));

        log.debug(
            "translateDiagnosticMessage Entry resultCode='{}', diagnosticMessage='{}'",
            resultCode,
            diagnosticMessage
        );

        if (diagnosticMessage == null) {
            diagnosticMessage = "";
        }
        diagnosticMessage = diagnosticMessage.replace((char)0, ' ').trim();

        String prefix = resultCode;
        String suffix;

        if (diagProps.getString(null, prefix, "translation", "pattern") != null) {
            log.debug("apply pattern from key specific");
            suffix = applyPattern(diagProps.get(prefix, "translation"), diagnosticMessage);
        } else {
            suffix = applyPattern(diagProps.get("translation"), diagnosticMessage);
        }

        log.debug(
            "Ready: prefix='{}', suffix='{}'",
            prefix,
            suffix
        );

        String ret = diagProps.getString(
            diagProps.getString(
                diagProps.getMandatoryString("default"),
                prefix
            ),
            prefix,
            suffix
        );

        log.debug(
            "translateDiagnosticMessage Return '{}'",
            ret
        );

        return ret;
    }


    private BindRequest createBindRequest(MapProperties poolProps, String user, String password) throws LDAPException {

        BindRequest bindRequest = null;

        final String POOL_PREFIX_AUTH = "auth";
        String authType = poolProps.getString("none", POOL_PREFIX_AUTH, "type");
        MapProperties authProps = poolProps.getOrEmpty(POOL_PREFIX_AUTH, authType);

        log.debug("createBindRequest Entry type='{}', user='{}'", authType, user);

        if ("none".equals(authType)) {
            bindRequest = new SimpleBindRequest();
        } else if ("simple".equals(authType)) {
            bindRequest = new SimpleBindRequest(
                authProps.getString(user, "bindDN"),
                authProps.getString(password, "password")
            );
        } else if ("external".equals(authType)) {
            bindRequest = new EXTERNALBindRequest();
        } else if ("sasl-anonymous".equals(authType)) {
            bindRequest = new ANONYMOUSBindRequest();
        } else if ("sasl-plain".equals(authType)) {
            bindRequest = new PLAINBindRequest(
                authProps.getString(user, "authenticationID"),
                authProps.getString(password, "password")
            );
        } else if ("cram-md5".equals(authType)) {
            bindRequest = new CRAMMD5BindRequest(
                authProps.getString(user, "authenticationID"),
                authProps.getString(password, "password")
            );
        } else if ("digest-md5".equals(authType)) {
            String realm = null;
            String ruser = user;
            String[] userComps = user.split("@", 2);
            if (userComps.length == 2) {
                realm = userComps[1];
                ruser = userComps[0];
            }
            DIGESTMD5BindRequestProperties bindprops = new DIGESTMD5BindRequestProperties(ruser, password);
            bindprops.setRealm(realm);
            Util.setObjectByProperties(bindprops, authProps, "set");
            log.debug("DIGESTMD5BindRequestProperties: {}", bindprops);
            bindRequest = new DIGESTMD5BindRequest(bindprops);
        } else if ("gssapi".equals(authType)) {
            String ruser = user;
            String[] userComps = user.split("@", 2);
            if (userComps.length == 2) {
                ruser = userComps[0] + "@" + userComps[1].toUpperCase();
            }
            GSSAPIBindRequestProperties bindprops = new GSSAPIBindRequestProperties(ruser, password);
            Util.setObjectByProperties(bindprops, authProps, "set");
            log.debug("GSSAPIBindRequestProperties: {}", bindprops);
            bindRequest = new GSSAPIBindRequest(bindprops);
        } else {
            throw new IllegalArgumentException(
                String.format("Invalid authentication type '%s'", authType)
            );
        }

        log.debug("createBindRequest Return {}", bindRequest);

        return bindRequest;
    }

    public Framework(String logPrefix, MapProperties props) throws IOException {

        this.logPrefix = logPrefix;
        this.props = applyDefault(props);
        dumpProperties(this.props);

        statsTTL = this.props.getMandatoryInt("stats", "interval");

        MapProperties debugProps = this.props.getOrEmpty("sdk", "debug");
        Boolean debug = debugProps.getBoolean(null, "enable");
        if (debug != null) {
            Debug.setEnabled(
                debug,
                new HashSet<DebugType>(
                    Util.getEnumFromString(
                        DebugType.class,
                        debugProps.getString("", "types")
                    )
                )
            );
        }
        String level = debugProps.getString(null, "level");
        if (level != null) {
            Debug.getLogger().setLevel(
                (java.util.logging.Level)Util.getObjectValueByString(
                    java.util.logging.Level.class,
                    level
                )
            );
        }
    }

    private Resolver createResolver(MapProperties props) throws NamingException, IOException {
        log.debug("Creating resolver");
        Resolver resolver = new Resolver(
            props.getOrEmpty("jndi-properties").toProperties()
        );
        Util.setObjectByProperties(resolver, props, "set");
        resolver.open();
        log.debug("Resolver: {}", resolver);
        return resolver;
    }

    private LDAPConnectionPool createConnectionPool(MapProperties poolProps) throws Exception {
        log.debug("createConnectionPool Entry");

        SSLSocketVerifier sslSocketVerifier = null;
        PostConnectProcessor postConnectProcessor = null;
        SocketFactory socketFactory = SocketFactory.getDefault();
        TrustManager[] trustManagers = null;
        KeyManager[] keyManagers = null;
        MapProperties sslProps = poolProps.get("ssl");
        boolean enableSSL = sslProps.getBoolean(Boolean.FALSE, "enable");
        boolean enableStartTLS = sslProps.getBoolean(Boolean.FALSE, "startTLS");
        if (enableSSL || enableStartTLS) {
            if (sslProps.getBoolean(Boolean.TRUE, "host-name-verify", "enable")) {
                log.debug("Creating HostNameSSLSocketVerifier");
                sslSocketVerifier = new HostNameSSLSocketVerifier(
                    sslProps.getBoolean(Boolean.TRUE, "host-name-verify", "wildcards")
                );
                log.debug("HostNameSSLSocketVerifier: {}", sslSocketVerifier);
            }

            if (sslProps.getBoolean(Boolean.FALSE, "insecure")) {
                log.warn("{} TLS/SSL insecure mode", logPrefix);
                trustManagers = new TrustManager[] {new TrustAllTrustManager()};
            } else {
                log.debug("Creating trust store");
                MapProperties truststoreProps = sslProps.getOrEmpty("truststore");

                TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    truststoreProps.getString(
                        KeyManagerFactory.getDefaultAlgorithm(),
                        "trustmanager",
                        "algorithm"
                    )
                );
                tmf.init(
                    Util.loadKeyStore(
                        truststoreProps.getString(null, "provider"),
                        truststoreProps.getString(null, "type"),
                        truststoreProps.getString(null, "file"),
                        truststoreProps.getString("changeit", "password")
                    )
                );
                trustManagers = tmf.getTrustManagers();
            }

            log.debug("Creating key store");
            MapProperties keystoreProps = sslProps.getOrEmpty("keystore");
            KeyStore keyStore = Util.loadKeyStore(
                keystoreProps.getString(null, "provider"),
                keystoreProps.getString(null, "type"),
                keystoreProps.getString(null, "file"),
                keystoreProps.getString("changeit", "password")
            );
            if (keyStore != null) {
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    keystoreProps.getString(
                        KeyManagerFactory.getDefaultAlgorithm(),
                        "keymanager",
                        "algorithm"
                    )
                );
                kmf.init(keyStore, keystoreProps.getMandatoryString("password").toCharArray());
                keyManagers = kmf.getKeyManagers();
            }

            if (enableSSL) {
                log.debug("Creating SocketFactory");
                socketFactory = new SSLUtil(keyManagers, trustManagers).createSSLContext(
                    sslProps.getString("TLSv1", "protocol")
                ).getSocketFactory();
            }

            if (enableStartTLS) {
                log.debug("Creating StartTLSPostConnectProcessor");
                postConnectProcessor =  new StartTLSPostConnectProcessor(
                    new SSLUtil(keyManagers, trustManagers).createSSLContext(
                        sslProps.getString("TLSv1", "startTLSProtocol")
                    )
                );
                log.debug("StartTLSPostConnectProcessor: {}", postConnectProcessor);
            }
        }

        log.debug("Creating LDAPConnectionOptions");
        final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
        connectionOptions.setSSLSocketVerifier(sslSocketVerifier);
        Util.setObjectByProperties(connectionOptions, poolProps.get("connection-options"), "set");
        log.debug("LDAPConnectionOptions: {}", connectionOptions);

        log.debug("Creating SocketFactory");
        final String POOL_PREFIX_SOCKET_FACTORY = "socketfactory";
        String socketFactoryType = poolProps.getString("java", POOL_PREFIX_SOCKET_FACTORY, "type");
        MapProperties socketFactoryProps = poolProps.get(POOL_PREFIX_SOCKET_FACTORY, socketFactoryType);
        if ("java".equals(socketFactoryType)) {
        } else if ("resolver".equals(socketFactoryType)) {
            final Resolver resolver = createResolver(socketFactoryProps);
            /*
             * HACK-BEGIN
             * unboundid SDK resolves host using java native we need
             * dynamic support.
             */
            socketFactory = new ResolverSocketFactory(
                resolver,
                socketFactory
            );
            Util.setObjectByProperties(socketFactory, socketFactoryProps, "set");
            /* HACK-END */
            /*
             * HACK-BEGIN
             * unboundid SDK resolves host internally within its default
             * getReferralConnection(), until this is fixed, we need to
             * implement our own.
             */
            connectionOptions.setReferralConnector(new ResolverReferralConnector(resolver));
            /* HACK-END */
        } else {
            throw new IllegalArgumentException(
                String.format("Invalid socket factory set type '%s'", socketFactoryType)
            );
        }
        log.debug("SocketFactory: {}", socketFactory);

        log.debug("Creating ServerSet");
        final String POOL_PREFIX_SERVERSET = "serverset";
        final String SERVERSET_SERVER = "server";
        final String SERVERSET_PORT = "port";
        String serversetType = poolProps.getString("single", POOL_PREFIX_SERVERSET, "type");
        MapProperties serverSetProps = poolProps.get(POOL_PREFIX_SERVERSET, serversetType);
        String defaultPort = serverSetProps.getString("389", SERVERSET_PORT);
        ServerSet serverset;
        if ("single".equals(serversetType)) {
            serverset = new SingleServerSet(
                serverSetProps.getString(null, SERVERSET_SERVER),
                serverSetProps.getInt(null, SERVERSET_PORT),
                socketFactory,
                connectionOptions
            );
        } else if ("round-robin".equals(serversetType)) {
            serverset = new RoundRobinServerSet(
                Util.getValueFromMapRecord(serverSetProps, SERVERSET_SERVER, null).toArray(new String[0]),
                Util.asIntArray(Util.getValueFromMapRecord(serverSetProps, SERVERSET_PORT, defaultPort)),
                socketFactory,
                connectionOptions
            );
        } else if ("failover".equals(serversetType)) {
            serverset = new FailoverServerSet(
                Util.getValueFromMapRecord(serverSetProps, SERVERSET_SERVER, null).toArray(new String[0]),
                Util.asIntArray(Util.getValueFromMapRecord(serverSetProps, SERVERSET_PORT, defaultPort)),
                socketFactory,
                connectionOptions
            );
        } else if ("fastest-connect".equals(serversetType)) {
            serverset = new FastestConnectServerSet(
                Util.getValueFromMapRecord(serverSetProps, SERVERSET_SERVER, null).toArray(new String[0]),
                Util.asIntArray(Util.getValueFromMapRecord(serverSetProps, SERVERSET_PORT, defaultPort)),
                socketFactory,
                connectionOptions
            );
        } else if ("fewest-connections".equals(serversetType)) {
            serverset = new FewestConnectionsServerSet(
                Util.getValueFromMapRecord(serverSetProps.get(POOL_PREFIX_SERVERSET), SERVERSET_SERVER, null).toArray(new String[0]),
                Util.asIntArray(Util.getValueFromMapRecord(serverSetProps.get(POOL_PREFIX_SERVERSET), SERVERSET_PORT, defaultPort)),
                socketFactory,
                connectionOptions
            );
        } else if ("dns-round-robin".equals(serversetType)) {
            serverset = new RoundRobinDNSServerSet(
                serverSetProps.getString(null, SERVERSET_SERVER),
                serverSetProps.getInt(null, SERVERSET_PORT),
                (RoundRobinDNSServerSet.AddressSelectionMode)Util.getObjectValueByString(
                    RoundRobinDNSServerSet.AddressSelectionMode.class,
                    serverSetProps.getString(null, "selectionMode")
                ),
                serverSetProps.getLong(0l, "cacheTimeoutMillis"),
                null,
                serverSetProps.getOrEmpty("jndi-properties").toProperties(),
                (String[])Util.getObjectValueByString(
                    String[].class,
                    serverSetProps.getString(null, "dnsRecordTypes")
                ),
                socketFactory,
                connectionOptions
            );
        } else if ("srvrecord".equals(serversetType)) {
            final String CONVERSION_PREFIX = "domain-conversion";
            String conversionType = serverSetProps.getString("none", CONVERSION_PREFIX, "type");
            MapProperties conversionProps = serverSetProps.getOrEmpty(CONVERSION_PREFIX, conversionType);
            String domain = serverSetProps.getMandatoryString("domain");
            if ("none".equals(conversionType)) {
                // noop
            } else if ("regex".equals(conversionType)) {
                String pattern = conversionProps.getMandatoryString("pattern");
                String flags = conversionProps.getString("", "flags");
                log.debug("Domain conversion pattern: {} ({})", pattern, flags);
                Matcher matcher = Pattern.compile(pattern).matcher(domain);
                domain = (
                    flags.indexOf('a') != -1 ?
                    matcher.replaceAll(conversionProps.getMandatoryString("replacement")) :
                    matcher.replaceFirst(conversionProps.getMandatoryString("replacement"))
                );
            } else {
                throw new IllegalArgumentException(
                    String.format("Invalid srvrecord set conversion type '%s'", conversionType)
                );
            }

            serverset = new DNSSRVRecordServerSet(
                String.format(
                    "_%s._%s.%s",
                    serverSetProps.getMandatoryString("service"),
                    serverSetProps.getMandatoryString("protocol"),
                    domain
                ),
                null,
                serverSetProps.getOrEmpty("jndi-properties").toProperties(),
                serverSetProps.getLong(0l, "ttlMillis"),
                socketFactory,
                connectionOptions
            );
        } else {
            throw new IllegalArgumentException(
                String.format("Invalid server set type '%s'", serversetType)
            );
        }
        log.debug("ServerSet: {}", serverset);

        log.debug("Creating BindRequest");
        BindRequest bindRequest = createBindRequest(poolProps, "", "");
        log.debug("BindRequest: {}", bindRequest);

        log.debug("Creating LDAPConnectionPool");
        MapProperties cpoolProps = poolProps.get("connection-pool");
        LDAPConnectionPool connectionPool = new LDAPConnectionPool(
            serverset,
            bindRequest,
            cpoolProps.getInt(1, "initialConnections"),
            cpoolProps.getInt(10, "maxConnections"),
            cpoolProps.getInt(1, "initialConnectThreads"),
            postConnectProcessor,
            true
        );
        Util.setObjectByProperties(connectionPool, cpoolProps, "set");
        log.debug("createConnectionPool Return: {}", connectionPool);

        return connectionPool;
    }

    private ConnectionPoolEntry createConnectionPoolEntry(String name, MapProperties poolProps, Map<String, Object> vars)
    throws Exception {

        log.info("{} Creating LDAP pool '{}'", logPrefix, name);
        log.debug("createPool Entry name='{}'", name);

        ConnectionPoolEntry entry = new ConnectionPoolEntry();
        entry.name = name;
        entry.props = poolProps;
        entry.connectionPool = createConnectionPool(entry.props);

        RootDSE rootDSE = entry.connectionPool.getRootDSE();
        if (rootDSE != null) {
            log.info(
                "{} LDAP pool '{}' information: vendor='{}' version='{}'",
                logPrefix,
                name,
                rootDSE.getVendorName(),
                rootDSE.getVendorVersion()
            );
            if (log.isDebugEnabled()) {
                log.debug("RootDSE: {}", rootDSE.getAttributes());
            }

            String supportedControls[] = rootDSE.getSupportedControlOIDs();
            if (supportedControls != null) {
                List<String> supportedControlsList = Arrays.asList(supportedControls);
                entry.supportPaging = supportedControlsList.contains(SimplePagedResultsControl.PAGED_RESULTS_OID);
            }

            String supportedExtendedOperations[] = rootDSE.getSupportedExtendedOperationOIDs();
            if (supportedExtendedOperations != null) {
                List<String> supportedExtendedOperationsList = Arrays.asList(supportedExtendedOperations);
                entry.supportPasswordModify = supportedExtendedOperationsList.contains(PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID);
                entry.supportWhoAmI = supportedExtendedOperationsList.contains(WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID);
            }
        }

        log.debug("createPool Return {}", entry);
        return entry;
    }

    public void init() throws Exception {
        log.debug("init Entry");

        globals.put(VARS_STOP, "false");
        for (MapProperties init : props.get("sequence-init").getOrEmpty().getOrEmpty("init").getMap().values()) {
            runSequence(init.getValue(), globals);
        }
        globals.put(VARS_STOP, "false");

        log.debug("init Return globals={}", globals);
    }

    public void open() throws Exception {
        log.debug("open Entry");

        Map<String, Object> tempGlobals = new HashMap<>(globals);

        tempGlobals.put(VARS_STOP, "false");
        for (MapProperties init : props.get("sequence-init").getOrEmpty().getOrEmpty("open").getMap().values()) {
            runSequence(init.getValue(), tempGlobals);
        }
        tempGlobals.put(VARS_STOP, "false");

        initglobals.clear();
        initglobals.putAll(globals);
        globals.putAll(tempGlobals);

        log.debug("open Return globals={}", globals);
    }

    @Override
    public void close() throws IOException {
        log.debug("close Entry");
        for (ConnectionPoolEntry entry : connectionPools.values()) {
            entry.close();
        }
        connectionPools.clear();
        if (initglobals != null) {
            globals.clear();
            globals.putAll(initglobals);
        }
        log.debug("close Return");
    }

    public ConnectionPoolEntry getConnectionPoolEntry(String name, String dn, Map<String, Object> vars)
    throws Exception {
        log.debug("getConnectionPoolEntry Entry name='{}', dn='{}'", name, dn);

        String domainComponent = null;
        if (dn != null && !dn.isEmpty()) {
            domainComponent = getDNDomainComponent(dn);
            if (domainComponent.isEmpty()) {
                domainComponent = null;
            }
        }

        final String PREFIX_POOL = "pool";
        final String PREFIX_POOL_DC_RESOLVE = "dc-resolve";
        final String VAR_RESOLVE_DOMAIN = "__dc_resolve_domain";
        MapProperties poolProps = new MapProperties(
            props.get(PREFIX_POOL, "default"),
            props.get(PREFIX_POOL, name)
        );
        if (domainComponent != null && !domainComponent.isEmpty()) {
            MapProperties poolPropsDC = new MapProperties(
                poolProps,
                poolProps.get(PREFIX_POOL_DC_RESOLVE, "default"),
                poolProps.get(PREFIX_POOL_DC_RESOLVE, domainComponent.replace('.', '_'))
            );
            if (poolPropsDC.getBoolean(false, PREFIX_POOL_DC_RESOLVE, "enable")) {
                log.debug("getConnectionPoolEntry dc-resolve enabled");
                poolProps = poolPropsDC;
                name += "@" + domainComponent;
                vars.put(VAR_RESOLVE_DOMAIN, domainComponent);
            }
        }

        ConnectionPoolEntry entry = connectionPools.get(name);
        if (entry == null) {
            log.debug("getConnectionPoolEntry no pool for '{}'", name);

            try {
                entry = createConnectionPoolEntry(
                    name,
                    Util.expandMap(
                        poolProps,
                        "seq",
                        vars
                    ),
                    vars
                );
                connectionPools.put(entry.name, entry);
            } finally {
                vars.remove(VAR_RESOLVE_DOMAIN);
            }
        }
        return entry;
    }

    public void stats() {
        if (log.isDebugEnabled()) {
            long now = new Date().getTime();
            if (now > nextStats) {
                nextStats = now + statsTTL;
                for (ConnectionPoolEntry entry : connectionPools.values()) {
                    log.debug("Stats: {} {}", entry.name, entry.connectionPool.getConnectionPoolStatistics());
                }
            }
        }
    }

    public void authCheck(
        String name,
        Map<String, Object> vars
    ) throws Exception {

        log.debug("authCheck Entry name='{}'", name);

        final String PREFIX_AUTH_CHECK = "auth-check";
        MapProperties authCheckProps = Util.expandMap(
            new MapProperties(
                props.get(PREFIX_AUTH_CHECK, "default"),
                props.get(PREFIX_AUTH_CHECK, name)
            ),
            "seq",
            vars
        );
        String pool = authCheckProps.getMandatoryString("pool");
        String user = authCheckProps.getMandatoryString("user");

        if (user == null || user.isEmpty()) {
            throw new IllegalArgumentException("User required for authentication check");
        }

        ConnectionPoolEntry connectionPoolEntry = getConnectionPoolEntry(pool, null, vars);
        LDAPConnection connection = null;
        try {
            connection = connectionPoolEntry.connectionPool.getConnection();

            log.debug("Creating BindRequest");
            BindRequest bindRequest = createBindRequest(
                authCheckProps,
                user,
                authCheckProps.getString(null, "password")
            );
            log.debug("BindRequest: {}", bindRequest);

            log.debug("bind");
            BindResult bindResult = connection.bind(bindRequest);
            log.debug("BindResult: {}", bindResult);

            PasswordExpiringControl expiringControl = PasswordExpiringControl.get(bindResult);
            if (expiringControl != null) {
                log.debug("Password about to expire");

                int secondsToExpiration = expiringControl.getSecondsUntilExpiration();
                vars.put(
                    VARS_MESSAGE,
                    String.format(
                        "Password will be expired in %s days",
                        expiringControl.getSecondsUntilExpiration() / 60 / 60 / 24
                    )
                );
            }

            if (
                connectionPoolEntry.supportWhoAmI &&
                authCheckProps.getBoolean(Boolean.TRUE, "whoami", "enable")
            ) {
                log.debug("Trying WhoAmI");
                WhoAmIExtendedResult whoAmIExtendedResult = (WhoAmIExtendedResult)connection.processExtendedOperation(
                    new WhoAmIExtendedRequest()
                );
                if (whoAmIExtendedResult.getResultCode() == ResultCode.SUCCESS) {
                    String authzID = whoAmIExtendedResult.getAuthorizationID();
                    log.debug("Got WhoAmI: {}", authzID);
                    if (!Arrays.asList("", "u:", "dn:").contains(authzID)) {
                        vars.put(VARS_AUTH_WHO_AM_I, authzID);
                    }
                }
            }

            vars.put(VARS_RESULT_CODE, resultCodeNameMap.get(ResultCode.SUCCESS));

        } catch(LDAPException e) {
            log.debug("Authentication exception", e);

            vars.put(VARS_RESULT_CODE, resultCodeNameMap.get(e.getResultCode()));
            vars.put(VARS_MESSAGE, e.getMessage());

            if (ResultCode.LOCAL_ERROR.equals(e.getResultCode())) {
                vars.put(
                    VARS_DIAGNOSTIC_MESSAGE,
                    String.format(
                        "%s:%s",
                        e.getCause().getClass().getName(),
                        e.getCause().getMessage()
                    )
                );
            } else {
                if (e.getDiagnosticMessage() != null) {
                    vars.put(VARS_DIAGNOSTIC_MESSAGE, e.getDiagnosticMessage());
                }
            }

            try {
                if (PasswordExpiredControl.get(e) != null) {
                    log.debug("Password is expired");
                    vars.put(VARS_RESULT_CODE, "PASSWORD_EXPIRED");
                    vars.put(VARS_MESSAGE, "Password expired");
                }
            } catch(LDAPException e1) {
                log.debug("Ignoring xception during get of expired control", e1);
            }
        } catch(Exception e) {
            log.debug("Authentication exception", e);

            vars.put(VARS_MESSAGE, e.getMessage());
            vars.put(
                VARS_DIAGNOSTIC_MESSAGE,
                String.format(
                    "%s:%s",
                    e.getClass().getName(),
                    e.getMessage()
                )
            );
        } finally {
            if (connection != null) {
                if (authCheckProps.getBoolean(Boolean.FALSE, "reuse-connections")) {
                    connectionPoolEntry.connectionPool.releaseAndReAuthenticateConnection(connection);
                } else {
                    connectionPoolEntry.connectionPool.discardConnection(connection);
                }
            }
        }

        vars.put(
            VARS_AUTH_TRANSLATED_MESSAGE,
            translateDiagnosticMessage(
                authCheckProps.get("diagnostic"),
                vars
            )
        );

        log.debug("authCheck Return");
    }

    public void modifyCredentials(
        String pool,
        String user,
        String currentPassword,
        String newPassword,
        Map<String, Object> vars
    ) throws Exception {
        PasswordModifyExtendedResult passwordModifyResult = (PasswordModifyExtendedResult)getConnectionPoolEntry(
            pool,
            null,
            vars
        ).connectionPool.processExtendedOperation(
            new PasswordModifyExtendedRequest(user, currentPassword, newPassword)
        );
        if (passwordModifyResult.getResultCode() != ResultCode.SUCCESS) {
            throw new LDAPException(passwordModifyResult);
        }
    }

    public List<AttrMapInfo> getAttrMap(
        String name,
        Map<String, Object> vars
    ) throws LDAPException {

        log.debug("getAttrMap Entry name='{}'", name);

        List<AttrMapInfo> ret = new ArrayList<>();

        final String PREFIX_ATTRMAP = "attrmap";
        MapProperties attrProps = Util.expandMap(
            new MapProperties(
                props.get(PREFIX_ATTRMAP, "default"),
                props.get(PREFIX_ATTRMAP, name)
            ),
            "seq",
            vars
        );
        for (Map.Entry<String, MapProperties> entry : attrProps.getOrEmpty("attr").getMap().entrySet()) {
            if (entry.getValue().getBoolean(true, "enable")) {
                ret.add (new AttrMapInfo(entry.getKey(), entry.getValue()));
            }
        }

        log.debug("getAttrMap Return {}", ret);

        return ret;
    }

    private List<Map<String, List<String>>> searchMapEntries(
        List<SearchResultEntry> entries,
        List<AttrMapInfo> attrMap
    ) {
        List<Map<String, List<String>>> ret = new LinkedList<>();

        for (SearchResultEntry entry : entries) {
            Map<String, List<String>> mapped = new HashMap<>();
            ret.add(mapped);
            mapped.put(VARS_DN, Arrays.asList(entry.getDN()));
            for (AttrMapInfo attrInfo : attrMap) {
                if (VARS_DN.equals(attrInfo.getMap())) {
                    mapped.put(attrInfo.getName(), Arrays.asList(entry.getDN()));
                }
            }
            for (Attribute attribute : entry.getAttributes()) {
                boolean found = false;
                for (AttrMapInfo attrInfo : attrMap) {
                    if (attribute.getBaseName().equals(attrInfo.getMap())) {
                        found = true;
                        List<String> values = new ArrayList<>();
                        for (ASN1OctetString value : attribute.getRawValues()) {
                            values.add(attrInfo.encode(value));
                        }
                        mapped.put(attrInfo.getName(), values);
                    }
                }
                if (!found) {
                    List<String> values = new ArrayList<>();
                    for (ASN1OctetString value : attribute.getRawValues()) {
                        values.add(value.stringValue());
                    }
                    mapped.put(attribute.getBaseName(), values);
                }
            }
        }

        return ret;
    }

    public List<Map<String, List<String>>> search(
        String name,
        int pageSize,
        int limit,
        Map<String, Object> vars
    ) throws Exception {
        List<Map<String, List<String>>> ret = new LinkedList<>();
        SearchInstance searchInstance = searchOpen(
            name,
            pageSize,
            limit,
            vars
        );
        try {
            while (true) {
                List<Map<String, List<String>>> result = searchExecute(searchInstance, 0);
                if (result == null) {
                    break;
                }
                ret.addAll(result);
            }
        } finally {
            searchClose(searchInstance);
        }
        return ret;
    }

    public SearchInstance searchOpen(
        String name,
        int pageSize,
        int limit,
        Map<String, Object> vars
    ) throws Exception {

        log.debug(
            "searchOpen Entry name='{}', pageSize={}, limit={}",
            name,
            pageSize,
            limit
        );

        Map<String, Object> encodedvars = new HashMap<>(vars);
        for (String key : new HashSet<>(encodedvars.keySet())) {
            encodedvars.put(key + "_encoded", Filter.encodeValue(Util.toString(encodedvars.get(key))));
        }

        final String PREFIX_SEARCH = "search";
        MapProperties searchProps = Util.expandMap(
            new MapProperties(
                props.get(PREFIX_SEARCH, "default"),
                props.get(PREFIX_SEARCH, name)
            ),
            "seq",
            encodedvars
        );

        log.debug("Creating SearchRequest");
        SearchRequest searchRequest = new SearchRequest("", SearchScope.SUB, Filter.createEqualityFilter("objectClass", "invalid"));
        Util.setObjectByProperties(searchRequest, searchProps.get("search-request"), "set");
        log.debug("SearchRequest: {}", searchRequest);

        SearchInstance instance = new SearchInstance();
        instance.connectionPoolEntry = getConnectionPoolEntry(
            searchProps.getMandatoryString("pool"),
            searchProps.getBoolean(true, "dc-resolve", "enable") ? searchRequest.getBaseDN() : null,
            vars
        );
        instance.searchRequest = searchRequest;
        instance.doPaging = instance.connectionPoolEntry.supportPaging && searchProps.getBoolean(Boolean.TRUE, "paging");
        instance.pageSize = pageSize != 0 ? pageSize : searchProps.getInt(100, "pageSize");
        instance.limitLeft = limit != 0 ? limit : searchProps.getInt(Integer.MAX_VALUE, "limit");
        instance.attrMap = getAttrMap(searchProps.getString("", "attrmap"), vars);

        log.debug("SearchOpen Return {}", instance);

        return instance;
    }

    public void searchClose(SearchInstance instance) {
        log.debug("searchClose Entry");

        if (instance.connection != null) {
            try {
                log.debug("We have connection");
                if (instance.resumeCookie != null) {
                    log.debug("Closing unfinished search");
                    instance.searchRequest.setControls(
                        new SimplePagedResultsControl(
                            0,
                            instance.resumeCookie
                        )
                    );
                    instance.connection.search(instance.searchRequest);
                }
            } catch(LDAPException e) {
                log.debug("Ignoring exception", e);
            } finally {
                log.debug("Releasing connection");
                instance.connectionPoolEntry.connectionPool.releaseConnection(instance.connection);
            }
        }

        log.debug("searchClose Return");
    }

    public List<Map<String, List<String>>> searchExecute(
        SearchInstance instance,
        int pageSize
    ) throws LDAPException {

        log.trace("searchExecute Entry");

        List<Map<String, List<String>>> ret = null;

        if (!instance.done) {
            if (instance.connection == null) {
                log.debug("Getting connection out of pool '{}'", instance.connectionPoolEntry.name);
                instance.connection = instance.connectionPoolEntry.connectionPool.getConnection();
            }

            if (instance.doPaging) {
                instance.searchRequest.setControls(
                    new SimplePagedResultsControl(
                        pageSize != 0 ? pageSize : instance.pageSize,
                        instance.resumeCookie
                    )
                );
            }
            log.debug("SearchRequest: {}", instance.searchRequest);
            instance.resumeCookie = null;
            SearchResult searchResult;
            try {
                searchResult = instance.connection.search(instance.searchRequest);
            } catch (LDAPSearchException e) {
                log.debug("SearchRequest: Exception {}", (Object)e);
                log.trace("SearchRequest: Exception", e);
                log.trace("SearchRequest: Exception SearchReferences: {}", e.getSearchReferences());
                searchResult = e.getSearchResult();
            }
            log.debug("SearchResult: {}", searchResult);
            log.trace("SearchReferences: {}", searchResult.getSearchReferences());
            log.trace("SearchReferences: {}", searchResult.getSearchReferences());
            if (searchResult.getReferralURLs() != null && searchResult.getReferralURLs().length > 0) {
                if (log.isTraceEnabled()) {
                    log.trace("Search Referral URLs: {}", Arrays.asList(searchResult.getReferralURLs()));
                }
                String host = searchResult.getReferralURLs()[0];
                try {
                    LDAPConnection connection = instance.connection.getReferralConnector().getReferralConnection(
                        new LDAPURL(host),
                        instance.connection
                    );
                    instance.connection.close();
                    instance.connection = connection;
                    ret = new ArrayList<Map<String, List<String>>>();
                } catch (LDAPException e) {
                    log.warn("{} Cannot connect referral '{}': {}", logPrefix, host, e.getMessage());
                    log.debug("Exception", e);
                }
            } else {
                if (searchResult.getEntryCount() > 0) {
                    ret = searchMapEntries(
                        searchResult.getSearchEntries(),
                        instance.attrMap
                    );
                }

                if (searchResult.hasResponseControl(SimplePagedResultsControl.PAGED_RESULTS_OID)) {
                    SimplePagedResultsControl responseControl = SimplePagedResultsControl.get(searchResult);
                    if (responseControl.moreResultsToReturn()) {
                        instance.resumeCookie = responseControl.getCookie();
                    }
                }

                instance.limitLeft -= searchResult.getEntryCount();

                if (instance.resumeCookie == null || instance.limitLeft <= 0) {
                    instance.done = true;
                }
            }
        }

        log.trace("searchExecute Return: {}", ret);
        return ret;
    }

    public Map<String, Object> getGlobals() {
        return globals;
    }

    public Map<String, Object> createSequenceVars() {
        Map<String, Object> vars = new HashMap<>(globals);
        return vars;
    }

    public void runSequence(String name, Map<String, Object> vars)
    throws Exception {

        // skip null sequences
        if (name == null) {
            return;
        }

        stats();

        log.debug("runSequence Entry name='{}'", name);

        try {
            boolean do_return = false;
            for (Map.Entry<String, MapProperties> _entry : props.getOrEmpty("sequence", name).getMap().entrySet()) {
                if (do_return) {
                    break;
                }
                if (Boolean.valueOf(Util.toString(vars.get(VARS_STOP)))) {
                    break;
                }

                MapProperties entry = Util.expandMap(
                    _entry.getValue(),
                    "seq",
                    vars
                );

                String type = entry.getString("noop", "type");
                log.debug("Running sequence {}/{}/{} {}", name, _entry.getKey(), type, entry.getString("", "description"));
                dumpVariables(vars);

                try {
                    boolean run = false;
                    MapProperties condProps = entry.getOrEmpty("condition");
                    String conditionType = condProps.getString("true", "type");
                    MapProperties conditionProps = condProps.getOrEmpty(conditionType);
                    if ("true".equals(conditionType)) {
                        run = true;
                    } else if ("var-set".equals(conditionType)) {
                        run = vars.get(
                            conditionProps.getMandatoryString("variable")
                        ) != null;
                    } else if ("compare".equals(conditionType)) {
                        String convertType = conditionProps.getString("string", "conversion");
                        Object left = conditionProps.getMandatoryString("left");
                        Object right = conditionProps.getMandatoryString("right");
                        if ("string".equals(convertType)) {
                        } else if ("numeric".equals(convertType)) {
                            left = Long.valueOf(left.toString());
                            right = Long.valueOf(right.toString());
                        } else {
                            throw new IllegalArgumentException(
                                String.format("Invalid compare conversion '%s'", convertType)
                            );
                        }
                        @SuppressWarnings("unchecked")
                        int result = ((Comparable)left).compareTo(right);
                        if (result < 0) {
                            result = -1;
                        } else if (result > 0) {
                            result = 1;
                        }
                        run = result == conditionProps.getInt(0, "result");
                    } else {
                        throw new IllegalArgumentException(
                            String.format("Invalid sequence condition type '%s'", conditionType)
                        );
                    }
                    if (condProps.getBoolean(Boolean.FALSE, "not")) {
                        run = !run;
                    }

                    if (!run) {
                        log.debug("Skip");
                    } else {
                        MapProperties opProps = entry.getOrEmpty(type);
                        if ("noop".equals(type)) {
                        } else if ("return".equals(type)) {
                            do_return = true;
                        } else if ("stop".equals(type)) {
                            vars.put(VARS_STOP, "true");
                        } else if ("log".equals(type)) {
                            log.getClass().getMethod(
                                opProps.getString("info", "level"),
                                String.class
                            ).invoke(
                                log,
                                opProps.getString("", "message")
                            );
                        } else if ("call".equals(type)) {
                            runSequence(
                                opProps.getMandatoryString("name"),
                                vars
                            );
                        } else if ("for-each".equals(type)) {
                            Object values = vars.get(opProps.getMandatoryString("variable"));
                            if (values != null) {
                                if (!(values instanceof Collection)) {
                                    values = Arrays.asList(values);
                                }
                                int vi = 0;
                                for (Object v : (Collection)values) {
                                    vars.put(opProps.getString("forEachIndex", "var-index"), vi++);
                                    vars.put(opProps.getString("forEachValue", "var-value"), v);
                                    runSequence(
                                        opProps.getMandatoryString("sequence"),
                                        vars
                                    );
                                }
                            }
                        } else if ("auth-check".equals(type)) {
                            authCheck(
                                opProps.getMandatoryString("name"),
                                vars
                            );
                        } else if ("fetch-record".equals(type)) {
                            final String ATTRVARS_PREFIX = "search_attr_";
                            Util.removeKeysWithPrefix(vars, ATTRVARS_PREFIX);
                            List<Map<String, List<String>>> searchEntries = search(
                                opProps.getMandatoryString("search"),
                                0,
                                5,
                                vars
                            );
                            for (Map<String, List<String>> searchEntry : searchEntries) {
                                Util.removeKeysWithPrefix(vars, ATTRVARS_PREFIX);
                                MapProperties mapProps = opProps.getOrEmpty("map");
                                for (Map.Entry<String, List<String>> e : searchEntry.entrySet()) {
                                    MapProperties info = mapProps.get(e.getKey());
                                    if (info == null) {
                                        vars.put(ATTRVARS_PREFIX + e.getKey(), e.getValue().get(0));
                                    } else {
                                        String varname = info.getMandatoryString("name");
                                        int select = info.getInt(0, "select");
                                        if (select == -1) {
                                            vars.put(varname, e.getValue());
                                        } else {
                                            if (select < e.getValue().size()) {
                                                vars.put(varname, e.getValue().get(select));
                                            }
                                        }
                                    }
                                }
                                runSequence(
                                    opProps.getString(null, "sequence"),
                                    vars
                                );
                            }
                        } else if ("var-set".equals(type)) {
                            vars.put(
                                opProps.getMandatoryString("variable"),
                                opProps.getMandatoryString("value")
                            );
                        } else if ("var-list-get".equals(type)) {
                            vars.remove(opProps.getMandatoryString("variable"));
                            String varName = opProps.getMandatoryString("var-list");
                            Object varValue = vars.get(varName);
                            if (varValue != null) {
                                if (!(varValue instanceof Collection)) {
                                    throw new IllegalArgumentException(
                                        String.format(
                                            "Variable '%s' expected to contain Collection while it contains '%s'",
                                            varName,
                                            varValue.getClass().getName()
                                        )
                                    );
                                }
                                Collection<? extends Object> c = (Collection<? extends Object>)varValue;
                                int index = opProps.getInt(0, "index");
                                if (index < c.size()) {
                                    vars.put(
                                        opProps.getMandatoryString("variable"),
                                        new ArrayList<Object>(c).get(index)
                                    );
                                }
                            }
                        } else if ("var-list-set".equals(type)) {
                            List<Object> l = new ArrayList<>();
                            for (MapProperties e : opProps.getOrEmpty("values").getMap().values()) {
                                String v = e.getString(null, "value");
                                if (v != null) {
                                    l.add(v);
                                }
                                String var = e.getString(null, "var");
                                if (var != null) {
                                    Object varValue = vars.get(var);
                                    if (varValue != null) {
                                        l.add(varValue);
                                    }
                                }
                                var = e.getString(null, "var-list");
                                if (var != null) {
                                    Object varValue = vars.get(var);
                                    if (varValue != null) {
                                        if (!(varValue instanceof Collection)) {
                                            throw new IllegalArgumentException(
                                                String.format(
                                                    "Variable '%s' expected to contain Collection while it contains '%s'",
                                                    var,
                                                    varValue.getClass().getName()
                                                )
                                            );
                                        }
                                        l.addAll((Collection<? extends Object>)varValue);
                                    }
                                }
                            }
                            vars.put(
                                opProps.getMandatoryString("variable"),
                                l
                            );
                        } else if ("sysprop-set".equals(type)) {
                            System.setProperty(
                                opProps.getMandatoryString("name"),
                                opProps.getMandatoryString("value")
                            );
                        } else if ("regex".equals(type)) {
                            String pattern = opProps.getMandatoryString("pattern");
                            String flags = opProps.getString("", "flags");
                            log.debug("Pattern: {} ({})", pattern, flags);
                            Matcher matcher = Pattern.compile(pattern).matcher(
                                opProps.getMandatoryString("value")
                            );
                            boolean all = flags.indexOf('a') != -1;
                            boolean always = flags.indexOf('a') != -1;
                            boolean force = flags.indexOf('f') != -1;
                            boolean go = force || (all ? matcher.find() : matcher.matches());
                            if (go) {
                                for (Map.Entry<String, MapProperties> e : opProps.getOrEmpty("replacement").getMap().entrySet()) {
                                    vars.put(
                                        e.getKey(),
                                        (
                                            all ?
                                            matcher.replaceAll(
                                                e.getValue().getValue()
                                            ) :
                                            matcher.replaceFirst(
                                                e.getValue().getValue()
                                            )
                                        )
                                    );
                                }
                            }
                        } else if ("credentials-change".equals(type)) {
                            modifyCredentials(
                                opProps.getMandatoryString("pool"),
                                opProps.getMandatoryString("user"),
                                opProps.getMandatoryString("password", "current"),
                                opProps.getMandatoryString("password", "new"),
                                vars
                            );
                        } else if ("pool-create".equals(type)) {
                            getConnectionPoolEntry(
                                opProps.getMandatoryString("name"),
                                null,
                                vars
                            );
                        } else if ("search-open".equals(type)) {
                            vars.put(
                                opProps.getMandatoryString("variable"),
                                searchOpen(
                                    opProps.getMandatoryString("search"),
                                    0,
                                    0,
                                    vars
                                )
                            );
                        } else if ("time-get".equals(type)) {
                            vars.put(
                                opProps.getMandatoryString("variable"),
                                Long.toString(new Date().getTime())
                            );
                        } else {
                            throw new IllegalArgumentException(
                                String.format("Invalid sequence type '%s'", type)
                            );
                        }

                        log.debug("End sequence {} {}", name, entry.getString("", "description"));
                        dumpVariables(vars);
                    }
                } catch (Exception e) {
                    log.debug("Sequence {} {} failed due to exception: {}", name, entry.getString("", "description"), e.getMessage());
                    throw e;
                }
            }
        } catch (LDAPException e) {
            log.debug("Exception during sequence", e);
            vars.put(VARS_RESULT_CODE, resultCodeNameMap.get(e.getResultCode()));
            vars.put(VARS_MESSAGE, e.getMessage());
            vars.put(VARS_DIAGNOSTIC_MESSAGE, e.getDiagnosticMessage());
            throw e;
        } catch (Exception e) {
            log.debug("Exception during sequence", e);
            vars.put(VARS_RESULT_CODE, resultCodeNameMap.get(ResultCode.LOCAL_ERROR));
            vars.put(VARS_MESSAGE, e.getMessage());
            throw e;
        }

        log.debug("runSequence Return name='{}'", name);
    }

}

// vim: expandtab tabstop=4 shiftwidth=4

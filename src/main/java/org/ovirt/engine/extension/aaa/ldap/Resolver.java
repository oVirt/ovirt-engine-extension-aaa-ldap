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
package org.ovirt.engine.extension.aaa.ldap;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class Resolver implements Closeable {

    /*
     * com.example.jndi.dns.timeout.initial
     * com.example.jndi.dns.timeout.retries
     *
     * http://docs.oracle.com/javase/7/docs/technotes/guides/jndi/jndi-dns.html
     */

    private static class CacheEntry {
        public List<InetAddress> addresses;
        public long expire;
    }

    private static final Logger log = LoggerFactory.getLogger(Resolver.class);

    protected static final String CONFIG_PREFIX = "config.dns.context.";

    private static final Pattern IPV4_PATTERN = Pattern.compile("(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])");
    private static final Pattern IPV6_PATTERN = Pattern.compile(
        "(" +
            "(([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|" +
            "(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|" +
            "(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|" +
            "(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|" +
            "(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|" +
            "(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|" +
            "(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|" +
            "(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))" +
        ")(%.+)?"
    );

    protected final Hashtable<String, Object> env = new Hashtable<>();
    private final ConcurrentMap<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final Random random;

    /**
     * Automatic detection of IP version used for DNS resolution based on what IP version is available on the default
     * gateway
     */
    private boolean detectIPVersion = true;

    /**
     * Manually enable support for IPv4 address resolution
     */
    private boolean supportIPv4 = false;

    /**
     * Manually enable support for IPv6 address resolution
     */
    private boolean supportIPv6 = false;

    private int cacheTTL = 10000;

    private DirContext ctx;

    public Resolver(Properties jndiprops) {
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch(NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        env.put(Context.PROVIDER_URL, "dns://");
        for (Map.Entry<Object, Object> entry : jndiprops.entrySet()) {
            env.put(entry.getKey().toString(), entry.getValue());
        }
    }

    public String getURL() {
        return (String)env.get(Context.PROVIDER_URL);
    }

    public void setURL(String url) {
        env.put(Context.PROVIDER_URL, url);
    }

    public int getCacheTTL() {
        return cacheTTL;
    }

    public void setCacheTTL(int cacheTTL) {
        this.cacheTTL = cacheTTL;
    }

    public boolean getDetectIPVersion() {
        return detectIPVersion;
    }

    public void setDetectIPVersion(boolean detectIPVersion) {
        this.detectIPVersion = detectIPVersion;
    }

    public boolean getSupportIPV6() {
        return supportIPv6;
    }

    public void setSupportIPv6(boolean supportIPv6) {
        this.supportIPv6 = supportIPv6;
    }

    public void setSupportIPv4(boolean supportIPv4) {
        this.supportIPv4 = supportIPv4;
    }

    public boolean getSupportIPv4() {
        return supportIPv4;
    }

    protected String fetchCommandOutput(String[] command) {
        String result = null;
        int exitCode = -1;
        ProcessBuilder pb = new ProcessBuilder();
        Process p = null;
        pb.command(command);
        try {
            p = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                result = reader.lines().collect(Collectors.joining("\n"));
            } catch (IOException ex) {
                log.error("Error fetching output of command '{}': {}", command, ex.getMessage());
                log.debug("Exception", ex);
            }
            exitCode = p.waitFor();
        } catch (Exception ex) {
            log.error("Error executing command '{}': {}", command, ex.getMessage());
            log.debug("Exception", ex);
        } finally {
            if (p != null) {
                p.destroy();
            }
        }
        log.debug("Execution finished with code {} and stdout: '{}'", exitCode, result);
        return result;
    }

    protected InetAddress fetchDefaultGateway(String ipVersion) {
        InetAddress addr = null;
        String[] command = {
                "/usr/sbin/ip",
                "-o",
                ipVersion,
                "route",
                "show",
                "default"
        };
        String output = fetchCommandOutput(command);
        if (output != null) {
            // For example "default via 192.168.75.1 dev wlp61s0 proto dhcp metric 600"
            String[] parts = output.split(" ");

            // InetAddress created from empty string will return an instance of "127.0.0.1", so we need to omit that
            if (parts.length > 3 && parts[2] != null && parts[2].length() > 0) {
                try {
                    addr = InetAddress.getByName(parts[2]);
                } catch (UnknownHostException ex) {
                    log.error("Error instantiating address '{}': {}", parts[2], ex.getMessage());
                    log.debug("Exception", ex);
                }
            }
        }
        return addr;
    }

    protected boolean isIPv4Available() {
        return fetchDefaultGateway("-4") != null;
    }

    protected boolean isIPv6Available() {
        return fetchDefaultGateway("-6") != null;
    }

    public void setEnvironment(String expression) {
        String[] comps = expression.split("=", 2);
        env.put(comps[0].trim(), comps[1].trim());
    }

    public void setEnvironment(String key, String value) {
        env.put(key, value);
    }

    public Resolver open() throws NamingException, IOException {
        log.debug("Open: Context: {}", env);
        ctx = createContext(env);
        return this;
    }

    @Override
    public void close() throws IOException {
        log.debug("Close");
        if (ctx != null) {
            try {
                ctx.close();
                ctx = null;
            } catch (NamingException e) {
                log.debug("Ignoring exception", e);
            }
        }
    }

    public static boolean isAddress(String name) {
        return IPV4_PATTERN.matcher(name).matches() || IPV6_PATTERN.matcher(name).matches();
    }

    private Attributes query(String name, String[] attrs) throws NamingException {
        if (log.isDebugEnabled()) {
            log.debug("query(): name='{}', attrs={}", name, Arrays.asList(attrs));
        }

        Attributes ret = ctx.getAttributes(name, attrs);

        log.debug("query() return: {}", ret);
        return ret;
    }

    protected List<String> getDnsRecordTypes() {
        List<String> attrNames = new ArrayList<>();
        if (detectIPVersion && isIPv4Available() || supportIPv4) {
            attrNames.add("A");
        }
        if (detectIPVersion && isIPv6Available() || supportIPv6) {
            attrNames.add("AAAA");
        }
        return attrNames;
    }

    private Set<String> queryARecord(String name)
    throws NamingException {

        log.debug("queryARecord(): name='{}'", name);

        Set<String> ret = new HashSet<>();

        for (String recordType : getDnsRecordTypes()) {
            Attributes attrs = query(name, new String[] { recordType });
            if (attrs != null) {
                Attribute a = attrs.get(recordType);
                if (a != null) {
                    for (Object address : Collections.list(a.getAll())) {
                        log.debug("Record type '{}', addresses: {}", recordType, address);
                        ret.add(address.toString());
                    }
                }
            }
        }

        log.debug("queryARecord() return: {}", ret);

        return ret;
    }

    private List<InetAddress> _resolveAll(String name) throws UnknownHostException {
        try {
            log.debug("_resolveAll(): name='{}'", name);
            List<InetAddress> ret = null;
            if (isAddress(name)) {
                log.debug("Not resolving address");
                ret = Arrays.asList(InetAddress.getByName(name));
            } else {
                long now = new Date().getTime();
                CacheEntry entry = cache.get(name);
                if (entry != null && now > entry.expire) {
                    log.debug("Invalidating cache entry");
                    entry = null;
                }
                if (entry == null) {
                    log.debug("Cache miss");
                    Set<String> result = queryARecord(name);
                    if (result.isEmpty()) {
                        throw new UnknownHostException(name);
                    }
                    entry = new CacheEntry();
                    entry.expire = now + cacheTTL;
                    entry.addresses = new ArrayList<>();
                    for (String address : result) {
                        entry.addresses.add(
                            InetAddress.getByAddress(
                                name,
                                InetAddress.getByName(address).getAddress()
                            )
                        );
                    }
                    cache.put(name, entry);
                }
                ret = entry.addresses;
            }
            log.debug("_resolveAll() return: {}", ret);
            return ret;
        } catch(NamingException e) {
            log.debug("Unable to resolve host '{}'", name);
            log.debug("Exception", e);
            throw new UnknownHostException(name);
        }
    }

    public List<InetAddress> resolveAll(String name) throws UnknownHostException {
        log.debug("resolveAll(): name='{}'", name);
        List<InetAddress> addresses = _resolveAll(name);
        List<InetAddress> ret;
        if (addresses.size() == 1) {
            ret = addresses;
        } else {
            ret = new ArrayList<>(addresses);
            Collections.shuffle(ret, random);
        }
        log.debug("resolveAll() return: {}", ret);
        return ret;
    }

    public InetAddress resolve(String name) throws UnknownHostException {
        log.debug("resolve(): name='{}'", name);
        List<InetAddress> addresses = _resolveAll(name);
        InetAddress ret = null;
        if (addresses.size() == 1) {
            ret = addresses.get(0);
        } else {
            byte[] r = new byte[1];
            random.nextBytes(r);
            ret = addresses.get((r[0] & 0xff) % addresses.size());
        }
        log.debug("resolve() return: {}", ret);
        return ret;
    }

    @Override
    public String toString() {
        return String.format(
                "Resolver(env='%s', detectIPVersion='%s', supportIPv4='%s', supportIPv6='%s', cacheTTL='%s')",
                env,
                detectIPVersion,
                supportIPv4,
            supportIPv6,
            cacheTTL
        );
    }

    protected InitialDirContext createContext(Hashtable<String, Object> env) throws NamingException {
        return new InitialDirContext(env);
    }
}

// vim: expandtab tabstop=4 shiftwidth=4

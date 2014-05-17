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
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import javax.naming.*;
import javax.naming.directory.*;

import org.slf4j.*;

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

    public boolean getSupportIPV6() {
        return supportIPv6;
    }

    public void setSupportIPv6(boolean supportIPv6) {
        this.supportIPv6 = supportIPv6;
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
                log.warn("Ignoring exception", e);
            }
        }
    }

    public static boolean isAddress(String name) {
        return IPV4_PATTERN.matcher(name).matches() || IPV6_PATTERN.matcher(name).matches();
    }

    private Attributes query(String name, String[] attrs) throws NamingException {
        if (log.isDebugEnabled()) {
            log.debug("Entry: name='{}', attrs=%s", name, Arrays.asList(attrs));
        }

        Attributes ret = ctx.getAttributes(name, attrs);

        log.debug("Return: {}", ret);
        return ret;
    }

    private Set<String> queryARecord(String name)
    throws NamingException {

        log.debug("Entry: name='{}'", name);

        Set<String> ret = new HashSet<>();
        List<String> attrNames = new ArrayList<>();

        attrNames.add("A");
        if (supportIPv6) {
            attrNames.add("AAAA");
        }

        Attributes attrs = query(name, attrNames.toArray(new String[0]));
        if (attrs != null) {
            for (String n : attrNames) {
                Attribute a = attrs.get(n);
                if (a != null) {
                    for (Object address : Collections.list(a.getAll())) {
                        log.debug("{} {}", n, address);
                        ret.add(address.toString());
                    }
                }
            }
        }

        log.debug("Return: {}", ret);

        return ret;
    }

    private List<InetAddress> _resolveAll(String name) throws UnknownHostException {
        try {
            log.debug("Entry: name='{}'", name);
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
            log.debug("Return: {}", ret);
            return ret;
        } catch(NamingException e) {
            log.debug("Unable to resolve host '{}'", name);
            log.debug("Exception", e);
            throw new UnknownHostException(name);
        }
    }

    public List<InetAddress> resolveAll(String name) throws UnknownHostException {
        log.debug("Entry: name='{}'", name);
        List<InetAddress> addresses = _resolveAll(name);
        List<InetAddress> ret;
        if (addresses.size() == 1) {
            ret = addresses;
        } else {
            ret = new ArrayList<InetAddress>(addresses);
            Collections.shuffle(ret, random);
        }
        log.debug("Return: {}", ret);
        return ret;
    }

    public InetAddress resolve(String name) throws UnknownHostException {
        log.debug("Entry: name='{}'", name);
        List<InetAddress> addresses = _resolveAll(name);
        InetAddress ret = null;
        if (addresses.size() == 1) {
            ret = addresses.get(0);
        } else {
            byte[] r = new byte[1];
            random.nextBytes(r);
            ret = addresses.get((r[0] & 0xff) % addresses.size());
        }
        log.debug("Return: {}", ret);
        return ret;
    }

    @Override
    public String toString() {
        return String.format(
            "Resolver(env='%s', supportIPv6='%s', cacheTTL='%s')",
            env,
            supportIPv6,
            cacheTTL
        );
    }

    protected InitialDirContext createContext(Hashtable<String, Object> env) throws NamingException {
        return new InitialDirContext(env);
    }
}

// vim: expandtab tabstop=4 shiftwidth=4

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
import java.security.*;
import java.util.*;
import java.util.regex.*;

public class Util {

    private static final Pattern VAR_PATTERN = Pattern.compile("\\$\\{((?<namespace>[^:}]*):)?(?<var>[^}]*)\\}");

    private static final Map<Class<?>, Class<?>> typeBox = new HashMap<>();
    static {
        typeBox.put(boolean.class, Boolean.class);
        typeBox.put(byte.class, Byte.class);
        typeBox.put(char.class, Character.class);
        typeBox.put(double.class, Double.class);
        typeBox.put(float.class, Float.class);
        typeBox.put(int.class, Integer.class);
        typeBox.put(long.class, Long.class);
        typeBox.put(short.class, Short.class);
        typeBox.put(void.class, Void.class);
    }

    public static String toString(Object o, String def) {
        return o != null ? o.toString() : def;
    }

    public static String toString(Object o) {
        return toString(o, "");
    }

    public static String expandString(String s, String namespace, Map<? extends Object, ? extends Object> vars) {
        StringBuilder ret = new StringBuilder();
        Matcher m = VAR_PATTERN.matcher(s);
        int last = 0;
        while (m.find()) {
            ret.append(s.substring(last, m.start()));
            if (
                (namespace == null && m.group("namespace") == null) ||
                (namespace != null && namespace.equals(m.group("namespace")))
            ) {
                Object o = vars.get(m.group("var"));
                if (o != null) {
                    ret.append(o);
                }
            } else {
                ret.append(m.group(0));
            }
            last = m.end();
        }
        ret.append(s.substring(last, m.regionEnd()));
        return ret.toString();
    }

    public static void _expandMap(MapProperties props, String namespace, Map<? extends Object, ? extends Object> vars) {
        if (props.getValue() != null) {
            props.setValue(expandString(props.getValue(), namespace, vars));
        }
        for (MapProperties entry : props.getMap().values()) {
            _expandMap(entry, namespace, vars);
        }
    }

    public static MapProperties expandMap(MapProperties props, String namespace, Map<? extends Object, ? extends Object> vars) {
        MapProperties ret = new MapProperties(props);
        MapProperties old;
        do {
            old = new MapProperties(ret);
            _expandMap(ret, namespace, vars);
        } while(!old.equals(ret));
        return ret;
    }

    public static Properties expandProperties(
        Properties props,
        String namespace,
        Map<? extends Object, ? extends Object> vars,
        boolean recursive
    ) {
        Properties ret = new Properties();
        ret.putAll(props);
        Properties old;
        do {
            old = new Properties();
            old.putAll(ret);
            for (Map.Entry<Object, Object> entry : ret.entrySet()) {
                entry.setValue(expandString(entry.getValue().toString(), namespace, vars));
            }
        } while(recursive && !old.equals(ret));
        return ret;
    }

    public static List<String> stringPropertyNames(Properties props, String prefix) {
        if (prefix.endsWith(".")) {
            prefix = prefix.substring(0, prefix.length()-1);
        }
        List<String> keys = new LinkedList<>();
        for (String key : props.stringPropertyNames()) {
            if (key.equals(prefix) || key.startsWith(prefix + ".")) {
                keys.add(key);
            }
        }
        Collections.sort(keys);
        return keys;
    }

    public static void includeProperties(
        Properties out,
        String includeKey,
        List<File> includeDirectories,
        File file
    ) throws IOException {
        Properties props = new Properties();
        props.load(
            new InputStreamReader(
                new FileInputStream(file),
                Charset.forName("UTF-8")
            )
        );
        props.put("_basedir", file.getParent());
        props = expandProperties(props, "local", props, true);
        for (String key : stringPropertyNames(props, includeKey)) {
            String include = props.getProperty(key);

            File includeFile = null;
            if (include.startsWith("<") && include.endsWith(">")) {
                include = include.substring(1, include.length()-1);
                for (File i : includeDirectories) {
                    File t = new File(i, include);
                    if (t.exists()) {
                        includeFile = t;
                        break;
                    }
                }
                if (includeFile == null) {
                    throw new FileNotFoundException(
                        String.format(
                            "Cannot include file '%s' from search path %s",
                            include,
                            includeDirectories
                        )
                     );
                }
            } else {
                includeFile = new File(include);
                if (!includeFile.isAbsolute()) {
                    includeFile = new File(file.getParentFile(), include);
                }
            }
            includeProperties(out, includeKey, includeDirectories, includeFile);
        }
        for (Map.Entry<Object, Object> entry : props.entrySet()) {
            out.put(entry.getKey(), entry.getValue());
        }
    }

    public static Properties loadProperties(List<File> includeDirectories, File... file) throws IOException {
        Properties props = new Properties();
        for (File f : file) {
            includeProperties(props, "include", includeDirectories, f);
        }
        props = expandProperties(props, "global", props, true);
        props = expandProperties(props, "sys", System.getProperties(), false);
        return props;
    }

    public static int[] asIntArray(List<?> l) {
        int[] ret = new int[l.size()];
        int i=0;
        for (Object o : l) {
            ret[i++] = Integer.valueOf(o.toString());
        }
        return ret;
    }

    public static List<String> getValueFromMapRecord(MapProperties props, String key, String def) {
        List<String> ret = new ArrayList<>();
        for (MapProperties entry : props.getMap().values()) {
            String v = entry.getString(null, key);
            if (v == null) {
                v = def;
            }
            ret.add(v);
        }
        return ret;
    }

    public static Object getObjectValueByString(Class<?> clazz, String value) {
        Object v = null;

        if (clazz.isPrimitive()) {
            clazz = typeBox.get(clazz);
        }

        if (v == null) {
            if (clazz.equals(Collection.class)) {
                List<Object> r = new ArrayList<>();
                for (String c : value.trim().split(" *, *")) {
                    if (!c.isEmpty()) {
                        r.add(getObjectValueByString(String.class, c));
                    }
                }
                v = r;
            }
        }

        if (v == null) {
            if (clazz.isArray() && Object.class.isAssignableFrom(clazz.getComponentType())) {
                List<Object> r = new ArrayList<>();
                for (String c : value.trim().split(" *, *")) {
                    if (!c.isEmpty()) {
                        r.add(getObjectValueByString(clazz.getComponentType(), c));
                    }
                }
                v = (Object)r.toArray((Object[])Array.newInstance(clazz.getComponentType(), 0));
            }
        }

        if (v == null) {
            try {
                Field f = clazz.getField(value);
                if (Modifier.isStatic(f.getModifiers())) {
                    v = f.get(null);
                }
            } catch(ReflectiveOperationException e) {}
        }

        if (v == null) {
            try {
                Method convert = clazz.getMethod("valueOf", String.class);
                if (Modifier.isStatic(convert.getModifiers())) {
                    v = convert.invoke(null, value);
                }
            } catch(ReflectiveOperationException e) {}
        }

        if (v == null) {
            try {
                Method convert = clazz.getMethod("valueOf", Object.class);
                if (Modifier.isStatic(convert.getModifiers())) {
                    v = convert.invoke(null, value);
                }
            } catch(ReflectiveOperationException e) {}
        }

        if (v == null) {
            try {
                Constructor<?> constructor = clazz.getDeclaredConstructor(String.class);
                v = constructor.newInstance(value);
            } catch(ReflectiveOperationException e) {}
        }

        return v;
    }

    public static void setObjectByProperties(Object o, MapProperties props, String... methodPrefixes) {
        if (props == null) {
            return;
        }

        for (Method m : o.getClass().getMethods()) {
            for (String p : methodPrefixes) {
                String methodName = m.getName();
                if (methodName.startsWith(p)) {
                    String name = (
                        methodName.substring(p.length(), p.length()+1).toLowerCase() +
                        methodName.substring(p.length()+1)
                    );
                    try {
                        List<String> values = new ArrayList<>();
                        MapProperties valueProps = props.getOrEmpty(name);
                        values.add(valueProps.getValue());
                        for (MapProperties valueProps1 : valueProps.getMap().values()) {
                            values.add(valueProps1.getValue());
                        }
                        for (String value : values) {
                            if (value != null) {
                                Class<?>[] args = m.getParameterTypes();
                                if (args.length == 1) {
                                    Object v = getObjectValueByString(args[0], value);
                                    if (v != null) {
                                        m.invoke(o, v);
                                    }
                                }
                            }
                        }
                    } catch(Exception e) {
                        throw new RuntimeException(
                            String.format(
                                "Cannot set key '%s', error: %s",
                                name,
                                e.getMessage()
                            ),
                            e
                        );
                    }
                }
            }
        }
    }

    public static <T extends Enum<T>> List<T> getEnumFromString(Class<T> clazz, String value) {
        List<T> ret = new ArrayList<>();
        if (value != null) {
            String[] comps = value.trim().split(" *, *");
            for (String c : comps) {
                if (!c.isEmpty()) {
                    ret.add(T.valueOf(clazz, c));
                }
            }
        }
        return ret;
    }

    public static KeyStore loadKeyStore(String provider, String type, String file, String password)
    throws GeneralSecurityException, IOException {

        KeyStore store = null;

        if (file != null) {
            try (InputStream in = new FileInputStream(file)) {
                if (type == null) {
                    type = KeyStore.getDefaultType();
                }

                if (provider == null) {
                    store = KeyStore.getInstance(
                        type
                    );
                } else {
                    store = KeyStore.getInstance(
                        type,
                        provider
                    );
                }

                store.load(in, password.toCharArray());
            }
        }

        return store;
    }
}

// vim: expandtab tabstop=4 shiftwidth=4

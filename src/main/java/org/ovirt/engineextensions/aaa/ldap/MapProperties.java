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

import java.io.IOException;
import java.io.StringReader;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListMap;

public class MapProperties {

    private Map<String, MapProperties> map = new ConcurrentSkipListMap<>();
    private String value;

    private void loadRecursive(MapProperties base, MapProperties props) {
        if (props != null) {
            if (props.value != null) {
                base.value = props.value;
            }
            for (Map.Entry<String, MapProperties> e : props.map.entrySet()) {
                MapProperties kbase = base.get(e.getKey());
                if (kbase == null) {
                    kbase = new MapProperties();
                    base.put(e.getKey(), kbase);
                }
                loadRecursive(kbase, e.getValue());
            }
        }
    }

    private void transform(Map<? extends Object, ? extends Object> props) {
        for (Map.Entry<? extends Object, ? extends Object> entry : props.entrySet()) {
            MapProperties last = this;
            for (String component : entry.getKey().toString().split("\\.")) {
                MapProperties current = last.map.get(component);
                if (current == null) {
                    current = new MapProperties();
                    last.map.put(component, current);
                }
                last = current;
            }
            last.value = entry.getValue().toString();
        }
    }

    private String escape(String s) {
        StringBuilder builder = new StringBuilder();
        for (char x : s.toCharArray()) {
            switch (x) {
            case ' ':
            case '=':
            case ':':
            case '\\':
                builder.append('\\');
            }
            builder.append(x);
        }
        return builder.toString();
    }

    private <T> T validateMandatory(T o, String... keys) {
        if (o == null) {
            StringBuffer sb = new StringBuffer();
            for (String k : keys) {
                if (sb.length() > 0) {
                    sb.append(".");
                }
                sb.append(k);
            }
            throw new IllegalStateException(
                String.format(
                    "%s must be specified",
                    sb
                )
            );
        }
        return o;
    }

    public MapProperties() {
    }

    @SuppressWarnings("unchecked")
    public MapProperties(Properties... props) {
        load(props);
    }

    @SuppressWarnings("unchecked")
    public MapProperties(MapProperties... props) {
        load(props);
    }

    @SuppressWarnings("unchecked")
    public void load(Properties... props) {
        for (Properties prop : props) {
            transform(prop);
        }
    }

    @SuppressWarnings("unchecked")
    public void load(MapProperties... props) {
        for (MapProperties prop : props) {
            loadRecursive(this, prop);
        }
    }

    public MapProperties put(String key, MapProperties props) {
        map.put(key, props);
        return this;
    }

    public StringBuilder toString(String prefix, Set<String> sensitiveKeys, StringBuilder builder) {
        if (value != null) {
            builder.append(prefix);
            builder.append('=');
            builder.append(
                escape(
                    sensitiveKeys.contains(
                        prefix.substring(
                            prefix.lastIndexOf(".")+1
                        )
                    ) ? "***" : value
                )
            );
            builder.append('\n');
        }
        for (Map.Entry<String, MapProperties> entry : map.entrySet()) {
            entry.getValue().toString(prefix + "." + entry.getKey(), sensitiveKeys, builder);
        }
        return builder;
    }

    @Override
    public int hashCode() {
        return map.hashCode() + value.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        return (
            o != null &&
            getClass() == o.getClass() &&
            map.equals(((MapProperties)o).map) &&
            (value == null ? ((MapProperties)o).value == null : value.equals(((MapProperties)o).value))
        );
    }

    @Override
    public String toString() {
        return toString(Collections.<String>emptySet());
    }

    public String toString(Set<String> sensitiveKeys) {
        return toString("", sensitiveKeys, new StringBuilder()).toString();
    }

    public Properties toProperties() {
        try {
            Properties props = new Properties();
            props.load(
                new StringReader(toString().replaceFirst("^\\.", "").replaceAll("\n\\.", "\n"))
            );
            return props;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Map<String, MapProperties> getMap() {
        return map;
    }

    public MapProperties get(String... keys) {
        MapProperties ret = this;
        for (String key : keys) {
            ret = ret.map.get(key);
            if (ret == null) {
                break;
            }
        }
        return ret;
    }

    public MapProperties getOrEmpty(String... keys) {
        MapProperties ret = get(keys);
        return ret == null ? new MapProperties() : ret;
    }

    public MapProperties get(List<String> keys) {
        return get(keys.toArray(new String[0]));
    }

    public String getString(String def, String... keys) {
        String ret = def;
        MapProperties props = get(keys);
        if (props != null && props.value != null) {
            ret = props.value;
        }
        return ret;
    }

    public Boolean getBoolean(Boolean def, String... keys) {
        MapProperties props = get(keys);
        if (props == null || props.value == null) {
            return def;
        } else {
            return Boolean.valueOf(props.value);
        }
    }

    public Integer getInt(Integer def, String... keys) {
        MapProperties props = get(keys);
        if (props == null || props.value == null) {
            return def;
        } else {
            return Integer.valueOf(props.value);
        }
    }

    public Long getLong(Long def, String... keys) {
        MapProperties props = get(keys);
        if (props == null || props.value == null) {
            return def;
        } else {
            return Long.valueOf(props.value);
        }
    }

    public String getMandatoryString(String... keys) {
        return validateMandatory(getString(null, keys), keys);
    }

    public Boolean getMandatoryBoolean(String... keys) {
        return validateMandatory(getBoolean(null, keys), keys);
    }

    public Integer getMandatoryInt(String... keys) {
        return validateMandatory(getInt(null, keys), keys);
    }

    public Long getMandatoryLong(String... keys) {
        return validateMandatory(getLong(null, keys), keys);
    }

}

// vim: expandtab tabstop=4 shiftwidth=4

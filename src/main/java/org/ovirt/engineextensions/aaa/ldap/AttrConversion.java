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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public enum AttrConversion {

    STRING(
        new Format() {
            @Override
            public String encode(ASN1OctetString value, MapProperties props) {
                return value.stringValue();
            }
            @Override
            public ASN1OctetString decode(String value, MapProperties props) {
                return new ASN1OctetString(value);
            }
            @Override
            public boolean isString() {
                return true;
            }
        }
    ),
    REGEX(
        new Format() {
            private String doPattern(String value, MapProperties props, String mode) {
                String pattern = props.getMandatoryString(mode, "pattern");
                Matcher matcher = Pattern.compile(pattern).matcher(value);
                String ret = value;
                if (matcher.matches()) {
                    ret = matcher.replaceFirst(props.getMandatoryString(mode, "replacement"));
                }
                log.debug("Mode: '{}', Pattern: {}, Value: '{}', Result='{}'", mode, pattern, value, ret);
                return ret;
            }
            @Override
            public String encode(ASN1OctetString value, MapProperties props) {
                return doPattern(value.stringValue(), props, "encode");
            }
            @Override
            public ASN1OctetString decode(String value, MapProperties props) {
                return new ASN1OctetString(doPattern(value, props, "decode"));
            }
            @Override
            public boolean isString() {
                return true;
            }
        }
    ),
    BASE64(
        new Format() {
            @Override
            public String encode(ASN1OctetString value, MapProperties props) {
                return Base64.encode(value.getValue());
            }
            @Override
            public ASN1OctetString decode(String value, MapProperties props) {
                try {
                    return new ASN1OctetString(Base64.decode(value));
                } catch (ParseException e) {
                    throw new RuntimeException(e);
                }
            }
            @Override
            public boolean isString() {
                return false;
            }
        }
    ),
    DATE(
        new Format() {
            private final Pattern GENERALIZED_TIME = Pattern.compile(
                "(?<date>\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d(\\d\\d(\\d\\d)?)?)([,.]\\d)?" +
                "(Z|(?<offset>[+-]\\d\\d(\\d\\d)?))"
            );

            @Override
            public String encode(ASN1OctetString value, MapProperties props) {
                try {
                    Matcher matcher = GENERALIZED_TIME.matcher(value.stringValue());
                    if (!matcher.matches()) {
                        throw new RuntimeException("Invalid date: " + value);
                    }
                    String date = matcher.group("date");
                    if (date == null) {
                        throw new RuntimeException("Invalid date: " + value);
                    }
                    date = (date + "0000").substring(0, 14);
                    String offset = matcher.group("offset");
                    if (offset == null) {
                        offset = "+0000";
                    } else {
                        offset = (offset + "00").substring(0, 5);
                    }

                    SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmssZ");
                    sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
                    return Long.toString(sdf.parse(date + offset).getTime());
                } catch (ParseException e) {
                    throw new RuntimeException("Invalid date: " + value, e);
                }
            }
            @Override
            public ASN1OctetString decode(String value, MapProperties props) {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
                sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
                return new ASN1OctetString(sdf.format(new Date(Long.valueOf(value)))+"Z");
            }
            @Override
            public boolean isString() {
                return false;
            }
        }
    );

    private interface Format {
        String encode(ASN1OctetString value, MapProperties props);
        ASN1OctetString decode(String value, MapProperties props);
        boolean isString();
    }

    private static final Logger log = LoggerFactory.getLogger(AttrConversion.class);

    private final Format format;

    private AttrConversion(Format format) {
        this.format = format;
    }

    public String encode(ASN1OctetString value, MapProperties props) {
        return format.encode(value, props);
    }

    public ASN1OctetString decode(String value, MapProperties props) {
        return format.decode(value, props);
    }

    public boolean isString() {
        return format.isString();
    }
}

// vim: expandtab tabstop=4 shiftwidth=4

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

import java.text.*;
import java.util.*;
import java.util.regex.*;

import com.unboundid.asn1.*;
import com.unboundid.util.Base64;

public enum AttrConversion {

    STRING(
        new Format() {
            public String encode(ASN1OctetString value) {
                return value.stringValue();
            }
            public ASN1OctetString decode(String value) {
                return new ASN1OctetString(value);
            }
        }
    ),
    BASE64(
        new Format() {
            public String encode(ASN1OctetString value) {
                return Base64.encode(value.getValue());
            }
            public ASN1OctetString decode(String value) {
                try {
                    return new ASN1OctetString(Base64.decode(value));
                } catch (ParseException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    ),
    DATE(
        new Format() {
            public String encode(ASN1OctetString value) {
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
            public ASN1OctetString decode(String value) {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
                sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
                return new ASN1OctetString(sdf.format(new Date(Long.valueOf(value)))+"Z");
            }
        }
    );

    private interface Format {
        String encode(ASN1OctetString value);
        ASN1OctetString decode(String value);
    }

    private static final Pattern GENERALIZED_TIME = Pattern.compile(
        "(?<date>\\d\\d\\d\\d\\d\\d\\d\\d\\d\\d(\\d\\d(\\d\\d)?)?)([,.]\\d)?" +
        "(Z|(?<offset>[+-]\\d\\d(\\d\\d)?))"
    );

    private final Format format;

    private AttrConversion(Format format) {
        this.format = format;
    }

    public String encode(ASN1OctetString value) {
        return format.encode(value);
    }

    public ASN1OctetString decode(String value) {
        return format.decode(value);
    }
}

// vim: expandtab tabstop=4 shiftwidth=4

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

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class ProfileTest {

    public static void main(String... args) throws Exception {

        String basedir = args[0];

        for (
            String file : new String[] {
                "brq-ipa.rhev.lab.eng.brq.redhat.com.properties",
                "ad-w2k12r2.rhev.lab.eng.brq.redhat.com.properties",
                "brq-ldap.rhev.lab.eng.brq.redhat.com.properties",
                "qa.lab.tlv.redhat.com-simple.properties",
                "qa.lab.tlv.redhat.com-digest-md5.properties",
                "qa.lab.tlv.redhat.com-digest-md5-srvrecord.properties",
                "qa.lab.tlv.redhat.com-gssapi.properties",
                "ldap.corp.redhat.com.properties",
                "directory.washington.edu-plain.properties",
                "directory.washington.edu-ssl.properties",
                "directory.washington.edu-starttls.properties",
                //"ldap.virginia.edu-ssl.properties",
                null
            }
        ) {
            if (file == null) {
                continue;
            }
            System.out.println("PROFILE: " + file);
            System.out.flush();
            try (
                Framework framework = new Framework(
                    "ProfileTest",
                    new MapProperties(
                        Util.loadProperties(
                            Arrays.asList(new File("profiles")),
                            new File(basedir, file),
                            new File(basedir, "profile-test.properties")
                        )
                    )
                )
            ) {
                framework.getGlobals().put("authz_enable", "1");
                framework.init();
                framework.open();

                Map<String, Object> vars = framework.createSequenceVars();
                framework.runSequence(
                    "profile-test",
                    vars
                );
                Framework.SearchInstance instance = (Framework.SearchInstance)vars.get("query");
                if (instance != null) {
                    try {
                        List<Map<String, List<String>>> result;
                        do {
                            result = framework.searchExecute(instance, 0);
                        } while (result != null);
                    } finally {
                        framework.searchClose(instance);
                    }
                }
            }
        }
    }
}

// vim: expandtab tabstop=4 shiftwidth=4

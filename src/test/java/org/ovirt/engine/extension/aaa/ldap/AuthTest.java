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
import java.io.File;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

public class AuthTest {

    public static void main(String... args) throws Exception {

        String file = args[0];

        System.out.println("PROFILE: " + file);

        try (
            Framework framework = new Framework(
                "AuthTest",
                new MapProperties(
                    Util.loadProperties(
                        Arrays.asList(new File("profiles")),
                        new File(file)
                    )
                )
            );
            Reader reader = new InputStreamReader(System.in, StandardCharsets.UTF_8);
            BufferedReader breader = new BufferedReader(reader);
        ) {
            framework.getGlobals().put("authn_enable", "1");
            framework.init();
            framework.open();

            for (int i=0;i<10;i++) {
                System.out.println("User:");
                System.out.flush();
                String user = breader.readLine();
                System.out.println("Password:");
                System.out.flush();
                String password = breader.readLine();

                Map<String, Object> vars = framework.createSequenceVars();
                vars.put(ExtensionUtil.VARS_USER, user);
                vars.put(ExtensionUtil.VARS_PASSWORD, password);
                framework.runSequence("authn", vars);
                System.out.println("CCCCCCCCCCC " + vars);
            }
        }
    }
}

// vim: expandtab tabstop=4 shiftwidth=4

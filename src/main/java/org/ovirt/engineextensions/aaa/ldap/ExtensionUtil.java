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
import java.util.*;

import org.ovirt.engine.api.extensions.*;

public class ExtensionUtil {

    public static final String PRINCIPAL_RECORD_PREFIX = "PrincipalRecord_";
    public static final String GROUP_RECORD_PREFIX = "GroupRecord_";

    public static final String VARS_AUTHN_ENABLE = "authn_enable";
    public static final String VARS_AUTHZ_ENABLE = "authz_enable";
    public static final String VARS_DN = "dn";
    public static final String VARS_DN_TYPE = "dnType";
    public static final String VARS_FILTER = "filter";
    public static final String VARS_MAX_FILTER_SIZE = "maxFilterSize";
    public static final String VARS_NAMESPACE = "namespace";
    public static final String VARS_AVAILABLE_NAMESPACE = "availableNamespace";
    public static final String VARS_PASSWORD = "password";
    public static final String VARS_PASSWORD_NEW = "passwordNew";
    public static final String VARS_QUERY = "query";
    public static final String VARS_CAPABILITY_RECUSRIVE_GROUP_RESOLUTION = "capability_resucrsiveGroupResolution";
    public static final String VARS_CAPABILITY_CREDENTIALS_CHANGE = "capability_credentialsChange";
    public static final String VARS_USER = "user";

    public static final ExtMap EXTENSION_INFO = new ExtMap().mput(
        Base.ContextKeys.AUTHOR,
        "The oVirt Project"
    ).mput(
        Base.ContextKeys.LICENSE,
        "ASL 2.0"
    ).mput(
        Base.ContextKeys.HOME_URL,
        "http://www.ovirt.org"
    ).mput(
        Base.ContextKeys.VERSION,
        Config.PACKAGE_VERSION
    ).mput(
        Base.ContextKeys.EXTENSION_NOTES,
        String.format(
            "Display name: %s",
            Config.PACKAGE_DISPLAY_NAME
        )
    ).mput(
        Base.ContextKeys.BUILD_INTERFACE_VERSION,
        Base.INTERFACE_VERSION_CURRENT
    );

    private static File getRelativeFile(String baseDir, String fileName) {
        File f = new File(fileName);
        if (!f.isAbsolute()) {
            f = new File(baseDir, fileName);
        }
        return f;
    }

    public static Framework frameworkCreate(ExtMap context, String extensionType) throws Exception {

        /*
         * TODO: remove reflection when ovirt-engine-3.5.1 out.
         */
        String baseDir = "/";
        try {
            baseDir = new File(context.<String>get((ExtKey)Base.ContextKeys.class.getField("CONFIGURATION_FILE").get(null)/*Base.ContextKeys.CONFIGURATION_FILE*/, "/dummy")).getParent();
        } catch(NoSuchFieldException e) {
            // Ignore
        }

        Properties configuration = context.<Properties>get(Base.ContextKeys.CONFIGURATION);

        List<File> searchdir = new ArrayList<>();
        searchdir.add(new File(Config.PROFILES_DIR));
        for (String prefix : Util.stringPropertyNames(configuration, "config.profile.searchdir")) {
            searchdir.add(getRelativeFile(baseDir, configuration.getProperty(prefix)));
        }

        List<File> includes = new ArrayList<>();
        for (String prefix : Util.stringPropertyNames(configuration, "config.profile.file")) {
            includes.add(getRelativeFile(baseDir, configuration.getProperty(prefix)));
        }

        Framework framework = new Framework(
            context.<String>get(Base.ContextKeys.INSTANCE_NAME),
            new MapProperties(
                Util.loadProperties(
                    searchdir,
                    includes.toArray(new File[0])
                )
            )
        );

        for (String key : Util.stringPropertyNames(configuration, "config.globals")) {
            framework.getGlobals().put(
                key.substring(key.lastIndexOf(".")+1),
                configuration.getProperty(key)
            );
        }

        framework.getGlobals().put(extensionType, "1");

        framework.init();

        return framework;
    }

}

// vim: expandtab tabstop=4 shiftwidth=4

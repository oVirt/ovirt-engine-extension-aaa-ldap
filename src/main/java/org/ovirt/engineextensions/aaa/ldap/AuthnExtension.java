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

import com.unboundid.ldap.sdk.*;
import org.slf4j.*;

import org.ovirt.engine.api.extensions.*;
import org.ovirt.engine.api.extensions.aaa.*;

public class AuthnExtension implements Extension {

    private static final String PREFIX_CONFIG_AUTHN = "config.authn.";

    private static final Logger log = LoggerFactory.getLogger(AuthnExtension.class);

    private Framework framework;
    private volatile boolean frameworkInitialized = false;

    private String sequenceAuthn;
    private String sequenceCredentialsChange;
    private String credentialsChangeMessage;
    private String credentialsChangeUrl;

    private void ensureFramework(ExtMap input) throws Exception {
        if (!frameworkInitialized) {
            synchronized(this) {
                if (!frameworkInitialized) {
                    framework.getGlobals().put(ExtensionUtil.VARS_AUTHN_ENABLE, "1");
                    framework.open();
                    frameworkInitialized = true;
                }
            }
        }
    }

    @Override
    public void invoke(ExtMap input, ExtMap output) {
        try {
            if (input.get(Base.InvokeKeys.COMMAND).equals(Base.InvokeCommands.LOAD)) {
                doLoad(input, output);
            } else if (input.get(Base.InvokeKeys.COMMAND).equals(Base.InvokeCommands.INITIALIZE)) {
                doInit(input, output);
            } else if (input.get(Base.InvokeKeys.COMMAND).equals(Base.InvokeCommands.TERMINATE)) {
                doTerminate(input, output);
            } else if (input.get(Base.InvokeKeys.COMMAND).equals(Authn.InvokeCommands.AUTHENTICATE_CREDENTIALS)) {
                doAuthenticateCredentials(input, output);
            } else if (input.get(Base.InvokeKeys.COMMAND).equals(Authn.InvokeCommands.CREDENTIALS_CHANGE)) {
                doCredentialsChange(input, output);
            } else {
                output.put(Base.InvokeKeys.RESULT, Base.InvokeResult.UNSUPPORTED);
            }
            output.putIfAbsent(Base.InvokeKeys.RESULT, Base.InvokeResult.SUCCESS);
        } catch (Exception e) {
            log.debug("Exception", e);
            output.mput(
                Base.InvokeKeys.RESULT, Base.InvokeResult.FAILED
            ).mput(
                Base.InvokeKeys.MESSAGE, e.getMessage()
            );
        }
    }

    private void doLoad(ExtMap input, ExtMap output) throws Exception {
        ExtMap context = input.<ExtMap> get(
            Base.InvokeKeys.CONTEXT
        );
        Properties configuration = context.<Properties> get(
            Base.ContextKeys.CONFIGURATION
        );
        context.mput(
            ExtensionUtil.EXTENSION_INFO
        ).mput(
            Base.ContextKeys.EXTENSION_NAME,
            "aaa.ldap.authn"
        ).mput(
            Authn.ContextKeys.CAPABILITIES,
            (
                Authn.Capabilities.AUTHENTICATE_CREDENTIALS |
                Authn.Capabilities.AUTHENTICATE_PASSWORD |
                0
            )
        );

        sequenceAuthn = configuration.getProperty(PREFIX_CONFIG_AUTHN + "sequence.authn.name", "authn");
        sequenceCredentialsChange = configuration.getProperty(PREFIX_CONFIG_AUTHN + "sequence.credentials-change.name", "credentials-change");
        credentialsChangeMessage = configuration.getProperty(PREFIX_CONFIG_AUTHN + "credentials-change.message");
        credentialsChangeUrl = configuration.getProperty(PREFIX_CONFIG_AUTHN + "credentials-change.url");

        framework = ExtensionUtil.frameworkCreate(context, "authn_enable");

        if (Boolean.valueOf(framework.getGlobals().get(ExtensionUtil.VARS_CAPABILITY_CREDENTIALS_CHANGE).toString())) {
            output.put(
                Authn.ContextKeys.CAPABILITIES,
                (
                    output.<Long>get(Authn.ContextKeys.CAPABILITIES) |
                    Authn.Capabilities.CREDENTIALS_CHANGE
                )
            );
        }
    }

    private void doInit(ExtMap input, ExtMap output) throws Exception {
        try {
            ensureFramework(input);
        } catch(Exception e) {
            log.error("Cannot initialize LDAP framework, deferring initialization. Error: {}", e.getMessage());
            log.debug("Exception", e);
        }
    }

    private void doTerminate(ExtMap input, ExtMap output) throws IOException {
        framework.close();
        framework = null;
    }

    private void doAuthenticateCredentials(ExtMap input, ExtMap output) throws Exception {

        log.debug("doAuthenticateCredentials Entry user='{}'", input.<String> get(Authn.InvokeKeys.USER));

        ensureFramework(input);

        Map<String, Object> vars = framework.createSequenceVars();
        vars.put(ExtensionUtil.VARS_USER, input.<String> get(Authn.InvokeKeys.USER));
        vars.put(ExtensionUtil.VARS_PASSWORD, input.<String> get(Authn.InvokeKeys.CREDENTIALS));
        framework.runSequence(sequenceAuthn, vars);

        int authResult = Authn.AuthResult.GENERAL_ERROR;
        try {
            String m = Util.toString(vars.get(Framework.VARS_AUTH_TRANSLATED_MESSAGE));
            if (m != null) {
                authResult = Authn.AuthResult.class.getField(m).getInt(null);
            }
        } catch(NoSuchFieldException|IllegalAccessException e) {
            // ignore
        }
        if (authResult == Authn.AuthResult.CREDENTIALS_EXPIRED) {
            vars.put(Framework.VARS_MESSAGE, credentialsChangeMessage);
            output.mput(
                Authn.InvokeKeys.CREDENTIALS_CHANGE_URL,
                credentialsChangeUrl
            );
        }

        output.mput(
            Authn.InvokeKeys.RESULT,
            authResult
        ).mput(
            Authn.InvokeKeys.PRINCIPAL,
            vars.get(ExtensionUtil.PRINCIPAL_RECORD_PREFIX + "NAME")
        ).mput(
            Authn.InvokeKeys.USER_MESSAGE,
            vars.get(Framework.VARS_MESSAGE)
        );

        if (authResult == Authn.AuthResult.SUCCESS) {
            output.mput(
                Authn.InvokeKeys.AUTH_RECORD,
                new ExtMap().mput(
                    Authn.AuthRecord.PRINCIPAL,
                    vars.get(ExtensionUtil.PRINCIPAL_RECORD_PREFIX + "NAME")
                )
            );
        }

        log.debug("doAuthenticateCredentials Return {}", output);
    }

    private void doCredentialsChange(ExtMap input, ExtMap output) throws Exception {

        log.debug(
            "doCredentialsChange Entry user='{}', principal='{}'",
            input.<String> get(Authn.InvokeKeys.USER),
            input.<String> get(Authn.InvokeKeys.PRINCIPAL)
        );

        ensureFramework(input);

        Map<String, Object> vars = framework.createSequenceVars();
        if (input.<String> get(Authn.InvokeKeys.PRINCIPAL) != null) {
            vars.put(ExtensionUtil.PRINCIPAL_RECORD_PREFIX + "NAME", input.<String> get(Authn.InvokeKeys.PRINCIPAL));
        } else {
            vars.put(ExtensionUtil.VARS_USER, input.<String> get(Authn.InvokeKeys.USER));
        }
        vars.put(ExtensionUtil.VARS_PASSWORD, input.<String> get(Authn.InvokeKeys.CREDENTIALS));
        vars.put(ExtensionUtil.VARS_PASSWORD_NEW, input.<String> get(Authn.InvokeKeys.CREDENTIALS_NEW));
        framework.runSequence(sequenceCredentialsChange, vars);
        output.put(Authn.InvokeKeys.RESULT, Authn.AuthResult.SUCCESS);

        log.debug("doCredentialsChange Return");
    }
}

// vim: expandtab tabstop=4 shiftwidth=4

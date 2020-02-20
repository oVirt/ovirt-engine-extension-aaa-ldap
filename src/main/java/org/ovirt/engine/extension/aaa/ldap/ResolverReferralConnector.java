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

import java.net.InetAddress;
import java.net.UnknownHostException;
import javax.net.SocketFactory;

import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.DisconnectType;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.ReferralConnector;
import com.unboundid.ldap.sdk.ResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ResolverReferralConnector implements ReferralConnector {

    private static final Logger log = LoggerFactory.getLogger(ResolverReferralConnector.class);

    final Resolver resolver;

    public ResolverReferralConnector(Resolver resolver) {
        this.resolver = resolver;
    }

    public LDAPConnection getReferralConnection(LDAPURL referralURL, LDAPConnection connection)
    throws LDAPException {
        final String host = referralURL.getHost();
        final int port = referralURL.getPort();
        BindRequest bindRequest = connection.getLastBindRequest().getRebindRequest(host, port);
        final ExtendedRequest connStartTLSRequest = connection.getStartTLSRequest();

        /*
         * Avoid double random resolution
         * disable our resolver socket factory.
         */
        SocketFactory sf = connection.getSocketFactory();
        if (sf instanceof ResolverSocketFactory) {
            sf = null;
        }

        final LDAPConnection conn = new LDAPConnection(
            sf,
            connection.getConnectionOptions()
        );

        LDAPException lastConnectException = null;
        try {
            for (InetAddress address : resolver.resolveAll(host)) {
                try {
                    conn.connect(
                        host,
                        address,
                        port,
                        connection.getConnectionOptions().getConnectTimeoutMillis()
                    );
                    break;
                } catch (final LDAPException e) {
                    lastConnectException = e;
                    log.debug("Cannot connect referral '{}'", address);
                    log.debug("Exception", e);
                }
            }
        } catch (final UnknownHostException e) {
            throw new LDAPException(ResultCode.CONNECT_ERROR, e);
        }
        if (!conn.isConnected()) {
            if (lastConnectException != null) {
                throw lastConnectException;
            } else {
                throw new LDAPException(ResultCode.CONNECT_ERROR, "Cannot connect referral " + host);
            }
        }

        if (connStartTLSRequest != null) {
            try {
                final ExtendedResult startTLSResult = conn.processExtendedOperation(connStartTLSRequest);
                if (startTLSResult.getResultCode() != ResultCode.SUCCESS) {
                    throw new LDAPException(startTLSResult);
                }
            } catch (final LDAPException le) {
                conn.setDisconnectInfo(DisconnectType.SECURITY_PROBLEM, null, le);
                conn.close();
                throw le;
            }
        }
        if (bindRequest != null) {
            try {
                conn.bind(bindRequest);
            } catch (final LDAPException le) {
                conn.setDisconnectInfo(DisconnectType.BIND_FAILED, null, le);
                conn.close();
                throw le;
            }
        }
        return conn;
    }
}

// vim: expandtab tabstop=4 shiftwidth=4

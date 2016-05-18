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
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import javax.net.SocketFactory;

public class ResolverSocketFactory extends SocketFactory {

    private final SocketFactory socketFactory;
    private final Resolver resolver;
    private boolean enableAddressOnly = false;

    private boolean checkAddress(InetAddress address) {
        boolean ret = false;
        ret = address.toString().charAt(0) == '/' || Resolver.isAddress(address.getHostName());
        if (ret && !enableAddressOnly) {
            throw new IllegalArgumentException();
        }
        return ret;
    }

    public ResolverSocketFactory(Resolver resolver, SocketFactory socketFactory) {
        if (socketFactory == null) {
            socketFactory = SocketFactory.getDefault();
        }
        this.socketFactory = socketFactory;
        this.resolver = resolver;
    }

    public ResolverSocketFactory(Resolver resolver) {
        this(resolver, null);
    }

    public void setEnableAddressOnly(boolean enableAddressOnly) {
        this.enableAddressOnly = enableAddressOnly;
    }

    public Socket createSocket()
    throws IOException {
        throw new UnsupportedOperationException();
    }

    public Socket createSocket(String host, int port)
    throws IOException, UnknownHostException {
        return socketFactory.createSocket(resolver.resolve(host), port);
    }

    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
    throws IOException, UnknownHostException {
        return socketFactory.createSocket(resolver.resolve(host), port, localHost, localPort);
    }

    public Socket createSocket(InetAddress host, int port)
    throws IOException {
        if (checkAddress(host)) {
            return socketFactory.createSocket(host, port);
        } else {
            return createSocket(host.getHostName(), port);
        }
    }

    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
    throws IOException {
        if (checkAddress(address)) {
            return socketFactory.createSocket(address, port, localAddress, localPort);
        } else {
            return createSocket(address.getHostName(), port, localAddress, localPort);
        }
    }
}

// vim: expandtab tabstop=4 shiftwidth=4

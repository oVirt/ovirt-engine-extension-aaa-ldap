package org.ovirt.engine.extension.aaa.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ResolverTest {
    public static enum AddressType {
        IPv4,
        IPv6
    };

    private Resolver resolver = new Resolver(new Properties());

    @ParameterizedTest
    @MethodSource("sourceForTestIsIPv4Available")
    void testIsIPv4Available(List<InetAddress> addrs, boolean result) {
        assertEquals(result,
                resolver.isIPv4Available(addrs),
                String.format("Addresses: '%s'", addrs.toString()));
    }

    public static Stream<Arguments> sourceForTestIsIPv4Available() throws UnknownHostException {
        return Stream.of(
                Arguments.of(
                        Arrays.asList(
                                InetAddress.getByName("192.168.1.1")),
                        true),
                Arguments.of(
                        Arrays.asList(
                                InetAddress.getByName("127.0.0.1"),
                                InetAddress.getByName("fe80::226:2dff:fefa:cd1f"),
                                InetAddress.getByName("192.168.1.1")),
                        true),
                Arguments.of(
                        Arrays.asList(
                                InetAddress.getByName("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
                                InetAddress.getByName("fe80::226:2dff:fefa:cd1f"),
                                InetAddress.getByName("192.168.1.1")),
                        true),
                Arguments.of(
                        Arrays.asList(
                                InetAddress.getByName("2001:0db8:85a3:0000:0000:8a2e:0370:7334")),
                        false),
                Arguments.of(
                        Arrays.asList(
                                InetAddress.getByName("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
                                InetAddress.getByName("fe80::226:2dff:fefa:cd1f")),
                        false),
                Arguments.of(
                        Collections.emptyList(),
                        false)
                );
    }

    @ParameterizedTest
    @MethodSource("sourceForTestIsIPv6Available")
    void testIsIPv6Available(List<InetAddress> addrs, boolean result) {
        assertEquals(result,
                resolver.isIPv6Available(addrs),
                String.format("Addresses: '%s'", addrs.toString()));
    }

    public static Stream<Arguments> sourceForTestIsIPv6Available() throws UnknownHostException {
        return Stream.of(
                Arguments.of(
                        Arrays.asList(
                                InetAddress.getByName("fe80::226:2dff:fefa:cd1f")),
                        true),
                Arguments.of(
                        Arrays.asList(
                                InetAddress.getByName("127.0.0.1"),
                                InetAddress.getByName("fe80::226:2dff:fefa:cd1f"),
                                InetAddress.getByName("192.168.1.1")),
                        true),
                Arguments.of(
                        Arrays.asList(
                                InetAddress.getByName("127.0.0.1"),
                                InetAddress.getByName("192.168.1.1"),
                                InetAddress.getByName("fe80::226:2dff:fefa:cd1f")),
                        true),
                Arguments.of(
                        Arrays.asList(
                                InetAddress.getByName("127.0.0.1")),
                        false),
                Arguments.of(
                        Arrays.asList(
                                InetAddress.getByName("127.0.0.1"),
                                InetAddress.getByName("192.168.1.1")),
                        false),
                Arguments.of(
                        Collections.emptyList(),
                        false));
    }
}

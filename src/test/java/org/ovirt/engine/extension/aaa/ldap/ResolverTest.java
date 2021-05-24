package org.ovirt.engine.extension.aaa.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;
import java.util.stream.Stream;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class ResolverTest {

    @ParameterizedTest
    @MethodSource("sourceForTestIsIPv4Available")
    void testIsIPv4Available(InetAddress addr, boolean expected) {
        Resolver resolver = spy(new Resolver(new Properties()));
        doReturn(addr).when(resolver).fetchDefaultGateway(anyString());
        assertEquals(expected,
                resolver.isIPv4Available(),
                String.format("Address: '%s'", addr));
    }

    public static Stream<Arguments> sourceForTestIsIPv4Available() throws UnknownHostException {
        return Stream.of(
                Arguments.of(
                        InetAddress.getByName("192.168.1.1"),
                        true),
                Arguments.of(
                        null,
                        false)
                );
    }

    @ParameterizedTest
    @MethodSource("sourceForTestIsIPv6Available")
    void testIsIPv6Available(InetAddress addr, boolean expected) {
        Resolver resolver = spy(new Resolver(new Properties()));
        doReturn(addr).when(resolver).fetchDefaultGateway(anyString());
        assertEquals(expected,
                resolver.isIPv6Available(),
                String.format("Address: '%s'", addr));
    }

    public static Stream<Arguments> sourceForTestIsIPv6Available() throws UnknownHostException {
        return Stream.of(
                Arguments.of(
                        InetAddress.getByName("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
                        true),
                Arguments.of(
                        null,
                        false)
                );
    }

    @ParameterizedTest
    @MethodSource("sourceForTestFetchDefaultGateway")
    void testFetchDefaultGateway(String output, InetAddress expected) {
        Resolver resolver = spy(new Resolver(new Properties()));
        doReturn(output).when(resolver).fetchCommandOutput(any());
        assertEquals(expected,
                resolver.fetchDefaultGateway(null),
                String.format("Output: '%s'", output));
    }

    public static Stream<Arguments> sourceForTestFetchDefaultGateway() throws UnknownHostException {
        return Stream.of(
                Arguments.of(
                        "default via 192.168.1.1 dev eth0 proto dhcp metric 100",
                        InetAddress.getByName("192.168.1.1")),
                Arguments.of(
                        "default via 2001:0db8:85a3:0000:0000:8a2e:0370:7334 dev eth0 proto ra metric 1024 expires"
                                + " 1631sec hoplimit 64 pref medium",
                        InetAddress.getByName("2001:0db8:85a3:0000:0000:8a2e:0370:7334")),
                Arguments.of(
                        "",
                        null),
                Arguments.of(
                        "\n",
                        null),
                Arguments.of(
                        "incorrect",
                        null),
                Arguments.of(
                        "incorrect result",
                        null));

    }
}

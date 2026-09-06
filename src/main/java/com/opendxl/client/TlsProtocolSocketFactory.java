/*---------------------------------------------------------------------------*
 * Copyright (c) 2018 McAfee, LLC - All Rights Reserved.                     *
 *---------------------------------------------------------------------------*/

package com.opendxl.client;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * An {@link SSLSocketFactory} that constrains every socket it creates to a TLS protocol range.
 * <P>
 * The client used to obtain its context with {@code SSLContext.getInstance("TLSv1.2")}, which
 * pins the connection to TLS 1.2 and makes TLS 1.3 unreachable even when both the JDK and the
 * broker support it. The context is now created for "TLS" - the highest version the runtime
 * offers - and the floor is applied here instead, so the client negotiates TLS 1.3 with a broker
 * that offers it and still refuses anything below the configured minimum.
 * </P>
 * <P>
 * This mirrors the Python client's {@code TlsMinVersion} setting (config key
 * {@code TlsMinVersion}, default 1.2). Protocol names are the JSSE ones: {@code TLSv1.2},
 * {@code TLSv1.3}.
 * </P>
 */
class TlsProtocolSocketFactory extends SSLSocketFactory {

    /**
     * Protocols in ascending order. Anything below TLS 1.2 is deliberately absent: no DXL broker
     * requires it and every current JDK disables it.
     */
    private static final String[] PROTOCOL_ORDER = {"TLSv1.2", "TLSv1.3"};

    /**
     * The factory doing the actual work
     */
    private final SSLSocketFactory delegate;

    /**
     * The protocols a socket from this factory may negotiate
     */
    private final String[] enabledProtocols;

    /**
     * Whether the broker's host name is verified against the certificate
     */
    private final boolean verifyHostname;

    /**
     * Constructs the factory
     *
     * @param delegate The underlying socket factory
     * @param minimumVersion The lowest acceptable TLS version, as a JSSE protocol name
     * @param verifyHostname Whether to verify the broker host name against the certificate
     */
    TlsProtocolSocketFactory(final SSLSocketFactory delegate, final String minimumVersion,
                             final boolean verifyHostname) {
        this.delegate = delegate;
        this.verifyHostname = verifyHostname;
        this.enabledProtocols = protocolsAtOrAbove(minimumVersion, delegate);
    }

    /**
     * Returns the supported protocols at or above the given minimum.
     * <P>
     * A JDK that does not know TLS 1.3 (Java 8 before 8u261) simply contributes fewer entries;
     * the result is never empty because TLS 1.2 is supported everywhere the client runs.
     * </P>
     *
     * @param minimumVersion The lowest acceptable protocol name
     * @param delegate The factory whose supported protocols are consulted
     * @return The protocol names to enable
     */
    private static String[] protocolsAtOrAbove(final String minimumVersion,
                                               final SSLSocketFactory delegate) {
        final Set<String> supported =
            new LinkedHashSet<>(Arrays.asList(supportedProtocols(delegate)));

        int start = 0;
        for (int i = 0; i < PROTOCOL_ORDER.length; i++) {
            if (PROTOCOL_ORDER[i].equals(minimumVersion)) {
                start = i;
                break;
            }
        }

        final List<String> enabled = new ArrayList<>();
        for (int i = start; i < PROTOCOL_ORDER.length; i++) {
            if (supported.isEmpty() || supported.contains(PROTOCOL_ORDER[i])) {
                enabled.add(PROTOCOL_ORDER[i]);
            }
        }
        if (enabled.isEmpty()) {
            enabled.add("TLSv1.2");
        }
        return enabled.toArray(new String[0]);
    }

    /**
     * Returns the protocols the delegate can enable, or an empty array if that cannot be
     * determined without creating a socket.
     *
     * @param delegate The socket factory
     * @return The supported protocol names
     */
    private static String[] supportedProtocols(final SSLSocketFactory delegate) {
        try (SSLSocket probe = (SSLSocket) delegate.createSocket()) {
            return probe.getSupportedProtocols();
        } catch (IOException ex) {
            return new String[0];
        }
    }

    /**
     * Applies the protocol range, and host name verification when it is switched on, to a socket
     *
     * @param socket The socket to configure
     * @return The same socket
     */
    private Socket configure(final Socket socket) {
        if (socket instanceof SSLSocket) {
            final SSLSocket sslSocket = (SSLSocket) socket;
            sslSocket.setEnabledProtocols(this.enabledProtocols);
            if (this.verifyHostname) {
                final javax.net.ssl.SSLParameters params = sslSocket.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS");
                sslSocket.setSSLParameters(params);
            }
        }
        return socket;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return this.delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return this.delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        return configure(this.delegate.createSocket());
    }

    @Override
    public Socket createSocket(final Socket socket, final String host, final int port,
                               final boolean autoClose) throws IOException {
        return configure(this.delegate.createSocket(socket, host, port, autoClose));
    }

    @Override
    public Socket createSocket(final String host, final int port)
        throws IOException, UnknownHostException {
        return configure(this.delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(final String host, final int port, final InetAddress localHost,
                               final int localPort) throws IOException, UnknownHostException {
        return configure(this.delegate.createSocket(host, port, localHost, localPort));
    }

    @Override
    public Socket createSocket(final InetAddress host, final int port) throws IOException {
        return configure(this.delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(final InetAddress address, final int port,
                               final InetAddress localAddress, final int localPort)
        throws IOException {
        return configure(this.delegate.createSocket(address, port, localAddress, localPort));
    }
}

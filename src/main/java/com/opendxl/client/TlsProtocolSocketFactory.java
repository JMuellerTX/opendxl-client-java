/*---------------------------------------------------------------------------*
 * Copyright (c) 2018 McAfee, LLC - All Rights Reserved.                     *
 *---------------------------------------------------------------------------*/

package com.opendxl.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
 * An {@link SSLSocketFactory} that constrains every socket it creates to a TLS protocol range and,
 * optionally, to a set of cipher suites.
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
 * <P>
 * The cipher suites come from the {@code TlsCiphers} setting and are JSSE cipher suite names, not
 * an OpenSSL cipher list (see {@link DxlClientConfig#getTlsCiphers()}). Restricting them to TLS 1.2
 * suites also keeps TLS 1.3 from being negotiated, because a TLS 1.3 handshake needs one of the
 * {@code TLS_AES_*} / {@code TLS_CHACHA20_*} suites.
 * </P>
 */
class TlsProtocolSocketFactory extends SSLSocketFactory {

    /**
     * The logger
     */
    private static final Logger logger = LogManager.getLogger(TlsProtocolSocketFactory.class);

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
     * The cipher suites a socket from this factory may negotiate, or {@code null} for the
     * cipher suites the JDK enables by default
     */
    private final String[] enabledCipherSuites;

    /**
     * Constructs the factory
     *
     * @param delegate The underlying socket factory
     * @param minimumVersion The lowest acceptable TLS version, as a JSSE protocol name
     * @param verifyHostname Whether to verify the broker host name against the certificate
     * @param cipherSuites The JSSE cipher suite names to enable, or {@code null} for the defaults
     * @throws IllegalArgumentException If none of the requested cipher suites is supported by the
     *                                  JDK, because connecting would then silently fall back to the
     *                                  default suites
     */
    TlsProtocolSocketFactory(final SSLSocketFactory delegate, final String minimumVersion,
                             final boolean verifyHostname, final String[] cipherSuites) {
        this.delegate = delegate;
        this.verifyHostname = verifyHostname;
        this.enabledProtocols = protocolsAtOrAbove(minimumVersion, delegate);
        this.enabledCipherSuites = supportedCipherSuites(cipherSuites, delegate);
    }

    /**
     * Returns the requested cipher suites that the JDK actually supports.
     * <P>
     * Suites the JDK does not know are dropped (a configuration shared with a newer or older
     * runtime stays usable); if nothing is left, the connection is refused rather than made with
     * the default suites, which is what {@code ssl.SSLContext.set_ciphers} does in the Python
     * client.
     * </P>
     *
     * @param cipherSuites The requested suites, or {@code null}
     * @param delegate The factory whose supported suites are consulted
     * @return The suites to enable, or {@code null} for the JDK defaults
     */
    private static String[] supportedCipherSuites(final String[] cipherSuites,
                                                  final SSLSocketFactory delegate) {
        if (cipherSuites == null || cipherSuites.length == 0) {
            return null;
        }
        final Set<String> supported =
            new LinkedHashSet<>(Arrays.asList(delegate.getSupportedCipherSuites()));
        final List<String> enabled = new ArrayList<>();
        final List<String> unsupported = new ArrayList<>();
        for (final String suite : cipherSuites) {
            if (supported.contains(suite)) {
                enabled.add(suite);
            } else {
                unsupported.add(suite);
            }
        }
        if (enabled.isEmpty()) {
            throw new IllegalArgumentException("None of the configured TLS cipher suites is "
                + "supported by this JDK: " + String.join(", ", unsupported));
        }
        if (!unsupported.isEmpty()) {
            logger.warn("Ignoring TLS cipher suites that this JDK does not support: "
                + String.join(", ", unsupported));
        }
        return enabled.toArray(new String[0]);
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
            if (this.enabledCipherSuites != null) {
                sslSocket.setEnabledCipherSuites(this.enabledCipherSuites);
            }
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

/*---------------------------------------------------------------------------*
 * Copyright (c) 2018 McAfee, LLC - All Rights Reserved.                     *
 *---------------------------------------------------------------------------*/

package com.opendxl.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * Keeps the TLS cipher suites required by OpenDXL brokers available on current Java runtimes.
 * <P>
 * OpenDXL brokers (and Trellix DXL brokers prior to 6.1.1) only offer TLS 1.2 cipher suites that use RSA key
 * exchange (for example {@code TLS_RSA_WITH_AES_128_CBC_SHA256}). Recent JDK updates (JDK-8245545) list these
 * suites as {@code TLS_RSA_*} in the {@code jdk.tls.disabledAlgorithms} security property, which makes every
 * connection attempt to such a broker fail with a TLS {@code handshake_failure}. JSSE reads the property once
 * when it is initialized and applies it on top of the cipher suites enabled on a socket, so the client cannot
 * re-enable the suites for its own connections only. The only way to keep the client working is to remove the
 * {@code TLS_RSA_*} entry from the security property before JSSE is used for the first time in the JVM.
 * </P>
 * <P>
 * Set the system property {@code dxlclient.tls.enableRsaKeyExchange} to {@code false} to keep the JDK default
 * (for example when all brokers are known to support ECDHE cipher suites). If TLS was already initialized by the
 * application before the first {@link DxlClient} was created, the change has no effect; in that case start the
 * JVM with {@code -Djava.security.properties=<file>} where the file contains an adjusted
 * {@code jdk.tls.disabledAlgorithms} value.
 * </P>
 */
final class TlsCompatibility {

    /**
     * System property used to opt out of re-enabling the cipher suites with RSA key exchange
     */
    static final String ENABLE_RSA_KEY_EXCHANGE_PROPERTY = "dxlclient.tls.enableRsaKeyExchange";

    /**
     * The security property listing the algorithms that are disabled for TLS
     */
    static final String DISABLED_ALGORITHMS_PROPERTY = "jdk.tls.disabledAlgorithms";

    /**
     * The entry of the security property that disables all cipher suites with RSA key exchange
     */
    private static final String RSA_KEY_EXCHANGE_ENTRY = "TLS_RSA_*";

    /**
     * Name prefix of the cipher suites with RSA key exchange
     */
    private static final String RSA_KEY_EXCHANGE_PREFIX = "TLS_RSA_WITH_";

    /**
     * The logger
     */
    private static Logger logger = LogManager.getLogger(TlsCompatibility.class);

    /**
     * Whether {@link #enableRsaKeyExchange()} already ran in this JVM
     */
    private static boolean applied = false;

    /**
     * Private constructor
     */
    private TlsCompatibility() {
        super();
    }

    /**
     * Removes the {@code TLS_RSA_*} entry from the {@code jdk.tls.disabledAlgorithms} security property so that the
     * cipher suites offered by OpenDXL brokers can be negotiated. This is done at most once per JVM and can be
     * disabled by setting the {@code dxlclient.tls.enableRsaKeyExchange} system property to {@code false}.
     */
    static synchronized void enableRsaKeyExchange() {
        if (applied) {
            return;
        }
        applied = true;

        if (!Boolean.parseBoolean(System.getProperty(ENABLE_RSA_KEY_EXCHANGE_PROPERTY, "true"))) {
            logger.debug("Not re-enabling TLS cipher suites with RSA key exchange ("
                + ENABLE_RSA_KEY_EXCHANGE_PROPERTY + "=false)");
            return;
        }

        final String disabledAlgorithms = Security.getProperty(DISABLED_ALGORITHMS_PROPERTY);
        if (disabledAlgorithms == null || disabledAlgorithms.trim().isEmpty()) {
            return;
        }

        final List<String> entries = new ArrayList<>();
        boolean found = false;
        for (final String entry : disabledAlgorithms.split(",")) {
            final String trimmed = entry.trim();
            if (RSA_KEY_EXCHANGE_ENTRY.equalsIgnoreCase(trimmed)) {
                found = true;
            } else if (!trimmed.isEmpty()) {
                entries.add(trimmed);
            }
        }
        if (!found) {
            return;
        }

        Security.setProperty(DISABLED_ALGORITHMS_PROPERTY, String.join(", ", entries));
        if (isRsaKeyExchangeEnabled()) {
            logger.warn("Removed '" + RSA_KEY_EXCHANGE_ENTRY + "' from the '" + DISABLED_ALGORITHMS_PROPERTY
                + "' security property because OpenDXL brokers only offer TLS cipher suites with RSA key exchange. "
                + "Set -D" + ENABLE_RSA_KEY_EXCHANGE_PROPERTY + "=false to keep the JDK default.");
        } else {
            logger.warn("Unable to re-enable TLS cipher suites with RSA key exchange because TLS was already "
                + "initialized in this JVM. Connections to OpenDXL brokers will fail with a TLS handshake failure "
                + "unless the JVM is started with -Djava.security.properties=<file> that removes '"
                + RSA_KEY_EXCHANGE_ENTRY + "' from '" + DISABLED_ALGORITHMS_PROPERTY + "'.");
        }
    }

    /**
     * Returns whether the default SSL context enables at least one cipher suite with RSA key exchange
     *
     * @return {@code true} if a cipher suite with RSA key exchange is enabled by default
     */
    static boolean isRsaKeyExchangeEnabled() {
        try {
            for (final String suite : SSLContext.getDefault().getDefaultSSLParameters().getCipherSuites()) {
                if (suite.startsWith(RSA_KEY_EXCHANGE_PREFIX)) {
                    return true;
                }
            }
        } catch (final NoSuchAlgorithmException ex) {
            logger.debug("Unable to determine the default cipher suites", ex);
        }
        return false;
    }

    /**
     * Returns whether the specified exception (or one of its causes) is a TLS handshake failure
     *
     * @param throwable The exception to check
     * @return {@code true} if the exception was caused by a TLS handshake failure
     */
    static boolean isHandshakeFailure(final Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (current instanceof SSLHandshakeException) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }
}

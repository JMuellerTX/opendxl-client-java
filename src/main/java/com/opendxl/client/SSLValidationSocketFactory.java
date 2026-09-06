/*---------------------------------------------------------------------------*
 * Copyright (c) 2018 McAfee, LLC - All Rights Reserved.                     *
 *---------------------------------------------------------------------------*/

package com.opendxl.client;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.security.SecureRandom;

/**
 * Helper class for SSL connections
 * <P>
 * Performs validation of presented server certificates and client authentication
 * </P>
 */
class SSLValidationSocketFactory {

    /**
     * Secure random
     */
    private static SecureRandom secureRandom = new SecureRandom();

    /**
     * Private constructor
     */
    private SSLValidationSocketFactory() {
        super();
    }

    /**
     * Returns a new instance of an {@link javax.net.ssl.SSLSocketFactory} that validates presented certificates.
     * We always return a new instance to avoid caching which wouldn't accurately represent a separate client
     * connecting to a broker.
     *
     * @param keyStore The keystore
     * @param keyStorePassword The keystore password
     * @param tlsMinVersion The lowest TLS version to negotiate, as a JSSE protocol name
     * @param verifyHostname Whether to verify the broker host name against the certificate
     * @return A new instance of an {@link javax.net.ssl.SSLSocketFactory} that validates presented certificates.
     * @throws Exception If an SSL exception occurs
     */
    public static SSLSocketFactory newInstance(final KeyStore keyStore, final String keyStorePassword,
                                               final String tlsMinVersion, final boolean verifyHostname)
        throws Exception {

        // OpenDXL brokers only offer cipher suites with RSA key exchange, which current JDKs disable by default
        TlsCompatibility.enableRsaKeyExchange();

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyStorePassword.toCharArray());

        // "TLS" yields the highest version the runtime supports, so a broker offering TLS 1.3
        // can be used. The floor is applied per socket by TlsProtocolSocketFactory; pinning the
        // context to "TLSv1.2" here is what previously made TLS 1.3 unreachable.
        final SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), secureRandom);
        return new TlsProtocolSocketFactory(sslContext.getSocketFactory(), tlsMinVersion, verifyHostname);
    }
}

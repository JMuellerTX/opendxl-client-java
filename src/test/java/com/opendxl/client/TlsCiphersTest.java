/*---------------------------------------------------------------------------*
 * Copyright (c) 2018 McAfee, LLC - All Rights Reserved.                     *
 *---------------------------------------------------------------------------*/

package com.opendxl.client;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for the {@code TlsCiphers} setting: JSSE cipher suite names are taken literally, the
 * OpenSSL cipher list syntax of the Python client is rejected (and ignored when it comes from a
 * configuration file), and the suites end up on the sockets the client creates.
 * <P>
 * No broker is required.
 * </P>
 */
public class TlsCiphersTest extends AbstractDxlTest {

    /**
     * A cipher suite every current JDK supports
     */
    private static final String ECDHE_SUITE = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";

    /**
     * Temporary folder for the configuration files
     */
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    /**
     * The default is the set of cipher suites the JDK enables
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testDefaultIsNull() throws Exception {
        assertNull(newConfig().getTlsCiphers());
    }

    /**
     * "default" and an empty value select the cipher suites of the JDK
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testDefaultKeywordSelectsJdkSuites() throws Exception {
        final DxlClientConfig config = newConfig();
        config.setTlsCiphers(ECDHE_SUITE);
        config.setTlsCiphers("default");
        assertNull(config.getTlsCiphers());
        config.setTlsCiphers("  ");
        assertNull(config.getTlsCiphers());
        config.setTlsCiphers(null);
        assertNull(config.getTlsCiphers());
    }

    /**
     * JSSE names are accepted comma separated, with whitespace, in any case
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testJsseNamesAreAccepted() throws Exception {
        final DxlClientConfig config = newConfig();
        config.setTlsCiphers(" tls_ecdhe_rsa_with_aes_128_gcm_sha256 , TLS_RSA_WITH_AES_128_CBC_SHA256 ");
        assertArrayEquals(new String[] {ECDHE_SUITE, "TLS_RSA_WITH_AES_128_CBC_SHA256"},
            config.getTlsCiphers());
    }

    /**
     * The OpenSSL cipher list syntax of the Python client is rejected by the setter
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testOpenSslSyntaxIsRejected() throws Exception {
        final DxlClientConfig config = newConfig();
        try {
            config.setTlsCiphers("ECDHE+AESGCM:ECDHE+AES:DHE+AES:AES128-SHA256:!aNULL:!eNULL");
            fail("An OpenSSL cipher list must not be accepted");
        } catch (final IllegalArgumentException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("JSSE"));
        }
    }

    /**
     * A configuration file written by the Python client carries an OpenSSL cipher list; it must be
     * ignored rather than making the file unreadable
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testOpenSslSyntaxInConfigFileIsIgnored() throws Exception {
        final File configFile = writeConfigFile(
            "ECDHE+AESGCM:ECDHE+AES:DHE+AES:AES128-SHA256:!aNULL:!eNULL");
        assertNull(DxlClientConfig.createDxlConfigFromFile(configFile.getPath()).getTlsCiphers());
    }

    /**
     * The setting survives a write/read round trip
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testConfigFileRoundTrip() throws Exception {
        final File configFile = writeConfigFile(ECDHE_SUITE + ",TLS_RSA_WITH_AES_128_CBC_SHA256");
        final DxlClientConfig config = DxlClientConfig.createDxlConfigFromFile(configFile.getPath());
        assertArrayEquals(new String[] {ECDHE_SUITE, "TLS_RSA_WITH_AES_128_CBC_SHA256"},
            config.getTlsCiphers());

        final File written = new File(folder.getRoot(), "written.config");
        config.write(written.getPath());
        final DxlClientConfig reread = DxlClientConfig.createDxlConfigFromFile(written.getPath());
        assertArrayEquals(config.getTlsCiphers(), reread.getTlsCiphers());

        // "default" must not end up in the file: a Python client reading the same
        // configuration would take TlsCiphers=default as "the ssl module's defaults" and lose
        // the AES128-SHA256 fallback it needs for brokers older than DXL 6.1.1.
        config.setTlsCiphers("default");
        config.write(written.getPath());
        assertFalse(new String(Files.readAllBytes(written.toPath()), StandardCharsets.UTF_8)
            .contains("TlsCiphers"));
        assertNull(DxlClientConfig.createDxlConfigFromFile(written.getPath()).getTlsCiphers());
    }

    /**
     * The configured suites are the ones enabled on the sockets the factory creates
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testSuitesAreAppliedToTheSocket() throws Exception {
        final SSLSocketFactory defaultFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        final TlsProtocolSocketFactory factory =
            new TlsProtocolSocketFactory(defaultFactory, "TLSv1.2", false, new String[] {ECDHE_SUITE});
        try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
            assertArrayEquals(new String[] {ECDHE_SUITE}, socket.getEnabledCipherSuites());
        }
    }

    /**
     * Suites this JDK does not know are dropped as long as one usable suite is left
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testUnsupportedSuitesAreDropped() throws Exception {
        final SSLSocketFactory defaultFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        final TlsProtocolSocketFactory factory = new TlsProtocolSocketFactory(defaultFactory, "TLSv1.2",
            false, new String[] {"TLS_MADE_UP_SUITE", ECDHE_SUITE});
        try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
            assertArrayEquals(new String[] {ECDHE_SUITE}, socket.getEnabledCipherSuites());
        }
    }

    /**
     * Nothing usable left means the connection is refused instead of silently falling back to the
     * default suites
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testNoSupportedSuiteIsAnError() throws Exception {
        final SSLSocketFactory defaultFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try {
            new TlsProtocolSocketFactory(defaultFactory, "TLSv1.2", false,
                new String[] {"TLS_MADE_UP_SUITE"});
            fail("A cipher suite list this JDK cannot use must not be accepted");
        } catch (final IllegalArgumentException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("TLS_MADE_UP_SUITE"));
        }
    }

    /**
     * Creates a configuration object with placeholder certificate files
     *
     * @return The configuration
     * @throws Exception If an error occurs
     */
    private DxlClientConfig newConfig() throws Exception {
        final Broker broker = new Broker("unit-test", 8883, "localhost", "127.0.0.1");
        final List<Broker> brokers = Collections.singletonList(broker);
        return new DxlClientConfig("ca.crt", "client.crt", "client.key", brokers);
    }

    /**
     * Writes a configuration file with the given {@code TlsCiphers} value and the placeholder
     * certificate files it refers to
     *
     * @param tlsCiphers The value of the TlsCiphers setting
     * @return The configuration file
     * @throws Exception If an error occurs
     */
    private File writeConfigFile(final String tlsCiphers) throws Exception {
        for (final String name : Arrays.asList("ca.crt", "client.crt", "client.key")) {
            Files.write(new File(folder.getRoot(), name).toPath(), new byte[0]);
        }
        final File configFile = new File(folder.getRoot(), "dxlclient.config");
        final String contents = "[General]\n"
            + "TlsCiphers=" + tlsCiphers + "\n"
            + "[Certs]\n"
            + "BrokerCertChain=ca.crt\n"
            + "CertFile=client.crt\n"
            + "PrivateKey=client.key\n"
            + "[Brokers]\n"
            + "unit-test=unit-test;8883;localhost;127.0.0.1\n";
        Files.write(configFile.toPath(), contents.getBytes(StandardCharsets.UTF_8));
        return configFile;
    }
}

/*---------------------------------------------------------------------------*
 * Copyright (c) 2018 McAfee, LLC - All Rights Reserved.                     *
 *---------------------------------------------------------------------------*/

package com.opendxl.client.cli;

import org.apache.commons.lang3.StringUtils;
import picocli.CommandLine;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Class containing members used for cli subcommands which communicating with a server require,
 * e.g., hostname and credential information.
 */
class ServerArgs {

    /**
     * User registered at the management service
     */
    @CommandLine.Option(names = {"-u", "--user"}, paramLabel = "USERNAME",
            description = "User registered at the management service")
    private String user;

    /**
     * Password for the management service user
     */
    @CommandLine.Option(names = {"-p", "--password"}, paramLabel = "PASSWORD",
            description = "Password for the management service user")
    private String password;

    /**
     * Port where the management service resides
     */
    @CommandLine.Option(names = {"-t", "--port"}, paramLabel = "PORT",
            description = "Port where the management service resides", defaultValue = "8443")
    private int port;

    /**
     * File with one or more PEM CA certificates used to validate the management server's certificate. Without it
     * the certificate is validated against the JVM's trusted CAs.
     */
    @CommandLine.Option(names = {"-e", "--truststore"}, paramLabel = "TRUSTSTORE_FILE",
            description = "File with one or more PEM CA certificates used to validate the management server's "
                    + "certificate (for a certificate issued by a private CA, e.g. the ePO server CA). Without this "
                    + "option the certificate is validated against the JVM's trusted CAs.")
    private String trustStoreFile;

    /**
     * Whether to skip validation of the management server's certificate entirely
     */
    @CommandLine.Option(names = "--insecure",
            description = "Do not validate the management server's certificate at all (not recommended; use -e with "
                    + "the server's CA instead)")
    private boolean insecure;

    /**
     * Get the user registered at the management service
     *
     * @return The user registered at the management service
     */
    String getUser() {
        return user;
    }

    /**
     * Set the user registered at the management service
     *
     * @param user The user registered at the management service
     */
    void setUser(String user) {
        this.user = user;
    }

    /**
     * Get the password for the management service user
     *
     * @return The password for the management service user
     */
    String getPassword() {
        return password;
    }

    /**
     * Set the password for the management service user
     *
     * @param password The password for the management service user
     */
    void setPassword(String password) {
        this.password = password;
    }

    /**
     * Get the port where the management service resides
     *
     * @return The port where the management service resides
     */
    int getPort() {
        return port;
    }

    /**
     * Set the port where the management service resides
     *
     * @param port The port where the management service resides
     */
    void setPort(int port) {
        this.port = port;
    }

    /**
     * Get the name of file containing one or more CA pems to use in validating the management server
     *
     * @return The name of file containing one or more CA pems to use in validating the management server
     */
    String getTrustStoreFile() {
        return trustStoreFile;
    }

    /**
     * Set the name of file containing one or more CA pems to use in validating the management server
     *
     * @param trustStoreFile The name of file containing one or more CA pems to use in validating the management server
     */
    void setTrustStoreFile(String trustStoreFile) {
        this.trustStoreFile = trustStoreFile;
    }

    /**
     * Whether validation of the management server's certificate was disabled with {@code --insecure}
     *
     * @return {@code true} if validation is disabled
     */
    boolean isInsecure() {
        return insecure;
    }

    /**
     * Set whether validation of the management server's certificate is disabled
     *
     * @param insecure {@code true} to disable validation
     */
    void setInsecure(boolean insecure) {
        this.insecure = insecure;
    }

    /**
     * Read the CA certificates named with {@code -e/--truststore}.
     *
     * @return the PEM content of the truststore file, or {@code null} when the option was not given (the
     * management server's certificate is then validated against the JVM's trusted CAs)
     * @throws IOException if the file does not exist or cannot be read
     * @throws IllegalArgumentException if {@code --insecure} and {@code -e/--truststore} were both given
     */
    String readTrustStorePems() throws IOException {
        if (StringUtils.isBlank(trustStoreFile)) {
            return null;
        }
        if (insecure) {
            throw new IllegalArgumentException("--insecure and -e/--truststore cannot be combined");
        }
        final File file = new File(trustStoreFile);
        if (!file.isFile()) {
            throw new IOException("Truststore file not found: " + trustStoreFile);
        }
        return new String(Files.readAllBytes(file.toPath()), StandardCharsets.US_ASCII);
    }

    /**
     * Method to prompt the user for the username and password if they were not passed as parameters initially
     *
     * @throws IOException If there is an issue getting data from the CLI
     */
    void promptServerArgs() throws IOException {
        if (StringUtils.isBlank(user)) {
            this.user = CommandLineInterface.getValueFromPrompt("server username", false);
        }

        if (StringUtils.isBlank(password)) {
            this.password = CommandLineInterface.getValueFromPrompt("server password", false);
        }
    }
}

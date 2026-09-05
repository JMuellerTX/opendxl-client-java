/*---------------------------------------------------------------------------*
 * Copyright (c) 2019 McAfee, LLC - All Rights Reserved.                     *
 *---------------------------------------------------------------------------*/

package com.opendxl.client.cli;

import org.junit.rules.Verifier;

import java.util.ArrayList;
import java.util.List;

/**
 * JUnit rule that runs the assertions registered by a test after the test method has returned, i.e. when the
 * command line interface has written all of its output to the captured streams.
 * <p>
 * It replaces the {@code ExpectedSystemExit} rule of system-rules, which installs a {@code SecurityManager};
 * JDK 18 and later refuse that (<a href="https://openjdk.org/jeps/411">JEP 411</a>), so the CLI tests failed
 * with an {@code UnsupportedOperationException} on JDK 21. The CLI never calls {@code System.exit}, the rule
 * was only used for its "check afterwards" hook.
 */
public class AfterTestAssertions extends Verifier {

    /**
     * An assertion that is executed after the test
     */
    @FunctionalInterface
    public interface Assertion {
        /**
         * Checks the assertion
         *
         * @throws Exception If the assertion fails or can not be evaluated
         */
        void checkAssertion() throws Exception;
    }

    /**
     * The registered assertions
     */
    private final List<Assertion> assertions = new ArrayList<>();

    /**
     * Registers an assertion that is checked after the test method has completed
     *
     * @param assertion The assertion
     */
    public void checkAssertionAfterwards(final Assertion assertion) {
        assertions.add(assertion);
    }

    @Override
    protected void verify() throws Throwable {
        for (final Assertion assertion : assertions) {
            assertion.checkAssertion();
        }
    }
}

package org.openl.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.StdOut;

import org.openl.itest.core.JettyServer;

/**
 * V14: Rule Services logs one startup WARN when authentication is disabled, and none when it is enabled.
 *
 * <p>The warning comes from the {@code AuthenticationDisabledWarning} component, which is created while the Spring
 * context of the webapp refreshes. The webapp is deployed synchronously by {@link JettyServer#start()}, so the line
 * is already written when the server has started, and each test only starts and stops the server. Only stable parts
 * of the message are matched, so a rewording of the rest of the sentence does not break the test.
 */
class AuthenticationDisabledWarningITest {

    // The property and value the warning names.
    private static final String DISABLED = "ruleservice.authentication.enabled=false";
    // The consequence the warning states.
    private static final String UNPROTECTED = "reachable without authentication";
    // The level, as both slf4j-simple ("[main] WARN logger - msg") and the ITEST log4j2 pattern ("[WARN ]") print it.
    private static final String WARN = "WARN";

    @Test
    @StdIo
    void warnsWhenAuthenticationIsDisabled(StdOut out, StdErr err) throws Exception {
        // No profile: openl-repository/application.properties leaves ruleservice.authentication.enabled at its
        // default, false. The server starts inside the method so that its startup logging lands in the captured
        // streams.
        try (var client = JettyServer.get().start()) {
            // Starting and stopping is enough: the WARN is logged while the webapp context initializes.
        }

        // Exactly one: a second line would mean the component is created twice, which is a defect of its own.
        assertEquals(1,
                countLines(out, err, DISABLED, UNPROTECTED, WARN),
                "Expected exactly one authentication-disabled startup WARN");
    }

    @Test
    @StdIo
    void noWarningWhenAuthenticationIsEnabled(StdOut out, StdErr err) throws Exception {
        // The jwt profile loads the unchanged application-jwt.properties, which sets
        // ruleservice.authentication.enabled = true, with the issuer and the JWKS of test-resources-jwt.
        try (var client = JettyServer.get().withProfile("jwt").start()) {
            // Starting and stopping is enough: the WARN would be logged while the webapp context initializes.
        }

        assertEquals(0,
                countLines(out, err, DISABLED),
                "Unexpected authentication-disabled WARN with authentication enabled");
    }

    /**
     * Counts the captured lines, across standard output and standard error, that contain every given fragment.
     *
     * @param out the captured standard output
     * @param err the captured standard error
     * @param fragments the substrings a line must all contain to be counted
     * @return the number of matching lines
     */
    private static long countLines(StdOut out, StdErr err, String... fragments) {
        // Both streams are searched. JettyServer protects org.slf4j. classes, so the webapp's slf4j loggers bind to
        // the test-classpath slf4j-simple, which prints to System.err. Events that reach log4j-core go to its
        // Console appender, which follows System.out.
        return Stream.concat(Stream.of(out.capturedLines()), Stream.of(err.capturedLines()))
                .filter(line -> Arrays.stream(fragments).allMatch(line::contains))
                .count();
    }
}

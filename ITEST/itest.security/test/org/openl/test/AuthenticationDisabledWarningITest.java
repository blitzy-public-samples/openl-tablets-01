package org.openl.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.regex.Pattern;
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
 * is already written when the server has started, and each test only starts and stops the server. The full warning
 * text is matched, together with the logger that emits it and the WARN level, so a warning that drops part of its
 * explanation, or the same words logged by another logger or at another level, fails the test. Failure messages are
 * fixed text and never quote captured output.
 */
class AuthenticationDisabledWarningITest {

    // The property and value the warning names; no line may carry it while authentication is enabled.
    private static final String DISABLED = "ruleservice.authentication.enabled=false";
    // The complete warning, word for word as the component logs it.
    private static final String MESSAGE = "ruleservice.authentication.enabled=false: every Rule Services endpoint,"
            + " including /admin/deploy when the deployer is enabled, is reachable without authentication.";
    // The logger name. slf4j-simple ("[main] WARN logger - msg") and the ITEST log4j2 pattern ("%c{20} - %msg")
    // both print the full name followed by " - " and the message.
    private static final String EMITTER = "org.openl.rules.ruleservice.spring.AuthenticationDisabledWarning";
    // The level as a whole token: slf4j-simple prints "WARN", the ITEST log4j2 pattern prints "[WARN ]".
    private static final Pattern WARN_LEVEL = Pattern.compile("\\bWARN\\b");

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
        var lines = linesContaining(out, err, MESSAGE);
        assertEquals(1, lines.size(), "Expected exactly one line carrying the authentication-disabled startup warning");

        var line = lines.getFirst();
        var emitterAt = line.indexOf(EMITTER + " - " + MESSAGE);
        assertTrue(emitterAt >= 0,
                "The authentication-disabled warning must be logged by AuthenticationDisabledWarning");
        // The level precedes the logger name in both layouts. Only that prefix is searched, so the word WARN
        // inside a message cannot stand in for the level.
        assertTrue(WARN_LEVEL.matcher(line.substring(0, emitterAt)).find(),
                "The authentication-disabled warning must be logged at WARN level");
    }

    @Test
    @StdIo
    void noWarningWhenAuthenticationIsEnabled(StdOut out, StdErr err) throws Exception {
        // The jwt profile loads the unchanged application-jwt.properties, which sets
        // ruleservice.authentication.enabled = true, with the issuer and the JWKS of test-resources-jwt.
        try (var client = JettyServer.get().withProfile("jwt").start()) {
            // Starting and stopping is enough: the WARN would be logged while the webapp context initializes.
        }

        // The property token alone is searched, so any variant of the warning, complete or not, is caught.
        assertEquals(0,
                linesContaining(out, err, DISABLED).size(),
                "Unexpected authentication-disabled WARN with authentication enabled");
    }

    /**
     * Collects the captured lines, across standard output and standard error, that contain the given text.
     *
     * @param out the captured standard output
     * @param err the captured standard error
     * @param text the substring a line must contain to be collected
     * @return the matching lines, standard output first
     */
    private static List<String> linesContaining(StdOut out, StdErr err, String text) {
        // Both streams are searched. JettyServer protects org.slf4j. classes, so the webapp's slf4j loggers bind to
        // the test-classpath slf4j-simple, which prints to System.err. Events that reach log4j-core go to its
        // Console appender, which follows System.out.
        return Stream.concat(Stream.of(out.capturedLines()), Stream.of(err.capturedLines()))
                .filter(line -> line.contains(text))
                .toList();
    }
}

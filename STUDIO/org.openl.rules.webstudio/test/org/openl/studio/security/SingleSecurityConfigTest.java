package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;

/**
 * Unit tests for {@link SingleSecurityConfig}: V14 startup warning when user.mode=single.
 *
 * <p>Single mode has no login and grants {@code ADMIN} to every visitor, so the configuration warns once when it
 * is created. The configuration is only created when {@code user.mode=single}, which is why constructing it
 * directly is enough to prove the warning; no Spring context is started.
 *
 * <p>Unit tests log through slf4j-simple, which writes to {@link System#err} and resolves that stream on every
 * write, so {@link StdIo} captures the line even when another test created the logger first. The assertions
 * match message substrings only and never the logger name, which is a detail of the logging binding.
 */
class SingleSecurityConfigTest {

    /** The text that opens the V14 warning and identifies it among any other captured lines. */
    private static final String SINGLE_MODE_MARKER = "user.mode=single";

    /** The property naming the anonymous single-mode principal; its value must never reach the log. */
    private static final String SINGLE_USERNAME_PROPERTY = "security.single.username";

    @Test
    @StdIo
    void warnsOnceThatSingleModeHasNoAuthentication(StdErr err) {
        new SingleSecurityConfig();

        String[] captured = err.capturedLines();
        List<String> warnings = Arrays.stream(captured).filter(line -> line.contains(SINGLE_MODE_MARKER)).toList();
        assertEquals(1, warnings.size(), () -> "exactly one single-mode warning must be logged, but got " + warnings);

        String warning = warnings.getFirst();
        assertTrue(warning.contains("WARN"), () -> "the single-mode message must be logged at WARN: " + warning);
        assertTrue(warning.contains("without authentication"),
                () -> "the warning must say that authentication is off: " + warning);
        assertTrue(warning.contains("ADMIN"),
                () -> "the warning must say that every visitor is an administrator: " + warning);

        assertSingleUsernameNotLogged(captured);
    }

    @Test
    @StdIo
    void instantiationDoesNotThrowAndKeepsInternalUsersDisabled(StdErr err) {
        SingleSecurityConfig config = assertDoesNotThrow(SingleSecurityConfig::new);

        assertEquals(false, config.canCreateInternalUsers(),
                "single mode must still refuse to create internal users");
        assertSingleUsernameNotLogged(err.capturedLines());
    }

    /**
     * Asserts that no captured line names the configured single-mode principal. These tests do not set the
     * property, so the check only has something to find when the JVM running them supplies it.
     */
    private static void assertSingleUsernameNotLogged(String[] captured) {
        String singleUsername = System.getProperty(SINGLE_USERNAME_PROPERTY);
        if (singleUsername == null || singleUsername.isBlank()) {
            return;
        }
        // The message names the property, never its value, so that a failure cannot echo it.
        assertTrue(Arrays.stream(captured).noneMatch(line -> line.contains(singleUsername)),
                () -> "no captured line may contain the value of " + SINGLE_USERNAME_PROPERTY);
    }
}

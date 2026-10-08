package org.openl.rules.ruleservice.spring;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.springframework.mock.env.MockEnvironment;

/**
 * Covers V14: Rule Services logs one startup WARN exactly when {@code ruleservice.authentication.enabled} is blank,
 * absent or case-insensitive {@code false}, the same values that leave {@link JWTValidator} uncreated.
 * <p>
 * The component is constructed inside each method, after JUnit Pioneer has replaced {@code System.err}, where the
 * test logger writes. Assertions count the lines carrying the fixed warning text and use fixed messages, so no
 * property value is ever printed.
 */
class AuthenticationDisabledWarningTest {

    private static final String PROPERTY = "ruleservice.authentication.enabled";
    private static final String MESSAGE = "ruleservice.authentication.enabled=false: every Rule Services endpoint,"
            + " including /admin/deploy when the deployer is enabled, is reachable without authentication.";

    @ParameterizedTest
    @ValueSource(strings = {"false", "FALSE", "   "})
    @EmptySource
    @StdIo
    void warnsWhenDisabled(String value, StdErr stdErr) {
        create(new MockEnvironment().withProperty(PROPERTY, value));
        assertSingleWarning(stdErr.capturedString());
    }

    @Test
    @StdIo
    void warnsWhenAbsent(StdErr stdErr) {
        create(new MockEnvironment());
        assertSingleWarning(stdErr.capturedString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "TRUE"})
    @StdIo
    void silentWhenEnabled(String value, StdErr stdErr) {
        create(new MockEnvironment().withProperty(PROPERTY, value));
        assertEquals(0, count(stdErr.capturedString()), "No warning may be logged while authentication is enabled");
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {" ", "False"})
    void isDisabled_forAbsentBlankOrFalse(String value) {
        assertTrue(AuthenticationDisabledWarning.isDisabled(value), "The value must count as disabled");
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "yes"})
    void isDisabled_isFalseForAnyOtherValue(String value) {
        assertFalse(AuthenticationDisabledWarning.isDisabled(value), "The value must count as enabled");
    }

    /**
     * Constructs the component as the Spring context does at startup. Construction must never fail, whatever the
     * property holds, because the component only logs.
     */
    private static void create(MockEnvironment env) {
        assertDoesNotThrow(() -> new AuthenticationDisabledWarning(env), "Construction must not fail");
    }

    private static void assertSingleWarning(String captured) {
        assertEquals(1, count(captured), "Exactly one line must carry the warning");
        assertTrue(captured.lines().filter(line -> line.contains(MESSAGE)).allMatch(line -> line.contains("WARN")),
                "The warning must be logged at WARN level");
    }

    private static long count(String captured) {
        return captured.lines().filter(line -> line.contains(MESSAGE)).count();
    }
}

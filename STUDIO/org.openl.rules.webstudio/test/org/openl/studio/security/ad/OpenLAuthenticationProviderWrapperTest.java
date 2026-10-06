package org.openl.studio.security.ad;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Unit tests for {@link OpenLAuthenticationProviderWrapper}.
 *
 * <p>They cover the V11 security audit lines the wrapper writes for every attempt its delegate handles
 * ({@code event=auth.success} for an authenticated result, {@code event=auth.failure} for a rejected attempt, and no
 * line for a {@code null} result or an unsupported token), and the {@link AuthenticationHolder} lifecycle: the
 * attempt is exposed while the delegate runs and cleared afterwards on every path.
 *
 * <p>The unit-test classpath binds slf4j to slf4j-simple, which writes to the current {@code System.err}, so
 * JUnit Pioneer's {@link StdIo} captures the audit lines per test. Only the stable markers of a line are asserted;
 * the exact line format belongs to the tests of the audit log itself. The password of every attempt is generated at
 * run time, and each capturing test asserts that it never reaches the captured output.
 */
@ExtendWith(MockitoExtension.class)
class OpenLAuthenticationProviderWrapperTest {

    private static final String USER_NAME = "jdoe";

    /**
     * The name of the authenticated result, as a directory may return it for the attempted name. It differs from
     * {@link #USER_NAME}, and neither contains the other, so a line can name only one of them.
     */
    private static final String AUTHENTICATED_NAME = "john.doe";

    private static final String SUCCESS_EVENT = "event=auth.success";
    private static final String FAILURE_EVENT = "event=auth.failure";
    private static final String ANY_EVENT = "event=";
    private static final String USER_PAIR = "user=\"" + USER_NAME + "\"";
    private static final String AUTHENTICATED_USER_PAIR = "user=\"" + AUTHENTICATED_NAME + "\"";

    @Mock
    private AuthenticationProvider delegate;

    private final String generatedPassword = RandomStringUtils.secure().nextAlphanumeric(16);

    @AfterEach
    void clearHolder() {
        // Defensive: a failing assertion must not leave an attempt on the thread for the next test.
        AuthenticationHolder.clear();
    }

    @Test
    @StdIo
    void logsSuccessAndExposesAttemptDuringDelegation(StdErr err) {
        var attempt = attempt();
        var result = UsernamePasswordAuthenticationToken.authenticated(AUTHENTICATED_NAME, null, List.of());
        var seen = new AtomicReference<Authentication>();
        when(delegate.supports(any())).thenReturn(true);
        when(delegate.authenticate(any())).thenAnswer(invocation -> {
            seen.set(AuthenticationHolder.getAuthentication());
            return result;
        });
        var wrapper = new OpenLAuthenticationProviderWrapper(delegate);

        assertSame(result, wrapper.authenticate(attempt));

        assertSame(attempt, seen.get(), "The attempt must be held while the delegate authenticates.");
        assertNull(AuthenticationHolder.getAuthentication(), "The holder must be cleared after a success.");
        var successLines = linesContaining(err, SUCCESS_EVENT);
        assertEquals(1, successLines.size(), "Exactly one success line is expected.");
        assertTrue(successLines.get(0).contains(AUTHENTICATED_USER_PAIR),
                "The success line must name the authenticated user.");
        assertFalse(successLines.get(0).contains(USER_PAIR), "The success line must not name the attempted user.");
        assertTrue(linesContaining(err, FAILURE_EVENT).isEmpty(), "No failure line is expected after a success.");
        assertNoPasswordLeak(err);
    }

    @Test
    @StdIo
    void logsFailureAndRethrowsSameException(StdErr err) {
        var attempt = attempt();
        var thrown = new BadCredentialsException("Bad credentials");
        when(delegate.supports(any())).thenReturn(true);
        when(delegate.authenticate(any())).thenThrow(thrown);
        var wrapper = new OpenLAuthenticationProviderWrapper(delegate);

        assertSame(thrown, assertThrows(BadCredentialsException.class, () -> wrapper.authenticate(attempt)));

        var failureLines = linesContaining(err, FAILURE_EVENT);
        assertEquals(1, failureLines.size(), "Exactly one failure line is expected.");
        assertTrue(failureLines.get(0).contains(USER_PAIR), "The failure line must name the attempted user.");
        assertTrue(linesContaining(err, SUCCESS_EVENT).isEmpty(), "No success line is expected after a failure.");
        assertNull(AuthenticationHolder.getAuthentication(), "The holder must be cleared after a failure.");
        assertNoPasswordLeak(err);
    }

    @Test
    @StdIo
    void nullResultWritesNoSuccessLine(StdErr err) {
        var attempt = attempt();
        when(delegate.supports(any())).thenReturn(true);
        when(delegate.authenticate(any())).thenReturn(null);
        var wrapper = new OpenLAuthenticationProviderWrapper(delegate);

        assertNull(wrapper.authenticate(attempt));

        assertTrue(linesContaining(err, SUCCESS_EVENT).isEmpty(), "No success line is expected for a null result.");
        assertTrue(linesContaining(err, FAILURE_EVENT).isEmpty(), "No failure line is expected for a null result.");
        assertNull(AuthenticationHolder.getAuthentication(), "The holder must be cleared after a null result.");
        assertNoPasswordLeak(err);
    }

    @Test
    @StdIo
    void unsupportedTokenIsSkipped(StdErr err) {
        var attempt = attempt();
        when(delegate.supports(any())).thenReturn(false);
        var wrapper = new OpenLAuthenticationProviderWrapper(delegate);

        assertNull(wrapper.authenticate(attempt));

        verify(delegate, never()).authenticate(any());
        assertTrue(linesContaining(err, ANY_EVENT).isEmpty(), "No audit line is expected for an unsupported token.");
        assertNull(AuthenticationHolder.getAuthentication(), "The holder must never be set for an unsupported token.");
        assertNoPasswordLeak(err);
    }

    @Test
    void supportsAnyAuthenticationType() {
        var wrapper = new OpenLAuthenticationProviderWrapper(delegate);

        assertFalse(wrapper.supports(null));
        assertTrue(wrapper.supports(UsernamePasswordAuthenticationToken.class));
        assertFalse(wrapper.supports(String.class));
    }

    /** A fresh, unauthenticated user name and password attempt carrying the generated password. */
    private UsernamePasswordAuthenticationToken attempt() {
        return new UsernamePasswordAuthenticationToken(USER_NAME, generatedPassword);
    }

    /** The captured lines that contain the given marker. */
    private static List<String> linesContaining(StdErr err, String marker) {
        return Arrays.stream(err.capturedLines()).filter(line -> line.contains(marker)).toList();
    }

    /** Asserts that the generated password reached no captured line; the message never quotes the password. */
    private void assertNoPasswordLeak(StdErr err) {
        assertFalse(err.capturedString().contains(generatedPassword),
                "The captured output must not contain the password of the attempt.");
    }
}

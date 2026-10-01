package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import static org.openl.studio.security.LoginLockoutAuthenticationProvider.LOCK_DURATION;
import static org.openl.studio.security.LoginLockoutAuthenticationProvider.MAX_ENTRIES;
import static org.openl.studio.security.LoginLockoutAuthenticationProvider.MAX_FAILURES;
import static org.openl.studio.security.LoginLockoutAuthenticationProvider.WINDOW;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.RandomStringUtils;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.mockito.MockSettings;
import org.mockito.invocation.InvocationOnMock;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Unit tests for {@link LoginLockoutAuthenticationProvider}.
 *
 * <p>V9: an account locks for {@link LoginLockoutAuthenticationProvider#LOCK_DURATION} once
 * {@link LoginLockoutAuthenticationProvider#MAX_FAILURES} consecutive failed logins fall within
 * {@link LoginLockoutAuthenticationProvider#WINDOW}; a successful login resets the counter; and a locked account, known
 * or not, answers exactly like a wrong password. The cases pin each edge of the window and of the lock to the
 * millisecond with a clock moved by hand, prove that concurrent failures always engage the lock, and prove that a
 * burst of distinct names keeps the state within {@link LoginLockoutAuthenticationProvider#MAX_ENTRIES}, purging
 * expired names before evicting the oldest live ones.
 *
 * <p>The delegate is a Mockito mock whose answer authenticates the generated password and rejects any other one the
 * way the DAO provider does. It counts its calls, so every helper proves whether an attempt reached it, and it can run
 * other logins while an attempt is in flight, which shows how a late failure meets an eviction or a lock that happened
 * meanwhile. The memory-bound cases use a stub-only mock, which records no invocations, so tens of thousands of
 * attempts stay cheap. Every password is generated at run time, and no assertion message carries one.
 */
class LoginLockoutAuthenticationProviderTest {

    /** The instant the clock of every test starts at. */
    private static final Instant START = Instant.parse("2025-01-01T12:00:00Z");

    /** The message of a rejected login, for a wrong password and for a locked account alike. */
    private static final String BAD_CREDENTIALS = "Bad credentials";

    /** How many times the concurrent-failure case runs, each time with a fresh provider and a fresh delegate. */
    private static final int CONCURRENT_ROUNDS = 100;

    /** The number of distinct names in the memory-bound burst: twice the bound. */
    private static final int BURST_NAMES = 2 * MAX_ENTRIES;

    /** How long a concurrent attempt may take before the test fails instead of hanging. */
    private static final long TIMEOUT_SECONDS = 30;

    private final String password = newPassword();
    private final String wrongPassword = newPassword();
    private final MutableClock clock = new MutableClock(START);

    /** Names the delegate does not know: it throws {@link UsernameNotFoundException} for them. */
    private final Set<String> unknownNames = ConcurrentHashMap.newKeySet();

    /** Names whose directory is unreachable: the delegate throws {@link InternalAuthenticationServiceException}. */
    private final Set<String> unreachableNames = ConcurrentHashMap.newKeySet();

    /** Names the delegate does not handle: it returns {@code null} for them. */
    private final Set<String> declinedNames = ConcurrentHashMap.newKeySet();

    /**
     * Logins to run once while the next attempt of a name is in flight, before the delegate answers it. They stand in
     * for the logins of other users that a server handles at the same time, without a second thread.
     */
    private final Map<String, Runnable> whileInFlight = new ConcurrentHashMap<>();

    /** Every call of every delegate this test created. */
    private final AtomicInteger delegateCalls = new AtomicInteger();

    /** The last result a delegate returned, so a test can prove it is passed through unchanged. */
    private final AtomicReference<@Nullable Authentication> lastResult = new AtomicReference<>();

    /** The last exception a delegate threw, so a test can prove it is rethrown unchanged. */
    private final AtomicReference<@Nullable AuthenticationException> lastFailure = new AtomicReference<>();

    private final AuthenticationProvider delegate = newDelegate(withSettings());
    private final LoginLockoutAuthenticationProvider provider = new LoginLockoutAuthenticationProvider(delegate,
            clock);

    @Test
    void successBeforeTheFifthFailureResetsTheCounter() {
        failLogins(provider, "alice", MAX_FAILURES - 1);
        assertAuthenticates(provider, "alice");

        // The success cleared the counter, so as many failures again still do not lock.
        failLogins(provider, "alice", MAX_FAILURES - 1);
        assertAuthenticates(provider, "alice");

        // Only MAX_FAILURES consecutive failures lock.
        failLogins(provider, "alice", MAX_FAILURES);
        assertLocked(provider, "alice");
    }

    @Test
    void fifthConsecutiveFailureLocksTheAccount() {
        failLogins(provider, "alice", MAX_FAILURES);

        var thrown = assertThrowsExactly(BadCredentialsException.class,
                () -> provider.authenticate(attempt("alice", password)));
        assertEquals(BAD_CREDENTIALS, thrown.getMessage());
        assertNull(thrown.getCause(), "A locked attempt must not wrap another exception");
        verify(delegate, times(MAX_FAILURES)).authenticate(any());
    }

    @Test
    void lockEndsExactlyLockDurationAfterTheLockingFailure() {
        failLogins(provider, "alice", MAX_FAILURES); // locked at L = START

        clock.advance(LOCK_DURATION.minusMillis(1)); // L + 14:59.999
        assertLocked(provider, "alice");

        clock.advance(Duration.ofMillis(1)); // exactly L + 15:00
        assertAuthenticates(provider, "alice");

        // The counter starts again from zero. Each failure reaches the delegate, so none of the first four locks;
        // the fifth does.
        failLogins(provider, "alice", MAX_FAILURES - 1);
        failLogin(provider, "alice");
        assertLocked(provider, "alice");
    }

    @Test
    void firstAttemptAfterTheLockStartsFromAClearedCounter() {
        failLogins(provider, "alice", MAX_FAILURES); // locked at L = START
        clock.advance(LOCK_DURATION); // exactly L + 15:00

        // The lock and the window both last 15 minutes, so the locking failures sit at the inclusive edge of the
        // window. The lock that ended cleared them: each new failure reaches the delegate, and only the fifth new
        // one locks again.
        failLogins(provider, "alice", MAX_FAILURES);
        assertLocked(provider, "alice");
        assertEquals(2 * MAX_FAILURES, delegateCalls.get(), "Attempts that reached the delegate");
    }

    @Test
    void fifthFailureExactlyWindowAfterTheFirstLocks() {
        failLogin(provider, "alice"); // T
        clock.advance(Duration.ofMinutes(1));
        failLogins(provider, "alice", MAX_FAILURES - 2); // T + 1:00
        clock.advance(WINDOW.minusMinutes(1)); // exactly T + 15:00
        failLogin(provider, "alice");

        assertLocked(provider, "alice");
    }

    @Test
    void fifthFailureJustAfterTheWindowDoesNotLock() {
        failLogin(provider, "alice"); // T
        clock.advance(Duration.ofMinutes(1));
        failLogins(provider, "alice", MAX_FAILURES - 2); // T + 1:00
        clock.advance(WINDOW.minusMinutes(1).plusMillis(1)); // T + 15:00.001: the first failure left the window
        failLogin(provider, "alice");

        assertAuthenticates(provider, "alice");
    }

    @Test
    void attemptsDuringTheLockDoNotExtendIt() {
        failLogins(provider, "alice", MAX_FAILURES); // locked at L = START

        clock.advance(Duration.ofMinutes(5)); // L + 5:00
        assertLocked(provider, "alice");
        assertRejectedWithoutDelegate(provider, attempt("alice", wrongPassword));

        clock.advance(Duration.ofMinutes(5)); // L + 10:00
        assertLocked(provider, "alice");
        assertRejectedWithoutDelegate(provider, attempt("alice", wrongPassword));

        clock.advance(LOCK_DURATION.minusMinutes(10)); // exactly L + 15:00
        assertAuthenticates(provider, "alice");
    }

    @Test
    void caseVariantsOfANameShareOneCounter() {
        failLogins(provider, "Alice", MAX_FAILURES - 2);
        failLogins(provider, "alice", 2);

        assertLocked(provider, "ALICE");
        assertLocked(provider, "alice");
        assertLocked(provider, "Alice");
    }

    @Test
    void unknownNameLocksAndAnswersLikeALockedExistingAccount() {
        unknownNames.add("ghost");
        for (int i = 0; i < MAX_FAILURES; i++) {
            int before = delegateCalls.get();
            var thrown = assertThrowsExactly(UsernameNotFoundException.class,
                    () -> provider.authenticate(attempt("ghost", password)));
            assertEquals(before + 1, delegateCalls.get(), "A counted failure must reach the delegate");
            assertSame(lastFailure.get(), thrown, "The delegate's exception must be rethrown unchanged");
        }
        BadCredentialsException ghostLocked = assertLocked(provider, "ghost");

        failLogins(provider, "alice", MAX_FAILURES);
        BadCredentialsException aliceLocked = assertLocked(provider, "alice");

        // Whether the account exists cannot be told from the locked response.
        assertSame(aliceLocked.getClass(), ghostLocked.getClass());
        assertEquals(aliceLocked.getMessage(), ghostLocked.getMessage());
        assertEquals(BAD_CREDENTIALS, ghostLocked.getMessage());
    }

    @Test
    void internalAuthenticationFailuresAreNotCounted() {
        unreachableNames.add("alice");
        for (int i = 0; i < 2 * MAX_FAILURES; i++) {
            var thrown = assertThrowsExactly(InternalAuthenticationServiceException.class,
                    () -> provider.authenticate(attempt("alice", password)));
            assertSame(lastFailure.get(), thrown, "The delegate's exception must be rethrown unchanged");
        }
        assertEquals(2 * MAX_FAILURES, delegateCalls.get(), "Every uncounted failure must reach the delegate");
        assertEquals(0, provider.size(), "An uncounted failure must leave no state behind");

        unreachableNames.remove("alice");
        assertAuthenticates(provider, "alice");
    }

    @Test
    void uncountedFailureKeepsTheEarlierFailures() {
        failLogins(provider, "alice", MAX_FAILURES - 1);
        unreachableNames.add("alice");
        assertThrowsExactly(InternalAuthenticationServiceException.class,
                () -> provider.authenticate(attempt("alice", password)));
        unreachableNames.remove("alice");

        // An unreachable directory is not a successful login, so the earlier failures still count.
        failLogin(provider, "alice");
        assertLocked(provider, "alice");
    }

    @Test
    void attemptTheDelegateDoesNotHandleIsNeitherCountedNorKept() {
        declinedNames.add("alice");
        for (int i = 0; i < 2 * MAX_FAILURES; i++) {
            assertNull(provider.authenticate(attempt("alice", wrongPassword)), "A declined attempt has no result");
        }
        assertEquals(2 * MAX_FAILURES, delegateCalls.get(), "Every declined attempt must reach the delegate");
        assertEquals(0, provider.size(), "A declined attempt must leave no state behind");
    }

    @Test
    void concurrentFailuresAlwaysEngageTheLock() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(MAX_FAILURES);
        try {
            for (int round = 0; round < CONCURRENT_ROUNDS; round++) {
                AuthenticationProvider roundDelegate = newDelegate(withSettings());
                var roundProvider = new LoginLockoutAuthenticationProvider(roundDelegate, clock);
                var ready = new CountDownLatch(MAX_FAILURES);
                var start = new CountDownLatch(1);
                var attempts = new ArrayList<Future<@Nullable Authentication>>(MAX_FAILURES);
                for (int i = 0; i < MAX_FAILURES; i++) {
                    attempts.add(executor.submit(() -> {
                        ready.countDown();
                        if (!start.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("The attempts were not released in time.");
                        }
                        return roundProvider.authenticate(attempt("alice", wrongPassword));
                    }));
                }
                assertTrue(ready.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "The attempts did not start in time");
                start.countDown();

                for (var pending : attempts) {
                    var thrown = assertThrows(ExecutionException.class,
                            () -> pending.get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
                    var cause = assertInstanceOf(BadCredentialsException.class, thrown.getCause());
                    assertEquals(BAD_CREDENTIALS, cause.getMessage());
                }
                assertLocked(roundProvider, "alice");
                verify(roundDelegate, times(MAX_FAILURES)).authenticate(any());
            }
        } finally {
            executor.shutdownNow();
            executor.awaitTermination(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }
    }

    @Test
    void burstOfDistinctNamesStaysWithinTheEntryBound() {
        var burstProvider = newBoundedProvider();

        for (int i = 0; i < BURST_NAMES; i++) {
            String name = "u" + i;
            var thrown = assertThrowsExactly(BadCredentialsException.class,
                    () -> burstProvider.authenticate(attempt(name, wrongPassword)));
            assertEquals(BAD_CREDENTIALS, thrown.getMessage());
            assertTrue(burstProvider.size() <= MAX_ENTRIES, "The state must never exceed the entry bound");
        }

        assertEquals(BURST_NAMES, delegateCalls.get(), "Every attempt of the burst must reach the delegate");
        assertEquals(MAX_ENTRIES, burstProvider.size(), "Names are evicted only down to the entry bound");
    }

    @Test
    void expiredEntriesArePurgedBeforeLiveOnesAreEvicted() {
        var boundedProvider = newBoundedProvider();
        failDistinctNames(boundedProvider, "old", MAX_ENTRIES - 2, Duration.ZERO);
        failLogins(boundedProvider, "expired-lock", MAX_FAILURES); // locked until START + 15:00

        clock.advance(WINDOW); // START + 15:00
        failLogins(boundedProvider, "live-lock", MAX_FAILURES); // locked until START + 30:00
        assertEquals(MAX_ENTRIES, boundedProvider.size());

        // One more name takes the state above the bound. Every single failure has left its window and the first
        // lock has ended, so they are purged; the live lock and the new name stay.
        clock.advance(Duration.ofMillis(1)); // START + 15:00.001
        failLogin(boundedProvider, "fresh");
        assertEquals(2, boundedProvider.size(), "Only the live lock and the new name must remain");

        assertLocked(boundedProvider, "live-lock");
        assertAuthenticates(boundedProvider, "expired-lock");
    }

    @Test
    void oldestEntryIsEvictedWhenNoEntryHasExpired() {
        var boundedProvider = newBoundedProvider();
        failDistinctNames(boundedProvider, "u", MAX_ENTRIES, Duration.ofMillis(1));
        assertEquals(MAX_ENTRIES, boundedProvider.size());

        failLogin(boundedProvider, "newest");
        assertEquals(MAX_ENTRIES, boundedProvider.size(), "One name must be evicted for the new one");

        // The oldest name was evicted, so its first failure is forgotten: four more failures do not lock it.
        failLogins(boundedProvider, "u0", MAX_FAILURES - 1);
        assertAuthenticates(boundedProvider, "u0");

        // The newest names were kept, so their earlier failure still counts.
        String recent = "u" + (MAX_ENTRIES - 1);
        failLogins(boundedProvider, recent, MAX_FAILURES - 1);
        assertLocked(boundedProvider, recent);
        failLogins(boundedProvider, "newest", MAX_FAILURES - 1);
        assertLocked(boundedProvider, "newest");
    }

    @Test
    void namesThatFailedAgainAreNotEvictedAsTheOldest() {
        var boundedProvider = newBoundedProvider();
        failDistinctNames(boundedProvider, "u", MAX_ENTRIES, Duration.ofMillis(1));
        failLogin(boundedProvider, "first-new"); // evicts u0, the oldest

        // The first half of the remaining names fails again, so the second half now holds the oldest last updates.
        for (int i = 1; i <= MAX_ENTRIES / 2; i++) {
            failLogin(boundedProvider, "u" + i);
        }
        failLogin(boundedProvider, "second-new");
        assertEquals(MAX_ENTRIES, boundedProvider.size());

        // The oldest name that did not fail again was evicted, so its only failure is forgotten.
        String oldestUntouched = "u" + (MAX_ENTRIES / 2 + 1);
        failLogins(boundedProvider, oldestUntouched, MAX_FAILURES - 1);
        assertAuthenticates(boundedProvider, oldestUntouched);

        // A name that failed again was kept with both of its failures.
        failLogins(boundedProvider, "u1", MAX_FAILURES - 2);
        assertLocked(boundedProvider, "u1");
    }

    @Test
    void everyExpiredNameIsPurgedWhenTheBoundIsExceededAgain() {
        var boundedProvider = newBoundedProvider();
        failDistinctNames(boundedProvider, "u", MAX_ENTRIES, Duration.ofMillis(1));
        failLogin(boundedProvider, "first-new"); // every name is live, so only the oldest is evicted
        assertEquals(MAX_ENTRIES, boundedProvider.size());

        clock.advance(WINDOW.plusMinutes(1)); // every failure so far has left its window
        failLogin(boundedProvider, "second-new");
        assertEquals(1, boundedProvider.size(), "Every expired name must be purged");
    }

    @Test
    void stateStaysBoundedAndEvictsTheOldestWhenTheClockGoesBack() {
        var boundedProvider = newBoundedProvider();
        failDistinctNames(boundedProvider, "u", MAX_ENTRIES, Duration.ofMillis(1));
        failLogin(boundedProvider, "first-new"); // evicts u0

        clock.advance(Duration.ofMillis(-1));
        failLogin(boundedProvider, "second-new"); // evicts u1, the oldest left
        assertEquals(MAX_ENTRIES, boundedProvider.size());

        failLogins(boundedProvider, "u1", MAX_FAILURES - 1);
        assertAuthenticates(boundedProvider, "u1");
        String recent = "u" + (MAX_ENTRIES - 1);
        failLogins(boundedProvider, recent, MAX_FAILURES - 1);
        assertLocked(boundedProvider, recent);
    }

    @Test
    void failureInFlightStillCountsWhenItsNameWasEvictedMeanwhile() {
        var boundedProvider = newBoundedProvider();
        // Other users fail while the victim's attempt is in flight. Their names are newer and fill the state, so
        // the victim's name, the oldest, is evicted before its attempt ends.
        whileInFlight.put("victim", () -> {
            clock.advance(Duration.ofMillis(1));
            failDistinctNames(boundedProvider, "other", MAX_ENTRIES, Duration.ZERO);
        });
        assertThrowsExactly(BadCredentialsException.class,
                () -> boundedProvider.authenticate(attempt("victim", wrongPassword)));

        // The failure was counted again for the victim's name, so four more lock it.
        failLogins(boundedProvider, "victim", MAX_FAILURES - 1);
        assertLocked(boundedProvider, "victim");
    }

    @Test
    void failureInFlightDuringALockEngagedMeanwhileDoesNotExtendIt() {
        var boundedProvider = newBoundedProvider();
        // While the victim's attempt is in flight, its name is evicted and then locked by five other attempts at L.
        whileInFlight.put("victim", () -> {
            clock.advance(Duration.ofMillis(1));
            failDistinctNames(boundedProvider, "other", MAX_ENTRIES, Duration.ZERO);
            failLogins(boundedProvider, "victim", MAX_FAILURES); // locked at L
            clock.advance(Duration.ofMinutes(1)); // the attempt in flight ends at L + 1:00
        });
        assertThrowsExactly(BadCredentialsException.class,
                () -> boundedProvider.authenticate(attempt("victim", wrongPassword)));

        clock.advance(LOCK_DURATION.minusMinutes(1).minusMillis(1)); // L + 14:59.999
        assertLocked(boundedProvider, "victim");
        clock.advance(Duration.ofMillis(1)); // exactly L + 15:00: the late failure did not extend the lock
        assertAuthenticates(boundedProvider, "victim");
    }

    @Test
    void failureInFlightAfterALockEndedMeanwhileCountsFromZero() {
        var boundedProvider = newBoundedProvider();
        // While the victim's attempt is in flight, its name is evicted, locked by five other attempts, and the
        // lock ends before the attempt in flight does.
        whileInFlight.put("victim", () -> {
            clock.advance(Duration.ofMillis(1));
            failDistinctNames(boundedProvider, "other", MAX_ENTRIES, Duration.ZERO);
            failLogins(boundedProvider, "victim", MAX_FAILURES); // locked at L
            clock.advance(LOCK_DURATION); // the attempt in flight ends at exactly L + 15:00
        });
        assertThrowsExactly(BadCredentialsException.class,
                () -> boundedProvider.authenticate(attempt("victim", wrongPassword)));

        // The late failure is the first of a new count, so four more lock the name again.
        failLogins(boundedProvider, "victim", MAX_FAILURES - 1);
        assertLocked(boundedProvider, "victim");
    }

    @Test
    void supportsAsksTheDelegate() {
        when(delegate.supports(TestingAuthenticationToken.class)).thenReturn(false);

        assertTrue(provider.supports(UsernamePasswordAuthenticationToken.class));
        assertFalse(provider.supports(TestingAuthenticationToken.class));
        verify(delegate).supports(UsernamePasswordAuthenticationToken.class);
        verify(delegate).supports(TestingAuthenticationToken.class);
    }

    /**
     * V11: the lock that engages writes exactly one {@code auth.lockout} line to the security audit trail, through
     * {@link org.openl.studio.security.audit.SecurityAuditLog#lockout(Authentication)}; attempts rejected during the
     * lock write none, and no captured line carries a password.
     */
    @Test
    @StdIo
    void lockIsAuditedOnce(StdErr err) {
        failLogins(provider, "alice", MAX_FAILURES);
        assertLocked(provider, "alice");
        assertRejectedWithoutDelegate(provider, attempt("alice", wrongPassword));

        String[] captured = err.capturedLines();
        List<String> lockouts = Arrays.stream(captured).filter(line -> line.contains("event=auth.lockout")).toList();
        assertEquals(1, lockouts.size(), "Exactly one lockout line must be written");
        String lockout = lockouts.getFirst();
        assertTrue(lockout.contains("WARN"), "The lockout line must be written at WARN");
        assertTrue(lockout.contains("outcome=locked"), "The lockout line must carry outcome=locked");
        assertTrue(lockout.contains("user=\"alice\""), "The lockout line must name the locked user");

        // The message names no value, so a failure cannot echo a password.
        assertTrue(Arrays.stream(captured).noneMatch(line -> line.contains(password) || line.contains(wrongPassword)),
                "No captured line may contain a password");
    }

    /**
     * Makes one attempt with the wrong password, which must reach the delegate and fail with the delegate's own
     * exception.
     */
    private void failLogin(LoginLockoutAuthenticationProvider target, String name) {
        int before = delegateCalls.get();
        var thrown = assertThrowsExactly(BadCredentialsException.class,
                () -> target.authenticate(attempt(name, wrongPassword)));
        assertEquals(before + 1, delegateCalls.get(), "A counted failure must reach the delegate");
        assertSame(lastFailure.get(), thrown, "The delegate's exception must be rethrown unchanged");
    }

    private void failLogins(LoginLockoutAuthenticationProvider target, String name, int count) {
        for (int i = 0; i < count; i++) {
            failLogin(target, name);
        }
    }

    /**
     * Fails one login for each of {@code count} distinct names, {@code prefix + 0} first, and advances the clock by
     * {@code step} after each, so a positive step gives every name a later last update than the one before.
     */
    private void failDistinctNames(LoginLockoutAuthenticationProvider target, String prefix, int count, Duration step) {
        for (int i = 0; i < count; i++) {
            failLogin(target, prefix + i);
            clock.advance(step);
        }
    }

    /**
     * Asserts that the correct password of the name is rejected as a locked attempt.
     *
     * @return the exception of the locked attempt
     */
    private BadCredentialsException assertLocked(LoginLockoutAuthenticationProvider target, String name) {
        return assertRejectedWithoutDelegate(target, attempt(name, password));
    }

    /**
     * Asserts that the attempt is rejected like a wrong password without reaching the delegate.
     *
     * @return the exception of the rejected attempt
     */
    private BadCredentialsException assertRejectedWithoutDelegate(LoginLockoutAuthenticationProvider target,
                                                                  Authentication attempt) {
        int before = delegateCalls.get();
        var thrown = assertThrowsExactly(BadCredentialsException.class, () -> target.authenticate(attempt));
        assertEquals(BAD_CREDENTIALS, thrown.getMessage());
        assertNull(thrown.getCause(), "A locked attempt must not wrap another exception");
        assertEquals(before, delegateCalls.get(), "A locked attempt must not reach the delegate");
        return thrown;
    }

    /**
     * Asserts that the correct password of the name reaches the delegate and that the delegate's result is returned
     * unchanged.
     */
    private void assertAuthenticates(LoginLockoutAuthenticationProvider target, String name) {
        int before = delegateCalls.get();
        Authentication result = target.authenticate(attempt(name, password));
        assertEquals(before + 1, delegateCalls.get(), "The attempt must reach the delegate");
        assertSame(lastResult.get(), result, "The delegate's result must be returned unchanged");
        var authenticated = assertInstanceOf(UsernamePasswordAuthenticationToken.class, result);
        assertTrue(authenticated.isAuthenticated());
        assertEquals(name, authenticated.getName());
    }

    /**
     * Creates a provider over a stub-only delegate, which records no invocations, for the cases that make tens of
     * thousands of attempts.
     */
    private LoginLockoutAuthenticationProvider newBoundedProvider() {
        return new LoginLockoutAuthenticationProvider(newDelegate(withSettings().stubOnly()), clock);
    }

    /**
     * Creates a delegate that answers through {@link #answer(InvocationOnMock)} and supports every authentication
     * type unless a test stubs otherwise.
     */
    private AuthenticationProvider newDelegate(MockSettings settings) {
        AuthenticationProvider mock = mock(AuthenticationProvider.class, settings);
        when(mock.supports(any())).thenReturn(true);
        when(mock.authenticate(any())).thenAnswer(this::answer);
        return mock;
    }

    /**
     * Answers like the DAO provider: a declined name is not handled, an unknown name is not found, an unreachable
     * directory is an internal failure, the generated password authenticates, and any other password is rejected.
     * Every call is counted, and its result or exception is kept. The logins registered in {@link #whileInFlight}
     * for the name run first, while the attempt is in flight.
     */
    private @Nullable Authentication answer(InvocationOnMock invocation) {
        delegateCalls.incrementAndGet();
        Authentication attempt = invocation.getArgument(0);
        String name = attempt.getName();
        Runnable concurrentLogins = whileInFlight.remove(name);
        if (concurrentLogins != null) {
            concurrentLogins.run();
        }
        AuthenticationException failure;
        if (declinedNames.contains(name)) {
            return null;
        } else if (unknownNames.contains(name)) {
            failure = new UsernameNotFoundException("The user is not found.");
        } else if (unreachableNames.contains(name)) {
            failure = new InternalAuthenticationServiceException("The directory is unreachable.");
        } else if (password.equals(attempt.getCredentials())) {
            Authentication result = UsernamePasswordAuthenticationToken.authenticated(name, null, List.of());
            lastResult.set(result);
            return result;
        } else {
            failure = new BadCredentialsException(BAD_CREDENTIALS);
        }
        lastFailure.set(failure);
        throw failure;
    }

    private static Authentication attempt(String name, String credential) {
        return new UsernamePasswordAuthenticationToken(name, credential);
    }

    private static String newPassword() {
        return RandomStringUtils.secure().nextAlphanumeric(16);
    }

    /** A clock that a test moves by hand and that any thread can read. */
    private static final class MutableClock extends Clock {

        private final AtomicReference<Instant> now;
        private final ZoneId zone;

        MutableClock(Instant start) {
            this(new AtomicReference<>(start), ZoneOffset.UTC);
        }

        private MutableClock(AtomicReference<Instant> now, ZoneId zone) {
            this.now = now;
            this.zone = zone;
        }

        void advance(Duration duration) {
            now.updateAndGet(instant -> instant.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(now, zone);
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }
}

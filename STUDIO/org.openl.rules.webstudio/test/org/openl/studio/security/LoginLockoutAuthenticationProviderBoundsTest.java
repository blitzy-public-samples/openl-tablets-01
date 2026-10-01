package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import static org.openl.studio.security.LoginLockoutAuthenticationProvider.LOCK_DURATION;
import static org.openl.studio.security.LoginLockoutAuthenticationProvider.MAX_ENTRIES;
import static org.openl.studio.security.LoginLockoutAuthenticationProvider.MAX_FAILURES;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import org.apache.commons.lang3.RandomStringUtils;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Regression tests for the parallel-attempt and key-size bounds of {@link LoginLockoutAuthenticationProvider} (V9).
 *
 * <p>The delegate is a hand-written thread-safe double that counts its calls and holds the calls of a chosen
 * credential at a gate, so a test decides which attempts are in flight at once. Every password is generated at run
 * time, and no assertion message carries one.
 */
class LoginLockoutAuthenticationProviderBoundsTest {

    /** How long a test waits for an attempt to arrive or to end before it fails instead of hanging. */
    private static final Duration TIMEOUT = Duration.ofSeconds(60);

    /** The instant the clock of every test starts at. */
    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

    /** How many attempts of one name are released together. */
    private static final int PARALLEL_ATTEMPTS = 64;

    /** The message of a rejected login, for a wrong password and for a locked or saturated name alike. */
    private static final String BAD_CREDENTIALS = "Bad credentials";

    /** The size of a long name: far beyond any login column and any header limit. */
    private static final int LONG_NAME_LENGTH = 100 * 1024;

    private final String password = newPassword();
    private final String wrongPassword = newPassword();
    private final MutableClock clock = new MutableClock(START);
    private final GatedDelegate delegate = new GatedDelegate(password);
    private final LoginLockoutAuthenticationProvider provider = new LoginLockoutAuthenticationProvider(delegate,
            clock);
    private final ExecutorService executor = Executors.newCachedThreadPool();

    @AfterEach
    void stopAttempts() throws InterruptedException {
        delegate.openAllGates();
        executor.shutdownNow();
        assertTrue(executor.awaitTermination(TIMEOUT.toSeconds(), TimeUnit.SECONDS), "An attempt did not end.");
    }

    @RepeatedTest(20)
    void parallelAttemptsOfOneNameReachTheDelegateAtMostMaxFailuresTimes() throws Exception {
        CountDownLatch gate = delegate.gate(wrongPassword);
        var ready = new CountDownLatch(PARALLEL_ATTEMPTS);
        var start = new CountDownLatch(1);
        var attempts = new ArrayList<Future<@Nullable Authentication>>(PARALLEL_ATTEMPTS);
        for (int i = 0; i < PARALLEL_ATTEMPTS; i++) {
            attempts.add(executor.submit(() -> {
                ready.countDown();
                await(start);
                return provider.authenticate(attempt("target", wrongPassword));
            }));
        }
        assertTrue(ready.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS), "The attempts did not start.");
        start.countDown();

        // An attempt that reached the delegate waits at the gate; every other one has been rejected.
        awaitUntil(() -> delegate.calls() + countDone(attempts) == PARALLEL_ATTEMPTS);
        assertEquals(MAX_FAILURES, delegate.calls(), "Parallel attempts that reached the delegate");
        for (var attempt : attempts) {
            if (attempt.isDone()) {
                assertBadCredentials(attempt);
            }
        }

        gate.countDown();
        for (var attempt : attempts) {
            assertBadCredentials(attempt);
        }
        assertRejectedWithoutDelegate("target", password);
        assertEquals(MAX_FAILURES, delegate.calls());
    }

    @Test
    void successKeepsTheSlotsOfTheOtherAttemptsInFlight() throws Exception {
        CountDownLatch successGate = delegate.gate(password);
        CountDownLatch failureGate = delegate.gate(wrongPassword);
        var success = submit("alice", password);
        var failures = new ArrayList<Future<@Nullable Authentication>>();
        for (int i = 0; i < MAX_FAILURES - 1; i++) {
            failures.add(submit("alice", wrongPassword));
        }
        awaitCalls(MAX_FAILURES);

        successGate.countDown();
        assertAuthenticated("alice", success.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));

        // The success freed its own slot only, so one more attempt is admitted and the next one is not.
        failures.add(submit("alice", wrongPassword));
        awaitCalls(MAX_FAILURES + 1);
        assertRejectedWithoutDelegate("alice", password);

        failureGate.countDown();
        for (var failure : failures) {
            assertBadCredentials(failure);
        }
        assertRejectedWithoutDelegate("alice", password);

        clock.advance(LOCK_DURATION);
        assertAuthenticated("alice", provider.authenticate(attempt("alice", password)));
        assertEquals(MAX_FAILURES + 2, delegate.calls());
    }

    @Test
    void successDoesNotEraseALockEngagedWhileItWasInFlight() throws Exception {
        CountDownLatch successGate = delegate.gate(password);
        var success = submit("victim", password);
        awaitCalls(1);

        // A burst of distinct names evicts the oldest entry, the one of the success in flight.
        clock.advance(Duration.ofMillis(1));
        for (int i = 0; i < MAX_ENTRIES; i++) {
            assertBadCredentials(attempt("burst-" + i, wrongPassword));
        }
        assertEquals(MAX_ENTRIES, provider.size());

        clock.advance(Duration.ofMillis(1));
        for (int i = 0; i < MAX_FAILURES; i++) {
            assertBadCredentials(attempt("victim", wrongPassword));
        }
        assertEquals(1 + MAX_ENTRIES + MAX_FAILURES, delegate.calls(), "Every failure reached the delegate");

        successGate.countDown();
        assertAuthenticated("victim", success.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        assertRejectedWithoutDelegate("victim", password);
    }

    @Test
    void lateUncountedOutcomesOfAnEvictedEntryKeepTheSlotsOfItsSuccessor() throws Exception {
        String outage = delegate.answer(newPassword(), Outcome.OUTAGE);
        CountDownLatch outageGate = delegate.gate(outage);
        var late = new ArrayList<Future<@Nullable Authentication>>();
        for (int i = 0; i < MAX_FAILURES; i++) {
            late.add(submit("victim", outage));
        }
        awaitCalls(MAX_FAILURES);
        evictOlderEntriesWithABurst();
        int calls = delegate.calls();

        clock.advance(Duration.ofMillis(1));
        CountDownLatch failureGate = delegate.gate(wrongPassword);
        var current = new ArrayList<Future<@Nullable Authentication>>();
        for (int i = 0; i < MAX_FAILURES; i++) {
            current.add(submit("victim", wrongPassword));
        }
        awaitCalls(calls + MAX_FAILURES);
        assertRejectedWithoutDelegate("victim", password);

        outageGate.countDown();
        for (var attempt : late) {
            var thrown = assertThrows(ExecutionException.class,
                    () -> attempt.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
            var cause = assertInstanceOf(InternalAuthenticationServiceException.class, thrown.getCause());
            assertSame(InternalAuthenticationServiceException.class, cause.getClass());
        }
        // The attempts of the evicted entry released none of the slots its successor granted.
        assertRejectedWithoutDelegate("victim", password);

        failureGate.countDown();
        for (var attempt : current) {
            assertBadCredentials(attempt);
        }
        assertRejectedWithoutDelegate("victim", password);
        assertEquals(calls + MAX_FAILURES, delegate.calls());
    }

    @Test
    void lateFailureOfAnEvictedEntryCountsWithoutFreeingASlotOfItsSuccessor() throws Exception {
        String lateCredential = newPassword();
        CountDownLatch lateGate = delegate.gate(lateCredential);
        var late = submit("victim", lateCredential);
        awaitCalls(1);
        evictOlderEntriesWithABurst();
        int calls = delegate.calls();

        clock.advance(Duration.ofMillis(1));
        CountDownLatch failureGate = delegate.gate(wrongPassword);
        var current = new ArrayList<Future<@Nullable Authentication>>();
        for (int i = 0; i < MAX_FAILURES - 1; i++) {
            current.add(submit("victim", wrongPassword));
        }
        awaitCalls(calls + MAX_FAILURES - 1);

        lateGate.countDown();
        assertBadCredentials(late);
        // The late failure took the last free slot as a failure and released none of the successor's slots.
        assertRejectedWithoutDelegate("victim", password);

        failureGate.countDown();
        for (var attempt : current) {
            assertBadCredentials(attempt);
        }
        assertRejectedWithoutDelegate("victim", password);
        assertEquals(calls + MAX_FAILURES - 1, delegate.calls());
    }

    @Test
    void lateSuccessOfAnEvictedEntryKeepsTheSlotsOfItsSuccessor() throws Exception {
        CountDownLatch successGate = delegate.gate(password);
        var late = submit("victim", password);
        awaitCalls(1);
        evictOlderEntriesWithABurst();
        int calls = delegate.calls();

        clock.advance(Duration.ofMillis(1));
        CountDownLatch failureGate = delegate.gate(wrongPassword);
        var current = new ArrayList<Future<@Nullable Authentication>>();
        for (int i = 0; i < MAX_FAILURES; i++) {
            current.add(submit("victim", wrongPassword));
        }
        awaitCalls(calls + MAX_FAILURES);

        successGate.countDown();
        assertAuthenticated("victim", late.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        // The late success released none of the slots the successor granted.
        assertRejectedWithoutDelegate("victim", password);

        failureGate.countDown();
        for (var attempt : current) {
            assertBadCredentials(attempt);
        }
        assertRejectedWithoutDelegate("victim", password);
        assertEquals(calls + MAX_FAILURES, delegate.calls());
    }

    @Test
    void uncountedOutcomeReleasesTheLastFreeSlot() throws Exception {
        for (int i = 0; i < MAX_FAILURES - 1; i++) {
            assertBadCredentials(attempt("carol", wrongPassword));
        }
        String outage = delegate.answer(newPassword(), Outcome.OUTAGE);
        CountDownLatch outageGate = delegate.gate(outage);
        var inFlight = submit("carol", outage);
        awaitCalls(MAX_FAILURES);
        assertRejectedWithoutDelegate("carol", password);

        outageGate.countDown();
        var thrown = assertThrows(ExecutionException.class,
                () -> inFlight.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        var cause = assertInstanceOf(InternalAuthenticationServiceException.class, thrown.getCause());
        assertSame(InternalAuthenticationServiceException.class, cause.getClass());

        assertAuthenticated("carol", provider.authenticate(attempt("carol", password)));
        assertEquals(MAX_FAILURES + 1, delegate.calls());
        assertEquals(0, provider.size());
    }

    @Test
    void uncountedOutcomesLeaveNoState() {
        String declined = delegate.answer(newPassword(), Outcome.DECLINE);
        String outage = delegate.answer(newPassword(), Outcome.OUTAGE);
        String fault = delegate.answer(newPassword(), Outcome.FAULT);
        String error = delegate.answer(newPassword(), Outcome.ERROR);
        for (int i = 0; i < 2 * MAX_FAILURES; i++) {
            assertNull(provider.authenticate(attempt("dave", declined)));
            assertEquals(0, provider.size());
            assertThrowsExactly(InternalAuthenticationServiceException.class, () -> authenticate("dave", outage));
            assertThrowsExactly(IllegalStateException.class, () -> authenticate("dave", fault));
            assertThrowsExactly(LinkageError.class, () -> authenticate("dave", error));
        }
        assertEquals(4 * 2 * MAX_FAILURES, delegate.calls(), "Uncounted attempts that reached the delegate");
        assertEquals(0, provider.size());
    }

    @Test
    void everyKeyHasTheSameSizeAndCaseVariantsShareOne() {
        String longName = "n".repeat(LONG_NAME_LENGTH);
        assertEquals(64, keyOf(longName).length());
        assertEquals(64, keyOf("").length());
        assertEquals(keyOf("Alice"), keyOf("ALICE"));
        assertEquals(keyOf("Alice"), keyOf("alice"));
        assertNotEquals(keyOf("alice"), keyOf("bob"));
        assertNotEquals(keyOf(longName), keyOf(longName + "n"));
    }

    @Test
    void longNameLocksExactlyLikeShortOne() {
        assertLocksAfterMaxFailures("eve");
        assertLocksAfterMaxFailures("e".repeat(LONG_NAME_LENGTH));
        assertEquals(2, provider.size());
    }

    @Test
    void caseVariantsOfOneNameShareOneCounter() {
        List<String> variants = List.of("Frank", "FRANK", "frank", "fRaNk", "FrAnK");
        for (String variant : variants) {
            assertBadCredentials(attempt(variant, wrongPassword));
        }
        assertRejectedWithoutDelegate("frank", password);
        assertEquals(1, provider.size());
    }

    @Test
    void distinctLongNamesStayWithinTheEntryBound() {
        String filler = "n".repeat(10 * 1024);
        for (int i = 0; i <= MAX_ENTRIES; i++) {
            String name = filler + i;
            assertBadCredentials(attempt(name, wrongPassword));
            assertTrue(provider.size() <= MAX_ENTRIES, "Tracked names after a failure");
            // The state is keyed by keyOf, so it retains 64 characters per tracked name, not the name.
            assertEquals(64, keyOf(name).length(), "Key length of a long name");
        }
        assertEquals(MAX_ENTRIES, provider.size());
        assertEquals(MAX_ENTRIES + 1, delegate.calls());
    }

    /**
     * Advances the clock and fails {@value LoginLockoutAuthenticationProvider#MAX_ENTRIES} new names once each, so
     * the oldest entry tracked before the burst is evicted.
     */
    private void evictOlderEntriesWithABurst() {
        clock.advance(Duration.ofMillis(1));
        for (int i = 0; i < MAX_ENTRIES; i++) {
            assertBadCredentials(attempt("burst-" + i, wrongPassword));
        }
        assertEquals(MAX_ENTRIES, provider.size());
    }

    /** Fails a name {@value LoginLockoutAuthenticationProvider#MAX_FAILURES} times, then expects it to be locked. */
    private void assertLocksAfterMaxFailures(String name) {
        int calls = delegate.calls();
        for (int i = 0; i < MAX_FAILURES; i++) {
            assertBadCredentials(attempt(name, wrongPassword));
        }
        assertEquals(calls + MAX_FAILURES, delegate.calls(), "Failures that reached the delegate");
        assertRejectedWithoutDelegate(name, password);
    }

    /** Expects an attempt to be rejected with the ordinary failed-login exception, without calling the delegate. */
    private void assertRejectedWithoutDelegate(String name, String credential) {
        int calls = delegate.calls();
        assertBadCredentials(attempt(name, credential));
        assertEquals(calls, delegate.calls(), "The rejected attempt reached the delegate");
    }

    /** Expects an attempt to fail with the ordinary failed-login exception. */
    private void assertBadCredentials(Authentication attempt) {
        var thrown = assertThrowsExactly(BadCredentialsException.class, () -> provider.authenticate(attempt));
        assertEquals(BAD_CREDENTIALS, thrown.getMessage());
    }

    /** Expects an attempt run in the background to fail with the ordinary failed-login exception. */
    private static void assertBadCredentials(Future<@Nullable Authentication> attempt) {
        var thrown = assertThrows(ExecutionException.class, () -> attempt.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        var cause = assertInstanceOf(BadCredentialsException.class, thrown.getCause());
        assertSame(BadCredentialsException.class, cause.getClass());
        assertEquals(BAD_CREDENTIALS, cause.getMessage());
    }

    private static void assertAuthenticated(String name, @Nullable Authentication result) {
        assertNotNull(result);
        assertTrue(result.isAuthenticated());
        assertEquals(name, result.getName());
    }

    private void authenticate(String name, String credential) {
        provider.authenticate(attempt(name, credential));
    }

    private Future<@Nullable Authentication> submit(String name, String credential) {
        return executor.submit(() -> provider.authenticate(attempt(name, credential)));
    }

    private void awaitCalls(int calls) throws InterruptedException {
        awaitUntil(() -> delegate.calls() == calls);
        assertEquals(calls, delegate.calls(), "Attempts that reached the delegate");
    }

    private static String keyOf(String name) {
        return LoginLockoutAuthenticationProvider.keyOf(attempt(name, newPassword()));
    }

    private static Authentication attempt(String name, String credential) {
        return UsernamePasswordAuthenticationToken.unauthenticated(name, credential);
    }

    private static String newPassword() {
        return RandomStringUtils.secure().nextAlphanumeric(16);
    }

    private static long countDone(List<? extends Future<?>> attempts) {
        return attempts.stream().filter(Future::isDone).count();
    }

    /** Polls the condition until it holds, and fails the test once {@link #TIMEOUT} has passed. */
    private static void awaitUntil(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() - deadline > 0) {
                fail("The attempts did not reach the expected state in time.");
            }
            TimeUnit.MILLISECONDS.sleep(1);
        }
    }

    /** Waits for a latch on an attempt thread, which fails instead of hanging when the latch is never opened. */
    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS)) {
                throw new IllegalStateException("The latch was not opened in time.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for the latch.", e);
        }
    }

    /** How the delegate answers a credential that is not the correct password. */
    private enum Outcome {
        /** Rejected like a wrong password, which is counted. */
        REJECT,
        /** Not handled: the delegate returns {@code null}. */
        DECLINE,
        /** The directory is unreachable, which is not counted. */
        OUTAGE,
        /** An unexpected runtime failure of the delegate. */
        FAULT,
        /** An error of the delegate's runtime. */
        ERROR
    }

    /**
     * A thread-safe delegate. It counts its calls, holds the calls of a gated credential until that gate opens, and
     * then answers by the credential: the correct password authenticates, a credential given an {@link Outcome} gets
     * it, and any other credential is rejected like a wrong password.
     */
    private static final class GatedDelegate implements AuthenticationProvider {

        private final String password;
        private final AtomicInteger calls = new AtomicInteger();
        private final Map<String, CountDownLatch> gates = new ConcurrentHashMap<>();
        private final Map<String, Outcome> outcomes = new ConcurrentHashMap<>();

        GatedDelegate(String password) {
            this.password = password;
        }

        /** Closes a gate for the calls with the credential, and returns the latch that opens it. */
        CountDownLatch gate(String credential) {
            return gates.computeIfAbsent(credential, c -> new CountDownLatch(1));
        }

        /** Makes the calls with the credential end in the outcome, and returns the credential. */
        String answer(String credential, Outcome outcome) {
            outcomes.put(credential, outcome);
            return credential;
        }

        int calls() {
            return calls.get();
        }

        void openAllGates() {
            gates.values().forEach(CountDownLatch::countDown);
        }

        @Override
        public @Nullable Authentication authenticate(Authentication authentication) {
            calls.incrementAndGet();
            String credential = String.valueOf(authentication.getCredentials());
            CountDownLatch gate = gates.get(credential);
            if (gate != null) {
                await(gate);
            }
            if (password.equals(credential)) {
                return UsernamePasswordAuthenticationToken.authenticated(authentication.getName(), null, List.of());
            }
            return switch (outcomes.getOrDefault(credential, Outcome.REJECT)) {
                case REJECT -> throw new BadCredentialsException(BAD_CREDENTIALS);
                case DECLINE -> null;
                case OUTAGE -> throw new InternalAuthenticationServiceException("The directory is unreachable.");
                case FAULT -> throw new IllegalStateException("The delegate is broken.");
                case ERROR -> throw new LinkageError("The delegate cannot run.");
            };
        }

        @Override
        public boolean supports(Class<?> authentication) {
            return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        }
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

package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

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
import java.util.concurrent.atomic.AtomicBoolean;
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
 * Tests of {@link LoginLockoutAuthenticationProvider} (V9) for parallel attempts of one name and the permits that bound
 * them, attempts that end after their name was evicted, the entry bound under concurrent insertions and the key size.
 *
 * <p>The expected policy values are this class's own constants, the specified V9 values, never the constants of the
 * provider, so a change of the provider's policy fails these tests. The delegate is a hand-written thread-safe
 * double that counts its calls and holds the calls of a chosen credential at a gate, so a test decides which
 * attempts are in flight at once; besides the most calls it held at once it records nothing else, so tens of
 * thousands of attempts stay within the small test heap. Every password is generated at run time, and no assertion
 * message carries one.
 */
class LoginLockoutAuthenticationProviderBoundsTest {

    private static final int FAILURES_TO_LOCK = 5;

    private static final Duration WINDOW_LENGTH = Duration.ofMinutes(15);

    private static final Duration LOCK_LENGTH = Duration.ofMinutes(15);

    private static final int ENTRY_BOUND = 10_000;

    /** How long a test waits for an attempt to arrive or to end before it fails instead of hanging. */
    private static final Duration TIMEOUT = Duration.ofSeconds(60);

    /** The instant the clock of every test starts at. */
    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

    /** How many attempts of one name are released together. */
    private static final int PARALLEL_ATTEMPTS = 64;

    /** How many attempts of one name may be in flight at once: as many as the failures that lock. */
    private static final int PERMITS = FAILURES_TO_LOCK;

    /** How many correct logins of one name a test starts at once: more than the permits of the name. */
    private static final int LOGINS_IN_FLIGHT = PERMITS + 3;

    /** How long the attempts of a test's impatient provider wait for a permit. */
    private static final Duration SHORT_WAIT = Duration.ofMillis(100);

    /** How many times the concurrent-cleaning case runs, each time with a fresh provider and a fresh delegate. */
    private static final int CLEANING_ROUNDS = 30;

    /** How many attempts of the concurrent-cleaning wave track an evicted name again when they end. */
    private static final int NEW_NAMES = 1024;

    /** How many attempts of the concurrent-cleaning wave fail one of the oldest names again when they end. */
    private static final int REPLACED_NAMES = 512;

    /** The message of a rejected login, for a wrong password and for a locked name alike. */
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

    /**
     * However the parallel wrong passwords of one name interleave, at most {@value #PERMITS} of them are with the
     * delegate at once, and at most {@value #FAILURES_TO_LOCK} + {@value #PERMITS} - 1 reach it before the lock: the
     * failure that locks completes while at most {@value #PERMITS} - 1 others are still with the delegate, and every
     * attempt that takes a permit after it is refused by the lock.
     */
    @RepeatedTest(20)
    void parallelWrongAttemptsReachTheDelegateWithinThePermitsAndTheBoundBeforeTheLock() throws Exception {
        CountDownLatch wrongGate = delegate.gate(wrongPassword);
        List<Future<@Nullable Authentication>> attempts = startTogether("target", wrongPassword);

        // The permits let as many attempts reach the delegate as the failures that lock; every other one waits.
        awaitUntil(() -> provider.attemptsAtGate(keyOf("target")) == PARALLEL_ATTEMPTS
                && delegate.calls() == PERMITS);
        assertEquals(0, countDone(attempts), "An attempt ended while the permits were held");

        wrongGate.countDown();
        for (var attempt : attempts) {
            assertBadCredentials(attempt);
        }
        int calls = delegate.calls();
        assertTrue(calls >= FAILURES_TO_LOCK && calls <= FAILURES_TO_LOCK + PERMITS - 1,
                () -> "Wrong passwords that reached the delegate: " + calls);
        int mostAtOnce = delegate.mostAtOnce();
        assertEquals(PERMITS, mostAtOnce, "Most attempts of the name with the delegate at once");
        assertEquals(0, provider.attemptsAtGate(keyOf("target")), "The gate of the name outlived its attempts");

        assertRejectedWithoutDelegate("target", password);
        clock.advance(LOCK_LENGTH.minusMillis(1));
        assertRejectedWithoutDelegate("target", password);
        clock.advance(Duration.ofMillis(1));
        assertAuthenticated("target", provider.authenticate(attempt("target", password)));
        assertEquals(calls + 1, delegate.calls(), "The login after the lock did not reach the delegate");
    }

    /**
     * Four completed failures and a flood of wrong passwords reach the bound exactly: the permits let
     * {@value #PERMITS} of the flood through, the first of them to fail locks the name before it gives its permit
     * back, and every other attempt of the flood is then refused by the lock.
     */
    @RepeatedTest(20)
    void floodAfterFourFailuresReachesTheDelegateExactlyTheBound() throws Exception {
        failLogins("target", FAILURES_TO_LOCK - 1);
        CountDownLatch wrongGate = delegate.gate(wrongPassword);
        List<Future<@Nullable Authentication>> attempts = startTogether("target", wrongPassword);

        awaitUntil(() -> provider.attemptsAtGate(keyOf("target")) == PARALLEL_ATTEMPTS
                && delegate.calls() == FAILURES_TO_LOCK - 1 + PERMITS);
        assertEquals(0, countDone(attempts), "An attempt ended while the permits were held");

        wrongGate.countDown();
        for (var attempt : attempts) {
            assertBadCredentials(attempt);
        }
        assertEquals(FAILURES_TO_LOCK + PERMITS - 1, delegate.calls(), "Wrong passwords that reached the delegate");
        assertRejectedWithoutDelegate("target", password);
    }

    @Test
    void correctLoginsBeyondThePermitsWaitForOneAndAllSucceed() throws Exception {
        CountDownLatch successGate = delegate.gate(password);
        var successes = new ArrayList<Future<@Nullable Authentication>>();
        for (int i = 0; i < LOGINS_IN_FLIGHT; i++) {
            successes.add(submit("alice", password));
        }

        // As many logins as the permits reach the delegate; the others wait for a permit and are not rejected.
        awaitUntil(() -> provider.attemptsAtGate(keyOf("alice")) == LOGINS_IN_FLIGHT && delegate.calls() == PERMITS);
        assertEquals(0, countDone(successes), "A login ended while the permits were held");

        successGate.countDown();
        for (var success : successes) {
            assertAuthenticated("alice", success.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        }
        assertEquals(LOGINS_IN_FLIGHT, delegate.calls(), "Logins that reached the delegate");
        assertEquals(PERMITS, delegate.mostAtOnce(), "Most logins of the name with the delegate at once");
        assertEquals(0, provider.size(), "The successes left an entry");
        assertEquals(0, provider.attemptsAtGate(keyOf("alice")), "The gate of the name outlived its logins");
        assertLocksAfterMaxFailures("alice");
    }

    @Test
    void attemptThatFindsNoPermitInTimeFailsUncountedWithoutTheDelegate() throws Exception {
        var impatient = new LoginLockoutAuthenticationProvider(delegate, clock, SHORT_WAIT);
        for (int i = 0; i < FAILURES_TO_LOCK - 1; i++) {
            assertThrowsExactly(BadCredentialsException.class,
                    () -> impatient.authenticate(attempt("grace", wrongPassword)));
        }
        String outage = delegate.answer(newPassword(), Outcome.OUTAGE);
        CountDownLatch outageGate = delegate.gate(outage);
        var held = new ArrayList<Future<@Nullable Authentication>>();
        for (int i = 0; i < PERMITS; i++) {
            held.add(executor.submit(() -> impatient.authenticate(attempt("grace", outage))));
        }
        awaitUntil(() -> delegate.calls() == FAILURES_TO_LOCK - 1 + PERMITS);

        // Every permit is held: the next attempt waits for one, then fails like a wrong password.
        long started = System.nanoTime();
        var thrown = assertThrowsExactly(BadCredentialsException.class,
                () -> impatient.authenticate(attempt("grace", password)));
        long waited = System.nanoTime() - started;
        assertEquals(BAD_CREDENTIALS, thrown.getMessage());
        assertNull(thrown.getCause(), "An attempt without a permit must not wrap another exception");
        assertTrue(waited >= SHORT_WAIT.toNanos(), "The attempt did not wait for a permit");
        assertEquals(FAILURES_TO_LOCK - 1 + PERMITS, delegate.calls(), "An attempt without a permit reached it");
        assertEquals(PERMITS, impatient.attemptsAtGate(keyOf("grace")), "The attempt without a permit stayed");

        // It was not counted: after the held attempts end, the counter still holds four failures.
        outageGate.countDown();
        for (var attempt : held) {
            assertOutage(attempt);
        }
        int calls = delegate.calls();
        assertThrowsExactly(InternalAuthenticationServiceException.class,
                () -> impatient.authenticate(attempt("grace", outage)));
        assertThrowsExactly(BadCredentialsException.class,
                () -> impatient.authenticate(attempt("grace", wrongPassword)));
        assertEquals(calls + 2, delegate.calls(), "The attempts after the wait did not reach the delegate");
        assertThrowsExactly(BadCredentialsException.class,
                () -> impatient.authenticate(attempt("grace", password)));
        assertEquals(calls + 2, delegate.calls(), "The fifth failure did not lock the name");
        assertEquals(0, impatient.attemptsAtGate(keyOf("grace")), "The gate of the name outlived its attempts");
    }

    @Test
    void interruptedWaitForAPermitFailsUncountedAndKeepsTheInterrupt() throws Exception {
        String outage = delegate.answer(newPassword(), Outcome.OUTAGE);
        CountDownLatch outageGate = delegate.gate(outage);
        var held = new ArrayList<Future<@Nullable Authentication>>();
        for (int i = 0; i < PERMITS; i++) {
            held.add(submit("heidi", outage));
        }
        awaitCalls(PERMITS);

        var failure = new AtomicReference<@Nullable Throwable>();
        var interrupted = new AtomicBoolean();
        Thread waiter = new Thread(() -> {
            try {
                provider.authenticate(attempt("heidi", wrongPassword));
            } catch (RuntimeException e) {
                failure.set(e);
            }
            interrupted.set(Thread.currentThread().isInterrupted());
        });
        waiter.start();
        awaitUntil(() -> provider.attemptsAtGate(keyOf("heidi")) == PERMITS + 1);
        waiter.interrupt();
        waiter.join(TIMEOUT.toMillis());
        assertFalse(waiter.isAlive(), "The interrupted attempt did not end");

        var thrown = assertInstanceOf(BadCredentialsException.class, failure.get());
        assertSame(BadCredentialsException.class, thrown.getClass());
        assertEquals(BAD_CREDENTIALS, thrown.getMessage());
        assertNull(thrown.getCause(), "An interrupted attempt must not wrap another exception");
        assertTrue(interrupted.get(), "The interrupt status of the attempt was not restored");
        assertEquals(PERMITS, delegate.calls(), "The interrupted attempt reached the delegate");
        assertEquals(PERMITS, provider.attemptsAtGate(keyOf("heidi")), "The interrupted attempt stayed at the gate");

        // It was not counted: four failures after the held attempts end do not lock, the fifth does.
        outageGate.countDown();
        for (var attempt : held) {
            assertOutage(attempt);
        }
        failLogins("heidi", FAILURES_TO_LOCK - 1);
        assertReachesTheDelegateUncounted("heidi");
        failLogins("heidi", 1);
        assertRejectedWithoutDelegate("heidi", password);
    }

    @Test
    void fourFailuresAndALoginInFlightLetTheNextAttemptsThroughAndItsSuccessClearsTheLock() throws Exception {
        failLogins("bob", FAILURES_TO_LOCK - 1);
        CountDownLatch successGate = delegate.gate(password);
        var first = submit("bob", password);
        awaitAtTheGate(first, FAILURES_TO_LOCK);

        // Four failures and a login in flight are not five failures: another login reaches the delegate.
        var second = submit("bob", password);
        awaitAtTheGate(second, FAILURES_TO_LOCK + 1);

        // So does another wrong password: its failure is the fifth that completes, and it locks the name.
        assertBadCredentials(attempt("bob", wrongPassword));
        assertEquals(FAILURES_TO_LOCK + 2, delegate.calls(), "The fifth failure did not reach the delegate");
        assertRejectedWithoutDelegate("bob", password);

        // A success clears the counter and the lock, a lock engaged while it was in flight included.
        successGate.countDown();
        assertAuthenticated("bob", first.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        assertAuthenticated("bob", second.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        assertEquals(0, provider.size(), "The successes left an entry");
        assertLocksAfterMaxFailures("bob");
    }

    @Test
    void successInFlightClearsALockEngagedAfterItsEntryWasEvicted() throws Exception {
        CountDownLatch successGate = delegate.gate(password);
        var success = submit("victim", password);
        awaitCalls(1);

        // A burst of distinct names evicts the oldest entry, the one of the success in flight; five failures then lock
        // the name in a new entry.
        evictOlderEntriesWithABurst();
        clock.advance(Duration.ofMillis(1));
        assertLocksAfterMaxFailures("victim");
        assertEquals(ENTRY_BOUND, provider.size());

        // The success clears the lock of the new entry and removes it, since no attempt of the name is in flight.
        successGate.countDown();
        assertAuthenticated("victim", success.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        assertEquals(ENTRY_BOUND - 1, provider.size(), "The success left the entry of its name");
        int calls = delegate.calls();
        assertAuthenticated("victim", provider.authenticate(attempt("victim", password)));
        assertEquals(calls + 1, delegate.calls(), "The login after the reset did not reach the delegate");
    }

    @Test
    void lateUncountedOutcomesOfAnEvictedEntryKeepTheInFlightCountOfItsSuccessor() throws Exception {
        String lateOutage = delegate.answer(newPassword(), Outcome.OUTAGE);
        CountDownLatch lateGate = delegate.gate(lateOutage);
        var late = new ArrayList<Future<@Nullable Authentication>>();
        // Every permit of the name but one, which the successor's attempt takes.
        for (int i = 0; i < PERMITS - 1; i++) {
            late.add(submit("victim", lateOutage));
        }
        awaitCalls(PERMITS - 1);
        evictOlderEntriesWithABurst();

        // The successor: a new entry of the name with one attempt in flight, and no failure or lock.
        clock.advance(Duration.ofMillis(1));
        String currentOutage = delegate.answer(newPassword(), Outcome.OUTAGE);
        CountDownLatch currentGate = delegate.gate(currentOutage);
        var current = submit("victim", currentOutage);
        awaitAtTheGate(current, PERMITS + ENTRY_BOUND);
        assertEquals(ENTRY_BOUND, provider.size());

        // The late attempts end in the successor's generation, which never counted them in flight.
        lateGate.countDown();
        for (var attempt : late) {
            assertOutage(attempt);
        }
        assertEquals(ENTRY_BOUND, provider.size(), "A late outcome removed the entry of the successor");

        // Every burst failure has left the window, so the next new name purges the stale names. The successor holds
        // no failure and no lock: only the attempt it still counts in flight keeps it.
        clock.advance(WINDOW_LENGTH);
        assertBadCredentials(attempt("fresh", wrongPassword));
        assertEquals(2, provider.size(), "Only the successor and the new name may remain after the purge");

        // The successor's own attempt ends its in-flight count, which leaves nothing to keep.
        currentGate.countDown();
        assertOutage(current);
        assertEquals(1, provider.size(), "The entry of the successor outlived its last attempt");
    }

    @Test
    void lateFailureOfAnEvictedEntryCountsInItsSuccessor() throws Exception {
        String lateCredential = newPassword();
        CountDownLatch lateGate = delegate.gate(lateCredential);
        var late = submit("victim", lateCredential);
        awaitCalls(1);
        evictOlderEntriesWithABurst();

        // The successor: a new entry of the name with three completed failures and one attempt in flight.
        clock.advance(Duration.ofMillis(1));
        failLogins("victim", FAILURES_TO_LOCK - 2);
        String outage = delegate.answer(newPassword(), Outcome.OUTAGE);
        CountDownLatch outageGate = delegate.gate(outage);
        var current = submit("victim", outage);
        awaitAtTheGate(current, ENTRY_BOUND + FAILURES_TO_LOCK);

        // The late failure is the successor's fourth, which does not lock; the next failure is the fifth, which does.
        lateGate.countDown();
        assertBadCredentials(late);
        assertReachesTheDelegateUncounted("victim");
        failLogins("victim", 1);
        assertRejectedWithoutDelegate("victim", password);

        // The successor's own attempt ends uncounted and leaves the lock in force.
        outageGate.countDown();
        assertOutage(current);
        assertRejectedWithoutDelegate("victim", password);
        assertEquals(ENTRY_BOUND, provider.size());
    }

    @Test
    void lateSuccessOfAnEvictedEntryResetsItsSuccessorAndKeepsItsAttemptInFlight() throws Exception {
        CountDownLatch successGate = delegate.gate(password);
        var late = submit("victim", password);
        awaitCalls(1);
        evictOlderEntriesWithABurst();

        // The successor: a new entry of the name with four completed failures and one attempt in flight.
        clock.advance(Duration.ofMillis(1));
        failLogins("victim", FAILURES_TO_LOCK - 1);
        String outage = delegate.answer(newPassword(), Outcome.OUTAGE);
        CountDownLatch outageGate = delegate.gate(outage);
        var current = submit("victim", outage);
        awaitAtTheGate(current, ENTRY_BOUND + FAILURES_TO_LOCK + 1);

        // The late success clears the successor's counter but keeps its entry, which still counts an attempt.
        successGate.countDown();
        assertAuthenticated("victim", late.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        assertEquals(ENTRY_BOUND, provider.size(), "The late success removed an entry with an attempt in flight");

        // The counter starts again from zero: four failures do not lock, the fifth does.
        failLogins("victim", FAILURES_TO_LOCK - 1);
        assertReachesTheDelegateUncounted("victim");
        failLogins("victim", 1);
        assertRejectedWithoutDelegate("victim", password);

        outageGate.countDown();
        assertOutage(current);
        assertRejectedWithoutDelegate("victim", password);
    }

    @Test
    void uncountedAttemptInFlightNeitherCountsNorHoldsBackTheFifthFailure() throws Exception {
        failLogins("carol", FAILURES_TO_LOCK - 1);
        String outage = delegate.answer(newPassword(), Outcome.OUTAGE);
        CountDownLatch outageGate = delegate.gate(outage);
        var inFlight = submit("carol", outage);
        awaitAtTheGate(inFlight, FAILURES_TO_LOCK);

        // The attempt in flight is no failure: the next wrong password reaches the delegate as the fifth and locks.
        failLogins("carol", 1);
        assertRejectedWithoutDelegate("carol", password);

        // The uncounted outcome neither clears nor extends the lock.
        outageGate.countDown();
        assertOutage(inFlight);
        clock.advance(LOCK_LENGTH.minusMillis(1));
        assertRejectedWithoutDelegate("carol", password);
        clock.advance(Duration.ofMillis(1));
        assertAuthenticated("carol", provider.authenticate(attempt("carol", password)));
        assertEquals(FAILURES_TO_LOCK + 2, delegate.calls());
        assertEquals(0, provider.size());
    }

    @Test
    void uncountedOutcomesLeaveNoState() {
        String declined = delegate.answer(newPassword(), Outcome.DECLINE);
        String outage = delegate.answer(newPassword(), Outcome.OUTAGE);
        String fault = delegate.answer(newPassword(), Outcome.FAULT);
        String error = delegate.answer(newPassword(), Outcome.ERROR);
        for (int i = 0; i < 2 * FAILURES_TO_LOCK; i++) {
            assertNull(provider.authenticate(attempt("dave", declined)));
            assertEquals(0, provider.size());
            assertThrowsExactly(InternalAuthenticationServiceException.class, () -> authenticate("dave", outage));
            assertThrowsExactly(IllegalStateException.class, () -> authenticate("dave", fault));
            assertThrowsExactly(LinkageError.class, () -> authenticate("dave", error));
        }
        assertEquals(4 * 2 * FAILURES_TO_LOCK, delegate.calls(), "Uncounted attempts that reached the delegate");
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
        for (int i = 0; i <= ENTRY_BOUND; i++) {
            String name = filler + i;
            assertBadCredentials(attempt(name, wrongPassword));
            assertTrue(provider.size() <= ENTRY_BOUND, "Tracked names after a failure");
            // The state is keyed by keyOf, so it retains 64 characters per tracked name, not the name.
            assertEquals(64, keyOf(name).length(), "Key length of a long name");
        }
        assertEquals(ENTRY_BOUND, provider.size());
        assertEquals(ENTRY_BOUND + 1, delegate.calls());
    }

    /**
     * Ends within the entry bound however insertions and cleaning interleave. A wave of attempts waits at the delegate
     * while a burst evicts their names and fills the state, one name per nanosecond, so the first burst names are the
     * oldest. More attempts of the wave are put in flight on those oldest names, and the clock is set exactly one
     * window after the oldest failure: nothing is stale yet, but no kept candidate may be evicted without a full pass.
     * Then the gate opens, and all at once every attempt of the wave either tracks its evicted name again, which takes
     * the state above the bound, or fails one of the oldest names again, which replaces an entry a concurrent full
     * pass may have chosen for eviction. Every thread that finds another one cleaning leaves it the work, so once every
     * attempt has ended, the state must be back at the bound.
     */
    @RepeatedTest(CLEANING_ROUNDS)
    void concurrentInsertionsAndCandidateReplacementEndWithinTheEntryBound() throws Exception {
        String waveCredential = newPassword();
        CountDownLatch waveGate = delegate.gate(waveCredential);
        ExecutorService wave = Executors.newVirtualThreadPerTaskExecutor();
        try {
            var attempts = new ArrayList<Future<@Nullable Authentication>>(NEW_NAMES + REPLACED_NAMES);
            for (int i = 0; i < NEW_NAMES; i++) {
                String name = "new-" + i;
                attempts.add(wave.submit(() -> provider.authenticate(attempt(name, waveCredential))));
            }
            awaitCalls(NEW_NAMES);

            clock.advance(Duration.ofMillis(1));
            Instant oldest = clock.instant();
            for (int i = 0; i < ENTRY_BOUND; i++) {
                assertBadCredentials(attempt("old-" + i, wrongPassword));
                clock.advance(Duration.ofNanos(1));
            }
            assertEquals(ENTRY_BOUND, provider.size(), "Tracked names after the burst");

            for (int i = 0; i < REPLACED_NAMES; i++) {
                String name = "old-" + i;
                attempts.add(wave.submit(() -> provider.authenticate(attempt(name, waveCredential))));
            }
            awaitCalls(NEW_NAMES + ENTRY_BOUND + REPLACED_NAMES);

            clock.advance(Duration.between(clock.instant(), oldest.plus(WINDOW_LENGTH)));
            waveGate.countDown();
            for (var attempt : attempts) {
                assertBadCredentials(attempt);
            }
            int tracked = provider.size();
            assertTrue(tracked <= ENTRY_BOUND, () -> "Tracked names once every attempt has ended: " + tracked);
        } finally {
            waveGate.countDown();
            wave.shutdownNow();
            assertTrue(wave.awaitTermination(TIMEOUT.toSeconds(), TimeUnit.SECONDS), "An attempt did not end.");
        }
    }

    /**
     * Advances the clock and fails {@value #ENTRY_BOUND} new names once each, so the oldest entry tracked before the
     * burst is evicted.
     */
    private void evictOlderEntriesWithABurst() {
        clock.advance(Duration.ofMillis(1));
        for (int i = 0; i < ENTRY_BOUND; i++) {
            assertBadCredentials(attempt("burst-" + i, wrongPassword));
        }
        assertEquals(ENTRY_BOUND, provider.size());
    }

    /**
     * Fails a name {@value #FAILURES_TO_LOCK} times, every failure reaching the delegate, then expects it to be
     * locked.
     */
    private void assertLocksAfterMaxFailures(String name) {
        int calls = delegate.calls();
        failLogins(name, FAILURES_TO_LOCK);
        assertEquals(calls + FAILURES_TO_LOCK, delegate.calls(), "Failures that reached the delegate");
        assertRejectedWithoutDelegate(name, password);
    }

    /** Fails a name with the wrong password {@code count} times, every failure reaching the delegate. */
    private void failLogins(String name, int count) {
        for (int i = 0; i < count; i++) {
            int calls = delegate.calls();
            assertBadCredentials(attempt(name, wrongPassword));
            assertEquals(calls + 1, delegate.calls(), "A failure did not reach the delegate");
        }
    }

    /**
     * Expects an attempt to reach the delegate, so its name is not locked, and to end in an outcome that is not
     * counted, so it leaves the counter as it was.
     */
    private void assertReachesTheDelegateUncounted(String name) {
        String outage = delegate.answer(newPassword(), Outcome.OUTAGE);
        int calls = delegate.calls();
        assertThrowsExactly(InternalAuthenticationServiceException.class, () -> authenticate(name, outage));
        assertEquals(calls + 1, delegate.calls(), "The attempt did not reach the delegate");
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

    /** Expects an attempt run in the background to fail like an unreachable directory, which is not counted. */
    private static void assertOutage(Future<@Nullable Authentication> attempt) {
        var thrown = assertThrows(ExecutionException.class, () -> attempt.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
        var cause = assertInstanceOf(InternalAuthenticationServiceException.class, thrown.getCause());
        assertSame(InternalAuthenticationServiceException.class, cause.getClass());
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

    /**
     * Starts {@value #PARALLEL_ATTEMPTS} attempts of a name on their own threads, and lets them all go at once when
     * every one of them runs.
     */
    private List<Future<@Nullable Authentication>> startTogether(String name, String credential)
            throws InterruptedException {
        var ready = new CountDownLatch(PARALLEL_ATTEMPTS);
        var start = new CountDownLatch(1);
        var attempts = new ArrayList<Future<@Nullable Authentication>>(PARALLEL_ATTEMPTS);
        for (int i = 0; i < PARALLEL_ATTEMPTS; i++) {
            attempts.add(executor.submit(() -> {
                ready.countDown();
                await(start);
                return provider.authenticate(attempt(name, credential));
            }));
        }
        assertTrue(ready.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS), "The attempts did not start.");
        start.countDown();
        return attempts;
    }

    private void awaitCalls(int calls) throws InterruptedException {
        awaitUntil(() -> delegate.calls() == calls);
        assertEquals(calls, delegate.calls(), "Attempts that reached the delegate");
    }

    /**
     * Expects a gated attempt to wait at the delegate, rather than to have been rejected without reaching it, once the
     * delegate has received {@code calls} calls in all.
     */
    private void awaitAtTheGate(Future<?> attempt, int calls) throws InterruptedException {
        awaitUntil(() -> delegate.calls() == calls || attempt.isDone());
        assertFalse(attempt.isDone(), "The attempt ended without waiting at the delegate");
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
     * A thread-safe delegate. It counts its calls and the most calls it held at once, holds the calls of a gated
     * credential until that gate opens, and then answers by the credential: the correct password authenticates, a
     * credential given an {@link Outcome} gets it, and any other credential is rejected like a wrong password.
     */
    private static final class GatedDelegate implements AuthenticationProvider {

        private final String password;
        private final AtomicInteger calls = new AtomicInteger();
        private final AtomicInteger inside = new AtomicInteger();
        private final AtomicInteger mostInside = new AtomicInteger();
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

        /** The most calls that were inside this delegate at the same time. */
        int mostAtOnce() {
            return mostInside.get();
        }

        void openAllGates() {
            gates.values().forEach(CountDownLatch::countDown);
        }

        @Override
        public @Nullable Authentication authenticate(Authentication authentication) {
            calls.incrementAndGet();
            mostInside.accumulateAndGet(inside.incrementAndGet(), Math::max);
            try {
                return answer(authentication);
            } finally {
                inside.decrementAndGet();
            }
        }

        private @Nullable Authentication answer(Authentication authentication) {
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

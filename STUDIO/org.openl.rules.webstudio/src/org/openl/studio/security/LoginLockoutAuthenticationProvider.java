package org.openl.studio.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.PriorityQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.openl.studio.security.audit.SecurityAuditLog;

/**
 * V9: temporary lockout after repeated failed logins for the local (multi) and Active Directory providers; state is
 * in JVM memory and cleared on restart.
 * <p>
 * The provider decorates one {@link AuthenticationProvider}, the {@code DaoAuthenticationProvider} of the
 * {@code multi} mode or the {@code ActiveDirectoryLdapAuthenticationProvider} of the {@code ad} mode. Form login and
 * HTTP Basic both authenticate through the authentication manager that holds it, so both are covered. The rules are:
 * </p>
 * <ul>
 * <li>An account locks when its {@value #MAX_FAILURES}th consecutive failed login happens no more than
 * {@link #WINDOW} after the first of them, both ends inclusive. The window slides: a failure older than the window is
 * forgotten.</li>
 * <li>A lock lasts {@link #LOCK_DURATION} from the failure that engaged it. An attempt strictly before the lock ends
 * is rejected without calling the delegate and does not extend the lock. The first attempt at or after its end
 * proceeds with a cleared counter.</li>
 * <li>A successful login clears the counter and the lock, a lock engaged while it was in flight included.</li>
 * <li>Only {@link BadCredentialsException} and {@link UsernameNotFoundException} count as failures. Any other
 * {@link AuthenticationException}, for example an {@code InternalAuthenticationServiceException} while the directory
 * is unreachable, propagates without being counted.</li>
 * <li>A {@link DaoAuthenticationProvider} result whose name differs from the attempt's other than in case
 * ({@link Locale#ROOT}) is a failed login of the attempt's name: the user store matched the name to an account stored
 * under another one, as a database collation that ignores accents or trailing spaces does. It is counted like a wrong
 * password, leaves the counter and the lock of every name in place, and fails like one, so an account authenticates
 * only through its own name, whose counter limits the guesses at its password. The results of other delegates, such
 * as the Active Directory provider, are taken as they are.</li>
 * </ul>
 * <p>
 * A locked attempt fails with {@code new BadCredentialsException("Bad credentials")}, the exception the DAO and AD
 * providers raise for a wrong password, so the HTTP Basic 401 and the form-login failure redirect are identical to
 * those of an ordinary failed login. Names that do not exist are counted and locked exactly like existing ones, so
 * the response never tells whether an account exists.
 * </p>
 * <p>
 * The counter key is a SHA-256 digest of the attempt's name in lower case ({@link Locale#ROOT}), so case variants of
 * one name share one counter, and every key has the same small size however long the name is. Nothing else of the
 * attempt is kept, and its credentials are never read. The lockout audit line records the attempt's name, for a user
 * name and password attempt only, its source address and its attempt type, never its credentials.
 * </p>
 * <p>
 * Every read-modify-write of one key runs inside {@link ConcurrentHashMap#compute} or
 * {@link ConcurrentHashMap#computeIfPresent}, and the delegate is always called outside them. Before its lock is
 * checked, an attempt takes one of the {@value #MAX_ATTEMPTS_IN_FLIGHT} permits of its name and holds it until it
 * ends, so at most that many attempts of one name are in flight at once. The permits are fair: an attempt that finds
 * none free waits for one in arrival order, at most {@link #PERMIT_WAIT}, and if none comes free in that time it fails
 * like a wrong password without reaching the delegate and without being counted. Each failure is counted when it
 * completes, so the {@value #MAX_FAILURES}th completed failure always engages the lock, with at most
 * {@value #MAX_ATTEMPTS_IN_FLIGHT} - 1 other attempts of the name still in flight: at most {@value #MAX_FAILURES} +
 * {@value #MAX_ATTEMPTS_IN_FLIGHT} - 1 wrong passwords of a name reach the delegate per lock, however many arrive at
 * once, while concurrent correct logins of the name wait for a permit and succeed. The permits of a name exist only
 * while an attempt of it waits or is in flight: the first such attempt creates them and the last one to end removes
 * them, so they cost memory per attempt in progress, not per tracked name. Before the delegate is called, an attempt
 * is counted in flight in the entry of its name, and it leaves that count exactly once when it ends. The in-flight
 * count never rejects an attempt: it keeps an entry from being purged as stale while an attempt of the name is in
 * flight, and it tells whether an attempt that ends leaves an entry that can be removed. A success clears the counter
 * and the lock, and removes the entry unless another attempt of the name is still in flight. Every in-flight count
 * belongs to the generation of the entry that took it: a name evicted and tracked again while attempts were in flight
 * starts a new generation, and an attempt of an older generation that ends afterwards leaves the in-flight count of
 * the new one unchanged, although its failure still counts and its success still clears the counter and the lock.
 * The class is thread-safe.
 * </p>
 * <p>
 * The state holds at most {@value #MAX_ENTRIES} names once the attempts in flight have ended. When an attempt takes
 * it above that bound, a guarded pass removes the names whose window and lock have both elapsed and that have no
 * attempt in flight and then, if the state is still above the bound, the names with the oldest last update until it
 * is back at the bound; passes repeat while the state is above the bound. Eviction ignores whether a name exists, so
 * unknown names are treated exactly like known ones. A burst of more than {@value #MAX_ENTRIES} distinct names can
 * therefore evict an older lock or the entry of an attempt in flight; every such failure is still visible in the
 * security audit trail.
 * </p>
 */
public final class LoginLockoutAuthenticationProvider implements AuthenticationProvider {

    /**
     * The number of consecutive failed logins within {@link #WINDOW} that engages a lock.
     */
    static final int MAX_FAILURES = 5;

    /**
     * The sliding window in which {@link #MAX_FAILURES} failed logins engage a lock. A failure exactly this old is
     * still inside the window.
     */
    static final Duration WINDOW = Duration.ofMinutes(15);

    /**
     * How long a lock lasts, measured from the failure that engaged it.
     */
    static final Duration LOCK_DURATION = Duration.ofMinutes(15);

    /**
     * How many attempts of one name may be in flight at once: as many as the failures that engage a lock. The wrong
     * passwords of a name that reach the delegate per lock then stay below twice {@value #MAX_FAILURES}, at most
     * {@value #MAX_FAILURES} + {@value #MAX_ATTEMPTS_IN_FLIGHT} - 1, while the concurrent logins of one client, such
     * as its HTTP Basic requests, still run several at a time instead of one by one.
     */
    static final int MAX_ATTEMPTS_IN_FLIGHT = MAX_FAILURES;

    /**
     * How long an attempt waits for a permit of its name before it fails, uncounted, like a wrong password. Long
     * enough for a queue of legitimate logins of one name, such as the concurrent HTTP Basic requests of one API
     * client, to drain at the delegate's speed: a bcrypt check of the default cost takes about a tenth of a second,
     * so {@value #MAX_ATTEMPTS_IN_FLIGHT} permits pass about fifty attempts a second, and this wait lets a queue of
     * several hundred through. Short enough that a flood of attempts of one name holds a server thread no longer than
     * a client commonly waits for an answer.
     */
    static final Duration PERMIT_WAIT = Duration.ofSeconds(10);

    /**
     * The number of tracked names, each with its failures, lock or attempts in flight, that the guarded cleanup brings
     * the state back to whenever an attempt takes it above this size. It is not a cap at every instant: an attempt
     * adds its name before it cleans, and one that finds another thread cleaning leaves the work to it, so the state
     * can hold more names for a while, and holds at most this many once the attempts in flight have ended. The permit
     * gates of the names are not entries and are not counted.
     */
    static final int MAX_ENTRIES = 10_000;

    /**
     * The message of an attempt the decorator rejects itself, locked, without a permit or matched to another name,
     * which is the default message of the DAO and AD providers for a wrong password.
     */
    private static final String BAD_CREDENTIALS = "Bad credentials";

    /**
     * The digest of the lower-case name that keys the state.
     */
    private static final String KEY_DIGEST = "SHA-256";

    /**
     * The result of a reservation that was refused; every granted reservation names a generation above it.
     */
    private static final long NOT_RESERVED = 0;

    /**
     * How many eviction candidates a full pass selects beyond the current excess. They are kept, oldest first, for
     * the attempts that take the state above the bound next, so a burst of new names costs one traversal of every
     * name per this many names instead of one per name.
     */
    private static final int EVICTION_BATCH = 256;

    /**
     * The age from which an entry can be stale: an entry whose last update is younger than this is inside its window
     * or its lock, whichever applies.
     */
    private static final Duration STALE_AGE = Duration.ofNanos(Math.min(WINDOW.toNanos(), LOCK_DURATION.toNanos()));

    /**
     * Orders eviction candidates by last update, oldest first.
     */
    private static final Comparator<Candidate> OLDEST_FIRST = Comparator
            .comparing((Candidate candidate) -> candidate.entry().lastUpdate());

    /**
     * Orders eviction candidates newest first, so the head of a bounded heap is the newest of the oldest entries.
     */
    private static final Comparator<Candidate> NEWEST_FIRST = OLDEST_FIRST.reversed();

    private final AuthenticationProvider delegate;
    private final Clock clock;

    /**
     * Whether the delegate is the DAO provider, whose user store can match a name to an account stored under another
     * one, so a result of another name is a failed login of the attempt's name.
     */
    private final boolean checksResultName;

    /**
     * How long, in nanoseconds, an attempt waits for a permit of its name.
     */
    private final long permitWaitNanos;

    /**
     * The permit gates of the names that have an attempt waiting for a permit or in flight, by counter key. They are
     * not entries: the first attempt of a name creates its gate and the last one to end removes it, so their number
     * is bounded by the attempts in progress, independently of {@link #MAX_ENTRIES}.
     */
    private final ConcurrentHashMap<String, Gate> gates = new ConcurrentHashMap<>();

    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();
    private final AtomicBoolean cleaning = new AtomicBoolean();

    /**
     * The last generation given to a new entry. Each entry a name gets, first or after an eviction, has its own, so
     * an attempt leaves the in-flight count only of the entry that counted it.
     */
    private final AtomicLong generations = new AtomicLong(NOT_RESERVED);

    /**
     * The live entries the last full pass selected beyond those it evicted, oldest first. Read and written only by
     * the thread that holds {@link #cleaning}; the atomic flag orders those accesses between threads.
     */
    private final ArrayDeque<Candidate> pending = new ArrayDeque<>();

    /**
     * The instant the last full pass judged the entries against. Guarded like {@link #pending}.
     */
    private Instant pendingSince = Instant.MIN;

    /**
     * Creates a lockout decorator.
     *
     * @param delegate the provider that verifies the credentials
     * @param clock    the clock that stamps failures and measures windows and locks
     */
    public LoginLockoutAuthenticationProvider(AuthenticationProvider delegate, Clock clock) {
        this(delegate, clock, PERMIT_WAIT);
    }

    /**
     * Creates a lockout decorator whose attempts wait for a permit of their name at most the given time instead of
     * {@link #PERMIT_WAIT}.
     *
     * @param delegate   the provider that verifies the credentials
     * @param clock      the clock that stamps failures and measures windows and locks
     * @param permitWait how long an attempt waits for a permit; with zero or less it fails at once when none is free
     */
    LoginLockoutAuthenticationProvider(AuthenticationProvider delegate, Clock clock, Duration permitWait) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.checksResultName = delegate instanceof DaoAuthenticationProvider;
        this.permitWaitNanos = Objects.requireNonNull(permitWait, "permitWait").toNanos();
    }

    /**
     * Waits for a permit of the attempt's name, then rejects the attempt while its name is locked; otherwise delegates
     * it, clears the counter and the lock on success and counts a rejected credential.
     *
     * @param authentication the authentication attempt
     * @return the authenticated result of the delegate, or {@code null} when the delegate does not handle the attempt
     * @throws BadCredentialsException   without calling the delegate and without being counted: when no permit of
     *                                   the name comes free within the wait, when the waiting thread is interrupted,
     *                                   whose interrupt status is restored, or while the name is locked. Counted:
     *                                   when the delegate rejects the credentials, rethrown unchanged, or when the
     *                                   DAO delegate authenticates an account whose name differs from the attempt's
     *                                   other than in case, thrown as
     *                                   {@code new BadCredentialsException("Bad credentials")}
     * @throws UsernameNotFoundException when the delegate does not know the name, counted like a wrong password and
     *                                   rethrown unchanged
     * @throws AuthenticationException   any other failure of the delegate, unchanged and not counted
     */
    @Override
    public @Nullable Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String key = keyOf(authentication);
        Semaphore permits = enterGate(key);
        try {
            acquire(permits);
            try {
                return authenticateWithPermit(authentication, key);
            } finally {
                permits.release();
            }
        } finally {
            leaveGate(key);
        }
    }

    /**
     * Authenticates an attempt that holds a permit of its name: rejects it while the name is locked, otherwise
     * delegates it and records its outcome.
     */
    private @Nullable Authentication authenticateWithPermit(Authentication authentication, String key) {
        Instant now = clock.instant();
        long generation = reserve(key, now);
        if (generation == NOT_RESERVED) {
            throw new BadCredentialsException(BAD_CREDENTIALS);
        }

        // Every reservation is released exactly once, whatever ends the attempt.
        boolean released = false;
        try {
            evictIfNeeded(now);
            Authentication result;
            try {
                result = delegate.authenticate(authentication);
                if (result != null && checksResultName && !key.equals(keyOf(result))) {
                    // The store matched another name to the account: counted and thrown like a wrong password.
                    throw new BadCredentialsException(BAD_CREDENTIALS);
                }
            } catch (BadCredentialsException | UsernameNotFoundException e) {
                Instant failedAt = clock.instant();
                boolean engaged = recordFailure(key, failedAt, generation);
                released = true;
                if (engaged) {
                    SecurityAuditLog.lockout(authentication); // V11: audit line for an engaged lock
                }
                evictIfNeeded(failedAt);
                throw e;
            }

            if (result != null) {
                // A successful login clears the counter and the lock.
                recordSuccess(key, clock.instant(), generation);
                released = true;
            }
            return result;
        } finally {
            if (!released) {
                release(key, generation);
            }
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return delegate.supports(authentication);
    }

    /**
     * Returns the number of names currently tracked.
     *
     * @return the number of entries
     */
    int size() {
        return entries.size();
    }

    /**
     * Returns the number of attempts of the name with the given counter key that wait for a permit or hold one.
     *
     * @param key the counter key of the name
     * @return the attempts at the gate of the name, {@code 0} when it has no gate
     */
    int attemptsAtGate(String key) {
        Gate gate = gates.get(key);
        return gate == null ? 0 : gate.attempts();
    }

    /**
     * Counts an attempt at the gate of its name, atomically, and returns the permits of that gate. The first attempt
     * of a name creates its gate; every later one shares it until the last of them leaves.
     */
    private Semaphore enterGate(String key) {
        Gate gate = gates.compute(key, (k, current) -> current == null
                ? new Gate(new Semaphore(MAX_ATTEMPTS_IN_FLIGHT, true), 1)
                : new Gate(current.permits(), current.attempts() + 1));
        return Objects.requireNonNull(gate).permits();
    }

    /**
     * Takes an attempt that has ended out of the gate of its name, atomically, and removes the gate when it was the
     * last attempt there.
     */
    private void leaveGate(String key) {
        gates.computeIfPresent(key, (k, gate) -> gate.attempts() == 1
                ? null
                : new Gate(gate.permits(), gate.attempts() - 1));
    }

    /**
     * Takes a permit, waiting for one in arrival order for at most the permit wait.
     *
     * @throws BadCredentialsException when no permit comes free in time, or the thread is interrupted while it waits,
     *                                 which restores its interrupt status; the attempt is not counted
     */
    private void acquire(Semaphore permits) {
        boolean acquired;
        try {
            acquired = permits.tryAcquire(permitWaitNanos, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new BadCredentialsException(BAD_CREDENTIALS);
        }
        if (!acquired) {
            throw new BadCredentialsException(BAD_CREDENTIALS);
        }
    }

    /**
     * The counter key of an attempt: the SHA-256 digest of its name in lower case, in hexadecimal. Case variants
     * share one counter, and every key has the same 64 characters however long the name is, so the state retains
     * no attempt's name.
     *
     * @param authentication the authentication attempt
     * @return the counter key of its name
     */
    static String keyOf(Authentication authentication) {
        String name = Objects.toString(authentication.getName(), "").toLowerCase(Locale.ROOT);
        try {
            byte[] digest = MessageDigest.getInstance(KEY_DIGEST).digest(name.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            // Every Java platform must provide SHA-256.
            throw new IllegalStateException("The " + KEY_DIGEST + " digest is not available.", e);
        }
    }

    /**
     * Counts an attempt of the name in flight atomically, before the delegate is called. The attempt is refused only
     * while the name is locked; a refused attempt leaves the entry unchanged, so it neither extends the lock nor counts
     * as a failure. A lock that has elapsed is cleared together with the counter, so the attempt proceeds from zero.
     * An unlocked name holds fewer than {@link #MAX_FAILURES} failures, because the failure that completes that many
     * engages the lock, so its attempt always proceeds; the permits of the name, taken before, bound how many of its
     * attempts are in flight. The attempt keeps the last update of an entry whose counter it keeps; a new entry, or
     * one whose elapsed lock it clears, is stamped with the attempt's instant. A new entry gets a new generation, and
     * an existing one keeps its own.
     *
     * @return the generation of the entry that counts the attempt in flight, or {@link #NOT_RESERVED} if the attempt
     *         is refused and must not reach the delegate
     */
    private long reserve(String key, Instant now) {
        var reserved = new long[]{NOT_RESERVED};
        entries.compute(key, (k, entry) -> {
            if (entry == null) {
                long generation = generations.incrementAndGet();
                reserved[0] = generation;
                return new Entry(List.of(), null, now, 1, generation);
            }
            Instant lockedUntil = entry.lockedUntil();
            if (lockedUntil != null) {
                if (now.isBefore(lockedUntil)) {
                    return entry;
                }
                reserved[0] = entry.generation();
                return new Entry(List.of(), null, now, entry.inFlight() + 1, entry.generation());
            }
            reserved[0] = entry.generation();
            return new Entry(inWindow(entry.failures(), now), null, entry.lastUpdate(), entry.inFlight() + 1,
                    entry.generation());
        });
        return reserved[0];
    }

    /**
     * Counts one failed login of the name and ends the attempt's in-flight count, atomically. A name evicted while the
     * attempt was in flight is counted again from this failure, in a new generation; an entry of a newer generation
     * counts the failure but keeps its in-flight count, which does not include this attempt.
     *
     * @param generation the generation of the entry that counted the attempt in flight
     * @return {@code true} if this failure engaged a lock
     */
    private boolean recordFailure(String key, Instant failedAt, long generation) {
        var engaged = new boolean[1];
        entries.compute(key, (k, entry) -> {
            List<Instant> previous = List.of();
            int inFlight = 0;
            long current;
            if (entry == null) {
                current = generations.incrementAndGet();
            } else {
                Entry released = entry.released(generation);
                inFlight = released.inFlight();
                current = entry.generation();
                Instant lockedUntil = entry.lockedUntil();
                if (lockedUntil == null) {
                    previous = entry.failures();
                } else if (failedAt.isBefore(lockedUntil)) {
                    // Another attempt has engaged the lock: this failure neither counts nor extends it.
                    return released;
                }
                // Otherwise the lock has elapsed, and the count starts again from this failure.
            }
            var failures = new ArrayList<>(inWindow(previous, failedAt));
            failures.add(failedAt);
            if (failures.size() >= MAX_FAILURES) {
                engaged[0] = true;
                return new Entry(List.of(), failedAt.plus(LOCK_DURATION), failedAt, inFlight, current);
            }
            // Concurrent threads may stamp their failures out of order; keep the list oldest first.
            failures.sort(Comparator.naturalOrder());
            return new Entry(failures, null, failedAt, inFlight, current);
        });
        return engaged[0];
    }

    /**
     * Resets the name after a successful login and ends the attempt's in-flight count, atomically: the counter and
     * the lock are cleared, a lock other attempts engaged while this one was in flight included, and the entry is
     * removed. Only while other attempts of the name are still in flight is the cleared entry kept, with their
     * in-flight count, so their outcomes are still told apart by generation. The success of an attempt whose entry was
     * evicted meanwhile resets the entry of the newer generation the same way but keeps its in-flight count, which
     * does not include this attempt.
     *
     * @param generation the generation of the entry that counted the attempt in flight
     */
    private void recordSuccess(String key, Instant now, long generation) {
        entries.computeIfPresent(key, (k, entry) -> {
            Entry released = entry.released(generation);
            return released.inFlight() == 0
                    ? null
                    : new Entry(List.of(), null, now, released.inFlight(), entry.generation());
        });
    }

    /**
     * Ends the in-flight count of an attempt that ended in neither a counted failure nor a success, atomically: the
     * delegate did not handle it, or failed in a way that is not counted. An entry of a newer generation is left
     * unchanged. An entry left with no failure, no lock and no attempt in flight is removed.
     *
     * @param generation the generation of the entry that counted the attempt in flight
     */
    private void release(String key, long generation) {
        entries.computeIfPresent(key, (k, entry) -> {
            Entry released = entry.released(generation);
            boolean empty = released.failures().isEmpty() && released.lockedUntil() == null
                    && released.inFlight() == 0;
            return empty ? null : released;
        });
    }

    /**
     * Returns the failures still inside the window at the given instant, oldest first. A failure exactly
     * {@link #WINDOW} old is still inside.
     */
    private static List<Instant> inWindow(List<Instant> failures, Instant now) {
        Instant windowStart = now.minus(WINDOW);
        var kept = new ArrayList<Instant>(MAX_FAILURES);
        for (Instant failure : failures) {
            if (!failure.isBefore(windowStart)) {
                kept.add(failure);
            }
        }
        return kept;
    }

    /**
     * Brings the state back to {@link #MAX_ENTRIES} names after an attempt has taken it above that bound: first the
     * names whose window and lock have both elapsed and that have no attempt in flight are removed, then the names
     * with the oldest last update are evicted until the state is back at the bound. Only one thread cleans at a time.
     * A thread that finds another one cleaning leaves the work to it, and a cleaner reads the size again each time it
     * lets go of the guard and cleans again while the state is above the bound: names may have been added during its
     * pass, or a pass may run out of candidates because the names it chose were updated meanwhile. A cleaner lets go
     * of the guard before it reads the size, and an attempt reads the guard only after it has added its name, so of
     * the two at least one sees the other, and the state is back at the bound once the attempts in flight have ended.
     * <p>
     * A full pass traverses every name. To keep a burst of new names from paying one traversal per name, the pass
     * selects {@value #EVICTION_BATCH} candidates beyond the current excess and keeps them for the next attempts that
     * take the state above the bound. Those attempts evict from the kept candidates without a traversal, which gives
     * the same result as a full pass for as long as no name can have become stale and the clock has not gone back:
     * every name that is not a kept candidate is then newer than all of them.
     * </p>
     *
     * @param now the instant stale names are judged against
     */
    private void evictIfNeeded(Instant now) {
        while (entries.size() > MAX_ENTRIES && cleaning.compareAndSet(false, true)) {
            try {
                if (!canEvictPending(now) || !evictPending()) {
                    fullPass(now);
                }
            } finally {
                cleaning.set(false);
            }
        }
    }

    /**
     * Tells whether the kept candidates may still be evicted in place of a full pass: the clock has not gone back
     * since that pass, and even the oldest kept candidate is younger than {@link #STALE_AGE}, so no name can have
     * become stale since.
     */
    private boolean canEvictPending(Instant now) {
        Candidate oldest = pending.peekFirst();
        return oldest != null
                && !now.isBefore(pendingSince)
                && now.minus(STALE_AGE).isBefore(oldest.entry().lastUpdate());
    }

    /**
     * Evicts the kept candidates, oldest first, until the state is back at the bound. A candidate is removed only
     * while its name still holds the entry that was judged, so a name updated since is kept.
     *
     * @return {@code true} if the state is back at the bound, {@code false} if the candidates ran out first
     */
    private boolean evictPending() {
        while (entries.size() > MAX_ENTRIES) {
            Candidate candidate = pending.pollFirst();
            if (candidate == null) {
                return false;
            }
            entries.remove(candidate.key(), candidate.entry());
        }
        return true;
    }

    /**
     * Traverses every name once: stale names are removed, and a heap bounded to the excess plus
     * {@value #EVICTION_BATCH} collects the live names with the oldest last update in O(n log k), instead of sorting
     * every name. The candidates become the new kept candidates, and the oldest are evicted until the state is back at
     * the bound or they run out; in that case the state is still above the bound, and {@link #evictIfNeeded} passes
     * again.
     */
    private void fullPass(Instant now) {
        Instant windowStart = now.minus(WINDOW);
        int capacity = Math.max(entries.size() - MAX_ENTRIES, 0) + EVICTION_BATCH;
        var oldest = new PriorityQueue<Candidate>(capacity + 1, NEWEST_FIRST);
        entries.forEach((key, entry) -> {
            if (isStale(entry, now, windowStart)) {
                // Re-checked atomically, so an entry updated since it was read is kept.
                entries.computeIfPresent(key, (k, current) -> isStale(current, now, windowStart) ? null : current);
            } else if (oldest.size() < capacity) {
                oldest.add(new Candidate(key, entry));
            } else if (entry.lastUpdate().isBefore(oldest.element().entry().lastUpdate())) {
                // Older than the newest candidate, the head of the heap: it replaces that candidate.
                oldest.remove();
                oldest.add(new Candidate(key, entry));
            }
        });

        var candidates = new ArrayList<>(oldest);
        candidates.sort(OLDEST_FIRST);
        pending.clear();
        pending.addAll(candidates);
        pendingSince = now;
        // When the candidates run out first, the state is still above the bound, and evictIfNeeded passes again.
        evictPending();
    }

    /**
     * Tells whether an entry no longer matters: no attempt of the name is in flight, and its lock has elapsed, or it
     * is unlocked and holds no failure inside the window. The failures are oldest first, so the newest decides.
     */
    private static boolean isStale(Entry entry, Instant now, Instant windowStart) {
        if (entry.inFlight() > 0) {
            return false;
        }
        Instant lockedUntil = entry.lockedUntil();
        if (lockedUntil != null) {
            return !now.isBefore(lockedUntil);
        }
        List<Instant> failures = entry.failures();
        return failures.isEmpty() || failures.getLast().isBefore(windowStart);
    }

    /**
     * The tracked state of one name.
     *
     * @param failures    the failures still inside the window, oldest first, at most {@link #MAX_FAILURES}; empty
     *                    while locked
     * @param lockedUntil the instant the lock ends, or {@code null} when the name is not locked
     * @param lastUpdate  the instant of the last failure, lock or cleared counter recorded for the name, or of the
     *                    attempt that created the entry; an attempt counted in flight in an existing entry keeps it
     * @param inFlight    the attempts of the name that this entry counted in flight and that have not ended yet,
     *                    never negative; it never rejects an attempt
     * @param generation  the generation of the entry, given when the name gets it and kept while the name stays
     *                    tracked, so the attempts it counts in flight are told apart from those of an evicted one
     */
    private record Entry(List<Instant> failures,
                         @Nullable Instant lockedUntil,
                         Instant lastUpdate,
                         int inFlight,
                         long generation) {

        private Entry {
            failures = List.copyOf(failures);
        }

        /**
         * Returns this entry with an attempt that ended taken out of its in-flight count. Only an attempt this entry
         * counted is in that count; for the attempt of an older, evicted generation the entry is returned unchanged.
         * The count never drops below zero.
         *
         * @param reservation the generation of the entry that counted the attempt in flight
         */
        private Entry released(long reservation) {
            if (reservation != generation) {
                return this;
            }
            return new Entry(failures, lockedUntil, lastUpdate, Math.max(inFlight - 1, 0), generation);
        }
    }

    /**
     * The permit gate of one name.
     *
     * @param permits  the fair semaphore of {@link #MAX_ATTEMPTS_IN_FLIGHT} permits that the attempts of the name take
     *                 before they are checked against the lock, and give back when they end
     * @param attempts the attempts of the name that wait for a permit or hold one, at least one
     */
    private record Gate(Semaphore permits, int attempts) {
    }

    /**
     * A name considered for eviction, with the entry it held when it was read.
     *
     * @param key   the counter key
     * @param entry the entry read for the key
     */
    private record Candidate(String key, Entry entry) {
    }
}

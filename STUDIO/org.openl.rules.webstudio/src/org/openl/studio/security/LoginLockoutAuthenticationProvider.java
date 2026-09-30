package org.openl.studio.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.PriorityQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
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
 * <li>A successful login clears the counter.</li>
 * <li>Only {@link BadCredentialsException} and {@link UsernameNotFoundException} count as failures. Any other
 * {@link AuthenticationException}, for example an {@code InternalAuthenticationServiceException} while the directory
 * is unreachable, propagates without being counted.</li>
 * </ul>
 * <p>
 * A locked attempt fails with {@code new BadCredentialsException("Bad credentials")}, the exception the DAO and AD
 * providers raise for a wrong password, so the HTTP Basic 401 and the form-login failure redirect are identical to
 * those of an ordinary failed login. Names that do not exist are counted and locked exactly like existing ones, so
 * the response never tells whether an account exists.
 * </p>
 * <p>
 * The counter key is the attempt's name in lower case ({@link Locale#ROOT}), so case variants of one name share one
 * counter. Nothing else of the attempt is kept or logged: its credentials are never read.
 * </p>
 * <p>
 * Every read-modify-write of one key runs inside {@link ConcurrentHashMap#compute} or
 * {@link ConcurrentHashMap#computeIfPresent}, so concurrent failures of one name are counted one after another and
 * the {@value #MAX_FAILURES}th always engages the lock. The class is thread-safe.
 * </p>
 * <p>
 * The state holds at most {@value #MAX_ENTRIES} names. When a failure takes it above that bound, one guarded pass
 * removes the names whose window and lock have both elapsed and then, if the state is still above the bound, the
 * names with the oldest last update until it is back at the bound. Eviction ignores whether a name exists, so unknown
 * names are treated exactly like known ones. A burst of more than {@value #MAX_ENTRIES} distinct names can therefore
 * evict an older lock; every such failure is still visible in the security audit trail.
 * </p>
 */
@Slf4j
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
     * The maximum number of names whose failures or lock are tracked at once.
     */
    static final int MAX_ENTRIES = 10_000;

    /**
     * The message of a locked attempt, which is the default message of the DAO and AD providers for a wrong password.
     */
    private static final String BAD_CREDENTIALS = "Bad credentials";

    /**
     * How many eviction candidates a full pass selects beyond the current excess. They are kept, oldest first, for
     * the failures that take the state above the bound next, so a burst of new names costs one traversal of every
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
    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();
    private final AtomicBoolean cleaning = new AtomicBoolean();

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
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Rejects the attempt while its name is locked; otherwise delegates it, clears the counter on success and counts
     * a rejected credential.
     *
     * @param authentication the authentication attempt
     * @return the authenticated result of the delegate, or {@code null} when the delegate does not handle the attempt
     * @throws BadCredentialsException while the name is locked, or when the delegate rejects the credentials
     * @throws AuthenticationException any other failure of the delegate, unchanged and not counted
     */
    @Override
    public @Nullable Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String key = keyOf(authentication);
        if (isLocked(key, clock.instant())) {
            throw new BadCredentialsException(BAD_CREDENTIALS);
        }

        Authentication result;
        try {
            result = delegate.authenticate(authentication);
        } catch (BadCredentialsException | UsernameNotFoundException e) {
            Instant failedAt = clock.instant();
            if (recordFailure(key, failedAt)) {
                log.debug("An account has been locked for {} after {} failed logins.", LOCK_DURATION, MAX_FAILURES);
                SecurityAuditLog.lockout(authentication); // V11: audit line for an engaged lock
            }
            evictIfNeeded(failedAt);
            throw e;
        }

        if (result != null) {
            // A successful login clears the counter.
            entries.remove(key);
        }
        return result;
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
     * The counter key of an attempt: its name in lower case, so case variants share one counter.
     */
    private static String keyOf(Authentication authentication) {
        return Objects.toString(authentication.getName(), "").toLowerCase(Locale.ROOT);
    }

    /**
     * Tells whether the name is locked at the given instant. A lock that has elapsed is removed together with the
     * counter, so the attempt proceeds from zero. A locked attempt leaves the entry unchanged, so it neither extends
     * the lock nor counts as a failure.
     */
    private boolean isLocked(String key, Instant now) {
        var locked = new boolean[1];
        entries.computeIfPresent(key, (k, entry) -> {
            Instant lockedUntil = entry.lockedUntil();
            if (lockedUntil == null) {
                return entry;
            }
            if (now.isBefore(lockedUntil)) {
                locked[0] = true;
                return entry;
            }
            return null;
        });
        return locked[0];
    }

    /**
     * Counts one failed login of the name atomically.
     *
     * @return {@code true} if this failure engaged a lock
     */
    private boolean recordFailure(String key, Instant failedAt) {
        var engaged = new boolean[1];
        entries.compute(key, (k, entry) -> {
            List<Instant> previous = List.of();
            if (entry != null) {
                Instant lockedUntil = entry.lockedUntil();
                if (lockedUntil == null) {
                    previous = entry.failures();
                } else if (failedAt.isBefore(lockedUntil)) {
                    // A concurrent attempt has engaged the lock: this failure neither counts nor extends it.
                    return entry;
                }
                // Otherwise the lock has elapsed, and the count starts again from this failure.
            }
            Instant windowStart = failedAt.minus(WINDOW);
            var failures = new ArrayList<Instant>(MAX_FAILURES);
            for (Instant failure : previous) {
                if (!failure.isBefore(windowStart)) {
                    failures.add(failure);
                }
            }
            failures.add(failedAt);
            if (failures.size() >= MAX_FAILURES) {
                engaged[0] = true;
                return new Entry(List.of(), failedAt.plus(LOCK_DURATION), failedAt);
            }
            // Concurrent threads may stamp their failures out of order; keep the list oldest first.
            failures.sort(Comparator.naturalOrder());
            return new Entry(failures, null, failedAt);
        });
        return engaged[0];
    }

    /**
     * Brings the state back to {@link #MAX_ENTRIES} names after a failure has taken it above that bound: first the
     * names whose window and lock have both elapsed are removed, then the names with the oldest last update are
     * evicted until the state is back at the bound. Only one thread cleans at a time; a failure that arrives meanwhile
     * skips the cleaning, and the next one catches up.
     * <p>
     * A full pass traverses every name. To keep a burst of new names from paying one traversal per name, the pass
     * selects {@value #EVICTION_BATCH} candidates beyond the current excess and keeps them for the next failures that
     * take the state above the bound. Those failures evict from the kept candidates without a traversal, which gives
     * the same result as a full pass for as long as no name can have become stale and the clock has not gone back:
     * every name that is not a kept candidate is then newer than all of them.
     * </p>
     *
     * @param now the instant stale names are judged against
     */
    private void evictIfNeeded(Instant now) {
        if (entries.size() <= MAX_ENTRIES || !cleaning.compareAndSet(false, true)) {
            return;
        }
        try {
            if (!canEvictPending(now) || !evictPending()) {
                fullPass(now);
            }
        } finally {
            cleaning.set(false);
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
     * the bound.
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
        evictPending();
        log.debug("Login failure tracking was cleaned to {} entries.", entries.size());
    }

    /**
     * Tells whether an entry no longer matters: its lock has elapsed, or it is unlocked and every failure is older
     * than the window. An unlocked entry always holds at least one failure, oldest first, so its newest failure
     * decides.
     */
    private static boolean isStale(Entry entry, Instant now, Instant windowStart) {
        Instant lockedUntil = entry.lockedUntil();
        if (lockedUntil != null) {
            return !now.isBefore(lockedUntil);
        }
        return entry.failures().getLast().isBefore(windowStart);
    }

    /**
     * The tracked state of one name.
     *
     * @param failures    the failures still inside the window, oldest first, at most {@link #MAX_FAILURES}; empty
     *                    while locked
     * @param lockedUntil the instant the lock ends, or {@code null} when the name is not locked
     * @param lastUpdate  the instant of the last failure recorded for the name
     */
    private record Entry(List<Instant> failures, @Nullable Instant lockedUntil, Instant lastUpdate) {

        private Entry {
            failures = List.copyOf(failures);
        }
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

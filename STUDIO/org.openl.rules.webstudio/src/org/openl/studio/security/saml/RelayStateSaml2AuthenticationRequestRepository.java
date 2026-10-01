package org.openl.studio.security.saml;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jspecify.annotations.Nullable;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;

/**
 * V3: stores SAML AuthnRequests by {@code RelayState} instead of in the HTTP session, because the
 * {@code SameSite=Lax} session cookie is not sent on the IdP's cross-site POST; bounded (10,000) and expiring
 * (5 minutes).
 * <p>
 * The SAML response reaches Studio as a cross-site HTTP-POST from the IdP, and browsers do not attach a
 * {@code SameSite=Lax} cookie to such a request. A session-backed store would therefore lose the saved AuthnRequest
 * at the callback, and its {@code InResponseTo} could not be matched. The AuthnRequest resolver generates a random
 * {@code RelayState} for every request, and the IdP echoes it back as the {@code RelayState} form parameter, so this
 * repository keys each saved request by that value and never touches the HTTP session.
 * </p>
 * <p>
 * A request without a {@code RelayState}, or without a live entry for it, yields {@code null}, which is what the
 * session repository returns when nothing was saved. Unsolicited IdP-initiated responses therefore behave as before.
 * </p>
 * <p>
 * Entries expire {@link #TTL} after they are saved. The store holds at most {@link #MAX_ENTRIES} entries: expired
 * entries are purged on each save, and the entry with the oldest save time is evicted when the store is still full.
 * Any visitor, anonymous ones included, triggers a save by starting a SAML login, so a save never scans the store:
 * an index orders the entries by save time. Saves and removals are serialized on one lock, which keeps the cap and
 * the index exact under concurrency, and each costs O(log n) plus the expired entries it purges. Loads are
 * lock-free, and every single-key update is atomic. Spring's {@code CacheSaml2AuthenticationRequestRepository} is
 * not used because it is unbounded and rejects a request without {@code RelayState}.
 * </p>
 */
public final class RelayStateSaml2AuthenticationRequestRepository
        implements Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> {

    /**
     * How long a saved AuthnRequest stays usable. An entry is live strictly before this duration has elapsed.
     */
    static final Duration TTL = Duration.ofMinutes(5);

    /**
     * The maximum number of AuthnRequests held at once.
     */
    static final int MAX_ENTRIES = 10_000;

    /**
     * Orders entries from the oldest save to the newest. Every entry lives for the same {@link #TTL}, so expiry order
     * is save order; the unique sequence orders entries saved at the same instant and keeps distinct entries apart.
     */
    private static final Comparator<Entry> SAVE_ORDER = Comparator.comparing(Entry::expiresAt)
            .thenComparingLong(Entry::sequence);

    private final Clock clock;
    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();
    private final Object saveLock = new Object();

    /**
     * Exactly the values of {@link #entries}, in {@link #SAVE_ORDER}, whenever {@link #saveLock} is free. Guarded by
     * {@link #saveLock}, like every change to {@link #entries}.
     */
    private final NavigableSet<Entry> saveOrder = new TreeSet<>(SAVE_ORDER);

    /**
     * The sequence of the next saved entry. Guarded by {@link #saveLock}.
     */
    private long nextSequence;

    /**
     * Creates a repository that measures expiry with the system UTC clock.
     */
    public RelayStateSaml2AuthenticationRequestRepository() {
        this(Clock.systemUTC());
    }

    /**
     * Creates a repository that measures expiry with the given clock.
     *
     * @param clock the clock used to stamp and expire entries
     */
    RelayStateSaml2AuthenticationRequestRepository(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Returns the saved AuthnRequest whose {@code RelayState} matches the request's {@code RelayState} parameter. The
     * entry is kept, because the authentication filter removes it after the response has been converted.
     *
     * @param request the SAML response callback
     * @return the live AuthnRequest, or {@code null} when the request has no {@code RelayState} or no live entry
     */
    @Override
    public @Nullable AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
        String relayState = relayState(request);
        if (relayState == null) {
            return null;
        }
        return liveRequest(entries.get(relayState));
    }

    /**
     * Saves the AuthnRequest under its own {@code RelayState}, replacing an entry saved under the same value and
     * restarting its expiry. A request without a {@code RelayState} cannot be matched at the callback and is not
     * stored. A {@code null} AuthnRequest removes the entry keyed by the request's {@code RelayState} parameter, as
     * the session repository removes its saved request; nothing is removed when the request carries none.
     *
     * @param authenticationRequest the AuthnRequest sent to the IdP, or {@code null} to remove the saved one
     * @param request the request that initiated the login; its session is never used
     * @param response the response of the initiating request; not used
     */
    @Override
    public void saveAuthenticationRequest(@Nullable AbstractSaml2AuthenticationRequest authenticationRequest,
                                          HttpServletRequest request,
                                          HttpServletResponse response) {
        if (authenticationRequest == null) {
            removeAuthenticationRequest(request, response);
            return;
        }
        String relayState = nonBlank(authenticationRequest.getRelayState());
        if (relayState == null) {
            return;
        }
        synchronized (saveLock) {
            Instant now = clock.instant();
            purgeExpired(now);
            if (!entries.containsKey(relayState) && entries.size() >= MAX_ENTRIES) {
                discard(saveOrder.first());
            }
            Entry saved = new Entry(relayState, authenticationRequest, now.plus(TTL), nextSequence++);
            Entry replaced = entries.put(relayState, saved);
            if (replaced != null) {
                saveOrder.remove(replaced);
            }
            saveOrder.add(saved);
        }
    }

    /**
     * Removes the saved AuthnRequest whose {@code RelayState} matches the request's {@code RelayState} parameter. An
     * expired entry is removed as well, but is not returned.
     *
     * @param request the SAML response callback
     * @param response the response of the callback; not used
     * @return the removed live AuthnRequest, or {@code null} when the request has no {@code RelayState} or no live
     *         entry
     */
    @Override
    public @Nullable AbstractSaml2AuthenticationRequest removeAuthenticationRequest(HttpServletRequest request,
                                                                                   HttpServletResponse response) {
        String relayState = relayState(request);
        if (relayState == null) {
            return null;
        }
        Entry removed;
        synchronized (saveLock) {
            removed = entries.remove(relayState);
            if (removed != null) {
                saveOrder.remove(removed);
            }
        }
        return liveRequest(removed);
    }

    /**
     * Returns the number of entries currently held, expired ones included until the next save purges them.
     *
     * @return the number of stored entries
     */
    int size() {
        return entries.size();
    }

    /**
     * Removes the expired entries, oldest first. Expiry follows save order, so the walk stops at the first live entry
     * and costs O(log n) per purged entry. Called only while {@link #saveLock} is held.
     *
     * @param now the current instant
     */
    private void purgeExpired(Instant now) {
        while (!saveOrder.isEmpty()) {
            Entry oldest = saveOrder.first();
            if (oldest.isLive(now)) {
                return;
            }
            discard(oldest);
        }
    }

    /**
     * Removes the entry from the store and from the save-order index. Called only while {@link #saveLock} is held, so
     * no other save or removal can replace that entry concurrently.
     *
     * @param entry an entry currently held
     */
    private void discard(Entry entry) {
        saveOrder.remove(entry);
        entries.remove(entry.relayState(), entry);
    }

    private @Nullable AbstractSaml2AuthenticationRequest liveRequest(@Nullable Entry entry) {
        return entry != null && entry.isLive(clock.instant()) ? entry.request() : null;
    }

    private static @Nullable String relayState(HttpServletRequest request) {
        return nonBlank(request.getParameter(Saml2ParameterNames.RELAY_STATE));
    }

    private static @Nullable String nonBlank(@Nullable String value) {
        return value == null || value.isBlank() ? null : value;
    }

    /**
     * A saved AuthnRequest, its key, when it expires and its position among saves.
     *
     * @param relayState the {@code RelayState} the request is stored under
     * @param request the saved AuthnRequest
     * @param expiresAt the instant {@link #TTL} after the request was saved
     * @param sequence the unique, increasing number of the save that stored the request
     */
    private record Entry(String relayState,
                         AbstractSaml2AuthenticationRequest request,
                         Instant expiresAt,
                         long sequence) {

        /**
         * Tells whether the entry is still usable: strictly before {@link #TTL} has elapsed since it was saved.
         *
         * @param now the current instant
         * @return {@code true} if the entry has not expired
         */
        boolean isLive(Instant now) {
            return now.isBefore(expiresAt);
        }
    }
}

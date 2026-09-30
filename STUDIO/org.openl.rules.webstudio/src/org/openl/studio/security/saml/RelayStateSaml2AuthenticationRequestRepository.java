package org.openl.studio.security.saml;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Objects;
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
 * Saves are serialized so the cap holds under concurrency; loads and removals are lock-free, and every single-key
 * update is atomic. Spring's {@code CacheSaml2AuthenticationRequestRepository} is not used because it is unbounded
 * and rejects a request without {@code RelayState}.
 * </p>
 */
public final class RelayStateSaml2AuthenticationRequestRepository implements Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> {

    /**
     * How long a saved AuthnRequest stays usable. An entry is live strictly before this duration has elapsed.
     */
    static final Duration TTL = Duration.ofMinutes(5);

    /**
     * The maximum number of AuthnRequests held at once.
     */
    static final int MAX_ENTRIES = 10_000;

    private final Clock clock;
    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();
    private final Object saveLock = new Object();

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
     * Saves the AuthnRequest under its own {@code RelayState}. A request without a {@code RelayState} cannot be
     * matched at the callback and is not stored.
     *
     * @param authenticationRequest the AuthnRequest sent to the IdP
     * @param request the request that initiated the login; its session is never used
     * @param response the response of the initiating request; not used
     */
    @Override
    public void saveAuthenticationRequest(@Nullable AbstractSaml2AuthenticationRequest authenticationRequest,
                                          HttpServletRequest request,
                                          HttpServletResponse response) {
        if (authenticationRequest == null) {
            return;
        }
        String relayState = nonBlank(authenticationRequest.getRelayState());
        if (relayState == null) {
            return;
        }
        synchronized (saveLock) {
            Instant now = clock.instant();
            // The values view removes a mapping only while it still holds the tested value, so it never drops a
            // value it did not test, and a concurrent lock-free removal of the same key is harmless.
            entries.values().removeIf(entry -> !entry.isLive(now));
            if (!entries.containsKey(relayState) && entries.size() >= MAX_ENTRIES) {
                evictOldest();
            }
            entries.put(relayState, new Entry(authenticationRequest, now));
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
        return liveRequest(entries.remove(relayState));
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
     * Removes the entry with the oldest save time. Called only while {@link #saveLock} is held, so no other save can
     * replace that entry concurrently. Like the purge in {@code saveAuthenticationRequest}, it is a linear scan: saves
     * happen only when a login starts, and the store never holds more than {@link #MAX_ENTRIES} entries.
     */
    private void evictOldest() {
        entries.entrySet()
                .stream()
                .min(Map.Entry.comparingByValue(Comparator.comparing(Entry::savedAt)))
                .ifPresent(oldest -> entries.remove(oldest.getKey(), oldest.getValue()));
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
     * A saved AuthnRequest and the instant it was saved.
     *
     * @param request the saved AuthnRequest
     * @param savedAt the instant the request was saved
     */
    private record Entry(AbstractSaml2AuthenticationRequest request, Instant savedAt) {

        /**
         * Tells whether the entry is still usable: strictly before {@link #TTL} has elapsed since it was saved.
         *
         * @param now the current instant
         * @return {@code true} if the entry has not expired
         */
        boolean isLive(Instant now) {
            return now.isBefore(savedAt.plus(TTL));
        }
    }
}

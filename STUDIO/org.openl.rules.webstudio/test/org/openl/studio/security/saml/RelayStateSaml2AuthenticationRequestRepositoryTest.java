package org.openl.studio.security.saml;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Queue;
import java.util.UUID;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;

/**
 * Unit tests for {@link RelayStateSaml2AuthenticationRequestRepository}.
 * <p>
 * Finding V3: the SAML AuthnRequest store is keyed by {@code RelayState} instead of the HTTP session, so SAML login
 * survives the {@code SameSite=Lax} session cookie that the browser omits on the IdP's cross-site POST. Each entry is
 * single-use: the callback's load claims it, so a replayed callback with the same {@code RelayState}, concurrent ones
 * included, fails {@code InResponseTo} validation.
 * </p>
 * <p>
 * Every {@code RelayState}, AuthnRequest ID and SAML payload is a random UUID, and every AuthnRequest outside the
 * filter test is a stub-only mock, so no credential or token-like value appears in this test. Mocks are created on
 * the test thread only.
 * </p>
 */
class RelayStateSaml2AuthenticationRequestRepositoryTest {

    /**
     * The required expiry, stated here so that a wrong production value fails the tests.
     */
    private static final Duration POLICY_TTL = Duration.ofMinutes(5);
    /**
     * The required cap, stated here so that a wrong production value fails the tests.
     */
    private static final int POLICY_CAP = 10_000;

    private static final int THREADS = 8;
    private static final int SAVES_PER_THREAD = 250;
    private static final long WAIT_SECONDS = 30;
    /**
     * How long a callback of the two-callback test waits for the other one; shorter than {@link #WAIT_SECONDS}, so a
     * callback that never arrives fails the test with the rendezvous timeout.
     */
    private static final long RENDEZVOUS_SECONDS = 10;
    private static final String REGISTRATION_ID = "webstudio";

    private MutableClock clock;
    private RelayStateSaml2AuthenticationRequestRepository repository;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        repository = new RelayStateSaml2AuthenticationRequestRepository(clock);
    }

    @Test
    void savesAndLoadsByRelayStateWithoutSession() {
        var authnRequest = authnRequest();
        var initiatingRequest = new MockHttpServletRequest();

        repository.saveAuthenticationRequest(authnRequest, initiatingRequest, new MockHttpServletResponse());

        assertNull(initiatingRequest.getSession(false), "Saving must not create a session");

        var callback = requestWith(authnRequest.getRelayState());
        assertSame(authnRequest, repository.loadAuthenticationRequest(callback));
        assertNull(callback.getSession(false), "Loading must not create a session");
        assertNull(initiatingRequest.getSession(false), "Loading must not create a session");
    }

    @Test
    void loadClaimsTheEntryForTheLoadingRequestOnly() {
        var authnRequest = authnRequest();
        var relayState = authnRequest.getRelayState();
        save(authnRequest);
        var callback = requestWith(relayState);
        var response = new MockHttpServletResponse();

        assertSame(authnRequest, repository.loadAuthenticationRequest(callback));
        assertEquals(0, repository.size(), "Loading must claim the entry out of the store");
        assertNull(load(relayState), "Another request with the same RelayState must not obtain the claimed entry");
        assertSame(authnRequest,
                repository.loadAuthenticationRequest(callback),
                "A repeated load on the claiming request must return the claimed AuthnRequest");
        assertNull(remove(relayState), "Removing on another request must not obtain the claimed AuthnRequest");

        assertSame(authnRequest,
                repository.removeAuthenticationRequest(callback, response),
                "Removing on the claiming request must hand over the claimed AuthnRequest");
        assertNull(repository.removeAuthenticationRequest(callback, response), "A claim must be handed over once");
        assertNull(repository.loadAuthenticationRequest(callback), "A removed claim must not be loaded again");
    }

    @Test
    void publicConstructorUsesTheSystemClock() {
        var systemClockRepository = new RelayStateSaml2AuthenticationRequestRepository();
        var authnRequest = authnRequest();

        systemClockRepository
                .saveAuthenticationRequest(authnRequest, new MockHttpServletRequest(), new MockHttpServletResponse());

        assertSame(authnRequest,
                systemClockRepository.loadAuthenticationRequest(requestWith(authnRequest.getRelayState())));
    }

    @Test
    void loadReturnsNullWithoutRelayStateOrLiveEntry() {
        var authnRequest = authnRequest();
        save(authnRequest);

        assertNull(repository.loadAuthenticationRequest(new MockHttpServletRequest()));
        assertNull(load(UUID.randomUUID().toString()));
        assertNull(load(""));
        assertSame(authnRequest, load(authnRequest.getRelayState()), "Other lookups must not affect the entry");
    }

    @Test
    void entriesLiveFiveMinutesAndTheStoreHoldsTenThousand() {
        assertEquals(POLICY_TTL, RelayStateSaml2AuthenticationRequestRepository.TTL);
        assertEquals(POLICY_CAP, RelayStateSaml2AuthenticationRequestRepository.MAX_ENTRIES);
    }

    @Test
    void entryExpiresExactlyAtTtl() {
        // Saved at the same instant, so all three expire together; a load claims its entry, so each check uses its own.
        var live = authnRequest();
        var expiredOnLoad = authnRequest();
        var expiredOnRemove = authnRequest();
        save(live);
        save(expiredOnLoad);
        save(expiredOnRemove);

        clock.advance(POLICY_TTL.minusMillis(1));
        assertSame(live, load(live.getRelayState()), "The entry must be live just before the TTL elapses");

        clock.advance(Duration.ofMillis(1));
        var callback = requestWith(expiredOnLoad.getRelayState());
        var response = new MockHttpServletResponse();
        assertNull(repository.loadAuthenticationRequest(callback), "The entry must be expired exactly at the TTL");
        assertEquals(1, repository.size(), "Loading an expired entry must delete it");
        assertNull(repository.removeAuthenticationRequest(callback, response), "An expired entry must not be claimed");
        assertNull(remove(expiredOnRemove.getRelayState()), "The entry must be expired exactly at the TTL");
        assertEquals(0, repository.size(), "Removing an expired entry must delete it");
    }

    @Test
    void removeReturnsAndDeletesOnlyTheMatchingEntry() {
        var removed = authnRequest();
        var kept = authnRequest();
        save(removed);
        save(kept);

        assertSame(removed, remove(removed.getRelayState()));
        assertEquals(1, repository.size());
        assertNull(load(removed.getRelayState()));
        assertSame(kept, load(kept.getRelayState()));
    }

    @Test
    void removeReturnsNullWithoutRelayStateOrLiveEntry() {
        var authnRequest = authnRequest();
        save(authnRequest);

        assertNull(repository.removeAuthenticationRequest(new MockHttpServletRequest(), new MockHttpServletResponse()));
        assertNull(remove(UUID.randomUUID().toString()));
        assertNull(remove(""));
        assertSame(authnRequest, load(authnRequest.getRelayState()), "Other removals must not affect the entry");
    }

    @Test
    void evictsTheOldestEntryWhenTheStoreIsFull() {
        int total = POLICY_CAP + 1;
        List<AbstractSaml2AuthenticationRequest> authnRequests = new ArrayList<>(total);
        for (int i = 0; i < total; i++) {
            authnRequests.add(authnRequest());
        }

        // One millisecond between saves gives each entry a distinct save time; about 10 seconds pass in total, far
        // below the TTL, so nothing expires and only the cap can remove an entry.
        for (var authnRequest : authnRequests) {
            clock.advance(Duration.ofMillis(1));
            save(authnRequest);
        }

        assertEquals(POLICY_CAP, repository.size());
        var oldest = authnRequests.get(0);
        var second = authnRequests.get(1);
        var newest = authnRequests.get(total - 1);
        assertNull(load(oldest.getRelayState()), "The oldest entry must be evicted");
        assertSame(second, load(second.getRelayState()));
        assertSame(newest, load(newest.getRelayState()));
    }

    @Test
    void purgesExpiredEntriesOnSave() {
        var expired = List.of(authnRequest(), authnRequest(), authnRequest());
        expired.forEach(this::save);

        clock.advance(POLICY_TTL);
        var fresh = authnRequest();
        save(fresh);

        assertEquals(1, repository.size());
        for (var authnRequest : expired) {
            assertNull(load(authnRequest.getRelayState()));
        }
        assertSame(fresh, load(fresh.getRelayState()));
    }

    @Test
    void savingTheSameRelayStateReplacesTheEntryAndRestartsItsTtl() {
        var relayState = UUID.randomUUID().toString();
        var first = authnRequest(relayState);
        var second = authnRequest(relayState);
        save(first);

        clock.advance(Duration.ofMinutes(4));
        save(second);

        assertEquals(1, repository.size());

        // Eight minutes after the first save and four after the second: only the second save counts.
        clock.advance(Duration.ofMinutes(4));
        assertSame(second, load(relayState));
    }

    @Test
    void savingANullRequestRemovesOnlyTheEntryOfTheRequestRelayState() {
        var removed = authnRequest();
        var kept = authnRequest();
        save(removed);
        save(kept);
        var response = new MockHttpServletResponse();

        repository.saveAuthenticationRequest(null, requestWith(removed.getRelayState()), response);

        assertEquals(1, repository.size(), "Saving null must remove exactly one entry");
        assertNull(load(removed.getRelayState()), "Saving null must remove the entry of the request's RelayState");

        repository.saveAuthenticationRequest(null, new MockHttpServletRequest(), response);
        repository.saveAuthenticationRequest(null, requestWith(""), response);
        repository.saveAuthenticationRequest(null, requestWith(UUID.randomUUID().toString()), response);

        assertEquals(1, repository.size(), "Saving null without a matching RelayState must remove nothing");
        assertSame(kept, load(kept.getRelayState()), "Saving null must not remove another entry");
    }

    @Test
    void doesNotStoreAnAuthenticationRequestWithoutRelayState() {
        save(authnRequest(null));
        save(authnRequest(""));

        assertEquals(0, repository.size());
    }

    @Test
    void removingAnEntryFreesItsSlot() {
        var held = saveOneMillisecondApart(POLICY_CAP);
        var oldest = held.get(0);
        var second = held.get(1);
        var third = held.get(2);
        assertSame(oldest, remove(oldest.getRelayState()));
        assertEquals(POLICY_CAP - 1, repository.size());

        clock.advance(Duration.ofMillis(1));
        var refill = authnRequest();
        save(refill);

        assertEquals(POLICY_CAP, repository.size(), "Saving into a freed slot must not evict");

        clock.advance(Duration.ofMillis(1));
        var overflow = authnRequest();
        save(overflow);

        assertEquals(POLICY_CAP, repository.size(), "A removed entry must not stay in the eviction order");
        assertNull(load(second.getRelayState()), "The oldest entry still held must be evicted");
        assertSame(third, load(third.getRelayState()));
        assertSame(refill, load(refill.getRelayState()));
        assertSame(overflow, load(overflow.getRelayState()));
    }

    @Test
    void savingAHeldRelayStateIntoAFullStoreDoesNotEvictAndMakesItTheNewest() {
        var held = saveOneMillisecondApart(POLICY_CAP);
        var oldest = held.get(0);
        var second = held.get(1);
        var third = held.get(2);

        clock.advance(Duration.ofMillis(1));
        var replacement = authnRequest(oldest.getRelayState());
        save(replacement);

        assertEquals(POLICY_CAP, repository.size(), "Replacing an entry must not evict another");

        clock.advance(Duration.ofMillis(1));
        var overflow = authnRequest();
        save(overflow);

        assertEquals(POLICY_CAP, repository.size(), "A replaced entry must not stay in the eviction order");
        assertNull(load(second.getRelayState()), "The oldest save must be evicted, not the replaced entry");
        assertSame(replacement, load(oldest.getRelayState()));
        assertSame(third, load(third.getRelayState()));
        for (int i = 3; i < POLICY_CAP; i++) {
            var authnRequest = held.get(i);
            assertSame(authnRequest, load(authnRequest.getRelayState()), "Replacing an entry must not evict another");
        }
        assertSame(overflow, load(overflow.getRelayState()));
    }

    @Test
    void concurrentSavesKeepEveryEntry() throws Exception {
        var batches = batches();

        saveConcurrently(batches);

        assertEquals(THREADS * SAVES_PER_THREAD, repository.size());
        for (var batch : batches) {
            for (var authnRequest : batch) {
                assertSame(authnRequest, load(authnRequest.getRelayState()));
            }
        }
    }

    @Test
    void concurrentSavesIntoAFullStoreEvictTheOldestEntries() throws Exception {
        var held = saveOneMillisecondApart(POLICY_CAP);
        var batches = batches();
        // The clock then stands still: every new entry is saved after every held one, so whatever the interleaving,
        // each new save evicts the oldest held entry that is left.
        clock.advance(Duration.ofMillis(1));

        saveConcurrently(batches);

        int evicted = THREADS * SAVES_PER_THREAD;
        assertEquals(POLICY_CAP, repository.size(), "Concurrent saves must not exceed the cap");
        for (int i = 0; i < evicted; i++) {
            assertNull(load(held.get(i).getRelayState()), "The oldest entries must be evicted");
        }
        for (int i = evicted; i < POLICY_CAP; i++) {
            var authnRequest = held.get(i);
            assertSame(authnRequest, load(authnRequest.getRelayState()), "Newer held entries must be kept");
        }
        for (var batch : batches) {
            for (var authnRequest : batch) {
                assertSame(authnRequest, load(authnRequest.getRelayState()), "Every new entry must be kept");
            }
        }
    }

    @Test
    void concurrentLoadsOfOneRelayStateClaimTheEntryOnce() throws Exception {
        var authnRequest = authnRequest();
        var relayState = authnRequest.getRelayState();
        save(authnRequest);
        List<Callable<@Nullable AbstractSaml2AuthenticationRequest>> callbacks = new ArrayList<>(THREADS);
        for (int i = 0; i < THREADS; i++) {
            callbacks.add(() -> load(relayState));
        }

        var loaded = runTogether(callbacks);

        assertEquals(1, loaded.stream().filter(Objects::nonNull).count(), "Exactly one load must claim the entry");
        assertTrue(loaded.contains(authnRequest), "The claiming load must obtain the saved AuthnRequest");
        assertEquals(0, repository.size(), "The claimed entry must leave the store");
    }

    @Test
    void twoConcurrentCallbacksWithOneResponseAuthenticateOnce() throws Exception {
        var registration = RelyingPartyRegistration.withRegistrationId(REGISTRATION_ID)
                .assertingPartyMetadata(party -> party.entityId("https://idp.invalid")
                        .singleSignOnServiceLocation("https://idp.invalid/sso"))
                .build();
        var authnRequest = Saml2PostAuthenticationRequest.withRelyingPartyRegistration(registration)
                .id("_" + UUID.randomUUID())
                .relayState(UUID.randomUUID().toString())
                .samlRequest(base64(UUID.randomUUID().toString()))
                .build();
        save(authnRequest);

        // The converter loads the AuthnRequest and then resolves the registration, and the filter removes the entry
        // only after the conversion. Holding each callback in the registration lookup until both have arrived makes
        // both loads happen before either removal.
        var bothLoaded = new CyclicBarrier(2);
        RelyingPartyRegistrationRepository registrations = registrationId -> {
            rendezvous(bothLoaded);
            return REGISTRATION_ID.equals(registrationId) ? registration : null;
        };
        // Spring's InResponseTo rule: the response must answer the AuthnRequest carried by the token.
        AuthenticationManager inResponseToCheck = authentication -> {
            var stored = ((Saml2AuthenticationToken) authentication).getAuthenticationRequest();
            if (stored == null || !authnRequest.getId().equals(stored.getId())) {
                throw new Saml2AuthenticationException(new Saml2Error(Saml2ErrorCodes.INVALID_IN_RESPONSE_TO,
                        "No saved AuthnRequest matches the response"));
            }
            return UsernamePasswordAuthenticationToken.authenticated(UUID.randomUUID().toString(), null, List.of());
        };
        var successes = new AtomicInteger();
        Queue<AuthenticationException> failures = new ConcurrentLinkedQueue<>();
        // Built as SamlSecurityConfig.samlFilter builds it, so the default converter is Spring's own.
        var filter = new Saml2WebSsoAuthenticationFilter(registrations);
        filter.setAuthenticationManager(inResponseToCheck);
        filter.setAuthenticationSuccessHandler((request, response, authentication) -> successes.incrementAndGet());
        filter.setAuthenticationFailureHandler((request, response, exception) -> failures.add(exception));
        filter.setAuthenticationRequestRepository(repository);
        filter.afterPropertiesSet();

        var samlResponse = base64(UUID.randomUUID().toString());
        List<Callable<Void>> callbacks = new ArrayList<>(2);
        for (int i = 0; i < 2; i++) {
            callbacks.add(() -> {
                var callback = new MockHttpServletRequest("POST", "/login/saml2/sso/" + REGISTRATION_ID);
                callback.setParameter(Saml2ParameterNames.RELAY_STATE, authnRequest.getRelayState());
                callback.setParameter(Saml2ParameterNames.SAML_RESPONSE, samlResponse);
                filter.doFilter(callback, new MockHttpServletResponse(), new MockFilterChain());
                assertNull(callback.getSession(false), "The callback must not need a session");
                return null;
            });
        }

        runTogether(callbacks);

        assertEquals(1, successes.get(), "Exactly one of the two callbacks must authenticate");
        assertEquals(1, failures.size(), "The other callback must fail");
        var failure = assertInstanceOf(Saml2AuthenticationException.class, failures.peek());
        assertEquals(Saml2ErrorCodes.INVALID_IN_RESPONSE_TO, failure.getSaml2Error().getErrorCode());
        assertEquals(0, repository.size(), "The AuthnRequest must leave the store");
    }

    /**
     * Saves new AuthnRequests one millisecond apart, so each has a distinct save time. Ten thousand saves span about
     * ten seconds, far below the TTL, so nothing expires and only the cap can remove an entry.
     *
     * @param count the number of AuthnRequests to save
     * @return the saved AuthnRequests, oldest first
     */
    private List<AbstractSaml2AuthenticationRequest> saveOneMillisecondApart(int count) {
        List<AbstractSaml2AuthenticationRequest> saved = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            var authnRequest = authnRequest();
            clock.advance(Duration.ofMillis(1));
            save(authnRequest);
            saved.add(authnRequest);
        }
        return saved;
    }

    /**
     * Creates the AuthnRequests of the concurrency tests on the test thread, one batch per worker.
     *
     * @return {@link #THREADS} batches of {@link #SAVES_PER_THREAD} AuthnRequests
     */
    private static List<List<AbstractSaml2AuthenticationRequest>> batches() {
        List<List<AbstractSaml2AuthenticationRequest>> batches = new ArrayList<>(THREADS);
        for (int t = 0; t < THREADS; t++) {
            List<AbstractSaml2AuthenticationRequest> batch = new ArrayList<>(SAVES_PER_THREAD);
            for (int i = 0; i < SAVES_PER_THREAD; i++) {
                batch.add(authnRequest());
            }
            batches.add(batch);
        }
        return batches;
    }

    /**
     * Saves each batch on its own worker thread, with every worker released at once, and fails on any worker failure.
     *
     * @param batches the AuthnRequests of each worker
     * @throws Exception if a worker fails, is interrupted or does not finish in time
     */
    private void saveConcurrently(List<List<AbstractSaml2AuthenticationRequest>> batches) throws Exception {
        List<Callable<Void>> savers = new ArrayList<>(batches.size());
        for (var batch : batches) {
            savers.add(() -> {
                var request = new MockHttpServletRequest();
                var response = new MockHttpServletResponse();
                for (var authnRequest : batch) {
                    repository.saveAuthenticationRequest(authnRequest, request, response);
                }
                return null;
            });
        }
        runTogether(savers);
    }

    /**
     * Runs each task on its own worker thread, with every worker released at once, and fails on any worker failure.
     *
     * @param tasks the work of each worker
     * @param <T> the result type of the tasks
     * @return the result of each task, in the order of the tasks
     * @throws Exception if a worker fails, is interrupted or does not finish in time
     */
    private static <T extends @Nullable Object> List<T> runTogether(List<Callable<T>> tasks) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(tasks.size());
        var start = new CountDownLatch(1);
        var done = new CountDownLatch(tasks.size());
        List<Future<T>> workers = new ArrayList<>(tasks.size());
        try {
            for (var task : tasks) {
                workers.add(executor.submit(() -> {
                    try {
                        start.await();
                        return task.call();
                    } finally {
                        done.countDown();
                    }
                }));
            }
            start.countDown();

            assertTrue(done.await(WAIT_SECONDS, TimeUnit.SECONDS), "The workers must finish in time");
            List<T> results = new ArrayList<>(workers.size());
            for (var worker : workers) {
                // Rethrows any worker failure as an ExecutionException, which fails the test.
                results.add(worker.get(WAIT_SECONDS, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            executor.shutdown();
            if (!executor.awaitTermination(WAIT_SECONDS, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        }
    }

    /**
     * Waits until every party of the barrier has arrived, for at most {@link #RENDEZVOUS_SECONDS}.
     *
     * @param barrier the barrier the callbacks meet at
     * @throws IllegalStateException if the other parties do not arrive in time or the wait is interrupted
     */
    private static void rendezvous(CyclicBarrier barrier) {
        try {
            barrier.await(RENDEZVOUS_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for the other callback", e);
        } catch (BrokenBarrierException | TimeoutException e) {
            throw new IllegalStateException("The other callback did not reach the registration lookup in time", e);
        }
    }

    private static String base64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private void save(AbstractSaml2AuthenticationRequest authnRequest) {
        repository.saveAuthenticationRequest(authnRequest, new MockHttpServletRequest(), new MockHttpServletResponse());
    }

    private @Nullable AbstractSaml2AuthenticationRequest load(String relayState) {
        return repository.loadAuthenticationRequest(requestWith(relayState));
    }

    private @Nullable AbstractSaml2AuthenticationRequest remove(String relayState) {
        return repository.removeAuthenticationRequest(requestWith(relayState), new MockHttpServletResponse());
    }

    private static MockHttpServletRequest requestWith(String relayState) {
        var request = new MockHttpServletRequest();
        request.setParameter(Saml2ParameterNames.RELAY_STATE, relayState);
        return request;
    }

    private static AbstractSaml2AuthenticationRequest authnRequest() {
        return authnRequest(UUID.randomUUID().toString());
    }

    private static AbstractSaml2AuthenticationRequest authnRequest(String relayState) {
        // Stub-only mocks record no invocations, which keeps the ten thousand or more mocks of each cap test small and
        // makes the mocks safe to read from the worker threads of the concurrency tests.
        var authnRequest = mock(AbstractSaml2AuthenticationRequest.class, withSettings().stubOnly());
        when(authnRequest.getRelayState()).thenReturn(relayState);
        return authnRequest;
    }

    /**
     * A clock that stands still until the test advances it.
     */
    private static final class MutableClock extends Clock {

        private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-01-01T00:00:00Z"));

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }

        void advance(Duration duration) {
            now.updateAndGet(current -> current.plus(duration));
        }
    }
}

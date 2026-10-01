package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.function.BiFunction;
import jakarta.servlet.Filter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;

import org.apache.commons.lang3.RandomStringUtils;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.DefaultLocale;
import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.security.web.WebAttributes;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import org.openl.studio.security.ad.OpenLAuthenticationProviderWrapper;
import org.openl.studio.security.pat.filter.PatAuthenticationFilter;
import org.openl.studio.security.pat.service.PatAuthService;

/**
 * V9: proves that a locked account and an account that does not exist answer exactly like a wrong password, for HTTP
 * Basic on {@code /rest/**} and for the form login, through Studio's own {@code multi}-mode filter chains.
 * <p>
 * The chains are the beans of {@link SecurityConfig} and {@link FormBasedAuthenticationConfig}, served by the
 * application's {@code filterChainProxy}. Their authentication manager is built from the only
 * {@link AuthenticationProvider} bean: a {@link DaoAuthenticationProvider} decorated by
 * {@link LoginLockoutAuthenticationProvider} inside {@link OpenLAuthenticationProviderWrapper}.
 * </p>
 * <p>
 * Each attempt is captured as a {@link Snapshot} of everything a client or the login page can observe: the status,
 * the error message, the redirect and forward targets, every header with all its values, the exact body bytes, the
 * cookies and, for the session, its attribute names and the stored authentication failure. The first wrong-password
 * attempt is the reference. Every further wrong attempt, the correct password while the account is locked, a wrong
 * password while it is locked, and every attempt of an unknown account, before and after that name is locked, must
 * produce a snapshot equal to the reference.
 * </p>
 * <p>
 * The credentials are generated per run and never appear in an assertion message. The lockout state lives in the
 * provider, a singleton of the test context, so each test uses its own account names. The DAO provider localizes its
 * failure message with the default locale, so the locale is pinned to keep the reference message deterministic.
 * </p>
 */
@SpringJUnitConfig(LoginLockoutResponseIdentityTest.TestConfig.class)
@WebAppConfiguration
@TestPropertySource(properties = "user.mode=multi")
@DefaultLocale(language = "en")
class LoginLockoutResponseIdentityTest {

    private static final String PASSWORD = RandomStringUtils.secure().nextAlphanumeric(16);
    private static final String WRONG_PASSWORD = differentFrom(PASSWORD);

    private static final String BASIC_USER = "basic-user";
    private static final String BASIC_GHOST = "basic-ghost";
    private static final String FORM_USER = "form-user";
    private static final String FORM_GHOST = "form-ghost";

    /**
     * A fixed instant: no failure ever leaves the window and no lock ever elapses during a test.
     */
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

    private MockMvc mockMvc;

    @BeforeEach
    void setUp(WebApplicationContext context) {
        Filter filterChainProxy = context.getBean("filterChainProxy", Filter.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity(filterChainProxy))
                .build();
    }

    @Test
    void basicLockedAndUnknownAccountsAnswerLikeAWrongPassword() throws Exception {
        MvcResult success = mockMvc.perform(basic(BASIC_USER, PASSWORD)).andReturn();
        assertEquals(200, success.getResponse().getStatus(), "Basic: correct password before any failure");
        assertEquals(StubController.BODY, success.getResponse().getContentAsString(),
                "Basic: correct password before any failure");

        Snapshot reference = attempt(basic(BASIC_USER, WRONG_PASSWORD));
        assertEquals(401, reference.status(), "Basic: wrong password, attempt 1");

        assertLockoutSequence("Basic", reference, LoginLockoutResponseIdentityTest::basic, BASIC_USER, BASIC_GHOST);
    }

    @Test
    void formLoginLockedAndUnknownAccountsAnswerLikeAWrongPassword() throws Exception {
        MvcResult success = mockMvc.perform(form(FORM_USER, PASSWORD)).andReturn();
        assertEquals(302, success.getResponse().getStatus(), "Form: correct password before any failure");
        assertEquals("/", success.getResponse().getRedirectedUrl(), "Form: correct password before any failure");
        HttpSession successSession = success.getRequest().getSession(false);
        assertNull(successSession == null ? null : successSession.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION),
                "Form: correct password before any failure");

        Snapshot reference = attempt(form(FORM_USER, WRONG_PASSWORD));
        assertEquals(302, reference.status(), "Form: wrong password, attempt 1");
        assertEquals("/login?error", reference.redirectedUrl(), "Form: wrong password, attempt 1");
        assertEquals(BadCredentialsException.class.getName(), reference.sessionExceptionClass(),
                "Form: wrong password, attempt 1");
        assertEquals("Bad credentials", reference.sessionExceptionMessage(), "Form: wrong password, attempt 1");

        assertLockoutSequence("Form", reference, LoginLockoutResponseIdentityTest::form, FORM_USER, FORM_GHOST);
    }

    /**
     * Runs the lockout sequence after the first wrong password of {@code user} and asserts that every attempt answers
     * exactly like that first one.
     *
     * @param scenario  the name of the login flow, used in the assertion messages
     * @param reference the snapshot of the first wrong-password attempt of {@code user}
     * @param login     builds a login attempt from a user name and a password
     * @param user      an existing account with one failure recorded
     * @param ghost     a name that has no account and no failure recorded
     */
    private void assertLockoutSequence(String scenario,
                                       Snapshot reference,
                                       BiFunction<String, String, RequestBuilder> login,
                                       String user,
                                       String ghost) throws Exception {
        int maxFailures = LoginLockoutAuthenticationProvider.MAX_FAILURES;
        for (int attempt = 2; attempt <= maxFailures; attempt++) {
            assertEquals(reference, attempt(login.apply(user, WRONG_PASSWORD)),
                    scenario + ": wrong password, attempt " + attempt);
        }
        assertEquals(reference, attempt(login.apply(user, PASSWORD)),
                scenario + ": correct password while locked, attempt " + (maxFailures + 1));
        assertEquals(reference, attempt(login.apply(user, WRONG_PASSWORD)),
                scenario + ": wrong password while locked, attempt " + (maxFailures + 2));

        for (int attempt = 1; attempt <= maxFailures + 1; attempt++) {
            assertEquals(reference, attempt(login.apply(ghost, WRONG_PASSWORD)),
                    scenario + ": unknown account, attempt " + attempt);
        }
    }

    private Snapshot attempt(RequestBuilder request) throws Exception {
        return Snapshot.of(mockMvc.perform(request).andReturn());
    }

    private static RequestBuilder basic(String user, String password) {
        return get("/rest/repos").with(httpBasic(user, password));
    }

    private static RequestBuilder form(String user, String password) {
        return formLogin("/login").user(user).password(password);
    }

    private static String differentFrom(String password) {
        String other;
        do {
            other = RandomStringUtils.secure().nextAlphanumeric(16);
        } while (other.equals(password));
        return other;
    }

    /**
     * Everything a client or the login page can observe of one attempt. Session identifiers are left out: they differ
     * on every request by design.
     *
     * @param status                  the HTTP status
     * @param errorMessage            the message passed to {@code sendError}, if any
     * @param redirectedUrl           the redirect target, if any
     * @param forwardedUrl            the forward target, if any
     * @param headers                 every response header name with all its values
     * @param body                    the exact body bytes, one character per byte
     * @param cookies                 the cookies the response sets
     * @param sessionExists           whether the attempt left a session
     * @param sessionAttributes       the names of the session attributes, sorted
     * @param sessionExceptionClass   the class of the authentication failure stored in the session, if any
     * @param sessionExceptionMessage the message of the authentication failure stored in the session, if any
     */
    private record Snapshot(int status,
                            @Nullable String errorMessage,
                            @Nullable String redirectedUrl,
                            @Nullable String forwardedUrl,
                            SortedMap<String, List<String>> headers,
                            String body,
                            List<CookieView> cookies,
                            boolean sessionExists,
                            List<String> sessionAttributes,
                            @Nullable String sessionExceptionClass,
                            @Nullable String sessionExceptionMessage) {

        static Snapshot of(MvcResult result) {
            MockHttpServletResponse response = result.getResponse();
            var headers = new TreeMap<String, List<String>>();
            for (String name : response.getHeaderNames()) {
                headers.put(name, List.copyOf(response.getHeaders(name)));
            }
            List<CookieView> cookies = Arrays.stream(response.getCookies()).map(CookieView::of).toList();
            String body = new String(response.getContentAsByteArray(), StandardCharsets.ISO_8859_1);

            HttpSession session = result.getRequest().getSession(false);
            List<String> sessionAttributes = List.of();
            Object failure = null;
            if (session != null) {
                sessionAttributes = Collections.list(session.getAttributeNames()).stream().sorted().toList();
                failure = session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            }
            return new Snapshot(response.getStatus(),
                    response.getErrorMessage(),
                    response.getRedirectedUrl(),
                    response.getForwardedUrl(),
                    Collections.unmodifiableSortedMap(headers),
                    body,
                    cookies,
                    session != null,
                    sessionAttributes,
                    failure == null ? null : failure.getClass().getName(),
                    failure instanceof Throwable throwable ? throwable.getMessage() : null);
        }
    }

    /**
     * The observable attributes of one response cookie.
     */
    private record CookieView(String name,
                              @Nullable String value,
                              @Nullable String path,
                              @Nullable String domain,
                              int maxAge,
                              boolean secure,
                              boolean httpOnly) {

        static CookieView of(Cookie cookie) {
            return new CookieView(cookie.getName(),
                    cookie.getValue(),
                    cookie.getPath(),
                    cookie.getDomain(),
                    cookie.getMaxAge(),
                    cookie.getSecure(),
                    cookie.isHttpOnly());
        }
    }

    /**
     * Answers an authenticated request on the {@code /rest/**} chain, so a successful Basic login is observable.
     */
    @RestController
    static class StubController {

        static final String BODY = "repositories";

        @GetMapping("/rest/repos")
        String repos() {
            return BODY;
        }
    }

    @Configuration
    @EnableWebMvc
    @Import({SecurityConfig.class, FormBasedAuthenticationConfig.class, StubController.class})
    static class TestConfig {

        @Bean
        SessionRegistry sessionRegistry() {
            return new SessionRegistryImpl();
        }

        /**
         * No attempt carries a {@code Token} header, so the filter passes every request on.
         */
        @Bean
        PatAuthenticationFilter patAuthenticationFilter() {
            return new PatAuthenticationFilter(Mockito.mock(PatAuthService.class));
        }

        /**
         * The only {@link AuthenticationProvider} bean, and no {@code UserDetailsService} or
         * {@code AuthenticationManager} bean, so the authentication manager of every chain is built from it. The
         * lockout decorates the DAO provider inside the OpenL wrapper.
         */
        @Bean
        AuthenticationProvider authenticationProvider() {
            PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
            var users = new InMemoryUserDetailsManager(
                    User.withUsername(BASIC_USER).password(encoder.encode(PASSWORD)).roles("USER").build(),
                    User.withUsername(FORM_USER).password(encoder.encode(PASSWORD)).roles("USER").build());
            var dao = new DaoAuthenticationProvider(users);
            dao.setPasswordEncoder(encoder);
            return new OpenLAuthenticationProviderWrapper(new LoginLockoutAuthenticationProvider(dao, CLOCK));
        }
    }
}

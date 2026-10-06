package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import jakarta.servlet.Filter;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
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

import org.openl.studio.security.pat.filter.PatAuthenticationFilter;
import org.openl.studio.security.pat.service.PatAuthService;

/**
 * V10: {@code /rest/public/info/sys.json} and {@code /rest/public/info/http.json} require authentication in the
 * {@code ad} and {@code multi} user modes, while {@code /rest/public/info/openl.json} stays public.
 * <p>
 * No integration suite runs against an Active Directory server, but both modes activate the same chains: the
 * {@code @Order(0)} static chain of {@link SecurityConfig}, which applies in every mode, and the {@code /rest/**} and
 * default chains of {@link FormBasedAuthenticationConfig}. Only the authentication provider differs between the two
 * modes, and a request that already carries an authenticated session never reaches a provider. So {@link AdMode} and
 * {@link MultiMode} each start the real chains under their {@code user.mode} value, served by the application's own
 * {@code filterChainProxy} bean, with a stub authentication provider and a stub controller at the three endpoints.
 * Both run the identical checks of {@link ModeChecks}.
 * </p>
 * <p>
 * The tests use only API that exists before the V10 change, so they also compile on the unfixed code. There the
 * anonymous requests to {@code sys.json} and {@code http.json} are served with 200 by the static chain, which is
 * the failure that reproduces the finding.
 * </p>
 * <p>
 * The passwords are generated per run and never appear in an assertion message.
 * </p>
 */
class SysInfoAuthenticationChainTest {

    static final String USER = "sysinfo-user";
    static final String PASSWORD = RandomStringUtils.secure().nextAlphanumeric(16);
    static final String WRONG_PASSWORD = differentFrom(PASSWORD);

    static final String SYS_JSON = "/rest/public/info/sys.json";
    static final String HTTP_JSON = "/rest/public/info/http.json";
    static final String OPENL_JSON = "/rest/public/info/openl.json";

    /**
     * Generates a password that is guaranteed to differ from the given one, for the failed-login check.
     */
    private static String differentFrom(String password) {
        String other;
        do {
            other = RandomStringUtils.secure().nextAlphanumeric(16);
        } while (other.equals(password));
        return other;
    }

    @Nested
    @SpringJUnitConfig(TestConfig.class)
    @WebAppConfiguration
    @TestPropertySource(properties = "user.mode=ad")
    class AdMode extends ModeChecks {

        AdMode() {
            super("ad");
        }
    }

    @Nested
    @SpringJUnitConfig(TestConfig.class)
    @WebAppConfiguration
    @TestPropertySource(properties = "user.mode=multi")
    class MultiMode extends ModeChecks {

        MultiMode() {
            super("multi");
        }
    }

    /**
     * The checks shared by both modes. Each subclass runs them in its own Spring context, cached per
     * {@code user.mode} value.
     */
    abstract static class ModeChecks {

        private final String mode;

        @Autowired
        private WebApplicationContext ctx;

        private MockMvc mockMvc;
        private StubAuthenticationProvider provider;

        ModeChecks(String mode) {
            this.mode = mode;
        }

        @BeforeEach
        void setUp() {
            mockMvc = MockMvcBuilders.webAppContextSetup(ctx)
                    .apply(SecurityMockMvcConfigurers.springSecurity(ctx.getBean("filterChainProxy", Filter.class)))
                    .build();
            provider = ctx.getBean(StubAuthenticationProvider.class);
        }

        /**
         * Guards the premise of every other check: the context runs the given mode with the form-based chains.
         */
        @Test
        void formBasedChainsServeThisMode() {
            assertEquals(mode, ctx.getEnvironment().getProperty("user.mode"), message("user.mode property"));
            assertTrue(ctx.containsBean("staticResourcesFilterChain"), message("static chain is defined"));
            assertTrue(ctx.containsBean("restEndpointsFilterChain"), message("/rest/** chain is defined"));
            assertTrue(ctx.containsBean("defaultFilterChain"), message("default chain is defined"));
        }

        @Test
        void anonymousSysInfoIsRejected() throws Exception {
            perform(get(SYS_JSON), HttpStatus.UNAUTHORIZED, "anonymous GET " + SYS_JSON);
            perform(get(HTTP_JSON), HttpStatus.UNAUTHORIZED, "anonymous GET " + HTTP_JSON);
        }

        /**
         * The session a form login created authenticates both endpoints on its own: the requests carry no
         * {@code Authorization} header and no test security context, and the provider is not called again.
         */
        @Test
        void sessionFromFormLoginIsEnough() throws Exception {
            MockHttpSession session = formLogin(PASSWORD, "/", "form login at /login");
            int attemptsAfterLogin = provider.attempts();

            MvcResult sys = perform(get(SYS_JSON).session(session), HttpStatus.OK, "session GET " + SYS_JSON);
            assertEquals(StubInfoController.BODY,
                    sys.getResponse().getContentAsString(),
                    message("session GET " + SYS_JSON + " body"));
            MvcResult http = perform(get(HTTP_JSON).session(session), HttpStatus.OK, "session GET " + HTTP_JSON);
            assertEquals(StubInfoController.BODY,
                    http.getResponse().getContentAsString(),
                    message("session GET " + HTTP_JSON + " body"));

            assertEquals(attemptsAfterLogin,
                    provider.attempts(),
                    message("session GET " + SYS_JSON + " and " + HTTP_JSON + " reach no provider"));
        }

        /**
         * An authentication that spring-security-test saves through the chain's own security context repository,
         * with no login request at all, is served as well, and no provider is asked: the chains authorize the
         * stored authentication whichever provider created it, which is why {@code ad} needs no directory server.
         */
        @Test
        void authenticatedSecurityContextIsServed() throws Exception {
            Authentication authenticated = UsernamePasswordAuthenticationToken
                    .authenticated(USER, null, List.of(new SimpleGrantedAuthority("USER")));
            int attemptsBefore = provider.attempts();

            perform(get(SYS_JSON).with(SecurityMockMvcRequestPostProcessors.authentication(authenticated)),
                    HttpStatus.OK,
                    "authenticated-context GET " + SYS_JSON);
            perform(get(HTTP_JSON).with(SecurityMockMvcRequestPostProcessors.authentication(authenticated)),
                    HttpStatus.OK,
                    "authenticated-context GET " + HTTP_JSON);

            assertEquals(attemptsBefore,
                    provider.attempts(),
                    message("authenticated-context GET " + SYS_JSON + " and " + HTTP_JSON + " reach no provider"));
        }

        @Test
        void openlJsonStaysPublic() throws Exception {
            MvcResult result = perform(get(OPENL_JSON), HttpStatus.OK, "anonymous GET " + OPENL_JSON);
            assertEquals(StubInfoController.BODY,
                    result.getResponse().getContentAsString(),
                    message("anonymous GET " + OPENL_JSON + " body"));
        }

        /**
         * A failed form login also leaves a session behind (it holds the authentication failure), and that session
         * does not authenticate either endpoint.
         */
        @Test
        void wrongPasswordDoesNotAuthenticate() throws Exception {
            MockHttpSession session = formLogin(WRONG_PASSWORD, "/login?error", "failed form login at /login");

            perform(get(SYS_JSON).session(session), HttpStatus.UNAUTHORIZED, "failed-login session GET " + SYS_JSON);
            perform(get(HTTP_JSON).session(session), HttpStatus.UNAUTHORIZED, "failed-login session GET " + HTTP_JSON);
        }

        /**
         * Posts the login form for {@link #USER} and returns the session the login left behind.
         *
         * @param password the password to submit
         * @param expectedRedirect where the login is expected to redirect
         * @param step the step name used in assertion messages; it never contains the password
         */
        private MockHttpSession formLogin(String password, String expectedRedirect, String step) throws Exception {
            MvcResult login = perform(
                    SecurityMockMvcRequestBuilders.formLogin("/login").user(USER).password(password),
                    HttpStatus.FOUND,
                    step);
            assertEquals(expectedRedirect, login.getResponse().getRedirectedUrl(), message(step + " redirect"));
            MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);
            assertNotNull(session, message(step + " session"));
            return session;
        }

        private MvcResult perform(RequestBuilder request, HttpStatus expected, String step) throws Exception {
            MvcResult result = mockMvc.perform(request).andReturn();
            assertEquals(expected.value(), result.getResponse().getStatus(), message(step));
            return result;
        }

        private String message(String step) {
            return "user.mode=" + mode + ": " + step;
        }
    }

    @Configuration
    @EnableWebMvc
    @Import({SecurityConfig.class, FormBasedAuthenticationConfig.class, StubInfoController.class})
    static class TestConfig {

        @Bean
        SessionRegistry sessionRegistry() {
            return new SessionRegistryImpl();
        }

        /**
         * No request carries a {@code Token} header, so the filter passes every request on.
         */
        @Bean
        PatAuthenticationFilter patAuthenticationFilter() {
            return new PatAuthenticationFilter(Mockito.mock(PatAuthService.class));
        }

        /**
         * The only {@link AuthenticationProvider} bean, and no {@code UserDetailsService} or
         * {@code AuthenticationManager} bean, so the authentication manager of every chain is built from it. It
         * stands in for the DAO provider of {@code multi} and the Active Directory provider of {@code ad}.
         */
        @Bean
        StubAuthenticationProvider stubAuthenticationProvider() {
            return new StubAuthenticationProvider();
        }
    }

    /**
     * Accepts {@link #USER} with {@link #PASSWORD} only, and counts every authentication attempt that reaches it.
     */
    static final class StubAuthenticationProvider implements AuthenticationProvider {

        private final AtomicInteger attempts = new AtomicInteger();

        @Override
        public Authentication authenticate(Authentication authentication) {
            attempts.incrementAndGet();
            if (USER.equals(authentication.getName()) && PASSWORD.equals(authentication.getCredentials())) {
                return UsernamePasswordAuthenticationToken
                        .authenticated(USER, null, List.of(new SimpleGrantedAuthority("USER")));
            }
            throw new BadCredentialsException("Bad credentials");
        }

        @Override
        public boolean supports(Class<?> authentication) {
            return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        }

        int attempts() {
            return attempts.get();
        }
    }

    /**
     * Stands in for {@code SysInfoController} at the three endpoints. MockMvc runs with an empty servlet path, so
     * the full request paths are mapped as they are.
     */
    @RestController
    static class StubInfoController {

        static final String BODY = "ok";

        @GetMapping({SYS_JSON, HTTP_JSON, OPENL_JSON})
        String info() {
            return BODY;
        }
    }
}

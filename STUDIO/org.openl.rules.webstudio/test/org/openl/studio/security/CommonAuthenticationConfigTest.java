package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;

import org.openl.studio.security.ad.OpenLAuthenticationProviderWrapper;

/**
 * Pins where a visitor is sent after signing in.
 *
 * <p>The API is served by a servlet mapped at {@code /rest/*}, so a call to it arrives with {@code /rest} as
 * the servlet path and the rest as the path info — which is what the matcher reads. A screen is served by the
 * catch-all page servlet, so it arrives as a servlet path of its own.
 *
 * @author Yury Molchan
 */
class CommonAuthenticationConfigTest {

    private final CommonAuthenticationConfig config = new CommonAuthenticationConfig();

    // V9: a fixed instant, so every attempt of a test falls inside one lockout window
    private static final Clock LOCKOUT_CLOCK = Clock.fixed(Instant.parse("2025-01-01T12:00:00Z"), ZoneOffset.UTC);

    @Test
    void aScreenIsRememberedSoTheSignInReturnsToIt() {
        assertNotNull(savedRequestFor("/projects", null), "a screen must be remembered across the sign-in");
    }

    @Test
    void anApiCallIsNotRemembered() {
        // Answering an expired session on an API call must not make the sign-in land on JSON
        // instead of a screen.
        assertNull(savedRequestFor("/rest", "/projects"), "an API call must not be remembered");
        assertNull(savedRequestFor("/rest", "/ws"), "a WebSocket handshake must not be remembered");
    }

    // V4: a plain-HTTP response carries the default Spring Security headers, without HSTS and without a CSP
    @Test
    void aPlainResponseCarriesTheDefaultSecurityHeaders() throws Exception {
        var response = headersFor(false);

        assertEquals("nosniff", response.getHeader("X-Content-Type-Options"));
        assertEquals("DENY", response.getHeader("X-Frame-Options"));
        assertEquals("no-cache, no-store, max-age=0, must-revalidate", response.getHeader("Cache-Control"));
        assertEquals("no-cache", response.getHeader("Pragma"));
        assertEquals("0", response.getHeader("Expires"));
        assertEquals("0", response.getHeader("X-XSS-Protection"));
        assertNull(response.getHeader("Strict-Transport-Security"), "HSTS must be sent on secure requests only");
        assertNull(response.getHeader("Content-Security-Policy"), "no Content-Security-Policy must be added");
    }

    // V4: a secure response also carries HSTS, and still no CSP
    @Test
    void aSecureResponseAlsoCarriesStrictTransportSecurity() throws Exception {
        var response = headersFor(true);

        assertEquals("max-age=31536000 ; includeSubDomains", response.getHeader("Strict-Transport-Security"));
        assertEquals("nosniff", response.getHeader("X-Content-Type-Options"));
        assertEquals("DENY", response.getHeader("X-Frame-Options"));
        assertNull(response.getHeader("Content-Security-Policy"), "no Content-Security-Policy must be added");
    }

    // V5: the session ID changes at login and the new one is registered
    @Test
    void theSessionIdChangesAtLoginAndTheNewOneIsRegistered() {
        var registry = new SessionRegistryImpl();
        var strategy = config.sessionAuthenticationStrategy(registry);
        var request = new MockHttpServletRequest();
        var session = request.getSession(true);
        assertNotNull(session);
        session.setAttribute("pre-login", "kept");
        String oldId = session.getId();
        var token = UsernamePasswordAuthenticationToken
                .authenticated("jdoe", null, List.of(new SimpleGrantedAuthority("USER")));

        strategy.onAuthentication(token, request, new MockHttpServletResponse());

        var newSession = request.getSession(false);
        assertNotNull(newSession, "the session must survive the login");
        String newId = newSession.getId();
        // V5: compared without printing, so the session IDs never reach the failure output
        boolean rotated = !oldId.equals(newId);
        assertTrue(rotated, "the session ID must rotate at login");
        var registered = registry.getSessionInformation(newId);
        assertNotNull(registered, "the new session ID must be registered");
        assertEquals("jdoe", registered.getPrincipal());
        assertNull(registry.getSessionInformation(oldId), "the pre-login session ID must not be registered");
        // The request cache lives in the session, so its attributes must survive the rotation.
        assertEquals("kept", newSession.getAttribute("pre-login"), "session attributes must survive the login");
    }

    // V9: the local (multi) provider is locked, so the sixth failed login in the window never reaches it
    @Test
    void theLocalProviderStopsBeingCalledAfterFiveFailures() {
        var provider = mock(DaoAuthenticationProvider.class);

        failSixLogins(provider);

        verify(provider, times(5)).authenticate(any());
    }

    // V9: the Active Directory provider is locked, so the sixth failed login in the window never reaches it
    @Test
    void theActiveDirectoryProviderStopsBeingCalledAfterFiveFailures() {
        var provider = mock(ActiveDirectoryLdapAuthenticationProvider.class);

        failSixLogins(provider);

        verify(provider, times(5)).authenticate(any());
    }

    // V9: any other provider (SAML, OIDC, bearer, PAT) is not locked, so every failed login reaches it
    @Test
    void anotherProviderIsNotLocked() {
        var provider = mock(AuthenticationProvider.class);

        failSixLogins(provider);

        verify(provider, times(6)).authenticate(any());
    }

    // V9: the manager is a ProviderManager that wraps every provider and keeps the credentials for SAML
    @Test
    void theManagerWrapsEveryProviderAndKeepsTheCredentials() {
        var manager = assertInstanceOf(ProviderManager.class,
                config.authenticationManager(
                        List.of(mock(DaoAuthenticationProvider.class), mock(AuthenticationProvider.class)),
                        LOCKOUT_CLOCK));

        assertEquals(2, manager.getProviders().size());
        manager.getProviders().forEach(p -> assertInstanceOf(OpenLAuthenticationProviderWrapper.class, p));
        assertFalse(manager.isEraseCredentialsAfterAuthentication(), "SAML single sign-out needs the credentials");
    }

    // V9: a configuration without any provider fails instead of building a manager that rejects everything
    @Test
    void noProviderIsRejected() {
        var providers = List.<AuthenticationProvider>of();

        assertThrows(IllegalStateException.class, () -> config.authenticationManager(providers, LOCKOUT_CLOCK));
    }

    private Object savedRequestFor(String servletPath, String pathInfo) {
        var cache = config.httpSessionRequestCache();
        var request = new MockHttpServletRequest("GET", servletPath + (pathInfo == null ? "" : pathInfo));
        request.setServletPath(servletPath);
        request.setPathInfo(pathInfo);
        var response = new MockHttpServletResponse();
        cache.saveRequest(request, response);
        return cache.getRequest(request, response);
    }

    // V4: runs one request through the security headers filter, initialized as its bean definition does
    private MockHttpServletResponse headersFor(boolean secure) throws Exception {
        var filter = config.securityHeadersFilter();
        filter.afterPropertiesSet();
        var request = new MockHttpServletRequest("GET", "/");
        request.setSecure(secure);
        var response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    // V9: six failed logins of one user, at one instant, through a manager built over the given provider alone
    private void failSixLogins(AuthenticationProvider provider) {
        when(provider.supports(any())).thenReturn(true);
        when(provider.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));
        var manager = config.authenticationManager(List.of(provider), LOCKOUT_CLOCK);
        String generatedPassword = RandomStringUtils.secure().nextAlphanumeric(16);

        for (int attempt = 1; attempt <= 6; attempt++) {
            var login = new UsernamePasswordAuthenticationToken("jdoe", generatedPassword);
            assertThrows(BadCredentialsException.class, () -> manager.authenticate(login), "attempt " + attempt);
        }
    }
}

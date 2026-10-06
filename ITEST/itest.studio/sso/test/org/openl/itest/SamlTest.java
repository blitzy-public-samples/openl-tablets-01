package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.adobe.testing.s3mock.testcontainers.S3MockContainer;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;

/**
 * Verifies the SAML 2.0 login and SP-initiated Single Logout lifecycle against a real Keycloak Identity
 * Provider. Mirrors the OAuth2 scenario in {@link OAuthTest#singleLogout()}.
 *
 * @author Yury Molchan
 */
@DisabledIfSystemProperty(named = "noDocker", matches = ".*")
class SamlTest extends AbstractKeycloakTest {

    private static final String ENTITY_ID = "openlstudio-saml";

    @Test
    void singleLogout() throws Exception {
        try (var keycloak = keycloak();
             var s3 = new S3MockContainer("latest")) {
            keycloak.start();
            s3.start();
            var authServerUrl = keycloak.getAuthServerUrl();
            try (var httpClient = studio(s3).start()) {
                initStudio(httpClient, authServerUrl);

                var browser = new SsoBrowser(httpClient.getBaseURL());

                // Unauthenticated access is challenged.
                assertProtected(browser, "/saml2/authenticate/webstudio");

                // Log in; the session resolves to admin.
                // V3: the realm password is generated at runtime
                browser.loginViaSaml("admin", password("admin"));
                assertAdminSession(browser);

                // SP-initiated logout sends a SAML LogoutRequest to the IdP Single Logout Service.
                var logoutDestination = browser.logoutViaSaml();
                assertTrue(logoutDestination.startsWith(authServerUrl + "/realms/openlstudio/protocol/saml"),
                        "Logout must target the IdP Single Logout Service: " + logoutDestination);

                // Local session cleared; the IdP requires re-authentication.
                assertRestUnauthorized(browser);
                assertTrue(browser.samlChallengesForLogin(),
                        "Keycloak must require re-authentication after logout");
            }
        }
    }

    // V3: a browser withholds the SameSite=Lax session cookie on the IdP's cross-site POST, and the login still
    // completes, because Studio finds its AuthnRequest by RelayState instead of by session
    @Test
    void crossSiteSamlCallback() throws Exception {
        withSamlStudio(browser -> {
            // Unauthenticated access is challenged.
            assertProtected(browser, "/saml2/authenticate/webstudio");

            // The SAML response is posted without the Studio session cookie; the session resolves to admin.
            browser.loginViaSaml("admin", password("admin"), true);
            assertEquals(HttpStatus.SC_OK, browser.get("/rest/users/profile").statusCode(),
                    "/rest/users/profile after a cross-site SAML callback");
            assertAdminSession(browser);
        });
    }

    // V4: the SAML metadata, REST and catch-all chains send the default security headers, before and after login
    @Test
    void securityHeaders() throws Exception {
        withSamlStudio(browser -> {
            // V4: the first GET / creates the pre-login session, and Jetty marks every response that sets a cookie
            // "Expires: Thu, 01 Jan 1970", so Spring's cache writer backs off on that one response. The checks below
            // run with the session it created, so they see the complete default set.
            assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, browser.get("/").statusCode(), "/ creating the session");

            // Before login: the metadata chain serves, the REST chain rejects, the catch-all chain redirects.
            assertStatusAndSecurityHeaders(browser, "/saml2/service-provider-metadata/webstudio", HttpStatus.SC_OK);
            assertStatusAndSecurityHeaders(browser, "/rest/users/profile", HttpStatus.SC_UNAUTHORIZED);
            assertStatusAndSecurityHeaders(browser, "/", HttpStatus.SC_MOVED_TEMPORARILY);

            // After login: the REST chain serves the authenticated session.
            browser.loginViaSaml("admin", password("admin"));
            assertStatusAndSecurityHeaders(browser, "/rest/users/profile", HttpStatus.SC_OK);
        });
    }

    // V5: the Studio session ID that the first GET created is replaced when the SAML login completes
    @Test
    void sessionIdRotatesOnLogin() throws Exception {
        withSamlStudio(browser -> {
            // The pre-login session cookie is kept through the callback.
            var pre = browser.loginViaSamlReturningPreLoginSessionId("admin", password("admin"));
            assertNotNull(pre, "pre-login JSESSIONID");
            var post = browser.studioSessionId();
            assertNotNull(post, "post-login JSESSIONID");
            // Compared without assertEquals or assertNotEquals, whose failure text would print the session IDs.
            assertFalse(pre.equals(post), "Studio JSESSIONID must change on login");
            assertAdminSession(browser);
        });
    }

    // V10: sys.json and http.json answer 401 without a session and 200 with the SAML session cookie alone
    @Test
    void sysInfoRequiresSession() throws Exception {
        withSamlStudio(browser -> {
            // Before login: no session; openl.json, which the UI reads before login, stays public.
            assertSysInfo(browser, HttpStatus.SC_UNAUTHORIZED);
            assertEquals(HttpStatus.SC_OK, browser.get("/rest/public/info/openl.json").statusCode(),
                    "/rest/public/info/openl.json");

            // After login: only the session cookie authenticates; no Authorization header is sent.
            browser.loginViaSaml("admin", password("admin"));
            assertSysInfo(browser, HttpStatus.SC_OK);
        });
    }

    private void initStudio(org.openl.itest.core.HttpClient httpClient, String authServerUrl) {
        var samlConfig = (ObjectNode) httpClient.readTree("test-resources-saml/set-authentication-template.json");
        samlConfig.put("metadataUrl", authServerUrl + "/realms/openlstudio/protocol/saml/descriptor");
        samlConfig.put("entityId", ENTITY_ID);
        httpClient.postForObject("/rest/admin/settings/authentication", samlConfig);
    }

    // V3: one scenario of the security checks, run in a browser against its own Keycloak, S3 mock and Studio
    @FunctionalInterface
    private interface SamlScenario {
        void run(SsoBrowser browser) throws Exception;
    }

    // V3: starts Keycloak, the S3 mock and a SAML-configured Studio as singleLogout does, then runs the scenario
    // in a fresh browser; used only by the security checks
    private void withSamlStudio(SamlScenario scenario) throws Exception {
        try (var keycloak = keycloak();
             var s3 = new S3MockContainer("latest")) {
            keycloak.start();
            s3.start();
            var authServerUrl = keycloak.getAuthServerUrl();
            try (var httpClient = studio(s3).start()) {
                initStudio(httpClient, authServerUrl);

                scenario.run(new SsoBrowser(httpClient.getBaseURL()));
            }
        }
    }

    // V4: fetches url without following redirects, then checks its status and default security headers; the
    // messages name the URL only
    private static void assertStatusAndSecurityHeaders(SsoBrowser browser,
                                                       String url,
                                                       int expectedStatus) throws Exception {
        var response = browser.get(url);
        assertEquals(expectedStatus, response.statusCode(), url);
        assertSecurityHeaders(response, url);
    }
}

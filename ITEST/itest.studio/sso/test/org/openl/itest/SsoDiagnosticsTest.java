package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * Proves that the SSO test helpers fail without printing authentication-bearing content (V3). A loopback server
 * answers with malformed IdP and Studio pages that carry values generated per run, and each failure message must
 * name its fixed stage, pattern or status while leaving every generated value out. Needs no Docker.
 */
class SsoDiagnosticsTest {

    private static final String TOKEN_PATH = "/realms/openlstudio/protocol/openid-connect/token";
    private static final String END_SESSION_PATH = "/realms/openlstudio/protocol/openid-connect/logout";

    @BeforeAll
    static void httpTimeouts() {
        // The ITEST Surefire configuration sets both; these defaults serve only a run outside it.
        if (System.getProperty("http.timeout.connect") == null) {
            System.setProperty("http.timeout.connect", "10000");
        }
        if (System.getProperty("http.timeout.read") == null) {
            System.setProperty("http.timeout.read", "30000");
        }
    }

    @Test
    void samlResponseFormWithoutActionIsNotPrinted() throws Exception {
        var samlRequest = generated();
        var samlResponse = generated();
        var relayState = generated();
        var password = generated();
        try (var site = new LoopbackSite()) {
            site.page("/", 200, Map.of(), autoPostForm(site.url("/idp/sso"), "SAMLRequest", samlRequest, relayState));
            site.page("/idp/sso", 200, Map.of(), loginForm(site.url("/idp/login")));
            site.page("/idp/login", 200, Map.of(), autoPostForm(null, "SAMLResponse", samlResponse, relayState));

            var failure = failureOf(() -> new SsoBrowser(site.base()).loginViaSaml("admin", password));

            assertDiagnostic(failure,
                    AssertionError.class,
                    List.of("SAML response auto-submit form", "action=", "not found in the response (status 200)"),
                    List.of(samlRequest, samlResponse, relayState, password));
        }
    }

    @Test
    void keycloakLoginPageWithoutFormIsNotPrinted() throws Exception {
        var state = generated();
        var sessionCode = generated();
        var password = generated();
        try (var site = new LoopbackSite()) {
            site.page("/", 302, Map.of("Location", site.url("/idp/auth") + "?state=" + state), "");
            site.page("/idp/auth",
                    200,
                    Map.of(),
                    "<html><body><form action=\"" + site.url("/idp/other") + "\" method=\"post\">"
                            + "<input type=\"hidden\" name=\"session_code\" value=\"" + sessionCode + "\"/>"
                            + "</form></body></html>");

            var failure = failureOf(() -> new SsoBrowser(site.base()).loginViaOAuth2("admin", password));

            assertDiagnostic(failure,
                    AssertionError.class,
                    List.of("Keycloak login form", "kc-form-login", "not found in the response (status 200)"),
                    List.of(state, sessionCode, password));
        }
    }

    @Test
    void logoutRedirectWithoutSamlRequestIsNotPrinted() throws Exception {
        var token = generated();
        var sessionState = generated();
        try (var site = new LoopbackSite()) {
            site.page("/logout",
                    302,
                    Map.of("Location", site.url("/idp/logout") + "?token=" + token + "&session_state=" + sessionState),
                    "");

            var failure = failureOf(() -> new SsoBrowser(site.base()).logoutViaSaml());

            assertDiagnostic(failure,
                    AssertionError.class,
                    List.of("Logout redirect carries no SAMLRequest (status 302)"),
                    List.of(token, sessionState, "/idp/logout"));
        }
    }

    @Test
    void logoutPageWithoutSamlRequestIsNotPrinted() throws Exception {
        var samlResponse = generated();
        try (var site = new LoopbackSite()) {
            site.page("/logout", 200, Map.of(), autoPostForm(site.url("/idp/slo"), "SAMLResponse", samlResponse, ""));

            var failure = failureOf(() -> new SsoBrowser(site.base()).logoutViaSaml());

            assertDiagnostic(failure,
                    AssertionError.class,
                    List.of("Logout issued no SAML LogoutRequest (status 200)"),
                    List.of(samlResponse, "/idp/slo"));
        }
    }

    @Test
    void logoutFormWithoutActionIsNotPrinted() throws Exception {
        var samlRequest = generated();
        var relayState = generated();
        try (var site = new LoopbackSite()) {
            site.page("/logout", 200, Map.of(), autoPostForm(null, "SAMLRequest", samlRequest, relayState));

            var failure = failureOf(() -> new SsoBrowser(site.base()).logoutViaSaml());

            assertDiagnostic(failure,
                    AssertionError.class,
                    List.of("SAML LogoutRequest auto-submit form", "action=", "not found in the response (status 200)"),
                    List.of(samlRequest, relayState));
        }
    }

    @Test
    void oauthLogoutRedirectChecksNeverPrintTheIdToken() {
        var endSessionEndpoint = "http://127.0.0.1" + END_SESSION_PATH;
        var idToken = generatedJwt();
        var state = generated();

        // The redirect leaves for another host with a valid-looking id_token_hint.
        var wrongHost = failureOf(() -> OAuthTest.assertLogoutRedirect(
                "http://" + generated() + ".invalid" + END_SESSION_PATH + "?id_token_hint=" + idToken,
                endSessionEndpoint));
        assertDiagnostic(wrongHost,
                AssertionError.class,
                List.of("Logout must redirect to the OIDC end-session endpoint"),
                tokenParts(idToken));

        // The redirect reaches the endpoint but drops the hint; its other query values stay out too.
        var noHint = failureOf(() -> OAuthTest.assertLogoutRedirect(endSessionEndpoint + "?state=" + state,
                endSessionEndpoint));
        assertDiagnostic(noHint, AssertionError.class, List.of("Logout must pass the id_token_hint"), List.of(state));

        // A redirect that passes both checks does not fail.
        OAuthTest.assertLogoutRedirect(endSessionEndpoint + "?id_token_hint=" + idToken, endSessionEndpoint);
    }

    @Test
    void tokenEndpointFailureNeverPrintsTheResponse() throws Exception {
        var accessToken = generatedJwt();
        var idToken = generatedJwt();
        var refreshToken = generated();
        var password = generated();
        try (var site = new LoopbackSite()) {
            site.page(TOKEN_PATH,
                    401,
                    Map.of("Content-Type", "application/json"),
                    "{\"access_token\":\"" + accessToken + "\",\"id_token\":\"" + idToken + "\",\"refresh_token\":\""
                            + refreshToken + "\",\"error\":\"invalid_grant\"}");
            var authServerUrl = site.url("");

            var failure = failureOf(() -> new OAuthTest().getAccessTokenForUser(authServerUrl, "admin", password));

            var secrets = new ArrayList<String>();
            secrets.addAll(tokenParts(accessToken));
            secrets.addAll(tokenParts(idToken));
            secrets.addAll(List.of(refreshToken, password, AbstractKeycloakTest.clientSecret(), "invalid_grant"));
            assertDiagnostic(failure,
                    RuntimeException.class,
                    List.of("for user admin", authServerUrl + TOKEN_PATH, "status 401"),
                    secrets);
        }
    }

    // Asserts the failure's type, the generated values it must leave out and the fixed texts it must name. The
    // assertion messages are fixed too: they never print the failure, whose text is what is under test.
    private static void assertDiagnostic(Throwable failure,
                                         Class<? extends Throwable> expectedType,
                                         List<String> expectedTexts,
                                         List<String> secrets) {
        assertTrue(expectedType.isInstance(failure), "the failure must be a " + expectedType.getSimpleName());
        var printed = printedText(failure);
        for (var secret : secrets) {
            assertFalse(printed.contains(secret), "the diagnostic must not carry a generated value");
        }
        for (var expected : expectedTexts) {
            assertTrue(printed.contains(expected), "the diagnostic must name: " + expected);
        }
    }

    // The text a test report prints for a failure: the type and message of the failure, its suppressed failures
    // and each cause.
    private static String printedText(Throwable failure) {
        var printed = new StringBuilder();
        Throwable current = failure;
        for (int depth = 0; current != null && depth < 16; depth++) {
            printed.append(current).append('\n');
            for (var suppressed : current.getSuppressed()) {
                printed.append(suppressed).append('\n');
            }
            current = current.getCause();
        }
        return printed.toString();
    }

    // Runs the action and returns what it threw, without printing it.
    private static Throwable failureOf(Executable action) {
        try {
            action.execute();
        } catch (Throwable failure) {
            return failure;
        }
        return fail("the call must fail");
    }

    // 32 random alphanumerics, generated per call.
    private static String generated() {
        return AbstractKeycloakTest.randomValue() + AbstractKeycloakTest.randomValue();
    }

    // A JWT-shaped value: a base64url header and payload with generated claims, and a generated signature.
    private static String generatedJwt() {
        var encoder = Base64.getUrlEncoder().withoutPadding();
        var header = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"" + generated() + "\"}";
        var payload = "{\"sub\":\"" + generated() + "\",\"sid\":\"" + generated() + "\"}";
        return encoder.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "." + generated();
    }

    // The whole token and each of its parts, so that a partial leak is caught as well.
    private static List<String> tokenParts(String token) {
        var parts = new ArrayList<String>();
        parts.add(token);
        parts.addAll(List.of(token.split("\\.")));
        return parts;
    }

    // An HTTP-POST binding auto-submit form; a null action leaves the action attribute out.
    private static String autoPostForm(@Nullable String action, String field, String value, String relayState) {
        var actionAttribute = action == null ? "" : " action=\"" + action + "\"";
        return "<html><body onload=\"document.forms[0].submit()\"><form method=\"post\"" + actionAttribute + ">"
                + "<input type=\"hidden\" name=\"" + field + "\" value=\"" + value + "\"/>"
                + "<input type=\"hidden\" name=\"RelayState\" value=\"" + relayState + "\"/>"
                + "</form></body></html>";
    }

    // A Keycloak-like login form posting to the action.
    private static String loginForm(String action) {
        return "<html><body><form id=\"kc-form-login\" action=\"" + action + "\" method=\"post\">"
                + "<input name=\"username\"/><input name=\"password\" type=\"password\"/>"
                + "</form></body></html>";
    }

    // A server on the loopback interface that answers each registered path with a fixed page; closing it stops it.
    private static final class LoopbackSite implements AutoCloseable {

        private final HttpServer server;
        private final String baseUrl;

        LoopbackSite() throws IOException {
            var loopback = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
            server = HttpServer.create(new InetSocketAddress(loopback, 0), 0);
            server.start();
            baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        }

        URI base() {
            return URI.create(baseUrl + "/");
        }

        String url(String path) {
            return baseUrl + path;
        }

        void page(String path, int status, Map<String, String> headers, String body) {
            server.createContext(path, exchange -> respond(exchange, status, headers, body));
        }

        @Override
        public void close() {
            server.stop(0);
        }

        private static void respond(HttpExchange exchange,
                                    int status,
                                    Map<String, String> headers,
                                    String body) throws IOException {
            // Closing the exchange drains whatever request body the browser posted.
            try {
                var responseHeaders = exchange.getResponseHeaders();
                responseHeaders.set("Content-Type", "text/html; charset=UTF-8");
                headers.forEach(responseHeaders::set);
                var bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
                if (bytes.length > 0) {
                    exchange.getResponseBody().write(bytes);
                }
            } finally {
                exchange.close();
            }
        }
    }
}

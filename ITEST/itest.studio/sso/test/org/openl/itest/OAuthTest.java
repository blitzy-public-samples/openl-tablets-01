package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Stream;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;

import com.adobe.testing.s3mock.testcontainers.S3MockContainer;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.StdOut;

@DisabledIfSystemProperty(named = "noDocker", matches = ".*")
class OAuthTest extends AbstractKeycloakTest {

    private static final String CLIENT_ID = "openlstudio";
    // V3: randomness for the per-run unknown access token
    private static final SecureRandom TOKEN_RANDOM = new SecureRandom();
    // V12: the fixed text of the ADMIN name-match WARN of GetUserPrivileges, the PAT prefix and the polling limits
    private static final String ADMIN_MATCH = "which holds ADMIN";
    private static final String PAT_PREFIX = "openl_pat_";
    private static final Duration ADMIN_WARNING_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration SETTLE_TIMEOUT = Duration.ofSeconds(1);
    private static final Duration POLL_INTERVAL = Duration.ofMillis(100);

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(Integer.parseInt(System.getProperty("http.timeout.connect"))))
            .build();

    @Test
    void smoke() throws Exception {
        try (var keycloack = keycloak();
             var s3 = new S3MockContainer("latest")) {
            keycloack.start();
            s3.start();
            var authServerUrl = keycloack.getAuthServerUrl();
            var bearerTokens = retrieveBearerAccessTokens(authServerUrl);
            try (var httpClient = studio(s3).start()) {
                initStudio(httpClient, authServerUrl);

                httpClient.localEnv.putAll(bearerTokens);
                httpClient.test("test-resources-oauth2");

                // stop Keycloak to simulate the lag
                keycloack.stop();
                httpClient.test("test-resources-oauth2-lag");
            }
        }
    }

    @Test
    void smokePat() throws Exception {
        try (var keycloack = keycloak();
             var s3 = new S3MockContainer("latest")) {
            keycloack.start();
            s3.start();
            var authServerUrl = keycloack.getAuthServerUrl();
            var bearerTokens = retrieveBearerAccessTokens(authServerUrl);
            try (var httpClient = studio(s3).start()) {
                initStudio(httpClient, authServerUrl);

                httpClient.localEnv.putAll(bearerTokens);
                httpClient.test("test-resources-pat/000-setup");

                // Create PATs for users
                var adminPat = getPersonalAccessTokenForUser(httpClient,
                        bearerTokens.get("ADMIN_ACCESS_TOKEN"),
                        new CreatePersonalAccessTokenRequest("admin-pat", Date.from(Instant.now().plusSeconds(3600))));
                assertEquals("admin", adminPat.loginName());
                httpClient.localEnv.put("ADMIN_PAT", adminPat.token());
                httpClient.localEnv.put("ADMIN_PAT_PUBLIC_ID", adminPat.publicId());

                var user1Pat = getPersonalAccessTokenForUser(httpClient,
                        bearerTokens.get("USER1_ACCESS_TOKEN"),
                        new CreatePersonalAccessTokenRequest("user1-pat", Date.from(Instant.now().plusSeconds(3600))));
                assertEquals("user1", user1Pat.loginName());
                httpClient.localEnv.put("USER1_PAT", user1Pat.token());
                httpClient.localEnv.put("USER1_PAT_PUBLIC_ID", user1Pat.publicId());

                var user1Pat2 = getPersonalAccessTokenForUser(httpClient,
                        bearerTokens.get("USER1_ACCESS_TOKEN"),
                        new CreatePersonalAccessTokenRequest("user1-pat-second", Date.from(Instant.now().plusSeconds(3600))));
                assertEquals("user1", user1Pat2.loginName());
                httpClient.localEnv.put("USER1_PAT_2", user1Pat2.token());
                httpClient.localEnv.put("USER1_PAT_PUBLIC_ID_2", user1Pat2.publicId());

                var guestPat = getPersonalAccessTokenForUser(httpClient,
                        bearerTokens.get("GUEST_ACCESS_TOKEN"),
                        new CreatePersonalAccessTokenRequest("guest-pat", Date.from(Instant.now().plusSeconds(3600))));
                assertEquals("guest", guestPat.loginName());
                httpClient.localEnv.put("GUEST_PAT", guestPat.token());
                httpClient.localEnv.put("GUEST_PAT_PUBLIC_ID", guestPat.publicId());

                // Continue tests with PATs
                httpClient.test("test-resources-pat/100-pat-tests");
            }
        }
    }

    @Test
    void singleLogout() throws Exception {
        try (var keycloack = keycloak();
             var s3 = new S3MockContainer("latest")) {
            keycloack.start();
            s3.start();
            var authServerUrl = keycloack.getAuthServerUrl();
            try (var httpClient = studio(s3).start()) {
                initStudio(httpClient, authServerUrl);

                var browser = new SsoBrowser(httpClient.getBaseURL());

                // Unauthenticated access is challenged.
                assertProtected(browser, "/oauth2/authorization/webstudio");

                // Log in; the session resolves to admin.
                // V3: the realm password is generated at runtime
                browser.loginViaOAuth2("admin", password("admin"));
                assertAdminSession(browser);

                // SP-initiated logout redirects to the OIDC end-session endpoint with the id_token_hint.
                var logoutRedirect = browser.logoutViaOAuth2();
                // V3: the same two checks, whose messages never carry the redirect and its ID token
                assertLogoutRedirect(logoutRedirect,
                        authServerUrl + "/realms/openlstudio/protocol/openid-connect/logout");

                // Local session cleared; the IdP requires re-authentication.
                assertRestUnauthorized(browser);
                assertTrue(browser.oauth2ChallengesForLogin(),
                        "Keycloak must require re-authentication after logout");
            }
        }
    }

    // V3: checks the logout redirect with fixed messages, because its query carries the id_token_hint JWT
    static void assertLogoutRedirect(String logoutRedirect, String endSessionEndpoint) {
        assertTrue(logoutRedirect.startsWith(endSessionEndpoint),
                "Logout must redirect to the OIDC end-session endpoint");
        assertTrue(logoutRedirect.contains("id_token_hint="), "Logout must pass the id_token_hint");
    }

    // V4: the OIDC logout, callback, authorization, REST and catch-all chains send the default security headers
    // Strict-Transport-Security is sent only on a request marked secure.
    @Test
    void securityHeaders() throws Exception {
        try (var keycloak = keycloak();
             var s3 = new S3MockContainer("latest")) {
            keycloak.start();
            s3.start();
            var authServerUrl = keycloak.getAuthServerUrl();
            try (var httpClient = studio(s3).start()) {
                initStudio(httpClient, authServerUrl);

                var browser = new SsoBrowser(httpClient.getBaseURL());

                // V4: this first request only creates the Studio session for the checks below
                // Its response carries Jetty's Expires with the new cookie, so the cache writer backs off by design.
                // Responses below that set no cookie and no cache policy of their own must carry the full default set.
                assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, browser.get("/").statusCode(),
                        "/: session-creating status");

                // Before login: the authorization redirect, the REST challenge and the login redirect.
                assertSecurityHeadersOn(browser, "/oauth2/authorization/webstudio", HttpStatus.SC_MOVED_TEMPORARILY);
                assertSecurityHeadersOn(browser, "/rest/users/profile", HttpStatus.SC_UNAUTHORIZED);
                assertSecurityHeadersOn(browser, "/", HttpStatus.SC_MOVED_TEMPORARILY);
                // V4: the same chains marked secure (X-Forwarded-Proto: https) also send Strict-Transport-Security
                assertSecureSecurityHeadersOn(browser,
                        "/oauth2/authorization/webstudio",
                        HttpStatus.SC_MOVED_TEMPORARILY);
                assertSecureSecurityHeadersOn(browser, "/rest/users/profile", HttpStatus.SC_UNAUTHORIZED);
                assertSecureSecurityHeadersOn(browser, "/", HttpStatus.SC_MOVED_TEMPORARILY);
                // V4: the callback chain, asked without an authorization response, rejects with Jetty's error page
                // It is asked only before login, because the failed authentication clears the security context.
                assertCallbackChainSecurityHeadersOn(browser,
                        "/login/oauth2/code/webstudio",
                        HttpStatus.SC_UNAUTHORIZED);

                // After login: the REST chain serving the authenticated session.
                browser.loginViaOAuth2("admin", password("admin"));
                assertSecurityHeadersOn(browser, "/rest/users/profile", HttpStatus.SC_OK);
                // V4: the real IdP callback rotates the session ID and still carries the response-independent headers
                // Jetty adds its own Expires to that cookie-setting response, so the cache writer backs off by design.
                var callback = browser.lastStudioResponse("/login/oauth2/code/webstudio");
                assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, callback.statusCode(), "/login/oauth2/code/**: status");
                assertCookieSettingSecurityHeaders(callback, "/login/oauth2/code/**");

                // V4: the logout chain ends the session with a redirect to the IdP
                // It then answers a request marked secure on the ended session.
                assertSecurityHeadersOn(browser, "/logout", HttpStatus.SC_MOVED_TEMPORARILY);
                assertSecureSecurityHeadersOn(browser, "/logout", HttpStatus.SC_MOVED_TEMPORARILY);
            }
        }
    }

    // V4: one request without following redirects; the messages name the URL, never a body
    private static void assertSecurityHeadersOn(SsoBrowser browser, String url, int expectedStatus) throws Exception {
        var response = browser.get(url);
        assertEquals(expectedStatus, response.statusCode(), url + ": status");
        assertSecurityHeaders(response, url);
    }

    // V5: the OIDC login replaces the pre-login Studio session ID, so a fixated session ID is never authenticated
    @Test
    void sessionIdRotatesOnLogin() throws Exception {
        try (var keycloak = keycloak();
             var s3 = new S3MockContainer("latest")) {
            keycloak.start();
            s3.start();
            var authServerUrl = keycloak.getAuthServerUrl();
            try (var httpClient = studio(s3).start()) {
                initStudio(httpClient, authServerUrl);

                var browser = new SsoBrowser(httpClient.getBaseURL());

                // The session IDs are only compared, never printed.
                var pre = browser.loginViaOAuth2ReturningPreLoginSessionId("admin", password("admin"));
                assertNotNull(pre, "pre-login JSESSIONID");
                var post = browser.studioSessionId();
                assertNotNull(post, "post-login JSESSIONID");
                assertFalse(pre.equals(post), "Studio JSESSIONID must change on login");
                assertAdminSession(browser);
            }
        }
    }

    // V10: sys.json and http.json answer 401 without a session and 200 with only the browser's session cookie
    @Test
    void sysInfoRequiresSession() throws Exception {
        try (var keycloak = keycloak();
             var s3 = new S3MockContainer("latest")) {
            keycloak.start();
            s3.start();
            var authServerUrl = keycloak.getAuthServerUrl();
            try (var httpClient = studio(s3).start()) {
                initStudio(httpClient, authServerUrl);

                var browser = new SsoBrowser(httpClient.getBaseURL());

                // Without a session: the two endpoints are refused, the build info the UI reads stays public.
                assertSysInfo(browser, HttpStatus.SC_UNAUTHORIZED);
                assertEquals(HttpStatus.SC_OK, browser.get("/rest/public/info/openl.json").statusCode(),
                        "/rest/public/info/openl.json");

                // With the session cookie of an OIDC login, and no Authorization header.
                browser.loginViaOAuth2("admin", password("admin"));
                assertSysInfo(browser, HttpStatus.SC_OK);
            }
        }
    }

    // V12: an IdP login whose group matches an ADMIN-holding OpenL group is warned about
    // A login matching only non-ADMIN groups is not warned about, nor is a PAT request replaying stored groups.
    @Test
    @StdIo
    void adminGroupMatchWarns(StdOut out, StdErr err) throws Exception {
        // V12: both @StdIo captures go to the leak guard, which scans them after the test, passed or failed
        // @StdIo takes the streams from the guard's tees, so what this test writes reaches the captures, not the tees.
        // The scan covers Studio start-up and shutdown and looks for every generated and issued secret.
        scanCapturedAfterTest(out::capturedString);
        scanCapturedAfterTest(err::capturedString);
        try (var keycloak = keycloak();
             var s3 = new S3MockContainer("latest")) {
            keycloak.start();
            s3.start();
            var authServerUrl = keycloak.getAuthServerUrl();
            var bearerTokens = retrieveBearerAccessTokens(authServerUrl);
            try (var httpClient = studio(s3).start()) {
                initStudio(httpClient, authServerUrl);

                // 'openl-admin' holds ADMIN and 'openl-ba' does not. These bearer requests of admin may already warn,
                // so every check below reads only the output written after its own mark.
                httpClient.localEnv.putAll(bearerTokens);
                httpClient.test("test-resources-oauth2-admin-warning");

                // admin is in /openl-admin, so its login warns.
                var mark = Mark.of(out, err);
                new SsoBrowser(httpClient.getBaseURL()).loginViaOAuth2("admin", password("admin"));
                assertTrue(awaitLineAfter(out, err, mark, ADMIN_WARNING_TIMEOUT,
                                line -> line.contains(ADMIN_MATCH)
                                        && line.contains("'admin'")
                                        && line.contains("'openl-admin'")),
                        "Expected the WARN that external group 'openl-admin' of user 'admin' matches an OpenL group"
                                + " which holds ADMIN");

                // user1 is in /openl-ba and /openl-extra, neither of which holds ADMIN, so its login does not warn.
                mark = Mark.of(out, err);
                var user1Browser = new SsoBrowser(httpClient.getBaseURL());
                user1Browser.loginViaOAuth2("user1", password("user1"));
                var profile = user1Browser.get("/rest/users/profile");
                assertEquals(HttpStatus.SC_OK, profile.statusCode(), "/rest/users/profile of user1");
                assertEquals("user1", mapper.readTree(profile.body()).get("username").asText(), "username of user1");
                assertFalse(awaitLineAfter(out, err, mark, SETTLE_TIMEOUT, line -> line.contains(ADMIN_MATCH)),
                        "The login of user1 must not log the ADMIN name-match WARN");

                // A PAT request replays admin's stored groups and is not an IdP login, so it does not warn.
                var adminBearerToken = bearerTokens.get("ADMIN_ACCESS_TOKEN");
                assertNotNull(adminBearerToken, "ADMIN_ACCESS_TOKEN");
                var pat = getPersonalAccessTokenForUser(httpClient,
                        adminBearerToken,
                        new CreatePersonalAccessTokenRequest("admin-warning-pat",
                                Date.from(Instant.now().plusSeconds(3600))));
                var patToken = pat.token();
                mark = Mark.of(out, err);
                // V12: the cookie-less JDK client sends only the PAT, so the token alone authenticates this request
                // The harness client would also send its remembered session cookie, which belongs to the same user.
                // PatAuthenticationFilter would still resolve and map the PAT on such a request.
                // It would keep the same user's session context, though, instead of the token's.
                var patRequest = HttpRequest.newBuilder(httpClient.getBaseURL().resolve("/rest/users/profile"))
                        .header(HttpHeaders.AUTHORIZATION, "Token " + patToken)
                        .timeout(Duration.ofMillis(Integer.parseInt(System.getProperty("http.timeout.read"))))
                        .GET()
                        .build();
                var patProfile = client.send(patRequest, HttpResponse.BodyHandlers.ofString());
                assertEquals(HttpStatus.SC_OK, patProfile.statusCode(), "/rest/users/profile with the admin PAT");
                assertEquals("admin", mapper.readTree(patProfile.body()).get("username").asText(),
                        "username of the admin PAT");
                assertFalse(awaitLineAfter(out, err, mark, SETTLE_TIMEOUT, line -> line.contains(ADMIN_MATCH)),
                        "A PAT request must not log the ADMIN name-match WARN");
            }
        }
    }

    // V12: the number of characters captured on each stream before a step; only text after it belongs to the step
    private record Mark(int out, int err) {

        static Mark of(StdOut out, StdErr err) {
            return new Mark(out.capturedString().length(), err.capturedString().length());
        }
    }

    // V12: the lines of both captured streams written after the mark
    private static Stream<String> linesAfter(StdOut out, StdErr err, Mark mark) {
        return Stream.concat(out.capturedString().substring(mark.out()).lines(),
                err.capturedString().substring(mark.err()).lines());
    }

    // V12: this JDK loop polls until a line after the mark matches (true) or the timeout elapses (false)
    // A JDK loop is used because Awaitility is not on this module's test classpath and its POM gains no dependency.
    private static boolean awaitLineAfter(StdOut out,
                                          StdErr err,
                                          Mark mark,
                                          Duration timeout,
                                          Predicate<String> match) throws InterruptedException {
        var deadline = System.nanoTime() + timeout.toNanos();
        while (linesAfter(out, err, mark).noneMatch(match)) {
            if (System.nanoTime() - deadline >= 0) {
                return false;
            }
            Thread.sleep(POLL_INTERVAL.toMillis());
        }
        return true;
    }

    // V12: the leak guard scans for a PAT's secret part as well as for the whole token
    // The secret part is the text after the first '.' that follows the openl_pat_ prefix.
    private static String patSecret(String token) {
        assertTrue(token.startsWith(PAT_PREFIX), "personal access token must start with " + PAT_PREFIX);
        var separator = token.indexOf('.', PAT_PREFIX.length());
        assertTrue(separator > PAT_PREFIX.length() && separator < token.length() - 1,
                "personal access token must hold a public ID and a secret");
        return token.substring(separator + 1);
    }

    // V3: package-private, so a failure part-way through the acquisitions is tested without Keycloak
    Map<String, String> retrieveBearerAccessTokens(String authServerUrl)
            throws URISyntaxException, IOException, InterruptedException {
        Map<String, String> tokens = new HashMap<>();
        // V3: realm passwords are generated at runtime
        tokens.put("ADMIN_ACCESS_TOKEN", getAccessTokenForUser(authServerUrl, "admin", password("admin")));
        tokens.put("USER1_ACCESS_TOKEN", getAccessTokenForUser(authServerUrl, "user1", password("user1")));
        tokens.put("GUEST_ACCESS_TOKEN", getAccessTokenForUser(authServerUrl, "guest", password("guest")));
        tokens.put("EPBDS12973_DEPLOYER_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds12973_deployer", password("epbds12973_deployer")));
        tokens.put("EPBDS12973_EDITOR_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds12973_editor", password("epbds12973_editor")));
        tokens.put("EPBDS12973_VIEWER_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds12973_viewer", password("epbds12973_viewer")));
        tokens.put("EPBDS14584_MANAGER_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds14584_manager", password("epbds14584_manager")));
        tokens.put("EPBDS14584_CONTRIBUTOR_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds14584_contributor", password("epbds14584_contributor")));
        tokens.put("EPBDS14584_VIEWER_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds14584_viewer", password("epbds14584_viewer")));
        tokens.put("EPBDS14670_MANAGER_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds14670_manager", password("epbds14670_manager")));
        tokens.put("EPBDS14670_CONTRIBUTOR_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds14670_contributor", password("epbds14670_contributor")));
        tokens.put("EPBDS14670_VIEWER_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds14670_viewer", password("epbds14670_viewer")));
        tokens.put("EPBDS14670R_MANAGER_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds14670r_manager", password("epbds14670r_manager")));
        tokens.put("EPBDS14670R_CONTRIBUTOR_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds14670r_contributor", password("epbds14670r_contributor")));
        tokens.put("EPBDS14670R_VIEWER_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds14670r_viewer", password("epbds14670r_viewer")));
        tokens.put("EPBDS15131_ADMIN_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds15131_admin", password("epbds15131_admin")));
        tokens.put("EPBDS15134_USER_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds15134_user", password("epbds15134_user")));
        tokens.put("EPBDS15621_USER_TOKEN",
                getAccessTokenForUser(authServerUrl, "epbds15621_user", password("epbds15621_user")));
        // V3: a per-run JWT-shaped token that no realm key signs is kept for the leak scans as soon as it exists
        // Each issued token is kept by getAccessTokenForUser the moment Keycloak returns it.
        var unknownAccessToken = unknownAccessToken();
        registerSecret("unknown access token", unknownAccessToken);
        tokens.put("UNKNOWN_ACCESS_TOKEN", unknownAccessToken);
        return tokens;
    }

    // V3: header, payload and random signature, each base64url-encoded without padding
    private static String unknownAccessToken() {
        var encoder = Base64.getUrlEncoder().withoutPadding();
        var header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        var payload = "{\"sub\":\"" + randomValue() + "\",\"jti\":\"" + randomValue() + "\",\"iat\":"
                + Instant.now().getEpochSecond() + "}";
        var signature = new byte[32];
        TOKEN_RANDOM.nextBytes(signature);
        return encoder.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString(signature);
    }

    private void initStudio(org.openl.itest.core.HttpClient httpClient, String authServerUrl) {
        var oauth2Config = (ObjectNode) httpClient.readTree("test-resources-oauth2/set-authentication-template.json");
        oauth2Config.put("issuerUri", authServerUrl + "/realms/openlstudio");
        // V3: generated client secret
        oauth2Config.put("clientSecret", clientSecret());
        oauth2Config.put("clientId", CLIENT_ID);
        httpClient.postForObject("/rest/admin/settings/authentication", oauth2Config);
    }

    // V3: package-private, so the token-free failure message is tested without Keycloak
    String getAccessTokenForUser(String authServerUrl, String username, String password)
            throws URISyntaxException, IOException, InterruptedException {
        var request = HttpRequest.newBuilder()
                .uri(new URI(authServerUrl + "/realms/openlstudio/protocol/openid-connect/token"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .timeout(Duration.ofMillis(Integer.parseInt(System.getProperty("http.timeout.read"))))
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=password&scope=openid profile email" +
                        "&client_id=" + CLIENT_ID +
                        // V3: generated client secret
                        "&client_secret=" + clientSecret() +
                        "&username=" + username +
                        "&password=" + password))
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == HttpStatus.SC_OK) {
            String responseBody = response.body();
            var responseNode = mapper.readTree(responseBody);
            // V3: every token Keycloak issues is kept for the leak scans of this class the moment it arrives
            // A later failed acquisition therefore leaves no issued token unscanned.
            // The ID and refresh tokens are kept only when the response has them.
            registerSecret("ID token", responseNode.path("id_token").asText(null));
            registerSecret("refresh token", responseNode.path("refresh_token").asText(null));
            var accessToken = responseNode.get("access_token").asText();
            registerSecret("bearer access token", accessToken);
            return accessToken;
        } else {
            // V3: the endpoint, the user and the status only; the response body can carry tokens
            throw new RuntimeException("Failed to get Access Token for user " + username + " from " + request.uri()
                    + ": status " + response.statusCode());
        }
    }

    private PersonalAccessTokenResponse getPersonalAccessTokenForUser(org.openl.itest.core.HttpClient httpClient, String bearerToken, CreatePersonalAccessTokenRequest tokenData) {
        var patResponse = httpClient.postForObject("/rest/users/personal-access-tokens",
                tokenData,
                PersonalAccessTokenResponse.class,
                HttpStatus.SC_CREATED,
                HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
        // V3: the token and its secret part are kept for the leak scans of this class as soon as Studio issues them
        var token = patResponse.token();
        registerSecret("personal access token", token);
        assertNotNull(token, "personal access token");
        registerSecret("personal access token secret", patSecret(token));
        assertEquals(tokenData.name(), patResponse.name());
        assertTrue(patResponse.createdAt().before(tokenData.expiresAt()));
        assertEquals(tokenData.expiresAt(), patResponse.expiresAt());
        return patResponse;
    }

    public record PersonalAccessTokenResponse(
            String publicId,
            String name,
            String loginName,
            String token,
            @JsonDeserialize(using = UtcDateDeserializer.class)
            Date createdAt,
            @JsonDeserialize(using = UtcDateDeserializer.class)
            Date expiresAt) {
    }

    public record CreatePersonalAccessTokenRequest(
            String name,
            @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSZ")
            Date expiresAt) {
    }

    public static class UtcDateDeserializer extends JsonDeserializer<Date> {

        @Override
        public Date deserialize(JsonParser p, DeserializationContext ctxt)
                throws IOException {
            Instant instant = Instant.parse(p.getValueAsString());
            return Date.from(instant);
        }
    }

}

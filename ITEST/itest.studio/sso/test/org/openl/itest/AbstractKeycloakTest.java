package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import com.adobe.testing.s3mock.testcontainers.S3MockContainer;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.apache.http.HttpStatus;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.extension.RegisterExtension;

import org.openl.itest.core.JettyServer;

/**
 * Shared setup for integration tests that drive OpenL Studio against a Keycloak Identity Provider: the
 * realm-backed Keycloak container, the Studio server wired to an S3 design repository, and the
 * login-lifecycle assertions reused by the OAuth2 and SAML tests.
 *
 * @author Yury Molchan
 */
abstract class AbstractKeycloakTest {

    // V3: realm user passwords, the client secret and the S3 mock keys are generated once per JVM
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final List<String> REALM_USERS = List.of("admin",
            "user1",
            "guest",
            "epbds12973_deployer",
            "epbds12973_editor",
            "epbds12973_viewer",
            "epbds14584_manager",
            "epbds14584_contributor",
            "epbds14584_viewer",
            "epbds14670_manager",
            "epbds14670_contributor",
            "epbds14670_viewer",
            "epbds14670r_manager",
            "epbds14670r_contributor",
            "epbds14670r_viewer",
            "epbds15131_admin",
            "epbds15134_user",
            "epbds15621_user");
    private static final Map<String, String> PASSWORDS = generatePasswords();
    private static final String CLIENT_SECRET = randomValue();
    private static final String S3_ACCESS_KEY = randomValue();
    private static final String S3_SECRET_KEY = randomValue();
    // V3: the leak guard holds every generated credential and every one issued to the test class, by kind
    /**
     * Scans the output each test captures for every credential it holds once the test finishes, whether it passed
     * or failed, and, after the class, the responses saved under {@code server.responses}.
     */
    @RegisterExtension
    static final SecretLeakGuard SECRET_GUARD = new SecretLeakGuard()
            .retain("realm credential", PASSWORDS.values())
            .retain("client secret", List.of(CLIENT_SECRET))
            .retain("S3 key", List.of(S3_ACCESS_KEY, S3_SECRET_KEY));

    protected final ObjectMapper mapper = new ObjectMapper();

    // V3: the realm file reads each credential from the container environment at import time
    @SuppressWarnings("resource")
    protected static KeycloakContainer keycloak() {
        var container = new KeycloakContainer("quay.io/keycloak/keycloak:latest")
                .withRealmImportFile("/openlstudio-realm.json");
        for (Map.Entry<String, String> entry : PASSWORDS.entrySet()) {
            container.withEnv("ITEST_PASSWORD_" + entry.getKey().toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]", "_"),
                    entry.getValue());
        }
        container.withEnv("ITEST_CLIENT_SECRET", CLIENT_SECRET);
        return container;
    }

    // V3: Studio's production-s3 deployment repository connects to the S3 mock with the keys generated once per JVM
    protected static JettyServer studio(S3MockContainer s3) {
        return JettyServer.get()
                .withInitParam("repository.production-s3.service-endpoint", s3.getHttpEndpoint())
                .withInitParam("repository.production-s3.access-key", S3_ACCESS_KEY)
                .withInitParam("repository.production-s3.secret-key", S3_SECRET_KEY);
    }

    // V3: 16 random alphanumerics, safe in the un-encoded token request form body
    protected static String randomValue() {
        StringBuilder builder = new StringBuilder(16);
        for (int i = 0; i < 16; i++) {
            builder.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return builder.toString();
    }

    // V3: the generated password of a realm user
    protected static String password(String user) {
        String password = PASSWORDS.get(user);
        if (password == null) {
            throw new IllegalArgumentException("No generated password for realm user " + user);
        }
        return password;
    }

    // V3: the generated secret of the openlstudio client
    protected static String clientSecret() {
        return CLIENT_SECRET;
    }

    // V3: every generated credential, for leak scans of captured output
    protected static Set<String> generatedSecrets() {
        Set<String> secrets = new LinkedHashSet<>(PASSWORDS.values());
        secrets.add(CLIENT_SECRET);
        secrets.add(S3_ACCESS_KEY);
        secrets.add(S3_SECRET_KEY);
        return Collections.unmodifiableSet(secrets);
    }

    // V3: keeps a credential issued during the test class, such as a token or a session ID, for the leak scans
    /**
     * Keeps {@code value}, a credential the IdP or Studio issued while the test class runs, so that each test's
     * captured output and, after the class, the saved responses are scanned for it. A {@code null} or blank value
     * is ignored.
     *
     * @param kind the kind of credential, the only thing a failure message names
     * @param value the credential
     */
    static void registerSecret(String kind, @Nullable String value) {
        SECRET_GUARD.register(kind, value);
    }

    // V3: a test that captures its streams with @StdIo hands each capture over, so the guard still scans it
    /**
     * Adds output captured outside the guard's tees, such as JUnit Pioneer {@code StdOut} or {@code StdErr}, to the
     * leak scan that runs when the current test finishes, whether it passes or fails.
     *
     * @param captured supplies the captured text; it is read only when the test finishes
     */
    protected static void scanCapturedAfterTest(Supplier<String> captured) {
        SECRET_GUARD.scanAlso(captured);
    }

    // V3: the harness saves the body of every mismatching response under server.responses; none may hold a secret
    /**
     * Fails, naming only the kind of secret and the file's relative path, when a response saved under the
     * {@code server.responses} directory contains a credential generated for or issued to this test class.
     */
    @AfterAll
    static void assertNoSecretsSaved() {
        SECRET_GUARD.assertNoSecretsSaved(Path.of(System.getProperty("server.responses", "target/responses")));
    }

    // V3: one generated password per realm user, in realm order
    private static Map<String, String> generatePasswords() {
        Map<String, String> passwords = new LinkedHashMap<>();
        for (String user : REALM_USERS) {
            passwords.put(user, randomValue());
        }
        return Collections.unmodifiableMap(passwords);
    }

    /**
     * Asserts an unauthenticated client is challenged: the home page redirects to {@code loginEntry} and the
     * REST API answers 401.
     */
    protected void assertProtected(SsoBrowser browser, String loginEntry) throws Exception {
        var landing = browser.get("/");
        assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, landing.statusCode());
        // V3: the failure names the expected login entry only; the Location can carry an authorization code or state
        assertTrue(landing.headers().firstValue("Location").orElseThrow().endsWith(loginEntry),
                "Expected a redirect to the login entry " + loginEntry);
        assertRestUnauthorized(browser);
    }

    /**
     * Asserts the session resolves to the {@code admin} user with the administrator authority.
     */
    protected void assertAdminSession(SsoBrowser browser) throws Exception {
        var profile = browser.get("/rest/users/profile");
        assertEquals(HttpStatus.SC_OK, profile.statusCode());
        var user = mapper.readTree(profile.body());
        assertEquals("admin", user.get("username").asText());
        assertTrue(user.get("administrator").asBoolean(), "admin must be mapped to an administrator");
    }

    /**
     * Asserts that the REST API rejects the current client as unauthenticated.
     */
    protected void assertRestUnauthorized(SsoBrowser browser) throws Exception {
        assertEquals(HttpStatus.SC_UNAUTHORIZED, browser.get("/rest/users/profile").statusCode());
    }

    // V4: the Spring Security default header set that the SAML, OIDC and static chains must send
    /**
     * Asserts that {@code response} carries the Spring Security default security headers, and no
     * {@code Strict-Transport-Security}, which is written only on secure requests and the tests use plain HTTP.
     *
     * <p>Every failure message names the URL and the header only; the response body is never printed.
     *
     * @param response the response to check
     * @param url the requested URL, used in the failure messages
     */
    protected static void assertSecurityHeaders(HttpResponse<?> response, String url) {
        var headers = response.headers();
        assertEquals("nosniff", headers.firstValue("X-Content-Type-Options").orElse(null),
                url + ": X-Content-Type-Options");
        assertEquals("DENY", headers.firstValue("X-Frame-Options").orElse(null), url + ": X-Frame-Options");
        assertEquals("no-cache, no-store, max-age=0, must-revalidate",
                headers.firstValue("Cache-Control").orElse(null),
                url + ": Cache-Control");
        assertEquals("no-cache", headers.firstValue("Pragma").orElse(null), url + ": Pragma");
        assertEquals("0", headers.firstValue("Expires").orElse(null), url + ": Expires");
        assertEquals("0", headers.firstValue("X-XSS-Protection").orElse(null), url + ": X-XSS-Protection");
        assertFalse(headers.firstValue("Strict-Transport-Security").isPresent(),
                url + ": Strict-Transport-Security must be absent on plain HTTP");
    }

    // V4: the default set on a request marked secure, where the HSTS writer must add Strict-Transport-Security
    /**
     * Sends a GET for {@code path} marked secure with {@code X-Forwarded-Proto: https}, which Studio's forwarded-header
     * filter turns into a secure request, and asserts its status, the Spring Security default security headers and
     * the default {@code Strict-Transport-Security: max-age=31536000 ; includeSubDomains}. Redirects are not followed.
     *
     * <p>Every failure message names the path and the header only; the response body is never printed.
     *
     * @param browser the browser whose cookie jar carries the session, if any
     * @param path the path relative to the Studio base URL, with no query
     * @param expectedStatus the status the chain must answer
     */
    protected static void assertSecureSecurityHeadersOn(SsoBrowser browser,
                                                        String path,
                                                        int expectedStatus) throws Exception {
        var response = getMarkedSecure(browser, path);
        var label = path + " (secure)";
        assertEquals(expectedStatus, response.statusCode(), label + ": status");
        assertResponseIndependentHeaders(response, label, true);
        var headers = response.headers();
        assertEquals("no-cache, no-store, max-age=0, must-revalidate",
                headers.firstValue("Cache-Control").orElse(null),
                label + ": Cache-Control");
        assertEquals("no-cache", headers.firstValue("Pragma").orElse(null), label + ": Pragma");
        assertEquals("0", headers.firstValue("Expires").orElse(null), label + ": Expires");
    }

    // V4: Jetty marks a cookie-setting response "Expires: Thu, 01 Jan 1970", so the cache writer backs off there only
    /**
     * Asserts the security headers that never depend on the response on a plain-HTTP response that sets a cookie,
     * such as an IdP callback that rotates the session ID: {@code X-Content-Type-Options: nosniff},
     * {@code X-Frame-Options: DENY}, {@code X-XSS-Protection: 0} and no {@code Strict-Transport-Security}.
     *
     * <p>Jetty adds its own {@code Expires: Thu, 01 Jan 1970 00:00:00 GMT} to every response that sets a cookie, and
     * Spring's cache writer backs off whenever the response already has a cache header, so the cache headers are not
     * expected here; the caller asserts the cache headers on a session-bearing request to the same chain. The check
     * fails if the response sets no cookie, so this exception never stands in for the full set. Every failure message
     * names the route and the header only; no cookie, location or body is printed.
     *
     * @param response the cookie-setting response
     * @param route the route pattern of the chain that answered, used in the failure messages
     */
    protected static void assertCookieSettingSecurityHeaders(HttpResponse<?> response, String route) {
        assertTrue(response.headers().firstValue("Set-Cookie").isPresent(),
                route + ": expected a cookie-setting response");
        assertResponseIndependentHeaders(response, route, false);
    }

    // V4: no response of an IdP callback chain leaves its cache policy to Spring, so only no-store is required there
    /**
     * Sends a GET for {@code path} on the browser's session, plainly and then marked secure with
     * {@code X-Forwarded-Proto: https}, to an IdP callback chain, and asserts both statuses, the security headers that
     * never depend on the response, {@code Strict-Transport-Security: max-age=31536000 ; includeSubDomains} on the
     * secure request only, and a {@code Cache-Control} that forbids storing the response.
     *
     * <p>Every response of a callback chain sets its own cache policy, and Spring's cache writer gives way to it by
     * design: the callback itself rotates the session ID, so Jetty marks it with its own {@code Expires}; a request
     * without the IdP's parameters fails into Jetty's error page, which sets its own {@code Cache-Control}; any other
     * path under the chain serves the application page with its own {@code Cache-Control: no-store}. Every failure
     * message names the path and the header only; the response body is never printed.
     *
     * @param browser the browser whose cookie jar carries the session
     * @param path the path relative to the Studio base URL, with no query, so it carries no IdP parameter
     * @param expectedStatus the status the chain must answer to both requests
     */
    protected static void assertCallbackChainSecurityHeadersOn(SsoBrowser browser,
                                                               String path,
                                                               int expectedStatus) throws Exception {
        var plain = browser.get(path);
        assertEquals(expectedStatus, plain.statusCode(), path + ": status");
        assertResponseIndependentHeaders(plain, path, false);
        assertNoStore(plain, path);
        var secure = getMarkedSecure(browser, path);
        var label = path + " (secure)";
        assertEquals(expectedStatus, secure.statusCode(), label + ": status");
        assertResponseIndependentHeaders(secure, label, true);
        assertNoStore(secure, label);
    }

    // V4: the request header that Studio's forwarded-header filter turns into a secure request
    private static HttpResponse<String> getMarkedSecure(SsoBrowser browser, String path) throws Exception {
        return browser.get(path, Map.of("X-Forwarded-Proto", "https"));
    }

    // V4: asserts the response-independent default headers, with Strict-Transport-Security on secure requests only
    private static void assertResponseIndependentHeaders(HttpResponse<?> response, String label, boolean secure) {
        var headers = response.headers();
        assertEquals("nosniff", headers.firstValue("X-Content-Type-Options").orElse(null),
                label + ": X-Content-Type-Options");
        assertEquals("DENY", headers.firstValue("X-Frame-Options").orElse(null), label + ": X-Frame-Options");
        assertEquals("0", headers.firstValue("X-XSS-Protection").orElse(null), label + ": X-XSS-Protection");
        if (secure) {
            assertEquals("max-age=31536000 ; includeSubDomains",
                    headers.firstValue("Strict-Transport-Security").orElse(null),
                    label + ": Strict-Transport-Security");
        } else {
            assertFalse(headers.firstValue("Strict-Transport-Security").isPresent(),
                    label + ": Strict-Transport-Security must be absent on plain HTTP");
        }
    }

    // V4: the response's own cache policy must still forbid storing it
    private static void assertNoStore(HttpResponse<?> response, String label) {
        assertTrue(response.headers().firstValue("Cache-Control").orElse("").contains("no-store"),
                label + ": Cache-Control must carry no-store");
    }

    // V10: sys.json and http.json are authenticated by the browser's session cookie alone
    /**
     * Asserts the status of {@code /rest/public/info/sys.json} and {@code /rest/public/info/http.json} for the
     * browser's current session. No {@code Authorization} header is sent: only the session cookie in the
     * browser's jar can authenticate the requests.
     *
     * @param browser the browser whose cookie jar carries the session, if any
     * @param expectedStatus the status both endpoints must answer, 401 before login and 200 after it
     */
    protected static void assertSysInfo(SsoBrowser browser, int expectedStatus) throws Exception {
        assertEquals(expectedStatus, browser.get("/rest/public/info/sys.json").statusCode(),
                "/rest/public/info/sys.json");
        assertEquals(expectedStatus, browser.get("/rest/public/info/http.json").statusCode(),
                "/rest/public/info/http.json");
    }
}

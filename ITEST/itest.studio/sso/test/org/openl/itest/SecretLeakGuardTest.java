package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.openl.itest.core.HttpClient;
import org.openl.itest.core.JettyServer;

/**
 * V3: the leak guard of the SSO suite fails on a generated value in captured output or in a saved response, and on a
 * Studio session cookie printed with its value, as the real ITEST harness prints it; it names only the kind and the
 * relative path, never the value, and lets clean output and clean responses pass. The browser keeps the ID token and
 * the session cookies it receives, and each token acquisition keeps its tokens before a later one can fail. Every
 * value is generated per run, and the console the guard tees into is a local buffer, so nothing reaches the build
 * output. Needs no Docker.
 */
class SecretLeakGuardTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String TOKEN_PATH = "/realms/openlstudio/protocol/openid-connect/token";

    private final ByteArrayOutputStream consoleOut = new ByteArrayOutputStream();
    private final ByteArrayOutputStream consoleErr = new ByteArrayOutputStream();
    private final PrintStream fakeOut = new PrintStream(consoleOut, true, StandardCharsets.UTF_8);
    private final PrintStream fakeErr = new PrintStream(consoleErr, true, StandardCharsets.UTF_8);
    private PrintStream realOut = System.out;
    private PrintStream realErr = System.err;

    @BeforeAll
    static void httpProperties() {
        // The ITEST Surefire configuration sets all three; these defaults serve only a run outside it.
        if (System.getProperty("http.timeout.connect") == null) {
            System.setProperty("http.timeout.connect", "10000");
        }
        if (System.getProperty("http.timeout.read") == null) {
            System.setProperty("http.timeout.read", "30000");
        }
        // The harness client sends its own Host header.
        if (System.getProperty("jdk.httpclient.allowRestrictedHeaders") == null) {
            System.setProperty("jdk.httpclient.allowRestrictedHeaders", "Host");
        }
    }

    @BeforeEach
    void useFakeConsole() {
        realOut = System.out;
        realErr = System.err;
        System.setOut(fakeOut);
        System.setErr(fakeErr);
    }

    @AfterEach
    void restoreConsole() {
        System.setOut(realOut);
        System.setErr(realErr);
    }

    @Test
    void capturedSecretFailsNamingOnlyItsKindAndRestoresTheStreams() {
        var secret = generatedValue();
        var guard = new SecretLeakGuard();
        guard.register("bearer access token", secret);

        guard.startCapture();
        System.err.println("Authorization: Bearer " + secret);
        var error = assertThrows(AssertionError.class, () -> guard.finishCapture("SampleTest.leaks"));

        // Checked first, so a regression fails with this constant message instead of printing the message.
        assertFalse(messageOf(error).contains(secret), "the message must not hold the value");
        assertEquals("Generated or issued secrets found in the output captured during SampleTest.leaks:"
                + " [bearer access token]", messageOf(error));
        assertSame(fakeOut, System.out, "System.out restored");
        assertSame(fakeErr, System.err, "System.err restored");
        assertTrue(consoleErr.toString(StandardCharsets.UTF_8).contains(secret), "the console still receives output");
    }

    @Test
    void capturedSecretOnStdOutIsFoundToo() {
        var secret = generatedValue();
        var guard = new SecretLeakGuard().retain("realm credential", List.of(secret));

        guard.startCapture();
        System.out.print(secret);
        var error = assertThrows(AssertionError.class, () -> guard.finishCapture("SampleTest.prints"));

        assertTrue(messageOf(error).endsWith(": [realm credential]"), "the message names the kind");
        assertFalse(messageOf(error).contains(secret), "the message must not hold the value");
    }

    @Test
    void cleanOutputPasses() {
        var guard = new SecretLeakGuard().retain("client secret", List.of(generatedValue()));
        guard.register("personal access token", generatedValue());

        guard.startCapture();
        System.out.println("Studio started");
        System.err.println("WARN nothing secret");

        assertDoesNotThrow(() -> guard.finishCapture("SampleTest.clean"));
        assertSame(fakeOut, System.out, "System.out restored");
        assertSame(fakeErr, System.err, "System.err restored");
    }

    @Test
    void handedOverCaptureIsScannedAfterTheTeeWasBypassed() {
        var secret = generatedValue();
        var guard = new SecretLeakGuard();
        guard.register("personal access token secret", secret);

        guard.startCapture();
        var tee = System.out;
        // As JUnit Pioneer @StdIo does: the stream is swapped after the tee was installed and restored before the
        // guard finishes, so only the handed-over capture holds the line.
        var stdIo = new ByteArrayOutputStream();
        System.setOut(new PrintStream(stdIo, true, StandardCharsets.UTF_8));
        guard.scanAlso(() -> stdIo.toString(StandardCharsets.UTF_8));
        System.out.println("token secret " + secret);
        System.setOut(tee);
        var error = assertThrows(AssertionError.class, () -> guard.finishCapture("SampleTest.stdIo"));

        assertTrue(messageOf(error).endsWith(": [personal access token secret]"), "the message names the kind");
        assertFalse(messageOf(error).contains(secret), "the message must not hold the value");
        assertFalse(consoleOut.toString(StandardCharsets.UTF_8).contains(secret), "the tee was bypassed");
        assertSame(fakeOut, System.out, "System.out restored");
    }

    @Test
    void everyKindFoundIsNamedOnce() {
        var token = generatedValue();
        var sessionId = generatedValue();
        var guard = new SecretLeakGuard();
        guard.register("bearer access token", token);
        guard.register("Studio session ID", sessionId);

        guard.startCapture();
        System.out.println(token + " " + sessionId + " " + token);
        var error = assertThrows(AssertionError.class, () -> guard.finishCapture("SampleTest.both"));

        assertTrue(messageOf(error).endsWith(": [Studio session ID, bearer access token]"), "sorted kinds");
    }

    @Test
    void finishingWithoutCaptureDoesNothing() {
        var guard = new SecretLeakGuard().retain("S3 key", List.of(generatedValue()));

        assertDoesNotThrow(() -> guard.finishCapture("SampleTest.notStarted"));
        assertSame(fakeOut, System.out, "System.out untouched");
    }

    @Test
    void handOverOutsideCaptureIsRejected() {
        var guard = new SecretLeakGuard();

        assertThrows(IllegalStateException.class, () -> guard.scanAlso(() -> ""));
    }

    @Test
    void secondCaptureIsRejectedUntilTheFirstFinishes() {
        var guard = new SecretLeakGuard();
        guard.startCapture();
        try {
            assertThrows(IllegalStateException.class, guard::startCapture);
        } finally {
            guard.finishCapture("SampleTest.twice");
        }
        assertSame(fakeOut, System.out, "System.out restored");
    }

    @Test
    void savedResponseWithSecretFailsNamingOnlyKindAndRelativePath(@TempDir Path responses) throws IOException {
        var secret = generatedValue();
        var guard = new SecretLeakGuard();
        guard.register("ID token", secret);
        var saved = responses.resolve("test-resources-oauth2").resolve("010-logout.req.body");
        Files.createDirectories(saved.getParent());
        Files.writeString(saved, "{\"id_token\":\"" + secret + "\"}", StandardCharsets.UTF_8);
        Files.writeString(responses.resolve("000-clean.req.body"), "{\"status\":\"ok\"}", StandardCharsets.UTF_8);

        var error = assertThrows(AssertionError.class, () -> guard.assertNoSecretsSaved(responses));

        assertFalse(messageOf(error).contains(secret), "the message must not hold the value");
        assertEquals("Generated or issued secrets found in the saved responses under " + responses + ": [ID token in "
                + Path.of("test-resources-oauth2", "010-logout.req.body") + "]", messageOf(error));
    }

    @Test
    void cleanOrMissingSavedResponsesPass(@TempDir Path responses) throws IOException {
        var guard = new SecretLeakGuard().retain("realm credential", List.of(generatedValue()));
        guard.register("bearer access token", generatedValue());
        Files.writeString(responses.resolve("000-clean.req.body"), "{\"status\":\"ok\"}", StandardCharsets.UTF_8);

        assertDoesNotThrow(() -> guard.assertNoSecretsSaved(responses));
        assertDoesNotThrow(() -> guard.assertNoSecretsSaved(responses.resolve("absent")));
    }

    @Test
    void issuedSecretsAreForgottenPerClassAndGeneratedOnesKept(@TempDir Path responses) throws IOException {
        var generated = generatedValue();
        var issued = generatedValue();
        var guard = new SecretLeakGuard().retain("client secret", List.of(generated));
        guard.register("bearer access token", issued);
        Files.writeString(responses.resolve("010-issued.req.body"), issued, StandardCharsets.UTF_8);

        guard.resetIssued();
        assertDoesNotThrow(() -> guard.assertNoSecretsSaved(responses));

        Files.writeString(responses.resolve("020-generated.req.body"), generated, StandardCharsets.UTF_8);
        var error = assertThrows(AssertionError.class, () -> guard.assertNoSecretsSaved(responses));
        assertTrue(messageOf(error).endsWith(": [client secret in 020-generated.req.body]"), "generated kept");
    }

    @Test
    void nullBlankAndRepeatedValuesAreHandled() {
        var value = generatedValue();
        var guard = new SecretLeakGuard().retain("realm credential", List.of(value, " "));
        guard.register("Studio session ID", null);
        guard.register("Studio session ID", "");
        guard.register("bearer access token", value);

        var secrets = guard.secrets();
        assertEquals(1, secrets.size(), "only the non-blank value is kept");
        assertEquals("realm credential", secrets.get(value), "a value keeps its first kind");
    }

    @Test
    void suiteGuardRetainsEveryGeneratedCredential() {
        AbstractKeycloakTest.SECRET_GUARD.resetIssued();
        var secrets = AbstractKeycloakTest.SECRET_GUARD.secrets();

        assertTrue(secrets.keySet().containsAll(AbstractKeycloakTest.generatedSecrets()),
                "the SSO suite guard must scan for every generated credential");
        assertEquals(AbstractKeycloakTest.generatedSecrets().size(), secrets.size(), "only the generated ones");
    }

    @Test
    void browserKeepsTheIdTokenAndSessionCookiesItReceives() throws Exception {
        var idToken = generatedValue();
        var sessionId = generatedValue();
        var idpSession = generatedValue();
        var host = InetAddress.getLoopbackAddress().getHostAddress();
        var server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        // Studio's /logout sets its session cookie, an IdP cookie and a short flag, then redirects to the IdP with
        // the ID token; the IdP end-session endpoint answers 204.
        server.createContext("/", exchange -> {
            if ("/logout".equals(exchange.getRequestURI().getPath())) {
                var headers = exchange.getResponseHeaders();
                headers.add("Set-Cookie", "JSESSIONID=" + sessionId + "; Path=/");
                headers.add("Set-Cookie", "KEYCLOAK_IDENTITY=" + idpSession + "; Path=/");
                headers.add("Set-Cookie", "KC_FLAG=1; Path=/");
                headers.add("Location", "http://" + host + ":" + server.getAddress().getPort()
                        + "/realms/openlstudio/protocol/openid-connect/logout?client_id=openlstudio&id_token_hint="
                        + idToken);
                exchange.sendResponseHeaders(302, -1);
            } else {
                exchange.sendResponseHeaders(204, -1);
            }
            exchange.close();
        });
        server.start();
        try {
            AbstractKeycloakTest.SECRET_GUARD.resetIssued();

            var endpoint = new SsoBrowser(URI.create("http://" + host + ":" + server.getAddress().getPort() + "/"))
                    .logoutViaOAuth2();

            assertTrue(endpoint.contains("id_token_hint="), "the redirect carries the ID token");
            var secrets = AbstractKeycloakTest.SECRET_GUARD.secrets();
            assertEquals("ID token", secrets.get(idToken), "the id_token_hint value is kept");
            assertEquals("Studio session ID", secrets.get(sessionId), "the JSESSIONID value is kept");
            assertEquals("Keycloak session cookie", secrets.get(idpSession), "the IdP session cookie is kept");
            assertFalse(secrets.containsKey("1"), "a short flag cookie is not kept");
        } finally {
            AbstractKeycloakTest.SECRET_GUARD.resetIssued();
            server.stop(0);
        }
    }

    @Test
    void tokensIssuedBeforeAFailedAcquisitionAreKeptAndScanned(@TempDir Path responses) throws Exception {
        var accessToken = generatedValue();
        var idToken = generatedValue();
        var refreshToken = generatedValue();
        var requests = new AtomicInteger();
        var server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        // The token endpoint issues the tokens of the first realm user, then rejects every later one, as an expired
        // client secret or a disabled user would.
        server.createContext(TOKEN_PATH, exchange -> {
            try {
                if (requests.incrementAndGet() == 1) {
                    var body = ("{\"access_token\":\"" + accessToken + "\",\"id_token\":\"" + idToken
                            + "\",\"refresh_token\":\"" + refreshToken + "\",\"token_type\":\"Bearer\"}")
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, body.length);
                    exchange.getResponseBody().write(body);
                } else {
                    exchange.sendResponseHeaders(401, -1);
                }
            } finally {
                exchange.close();
            }
        });
        server.start();
        try {
            AbstractKeycloakTest.SECRET_GUARD.resetIssued();
            var authServerUrl = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                    + server.getAddress().getPort();

            var failure = assertThrows(RuntimeException.class,
                    () -> new OAuthTest().retrieveBearerAccessTokens(authServerUrl));

            var message = messageOf(failure);
            assertTrue(message.contains(" for user user1 from ") && message.endsWith(": status 401"),
                    "the acquisition for the second realm user fails");
            assertEquals(2, requests.get(), "no acquisition follows the failed one");
            var secrets = AbstractKeycloakTest.SECRET_GUARD.secrets();
            assertEquals("bearer access token", secrets.get(accessToken), "the earlier access token is kept");
            assertEquals("ID token", secrets.get(idToken), "the earlier ID token is kept");
            assertEquals("refresh token", secrets.get(refreshToken), "the earlier refresh token is kept");

            AbstractKeycloakTest.SECRET_GUARD.startCapture();
            System.err.println("Authorization: Bearer " + accessToken);
            var captured = assertThrows(AssertionError.class,
                    () -> AbstractKeycloakTest.SECRET_GUARD.finishCapture("OAuthTest.smoke"));
            assertFalse(messageOf(captured).contains(accessToken), "the message must not hold the value");
            assertEquals("Generated or issued secrets found in the output captured during OAuthTest.smoke:"
                    + " [bearer access token]", messageOf(captured));

            Files.writeString(responses.resolve("010-profile.get.req.body"),
                    "{\"token\":\"" + accessToken + "\"}",
                    StandardCharsets.UTF_8);
            var saved = assertThrows(AssertionError.class,
                    () -> AbstractKeycloakTest.SECRET_GUARD.assertNoSecretsSaved(responses));
            assertFalse(messageOf(saved).contains(accessToken), "the message must not hold the value");
            assertEquals("Generated or issued secrets found in the saved responses under " + responses
                    + ": [bearer access token in 010-profile.get.req.body]", messageOf(saved));
        } finally {
            AbstractKeycloakTest.SECRET_GUARD.resetIssued();
            server.stop(0);
        }
    }

    @Test
    void sessionCookieTheRealHarnessPrintsOnAMismatchFailsNamingOnlyItsKind(@TempDir Path dir) throws Exception {
        var sessionId = generatedValue();
        var server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        // Studio refuses a request its fixture expects to pass, and opens a session while doing so.
        server.createContext("/", exchange -> {
            try {
                var body = "denied".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Set-Cookie", "JSESSIONID=" + sessionId + "; Path=/; HttpOnly");
                exchange.getResponseHeaders().set("Content-Type", "text/plain");
                exchange.sendResponseHeaders(403, body.length);
                exchange.getResponseBody().write(body);
            } finally {
                exchange.close();
            }
        });
        var fixtures = Files.createDirectories(dir.resolve("fixtures"));
        Files.writeString(fixtures.resolve("010-profile.get.req"),
                "GET /rest/users/profile HTTP/1.1\r\n\r\n",
                StandardCharsets.UTF_8);
        Files.writeString(fixtures.resolve("010-profile.get.resp"), "HTTP/1.1 200 OK\r\n\r\n", StandardCharsets.UTF_8);
        var responses = dir.resolve("responses");
        var moduleResponses = System.getProperty("server.responses");
        // The harness saves the body of the mismatching response here instead of under the module's target.
        System.setProperty("server.responses", responses + File.separator);
        server.start();
        var guard = new SecretLeakGuard();
        try (var harness = harnessClient(URI.create("http://" + InetAddress.getLoopbackAddress().getHostAddress()
                + ":" + server.getAddress().getPort()))) {
            guard.startCapture();
            var mismatch = assertThrows(AssertionError.class, () -> harness.test(fixtures.toString()));
            var leak = assertThrows(AssertionError.class, () -> guard.finishCapture("SampleTest.harnessMismatch"));

            assertTrue(messageOf(mismatch).startsWith("Failed 1 of 1 requests"), "the harness fails on the mismatch");
            assertTrue(consoleErr.toString(StandardCharsets.UTF_8).contains("JSESSIONID=" + sessionId),
                    "the harness printed the session cookie with its value");
            assertFalse(messageOf(leak).contains(sessionId), "the message must not hold the value");
            assertEquals("Generated or issued secrets found in the output captured during SampleTest.harnessMismatch:"
                    + " [Studio session ID]", messageOf(leak));
            assertTrue(Files.isDirectory(responses), "the harness saved the mismatching body");
            assertDoesNotThrow(() -> guard.assertNoSecretsSaved(responses), "the saved body holds no session cookie");
        } finally {
            if (moduleResponses == null) {
                System.clearProperty("server.responses");
            } else {
                System.setProperty("server.responses", moduleResponses);
            }
            server.stop(0);
        }
    }

    @Test
    void savedSessionCookieWithItsValueFailsNamingOnlyKindAndRelativePath(@TempDir Path responses) throws IOException {
        var headerSessionId = generatedValue();
        var urlSessionId = generatedValue();
        var guard = new SecretLeakGuard();
        var header = responses.resolve("test-resources-oauth2").resolve("020-callback.get.req.body");
        Files.createDirectories(header.getParent());
        Files.writeString(header,
                "<p>Set-Cookie: JSESSIONID=" + headerSessionId + "; Path=/; HttpOnly</p>",
                StandardCharsets.UTF_8);
        Files.writeString(responses.resolve("030-link.get.req.body"),
                "<a href=\"/web/;jsessionid=" + urlSessionId + "\">home</a>",
                StandardCharsets.UTF_8);

        var error = assertThrows(AssertionError.class, () -> guard.assertNoSecretsSaved(responses));

        assertFalse(messageOf(error).contains(headerSessionId), "the message must not hold the cookie value");
        assertFalse(messageOf(error).contains(urlSessionId), "the message must not hold the URL value");
        assertEquals("Generated or issued secrets found in the saved responses under " + responses
                + ": [Studio session ID in 030-link.get.req.body, Studio session ID in "
                + Path.of("test-resources-oauth2", "020-callback.get.req.body") + "]", messageOf(error));
    }

    @Test
    void maskedEmptyOrAbsentSessionCookiePasses(@TempDir Path responses) throws IOException {
        var clean = List.of("Set-Cookie: JSESSIONID=***; Path=/; HttpOnly; SameSite=Lax",
                "{\"Set-Cookie\":\"JSESSIONID=***\"}",
                "Set-Cookie: JSESSIONID=; Path=/; Max-Age=0",
                "JSESSIONID=;",
                "Cookie: NO_JSESSIONID=noAuth",
                "pre-login JSESSIONID",
                "Studio started");
        var guard = new SecretLeakGuard();

        guard.startCapture();
        clean.forEach(System.err::println);
        assertDoesNotThrow(() -> guard.finishCapture("SampleTest.masked"));

        Files.write(responses.resolve("000-masked.get.req.body"), clean, StandardCharsets.UTF_8);
        assertDoesNotThrow(() -> guard.assertNoSecretsSaved(responses));
    }

    // the harness client of an unstarted Studio server, bound to the base URL; closing it stops no server
    private static HttpClient harnessClient(URI baseUrl) throws ReflectiveOperationException {
        // The harness creates its client only when it starts Studio, which this test does without.
        var constructor = HttpClient.class.getDeclaredConstructor(JettyServer.class, URI.class);
        constructor.setAccessible(true);
        return constructor.newInstance(JettyServer.get(), baseUrl);
    }

    // the message of a failure; the guard and the token request always set one
    private static String messageOf(Throwable error) {
        return String.valueOf(error.getMessage());
    }

    // a URL-safe random value of 32 characters, generated per run
    private static String generatedValue() {
        var bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}

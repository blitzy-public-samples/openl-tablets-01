package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.openl.itest.core.HttpClient;
import org.openl.itest.core.JettyServer;

class WebStudioTest {

    // V1: generator for runtime test credentials; alphanumeric so fixtures can embed the values unescaped
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    // V10: the V10 folder's form login, and the http.json request that carries only the session cookie it sets.
    // The http.json request lies outside test-resources, so the generic runner never sends, compares, prints or
    // saves its answer.
    private static final Path V10_LOGIN_REQUEST = Path.of("test-resources", "security-V10-sysinfo", "020-login.req");
    private static final Path V10_HTTP_JSON_REQUEST = Path.of("test-resources-security-V10-sysinfo",
            "031-http-json-session.req");
    private static final String SESSION_COOKIE = "JSESSIONID";
    // V10: http.json is read in memory to check that it shows no authentication, as before V10
    private static final String HTTP_JSON = "/rest/public/info/http.json";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern BCRYPT_PREFIX = Pattern.compile("\\$2[aby]\\$");

    // V1: 2000+ requests can meet a busy host's stall longer than the shared 10 s perf limit, so this suite allows 30 s
    private static final String READ_TIMEOUT_PROPERTY = "http.timeout.read";
    private static final int READ_TIMEOUT_FLOOR_MS = 30_000;

    // V1: the read timeout set before this suite started, or null when none was set
    private static @Nullable String readTimeoutBefore;

    // V1: before the client is built, raises a positive read timeout below 30 s to 30 s; a longer one (-DnoPerf) stays
    @BeforeAll
    static void raiseReadTimeout() {
        String configured = System.getProperty(READ_TIMEOUT_PROPERTY);
        readTimeoutBefore = configured;
        if (configured == null) {
            return;
        }
        int millis;
        try {
            millis = Integer.parseInt(configured);
        } catch (NumberFormatException e) {
            return;
        }
        if (millis > 0 && millis < READ_TIMEOUT_FLOOR_MS) {
            System.setProperty(READ_TIMEOUT_PROPERTY, String.valueOf(READ_TIMEOUT_FLOOR_MS));
        }
    }

    // V1: puts back the read timeout found before this suite started, clearing it when none was set
    @AfterAll
    static void restoreReadTimeout() {
        String before = readTimeoutBefore;
        if (before == null) {
            System.clearProperty(READ_TIMEOUT_PROPERTY);
        } else {
            System.setProperty(READ_TIMEOUT_PROPERTY, before);
        }
    }

    @Test
    void repos() throws Exception {
        // V1: runtime credentials, then scans of captured console output and saved responses for generated secrets
        Map<String, String> generated = new HashMap<>();
        var capture = OutputCapture.start(); // V1: the console output is copied from before the server starts
        // V1: the capture is the first resource, so it is restored only after the server has stopped
        try (capture; var client = JettyServer.get().start()) {
            putAdminCredentials(client, generated); // V1: the derived administrator header is scanned for too
            putPasswordPolicyValues(client, generated); // V7: generated local-user passwords
            putLockoutValues(client, generated); // V9: generated lockout-scenario credentials
            // V10: the http.json session check runs after the generic run, also when that run failed.
            // The generic failure stays the reported one and carries the check's failure as suppressed.
            try {
                client.test("test-resources");
            } catch (Throwable generic) {
                try {
                    assertHttpJsonNeedsOnlySession(client, generated);
                } catch (Throwable v10) {
                    if (v10 instanceof InterruptedException) {
                        Thread.currentThread().interrupt();
                    }
                    generic.addSuppressed(v10);
                }
                throw generic;
            }
            assertHttpJsonNeedsOnlySession(client, generated);
        } catch (Throwable t) {
            // V1: a scan error of any kind is attached to the suite failure instead of replacing it
            try {
                assertNoSecretsLeaked(generated, capture);
            } catch (AssertionError | RuntimeException scan) {
                t.addSuppressed(scan);
            }
            throw t;
        }
        assertNoSecretsLeaked(generated, capture); // V1: the suite passed, so a scan failure is the reported one
    }

    // V1: the administrator password and Basic header, derived at runtime from the first configured administrator
    static void putAdminCredentials(HttpClient client) {
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(Path.of("openl-repository", "application.properties"),
                StandardCharsets.UTF_8)) {
            properties.load(reader);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        String administrators = properties.getProperty("security.administrators");
        String name = administrators == null ? "" : administrators.split(",", -1)[0].trim();
        if (name.isEmpty()) {
            fail("security.administrators is not set in openl-repository/application.properties");
        }
        // AdminUsers seeds each configured administrator with its user name as the password.
        client.localEnv.put("ADMIN_PASSWORD", name);
        client.localEnv.put("ADMIN_AUTH_TOCKEN", basic(name, name));
    }

    // V1: puts the administrator credentials and registers the derived administrator header for the secret scans.
    // ADMIN_PASSWORD is not registered, because it equals the administrator name, which responses show.
    static void putAdminCredentials(HttpClient client, Map<String, String> generated) {
        putAdminCredentials(client);
        generated.put("ADMIN_AUTH_TOCKEN", client.localEnv.get("ADMIN_AUTH_TOCKEN"));
    }

    // V8: an expiresAt 400 days ahead, beyond the 365-day maximum.
    // Only PatExpiryITest sends the request that reads it, never the generic runner, because an unexpected 201 would
    // carry a token; so repos() does not call this.
    static void putPatExpiryValues(HttpClient client) {
        client.localEnv.put("PAT_EXPIRES_TOO_FAR", Instant.now().plus(Duration.ofDays(400)).toString());
    }

    // V7: generated passwords of the local users the fixtures create, and the password-policy boundary values
    private static void putPasswordPolicyValues(HttpClient client, Map<String, String> generated) {
        Map<String, String> values = new HashMap<>();
        // {login, key prefix}: each login gets <PREFIX>_PASSWORD and its Basic header value <PREFIX>_BASIC.
        String[][] users = {
                {"EPBDS_14372", "EPBDS_14372"},
                {"user1", "USER1"},
                {"user2", "USER2"},
                {"EPBDS_15600", "EPBDS_15600"},
                {"EPBDS_15621", "EPBDS_15621"},
                {"user16256", "USER16256"},
                {"EPBDS_16356", "EPBDS_16356"}};
        for (String[] user : users) {
            String password = randomPassword(16);
            values.put(user[1] + "_PASSWORD", password);
            values.put(user[1] + "_BASIC", basic(user[0], password));
        }
        // The task_EPBDS-16356 grantee authenticates as EPBDS_16356.
        values.put("GRANTEE_AUTH", values.get("EPBDS_16356_BASIC"));

        // Minimum: 12 code points. Maximum: 72 UTF-8 bytes. Multi-byte values use a 2-byte and a 3-byte character.
        String base = randomPassword(16);
        String shortAscii = randomPassword(11);
        String shortMb = randomPassword(9) + "\u00e9\u20ac";
        String minAscii = randomPassword(12);
        String minMb = randomPassword(10) + "\u00e9\u20ac";
        String maxAscii = randomPassword(72);
        String maxMb = randomPassword(12) + "\u20ac".repeat(20);
        String overAscii = randomPassword(73);
        String overMb = randomPassword(13) + "\u20ac".repeat(20);
        values.put("V7_BASE_PASSWORD", base);
        values.put("V7_SHORT_ASCII", shortAscii);
        values.put("V7_SHORT_MB", shortMb);
        values.put("V7_MIN_ASCII", minAscii);
        values.put("V7_MIN_MB", minMb);
        values.put("V7_MAX_ASCII", maxAscii);
        values.put("V7_MAX_MB", maxMb);
        values.put("V7_OVER_ASCII", overAscii);
        values.put("V7_OVER_MB", overMb);
        values.put("V7_PROFILE_BASIC_BASE", basic("v7_profile", base));
        values.put("V7_PROFILE_BASIC_MIN_ASCII", basic("v7_profile", minAscii));
        values.put("V7_PROFILE_BASIC_MIN_MB", basic("v7_profile", minMb));
        values.put("V7_PROFILE_BASIC_MAX_ASCII", basic("v7_profile", maxAscii));
        values.put("V7_PROFILE_BASIC_MAX_MB", basic("v7_profile", maxMb));

        // Each boundary is checked before any request is sent; a failure names the variable, never its value.
        for (String[] check : new String[][] {{"V7_SHORT_ASCII", shortAscii}, {"V7_SHORT_MB", shortMb}}) {
            if (check[1].codePointCount(0, check[1].length()) != 11) {
                fail(check[0]);
            }
        }
        for (String[] check : new String[][] {{"V7_MIN_ASCII", minAscii}, {"V7_MIN_MB", minMb}}) {
            if (check[1].codePointCount(0, check[1].length()) != 12) {
                fail(check[0]);
            }
        }
        for (String[] check : new String[][] {{"V7_MAX_ASCII", maxAscii}, {"V7_MAX_MB", maxMb}}) {
            if (check[1].getBytes(StandardCharsets.UTF_8).length != 72) {
                fail(check[0]);
            }
        }
        for (String[] check : new String[][] {{"V7_OVER_ASCII", overAscii}, {"V7_OVER_MB", overMb}}) {
            if (check[1].getBytes(StandardCharsets.UTF_8).length != 73) {
                fail(check[0]);
            }
        }
        if (minMb.getBytes(StandardCharsets.UTF_8).length > 72) {
            fail("V7_MIN_MB");
        }
        // The accepted 72-byte multibyte value has more than 25 code points, so only the byte limit decides it.
        if (maxMb.codePointCount(0, maxMb.length()) <= 25) {
            fail("V7_MAX_MB");
        }

        client.localEnv.putAll(values);
        generated.putAll(values);
    }

    // V9: generated credentials of the lockout, unknown-user, counter-reset and form-login scenarios
    private static void putLockoutValues(HttpClient client, Map<String, String> generated) {
        String lockoutPassword = randomPassword(16);
        String wrongPassword;
        do {
            wrongPassword = randomPassword(16);
        } while (wrongPassword.equals(lockoutPassword));
        // v9_ghost is never created, so any password is a failed login for it.
        String ghostPassword = randomPassword(16);
        String resetPassword = randomPassword(16);
        String resetWrongPassword;
        do {
            resetWrongPassword = randomPassword(16);
        } while (resetWrongPassword.equals(resetPassword));
        String formPassword = randomPassword(16);
        String formWrongPassword;
        do {
            formWrongPassword = randomPassword(16);
        } while (formWrongPassword.equals(formPassword));

        Map<String, String> values = new HashMap<>();
        values.put("LOCKOUT_PASSWORD", lockoutPassword);
        values.put("LOCKOUT_BASIC", basic("v9_lockout", lockoutPassword));
        values.put("WRONG_BASIC", basic("v9_lockout", wrongPassword));
        values.put("GHOST_BASIC", basic("v9_ghost", ghostPassword));
        values.put("RESET_PASSWORD", resetPassword);
        values.put("RESET_BASIC", basic("v9_reset", resetPassword));
        values.put("RESET_WRONG_BASIC", basic("v9_reset", resetWrongPassword));
        values.put("FORM_PASSWORD", formPassword);
        values.put("FORM_WRONG_PASSWORD", formWrongPassword);
        client.localEnv.putAll(values);
        generated.putAll(values);
        // The raw passwords behind the wrong Basic values are scanned for only; no fixture reads them.
        generated.put("V9_WRONG_PASSWORD", wrongPassword);
        generated.put("V9_GHOST_PASSWORD", ghostPassword);
        generated.put("V9_RESET_WRONG_PASSWORD", resetWrongPassword);
    }

    // V10: asserts that the session cookie of a form login alone gets 200 from http.json, and that neither that
    // answer nor the one to the administrator's Basic header shows the authentication.
    // http.json echoes the request's headers and cookies, so it is sent through a JDK client that keeps the answers
    // in memory only, never through the generic runner, which prints and saves a mismatching one.
    // The session ID joins the generated secrets before it is sent anywhere.
    static void assertHttpJsonNeedsOnlySession(HttpClient client, Map<String, String> generated)
            throws IOException, InterruptedException {
        // HTTP/1.1, as the harness client uses; by default redirects are not followed and no cookie is stored.
        try (var http = java.net.http.HttpClient.newBuilder()
                .version(java.net.http.HttpClient.Version.HTTP_1_1)
                .build()) {
            var login = http.send(PatExpiryITest.readRequest(V10_LOGIN_REQUEST, client.getBaseURL(), client.localEnv),
                    HttpResponse.BodyHandlers.discarding());
            assertEquals(302, login.statusCode(), "V10 form login: status");
            String sessionId = sessionId(login.headers().allValues("Set-Cookie"));
            generated.put("V10_SESSION_COOKIE", sessionId);
            Map<String, String> env = new HashMap<>(client.localEnv);
            env.put("V10_SESSION_COOKIE", SESSION_COOKIE + "=" + sessionId);
            var session = http.send(PatExpiryITest.readRequest(V10_HTTP_JSON_REQUEST, client.getBaseURL(), env),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(200, session.statusCode(), "V10 http.json with only the session cookie: status");
            assertNoAuthenticationShown(session.body(), "V10 http.json with only the session cookie");
            var basic = http.send(HttpRequest.newBuilder(URI.create(client.getBaseURL().toString() + HTTP_JSON))
                            .header("Authorization", client.localEnv.get("ADMIN_AUTH_TOCKEN"))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(200, basic.statusCode(), "V10 http.json with the administrator's Basic header: status");
            assertNoAuthenticationShown(basic.body(), "V10 http.json with the administrator's Basic header");
        }
    }

    // V10: http.json keeps the shape it had before V10: UserPrincipal and RemoteUser absent or null, and no password
    // field or bcrypt hash anywhere. The body is never printed or saved, and a failure message names only the check.
    private static void assertNoAuthenticationShown(String body, String step) {
        JsonNode json;
        try {
            json = MAPPER.readTree(body);
        } catch (IOException unparsable) {
            // The parser's message quotes the body, so neither it nor the exception is passed on.
            json = null;
        }
        if (json == null || !json.isObject()) {
            fail(step + ": the body is not a JSON object");
            return;
        }
        assertTrue(json.path("UserPrincipal").isNull() || json.path("UserPrincipal").isMissingNode(),
                step + ": UserPrincipal is absent or null");
        assertTrue(json.path("RemoteUser").isNull() || json.path("RemoteUser").isMissingNode(),
                step + ": RemoteUser is absent or null");
        assertFalse(hasPasswordField(json), step + ": no password field");
        assertFalse(BCRYPT_PREFIX.matcher(body).find(), step + ": no bcrypt hash");
    }

    // V10: whether any object in the tree has a field whose name contains "password", in any case
    private static boolean hasPasswordField(JsonNode node) {
        if (node.isObject()) {
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                if (field.getKey().toLowerCase(Locale.ROOT).contains("password")
                        || hasPasswordField(field.getValue())) {
                    return true;
                }
            }
        } else if (node.isArray()) {
            for (JsonNode element : node) {
                if (hasPasswordField(element)) {
                    return true;
                }
            }
        }
        return false;
    }

    // V10: the value of the last JSESSIONID pair the headers set; the failure message never quotes a header
    private static String sessionId(List<String> setCookieHeaders) {
        String id = null;
        for (String header : setCookieHeaders) {
            String pair = header.split(";", 2)[0].trim();
            if (pair.startsWith(SESSION_COOKIE + "=") && pair.length() > SESSION_COOKIE.length() + 1) {
                id = pair.substring(SESSION_COOKIE.length() + 1);
            }
        }
        if (id == null) {
            return fail("V10 form login: no " + SESSION_COOKIE + " cookie set");
        }
        return id;
    }

    // V1: random alphanumeric password of the given length
    static String randomPassword(int length) {
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(ALPHANUMERIC.charAt(RANDOM.nextInt(ALPHANUMERIC.length())));
        }
        return builder.toString();
    }

    // V1: HTTP Basic header value, UTF-8 encoded as Spring's BasicAuthenticationFilter decodes it
    static String basic(String user, String password) {
        return "Basic " + Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    // V1: fails, naming only the keys, when a generated secret appears in a saved mismatching response.
    // An unlistable or unreadable response also fails as an AssertionError, so callers' suppression covers it.
    static void assertNoSecretsSaved(Map<String, String> generated) {
        Path dir = Path.of(System.getProperty("server.responses", "target/responses"));
        if (!Files.exists(dir) || generated.isEmpty()) {
            return;
        }
        Set<String> names = new TreeSet<>();
        List<Path> files;
        try (Stream<Path> walk = Files.walk(dir)) {
            files = walk.filter(Files::isRegularFile).toList();
        } catch (IOException | UncheckedIOException e) {
            // The directory stream reports a failed traversal step unchecked.
            throw new AssertionError("Cannot list the saved responses under " + dir, e);
        }
        for (Path file : files) {
            String content;
            try {
                content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new AssertionError("Cannot read the saved response " + file, e);
            }
            for (Map.Entry<String, String> entry : generated.entrySet()) {
                String value = entry.getValue();
                if (value == null || value.isEmpty()) {
                    continue;
                }
                String needle = value.startsWith("Basic ") ? value.substring("Basic ".length()) : value;
                if (count(content, needle) > 0) {
                    names.add(entry.getKey());
                }
            }
        }
        if (!names.isEmpty()) {
            fail("Generated secrets found under server.responses: " + names);
        }
    }

    // V1: fails, naming only the sorted keys, when a generated secret appears in the captured stdout or stderr.
    // A Basic value is searched for by its Base64 part, which also covers the full header.
    // Each value is searched for as its stream's encoding prints it, so a character that encoding cannot represent
    // is matched as it was printed.
    static void assertNoSecretsPrinted(Map<String, String> generated, OutputCapture capture) {
        String out = capture.out();
        String err = capture.err();
        Set<String> names = new TreeSet<>();
        for (Map.Entry<String, String> entry : generated.entrySet()) {
            String value = entry.getValue();
            if (value == null || value.isEmpty()) {
                continue;
            }
            String needle = value.startsWith("Basic ") ? value.substring("Basic ".length()) : value;
            if (out.contains(printed(needle, capture.outCharset()))
                    || err.contains(printed(needle, capture.errCharset()))) {
                names.add(entry.getKey());
            }
        }
        if (!names.isEmpty()) {
            fail("Generated secrets found in the captured output: " + names);
        }
    }

    // V1: runs the captured-output scan, then the saved-response scan whatever the first did.
    // A saved-response failure is attached to a captured-output failure, which is the one thrown.
    static void assertNoSecretsLeaked(Map<String, String> generated, OutputCapture capture) {
        try {
            assertNoSecretsPrinted(generated, capture);
        } catch (AssertionError | RuntimeException leak) {
            try {
                assertNoSecretsSaved(generated);
            } catch (AssertionError | RuntimeException scan) {
                leak.addSuppressed(scan);
            }
            throw leak;
        }
        assertNoSecretsSaved(generated);
    }

    // V1: the text as a stream with the given encoding prints it
    private static String printed(String text, Charset charset) {
        return new String(text.getBytes(charset), charset);
    }

    // V1: copies System.out and System.err so the output can be scanned for generated secrets once the server stops.
    // Both streams also reach the console, which shows a mismatching response and the run's progress.
    static final class OutputCapture implements AutoCloseable {
        private final PrintStream originalOut = System.out;
        private final PrintStream originalErr = System.err;
        private final ByteArrayOutputStream outCopy = new ByteArrayOutputStream();
        private final ByteArrayOutputStream errCopy = new ByteArrayOutputStream();
        private final PrintStream teeOut = tee(originalOut, outCopy);
        private final PrintStream teeErr = tee(originalErr, errCopy);
        private boolean closed;

        private OutputCapture() {
        }

        /** Remembers the current System.out and System.err and installs streams that write to both them and a copy. */
        static OutputCapture start() {
            var capture = new OutputCapture();
            System.setOut(capture.teeOut);
            System.setErr(capture.teeErr);
            return capture;
        }

        /** A stream in the console stream's encoding that writes every byte to the console and to the copy. */
        private static PrintStream tee(PrintStream console, ByteArrayOutputStream copy) {
            return new PrintStream(new OutputStream() {
                @Override
                public void write(int b) {
                    console.write(b);
                    copy.write(b);
                }

                @Override
                public void write(byte[] b, int off, int len) {
                    console.write(b, off, len);
                    copy.write(b, off, len);
                }

                @Override
                public void flush() {
                    console.flush();
                }
            }, true, console.charset());
        }

        Charset outCharset() {
            return originalOut.charset();
        }

        Charset errCharset() {
            return originalErr.charset();
        }

        /** The text written to System.out so far, decoded with that stream's encoding. */
        String out() {
            return outCopy.toString(outCharset());
        }

        /** The text written to System.err so far, decoded with that stream's encoding. */
        String err() {
            return errCopy.toString(errCharset());
        }

        /** Flushes the copying streams and restores the remembered ones; later calls do nothing. */
        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            closed = true;
            teeOut.flush();
            teeErr.flush();
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }

    // V1: occurrence count of needle in content
    private static int count(String content, String needle) {
        int count = 0;
        int from = content.indexOf(needle);
        while (from >= 0) {
            count++;
            from = content.indexOf(needle, from + needle.length());
        }
        return count;
    }
}

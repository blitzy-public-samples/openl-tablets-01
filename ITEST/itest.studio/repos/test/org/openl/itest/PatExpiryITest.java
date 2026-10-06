package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import org.openl.itest.core.JettyServer;

/**
 * V8: proves end to end that a personal access token created without {@code expiresAt} expires after the default
 * lifetime of 90 days ({@code security.pat.default-expiration-days}), and that a token requested with an
 * {@code expiresAt} 400 days ahead, beyond the maximum lifetime of 365 days ({@code security.pat.max-expiration-days}),
 * is rejected with 400 and the key {@code openl.error.400.pat.expires-at.max.message}.
 *
 * <p>The {@code repos} server runs {@code user.mode=multi}. The token is created in Java through
 * {@code postForObject}, which asserts only the status, and its {@code expiresAt} is checked in Java. A {@code .resp}
 * file cannot make this check: its {@code "*"} wildcard also matches {@code null}, and a mismatch would print and save
 * the token-bearing body. The token is revoked afterwards, whether or not the check passes.
 *
 * <p><b>Over-maximum request.</b> The request file of {@code test-resources-security-V8-pat-expiry} is sent from here,
 * never by the generic runner of {@code test-resources}: a build without the maximum answers 201 with a token, and the
 * runner prints and saves every mismatching body. Here only the status and the {@code code} field are asserted, the
 * body is never printed or saved, and a token issued by mistake is revoked. Its {@code expiresAt} is computed when the
 * test runs, so the request stays 35 days beyond the maximum.
 *
 * <p><b>Secrets.</b> The administrator header is derived at runtime by {@link WebStudioTest#putAdminCredentials}.
 * The created token is never printed, logged or put into a message: failure messages name only the field or the
 * step. Once the server has stopped, the console output captured since before its start and the saved responses are
 * scanned for the Base64 part of the administrator header, the token and its secret part.
 */
class PatExpiryITest {

    /** The lifetime OpenL Studio applies by default: {@code security.pat.default-expiration-days = 90}. */
    private static final Duration DEFAULT_LIFETIME = Duration.ofDays(90);

    /** The allowed distance between the returned expiry and the default lifetime counted from the request. */
    private static final Duration TOLERANCE = Duration.ofMinutes(5);

    private static final String TOKENS_URL = "/rest/users/personal-access-tokens";

    // V8: the over-maximum request, outside test-resources so that the generic runner never sends or compares it
    private static final Path TOO_FAR_REQUEST = Path.of("test-resources-security-V8-pat-expiry",
            "010-expires-too-far.req");

    /** V8: the message key of the 400 answer to an {@code expiresAt} beyond the maximum lifetime. */
    private static final String EXPIRES_AT_MAX_KEY = "openl.error.400.pat.expires-at.max.message";

    // V8: the token format of OpenL Studio's PatToken, which is not on this classpath: PREFIX, then a public ID of
    // PUBLIC_ID_LENGTH Base62 characters, then '.' and the secret.
    private static final String PAT_PREFIX = "openl_pat_";
    private static final int PUBLIC_ID_LENGTH = 16;
    private static final Pattern PUBLIC_ID = Pattern.compile("[0-9A-Za-z]{" + PUBLIC_ID_LENGTH + "}");

    // V8: the request file syntax the harness reads: the headers end at the first empty line
    private static final Pattern HEADER_END = Pattern.compile("\\r?\\n\\r?\\n");
    private static final Pattern LINE_BREAK = Pattern.compile("\\r?\\n");
    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{(.*?)}");

    private static final ObjectMapper MAPPER = new ObjectMapper(); // V8: reads the over-maximum answer in Java

    @Test
    void tokenWithoutExpiryExpiresAfterDefaultLifetime() throws Exception {
        // V8: the generated secrets, searched for in the captured console output and the saved responses: the
        // administrator header by its Base64 part, the created token and its secret part.
        Map<String, String> generated = new HashMap<>();
        // The scan runs once the server has stopped, on success and on failure alike. It is not thrown from a
        // finally block, so a scan failure never replaces the test failure; it is attached to it instead.
        var capture = WebStudioTest.OutputCapture.start(); // V8: the console output is copied from before the start
        try (var client = JettyServer.get().start()) {
            WebStudioTest.putAdminCredentials(client, generated); // V8: the administrator header joins the scan
            // The message names only the variable, never its value.
            String admin = Objects.requireNonNull(client.localEnv.get("ADMIN_AUTH_TOCKEN"), "ADMIN_AUTH_TOCKEN");

            var before = Instant.now();
            // No expiresAt in the request: the server must apply the default lifetime.
            JsonNode created = client.postForObject(TOKENS_URL,
                    Map.of("name", "v8-default-expiry"),
                    JsonNode.class,
                    201,
                    "Authorization",
                    admin);
            var after = Instant.now();

            // V8: the token is registered for the scan, and the ID to revoke it by is taken, before any field is
            // required, so a response that lacks a field still has its token revoked.
            String token = optionalText(created, "token");
            if (token != null) {
                generated.put("PAT_TOKEN", token);
                generated.put("PAT_SECRET", token.substring(token.indexOf('.') + 1));
            }
            String cleanupId = cleanupId(created, token);

            String publicId;
            try {
                text(created, "token"); // V8: the required fields are read inside the cleanup scope
                publicId = text(created, "publicId");
                assertTrue(isPublicId(publicId), "publicId");
                Instant expiresAt = instant(created, "expiresAt");
                Instant lower = before.plus(DEFAULT_LIFETIME).minus(TOLERANCE);
                Instant upper = after.plus(DEFAULT_LIFETIME).plus(TOLERANCE);
                assertTrue(!expiresAt.isBefore(lower) && !expiresAt.isAfter(upper), "expiresAt");
            } catch (Throwable t) {
                // The token is removed even when the check fails; a failed revocation is attached to the check
                // failure, so the expiresAt failure stays the reported one.
                if (cleanupId != null) { // V8: revoked by the ID taken right after the creation
                    try {
                        revoke(client.getBaseURL(), cleanupId, admin);
                    } catch (Exception | AssertionError revokeFailure) {
                        if (revokeFailure instanceof InterruptedException) {
                            Thread.currentThread().interrupt();
                        }
                        t.addSuppressed(revokeFailure);
                    }
                }
                throw t;
            }
            revoke(client.getBaseURL(), publicId, admin);
        } catch (Throwable t) {
            capture.close(); // V8: the server has stopped, so the copy is complete; the console is restored
            try {
                WebStudioTest.assertNoSecretsLeaked(generated, capture); // V8: captured output, then saved responses
            } catch (AssertionError | RuntimeException scan) {
                t.addSuppressed(scan);
            }
            throw t;
        }
        capture.close(); // V8: as on the failure path
        WebStudioTest.assertNoSecretsLeaked(generated, capture);
    }

    // V8: the over-maximum request is sent from Java, so an unexpected token-bearing answer is never printed or saved
    @Test
    void tokenBeyondMaximumLifetimeIsRejected() throws Exception {
        // V8: the generated secrets, searched for in the captured console output and the saved responses: the
        // administrator header by its Base64 part, and the token and its secret part if one is issued by mistake.
        Map<String, String> generated = new HashMap<>();
        // The scan runs once the server has stopped, on success and on failure alike, and a scan failure is attached
        // to the test failure instead of replacing it.
        var capture = WebStudioTest.OutputCapture.start(); // V8: the console output is copied from before the start
        try (var client = JettyServer.get().start()) {
            WebStudioTest.putAdminCredentials(client, generated);
            WebStudioTest.putPatExpiryValues(client);
            // The message names only the variable, never its value.
            String admin = Objects.requireNonNull(client.localEnv.get("ADMIN_AUTH_TOCKEN"), "ADMIN_AUTH_TOCKEN");

            HttpRequest request = readRequest(TOO_FAR_REQUEST, client.getBaseURL(), client.localEnv);
            HttpResponse<byte[]> response;
            // HTTP/1.1, as the harness client uses, so no h2c upgrade is attempted.
            try (var http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build()) {
                response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
            }
            // The body is never printed, logged or put into a message; only its status and its code field are read.
            int status = response.statusCode();
            JsonNode body = json(response.body());
            if (status != 400) {
                var rejected = new AssertionError(
                        "over-maximum expiresAt: status ==> expected: <400> but was: <" + status + ">");
                if (status >= 200 && status < 300) {
                    // A token issued by mistake is registered for the scan, then revoked; a failed revocation is
                    // attached to the status failure, which stays the reported one.
                    String token = optionalText(body, "token");
                    if (token != null) {
                        generated.put("PAT_TOKEN", token);
                        generated.put("PAT_SECRET", token.substring(token.indexOf('.') + 1));
                    }
                    String cleanupId = cleanupId(body, token);
                    if (cleanupId != null) {
                        try {
                            revoke(client.getBaseURL(), cleanupId, admin);
                        } catch (Exception | AssertionError revokeFailure) {
                            if (revokeFailure instanceof InterruptedException) {
                                Thread.currentThread().interrupt();
                            }
                            rejected.addSuppressed(revokeFailure);
                        }
                    }
                }
                throw rejected;
            }
            assertTrue(body != null, "over-maximum expiresAt: body");
            assertTrue(EXPIRES_AT_MAX_KEY.equals(optionalText(body, "code")), "over-maximum expiresAt: code");
        } catch (Throwable t) {
            capture.close(); // V8: the server has stopped, so the copy is complete; the console is restored
            try {
                WebStudioTest.assertNoSecretsLeaked(generated, capture); // V8: captured output, then saved responses
            } catch (AssertionError | RuntimeException scan) {
                t.addSuppressed(scan);
            }
            throw t;
        }
        capture.close(); // V8: as on the failure path
        WebStudioTest.assertNoSecretsLeaked(generated, capture);
    }

    /**
     * V8: reads a request file as the harness does: the request line, the headers up to the first empty line, then
     * the body. Each {@code ${NAME}} of a header value or of the body is replaced from the environment, and the URI is
     * the base URL followed by the path. A failure names only the file part or the variable, never a value.
     */
    // V10: package-private, so WebStudioTest sends its http.json session check without the generic runner
    static HttpRequest readRequest(Path file, URI baseUrl, Map<String, String> env) throws IOException {
        String text = Files.readString(file, StandardCharsets.UTF_8);
        Matcher headerEnd = HEADER_END.matcher(text);
        if (!headerEnd.find()) {
            return fail(file + ": no empty line after the headers");
        }
        String[] lines = LINE_BREAK.split(text.substring(0, headerEnd.start()), -1);
        String[] requestLine = lines[0].split(" ", 3);
        if (requestLine.length < 2) {
            return fail(file + ": request line");
        }
        var builder = HttpRequest.newBuilder(URI.create(baseUrl.toString() + requestLine[1]))
                .method(requestLine[0],
                        HttpRequest.BodyPublishers.ofString(resolve(text.substring(headerEnd.end()), env),
                                StandardCharsets.UTF_8));
        for (int i = 1; i < lines.length; i++) {
            int separator = lines[i].indexOf(':');
            if (separator <= 0) {
                return fail(file + ": header line " + (i + 1));
            }
            builder.header(lines[i].substring(0, separator).trim(),
                    resolve(lines[i].substring(separator + 1).trim(), env));
        }
        // The same read timeout the harness applies to its own requests.
        int readTimeout = Integer.getInteger("http.timeout.read", 0);
        if (readTimeout > 0) {
            builder.timeout(Duration.ofMillis(readTimeout));
        }
        return builder.build();
    }

    /** V8: replaces each {@code ${NAME}} from the environment; an undefined name fails naming only the variable. */
    private static String resolve(String text, Map<String, String> env) {
        Matcher matcher = PLACEHOLDER.matcher(text);
        var result = new StringBuilder();
        while (matcher.find()) {
            String value = env.get(matcher.group(1));
            if (value == null) {
                return fail("Undefined environment variable: " + matcher.group(1));
            }
            matcher.appendReplacement(result, Matcher.quoteReplacement(value));
        }
        matcher.appendTail(result);
        return result.toString();
    }

    /**
     * V8: parses a response body, or returns {@code null} when it is empty or not JSON. The parse error is dropped,
     * not chained, because its message quotes the content.
     */
    private static @Nullable JsonNode json(byte[] body) {
        try {
            JsonNode node = MAPPER.readTree(body);
            return node == null || node.isMissingNode() ? null : node;
        } catch (IOException unparsable) {
            return null;
        }
    }

    /**
     * V8: returns the public ID to revoke a created token by: the {@code publicId} field when it is a valid ID,
     * otherwise the ID the token carries when it is a valid one, otherwise {@code null}.
     */
    private static @Nullable String cleanupId(@Nullable JsonNode created, @Nullable String token) {
        String publicId = optionalText(created, "publicId");
        if (isPublicId(publicId)) {
            return publicId;
        }
        int separator = PAT_PREFIX.length() + PUBLIC_ID_LENGTH;
        if (token != null && token.startsWith(PAT_PREFIX) && token.length() > separator
                && token.charAt(separator) == '.') {
            String carried = token.substring(PAT_PREFIX.length(), separator);
            if (isPublicId(carried)) {
                return carried;
            }
        }
        return null;
    }

    /** V8: whether the value is a public ID: exactly {@value #PUBLIC_ID_LENGTH} Base62 characters. */
    private static boolean isPublicId(@Nullable String value) {
        return value != null && PUBLIC_ID.matcher(value).matches();
    }

    /** V8: returns the non-blank text of a field of the response, or {@code null} when it has none. */
    private static @Nullable String optionalText(@Nullable JsonNode response, String field) {
        JsonNode value = response == null ? null : response.get(field);
        return value == null || !value.isTextual() || value.asText().isBlank() ? null : value.asText();
    }

    /**
     * Returns the non-blank text of a field of the response, or fails naming only the field.
     */
    private static String text(JsonNode response, String field) {
        JsonNode value = response == null ? null : response.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) {
            return fail(field);
        }
        return value.asText();
    }

    /**
     * Returns a field of the response parsed as an ISO-8601 instant, or fails naming only the field. The parse error
     * is not chained, because its message quotes the value.
     */
    private static Instant instant(JsonNode response, String field) {
        JsonNode value = response.get(field);
        if (value == null || value.isNull()) {
            return fail(field);
        }
        try {
            return Instant.parse(value.asText());
        } catch (DateTimeParseException unparsable) {
            return fail(field);
        }
    }

    /**
     * Revokes the token with the given public ID, as its owner, and asserts the {@code 204 No Content} answer.
     * The response body is discarded, and the failure message names only the step.
     */
    private static void revoke(URI baseUrl, String publicId, String authorization)
            throws IOException, InterruptedException {
        var request = HttpRequest.newBuilder(baseUrl.resolve(TOKENS_URL + "/" + publicId))
                .header("Authorization", authorization)
                .DELETE();
        // The same read timeout the harness applies to its own requests.
        int readTimeout = Integer.getInteger("http.timeout.read", 0);
        if (readTimeout > 0) {
            request.timeout(Duration.ofMillis(readTimeout));
        }
        // HTTP/1.1, as the harness client uses, so no h2c upgrade is attempted.
        try (var http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build()) {
            int status = http.send(request.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
            assertEquals(204, status, "revoke status");
        }
    }
}

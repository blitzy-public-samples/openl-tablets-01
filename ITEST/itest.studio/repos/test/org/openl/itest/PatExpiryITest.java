package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import org.openl.itest.core.JettyServer;

/**
 * V8: proves end to end that a personal access token created without {@code expiresAt} expires after the default
 * lifetime of 90 days ({@code security.pat.default-expiration-days}).
 *
 * <p>The {@code repos} server runs {@code user.mode=multi}. The token is created in Java through
 * {@code postForObject}, which asserts only the status, and its {@code expiresAt} is checked in Java. A {@code .resp}
 * file cannot make this check: its {@code "*"} wildcard also matches {@code null}, and a mismatch would print and save
 * the token-bearing body. The token is revoked afterwards, whether or not the check passes.
 *
 * <p><b>Secrets.</b> The administrator header is derived at runtime by {@link WebStudioTest#putAdminCredentials}.
 * The created token is never printed, logged or put into a message: failure messages name only the field or the
 * step. Once the server has stopped, the saved responses are scanned for the token and its secret part.
 */
class PatExpiryITest {

    /** The lifetime OpenL Studio applies by default: {@code security.pat.default-expiration-days = 90}. */
    private static final Duration DEFAULT_LIFETIME = Duration.ofDays(90);

    /** The allowed distance between the returned expiry and the default lifetime counted from the request. */
    private static final Duration TOLERANCE = Duration.ofMinutes(5);

    private static final String TOKENS_URL = "/rest/users/personal-access-tokens";

    @Test
    void tokenWithoutExpiryExpiresAfterDefaultLifetime() throws Exception {
        // The generated secrets: the created token and its secret part, searched for in the saved responses.
        Map<String, String> generated = new HashMap<>();
        // The scan runs once the server has stopped, on success and on failure alike. It is not thrown from a
        // finally block, so a scan failure never replaces the test failure; it is attached to it instead.
        try (var client = JettyServer.get().start()) {
            WebStudioTest.putAdminCredentials(client);
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

            // The token is registered for the scan before anything else can fail.
            String token = text(created, "token");
            generated.put("PAT_TOKEN", token);
            generated.put("PAT_SECRET", token.substring(token.indexOf('.') + 1));
            String publicId = text(created, "publicId");

            try {
                Instant expiresAt = instant(created, "expiresAt");
                Instant lower = before.plus(DEFAULT_LIFETIME).minus(TOLERANCE);
                Instant upper = after.plus(DEFAULT_LIFETIME).plus(TOLERANCE);
                assertTrue(!expiresAt.isBefore(lower) && !expiresAt.isAfter(upper), "expiresAt");
            } catch (Throwable t) {
                // The token is removed even when the check fails; a failed revocation is attached to the check
                // failure, so the expiresAt failure stays the reported one.
                try {
                    revoke(client.getBaseURL(), publicId, admin);
                } catch (Exception | AssertionError revokeFailure) {
                    if (revokeFailure instanceof InterruptedException) {
                        Thread.currentThread().interrupt();
                    }
                    t.addSuppressed(revokeFailure);
                }
                throw t;
            }
            revoke(client.getBaseURL(), publicId, admin);
        } catch (Throwable t) {
            try {
                WebStudioTest.assertNoSecretsSaved(generated);
            } catch (AssertionError | RuntimeException scan) {
                t.addSuppressed(scan);
            }
            throw t;
        }
        WebStudioTest.assertNoSecretsSaved(generated);
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

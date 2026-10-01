package org.openl.rules.ruleservice.spring;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Answers.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.mockito.MockedConstruction;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Covers V2: once JWT authentication is enabled, only {@code /admin/healthcheck/}, {@code /admin/info/} and
 * {@code /admin/config/} bypass the token check among the {@code /admin/} paths, while service OpenAPI documents
 * outside {@code /admin/} stay public.
 * <p>
 * Every key and token is generated at run time. The only file written is a JWKS holding the trusted public key.
 * Methods that present a token capture {@code System.err}, where the test logger writes. Rejected-token methods
 * assert that the fixed rejection line is logged and that no token material reaches the log: neither the token, its
 * payload, its JWT ID nor its claims. Assertion messages are fixed, so a failure never prints token material.
 */
class JWTValidatorTest {

    private static final String ISSUER = "itest";
    private static final String AUDIENCE = "https://openl-tablets.org";
    private static final String ISS_PROPERTY = "ruleservice.authentication.iss";
    private static final String AUD_PROPERTY = "ruleservice.authentication.aud";
    private static final String JWKS_PROPERTY = "ruleservice.authentication.jwks";
    private static final String REJECTED_TOKEN_LOG = "JWT rejected, jose4j error codes";
    private static final String UNEXPECTED_FAILURE_LOG = "JWT rejected, unexpected";

    @TempDir
    static Path tmp;

    private static RsaJsonWebKey trusted;
    private static RsaJsonWebKey untrusted;
    private static String jwksUrl;
    private static JWTValidator validator;

    @BeforeAll
    static void setUp() throws Exception {
        // RSA key generation is the costly step, so both keys are generated once for the whole class.
        trusted = RsaJwkGenerator.generateJwk(2048);
        trusted.setKeyId(UUID.randomUUID().toString());
        // The untrusted key shares the trusted key ID, so the resolver selects the trusted public key and the
        // signature verification itself is what rejects the token.
        untrusted = RsaJwkGenerator.generateJwk(2048);
        untrusted.setKeyId(trusted.getKeyId());

        Path jwks = tmp.resolve("jwks.json");
        Files.writeString(jwks, new JsonWebKeySet(trusted).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        jwksUrl = jwks.toUri().toString();
        validator = new JWTValidator(env(jwksUrl));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/deploy",
            "/admin/services",
            "/admin/deploy/x.zip",
            "/admin/deploy/openapi.json",
            "/admin/services/openapi.yaml",
            "/admin/healthcheck",
            "/admin/info",
            "/admin/config",
            "/admin/infox/sys.json",
            "/admin/configx/application.properties"})
    void adminPathOutsidePublicPrefixes_withoutToken_isRejected(String path) {
        assertFalse(validator.authorize(request(path, null)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/healthcheck/readiness",
            "/admin/info/sys.json",
            "/admin/config/application.properties",
            "/simple/openapi.json",
            "/simple/openapi.yaml"})
    void publicAdminPathOrServiceOpenApi_withoutToken_isAllowed(String path) {
        assertTrue(validator.authorize(request(path, null)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/deploy", "/simple/ping"})
    @StdIo
    void validBearerToken_isAllowed(String path, StdErr stdErr) throws JoseException {
        var token = sign(trusted, AUDIENCE, inSeconds(300));
        assertTrue(validator.authorize(request(path, "Bearer " + token)));
    }

    @Test
    @StdIo
    void validToken_withLowerCaseBearerScheme_isAllowed(StdErr stdErr) throws JoseException {
        var token = sign(trusted, AUDIENCE, inSeconds(300));
        assertTrue(validator.authorize(request("/admin/deploy", "bearer " + token)));
    }

    @Test
    @StdIo
    void validToken_withoutJwtId_isAllowed(StdErr stdErr) throws JoseException {
        var token = sign(trusted, ISSUER, AUDIENCE, inSeconds(300), null);
        assertTrue(validator.authorize(request("/admin/deploy", "Bearer " + token)));
        assertTrue(stdErr.capturedString().contains("Authorized for JWT ID=null"),
                "A token without a JWT ID must be logged as authorized");
    }

    @Test
    @StdIo
    void validToken_withLineBreakInJwtId_isLoggedOnOneLine(StdErr stdErr) throws JoseException {
        var marker = "FORGED-" + UUID.randomUUID();
        var jwtId = UUID.randomUUID() + "\r\n" + marker + " forged entry";
        var token = sign(trusted, ISSUER, AUDIENCE, inSeconds(300), jwtId);
        assertTrue(validator.authorize(request("/admin/deploy", "Bearer " + token)));

        var lines = stdErr.capturedString().lines().toList();
        assertFalse(lines.stream().anyMatch(line -> line.startsWith(marker)), "A JWT ID must never start a log line");
        var jwtIdLines = lines.stream().filter(line -> line.contains("JWT ID=")).toList();
        assertEquals(1, jwtIdLines.size(), "Exactly one log line must name the JWT ID");
        assertTrue(jwtIdLines.get(0).contains(marker), "The whole JWT ID must stay on the line that names it");
    }

    @Test
    @StdIo
    void validToken_withLongJwtId_isLoggedEscapedAndCapped(StdErr stdErr) throws JoseException {
        var head = UUID.randomUUID().toString();
        var tail = UUID.randomUUID().toString();
        // 36 + 1 + 36 + 1 + 36 characters precede the tail, so a 128-character cap keeps its first 18 characters.
        var jwtId = head + '\u2028' + UUID.randomUUID() + '\u2029' + UUID.randomUUID() + tail;
        var token = sign(trusted, ISSUER, AUDIENCE, inSeconds(300), jwtId);
        assertTrue(validator.authorize(request("/admin/deploy", "Bearer " + token)));

        var log = stdErr.capturedString();
        assertFalse(log.contains("\u2028") || log.contains("\u2029"), "Unicode line separators must be escaped");
        var jwtIdLines = log.lines().filter(line -> line.contains("JWT ID=")).toList();
        assertEquals(1, jwtIdLines.size(), "Exactly one log line must name the JWT ID");
        var line = jwtIdLines.get(0);
        assertTrue(line.contains(head + "\\u2028") && line.contains("\\u2029"),
                "Unicode line separators must be logged as escapes");
        assertTrue(line.endsWith(tail.substring(0, 18) + "..."), "A long JWT ID must be logged capped");
        assertFalse(line.contains(tail), "The part of a long JWT ID beyond the cap must not be logged");
    }

    @Test
    void servicePath_withoutAuthorizationHeader_isRejected() {
        assertFalse(validator.authorize(request("/simple/ping", null)));
    }

    // Rejected credentials are checked on a protected admin path and on a service path; both must be rejected.

    @ParameterizedTest
    @ValueSource(strings = {"/admin/deploy", "/simple/ping"})
    void basicScheme_isRejected(String path) {
        var randomBytes = new byte[24];
        new SecureRandom().nextBytes(randomBytes);
        var credentials = "Basic " + Base64.getEncoder().encodeToString(randomBytes);
        assertFalse(validator.authorize(request(path, credentials)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/deploy", "/simple/ping"})
    @StdIo
    void expiredToken_isRejected(String path, StdErr stdErr) throws JoseException {
        // Ten minutes in the past is well beyond the 30 seconds of allowed clock skew.
        var jwtId = UUID.randomUUID().toString();
        var token = sign(trusted, ISSUER, AUDIENCE, inSeconds(-600), jwtId);
        assertFalse(validator.authorize(request(path, "Bearer " + token)));
        assertRejectedWithoutTokenInLog(stdErr, REJECTED_TOKEN_LOG, token, jwtId);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/deploy", "/simple/ping"})
    @StdIo
    void tokenForAnotherAudience_isRejected(String path, StdErr stdErr) throws JoseException {
        var jwtId = UUID.randomUUID().toString();
        var token = sign(trusted, ISSUER, "https://" + UUID.randomUUID(), inSeconds(300), jwtId);
        assertFalse(validator.authorize(request(path, "Bearer " + token)));
        assertRejectedWithoutTokenInLog(stdErr, REJECTED_TOKEN_LOG, token, jwtId);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/deploy", "/simple/ping"})
    @StdIo
    void tokenFromAnotherIssuer_isRejected(String path, StdErr stdErr) throws JoseException {
        var jwtId = UUID.randomUUID().toString();
        var token = sign(trusted, "https://" + UUID.randomUUID(), AUDIENCE, inSeconds(300), jwtId);
        assertFalse(validator.authorize(request(path, "Bearer " + token)));
        assertRejectedWithoutTokenInLog(stdErr, REJECTED_TOKEN_LOG, token, jwtId);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/deploy", "/simple/ping"})
    @StdIo
    void tokenWithoutExpirationTime_isRejected(String path, StdErr stdErr) throws JoseException {
        var jwtId = UUID.randomUUID().toString();
        var token = sign(trusted, ISSUER, AUDIENCE, null, jwtId);
        assertFalse(validator.authorize(request(path, "Bearer " + token)));
        assertRejectedWithoutTokenInLog(stdErr, REJECTED_TOKEN_LOG, token, jwtId);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/deploy", "/simple/ping"})
    @StdIo
    void tokenSignedByUntrustedKey_isRejected(String path, StdErr stdErr) throws JoseException {
        var jwtId = UUID.randomUUID().toString();
        var token = sign(untrusted, ISSUER, AUDIENCE, inSeconds(300), jwtId);
        assertFalse(validator.authorize(request(path, "Bearer " + token)));
        assertRejectedWithoutTokenInLog(stdErr, REJECTED_TOKEN_LOG, token, jwtId);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/deploy", "/simple/ping"})
    @StdIo
    void malformedToken_isRejected(String path, StdErr stdErr) {
        var token = UUID.randomUUID().toString();
        assertFalse(validator.authorize(request(path, "Bearer " + token)));
        assertRejectedWithoutTokenInLog(stdErr, REJECTED_TOKEN_LOG, token, null);
    }

    @Test
    @StdIo
    void unexpectedProcessingFailure_isRejectedWithoutItsMessageInLog(StdErr stdErr) throws Exception {
        // A runtime failure inside token processing, such as one raised by a key resolver, can quote the token.
        var token = UUID.randomUUID().toString();
        var consumer = mock(JwtConsumer.class);
        when(consumer.processToClaims(token)).thenThrow(new IllegalStateException("Cannot process " + token));
        try (MockedConstruction<JwtConsumerBuilder> builders = mockConstruction(JwtConsumerBuilder.class,
                withSettings().defaultAnswer(RETURNS_SELF),
                (builder, context) -> when(builder.build()).thenReturn(consumer))) {
            var failing = new JWTValidator(env(jwksUrl));
            assertEquals(1, builders.constructed().size(), "The validator must build its consumer once");
            assertFalse(failing.authorize(request("/admin/deploy", "Bearer " + token)));
        }
        assertRejectedWithoutTokenInLog(stdErr, UNEXPECTED_FAILURE_LOG, token, null);
    }

    @Test
    void constructor_withoutIssuer_fails() {
        var env = new MockEnvironment().withProperty(AUD_PROPERTY, AUDIENCE).withProperty(JWKS_PROPERTY, jwksUrl);
        assertThrows(IllegalArgumentException.class, () -> new JWTValidator(env));
    }

    @Test
    void constructor_withoutJwks_fails() {
        var env = new MockEnvironment().withProperty(ISS_PROPERTY, ISSUER).withProperty(AUD_PROPERTY, AUDIENCE);
        assertThrows(IllegalArgumentException.class, () -> new JWTValidator(env));
    }

    @Test
    void constructor_withEmptyJwks_fails() {
        var env = env("");
        assertThrows(IllegalArgumentException.class, () -> new JWTValidator(env));
    }

    @Test
    void constructor_withHttpsJwks_resolvesKeysLazily() {
        // The HTTPS resolver fetches keys on first use only, so construction succeeds without any connection.
        // This instance is never asked to verify a token.
        var env = env("https://127.0.0.1:1/jwks.json");
        assertDoesNotThrow(() -> new JWTValidator(env));
    }

    private static MockEnvironment env(String jwks) {
        return new MockEnvironment().withProperty(ISS_PROPERTY, ISSUER)
                .withProperty(AUD_PROPERTY, AUDIENCE)
                .withProperty(JWKS_PROPERTY, jwks);
    }

    private static String sign(RsaJsonWebKey key, String audience, NumericDate exp) throws JoseException {
        return sign(key, ISSUER, audience, exp, UUID.randomUUID().toString());
    }

    /**
     * Signs a JWT issued now.
     *
     * @param exp the expiration time, or {@code null} for a token without an {@code exp} claim
     * @param jwtId the {@code jti} claim value, or {@code null} for a token without a {@code jti} claim
     */
    private static String sign(RsaJsonWebKey key,
            String issuer,
            String audience,
            @Nullable NumericDate exp,
            @Nullable String jwtId) throws JoseException {
        var claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setAudience(audience);
        if (exp != null) {
            claims.setExpirationTime(exp);
        }
        claims.setIssuedAtToNow();
        if (jwtId != null) {
            claims.setJwtId(jwtId);
        }

        var jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setKeyIdHeaderValue(key.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        return jws.getCompactSerialization();
    }

    private static NumericDate inSeconds(long seconds) {
        var date = NumericDate.now();
        date.addSeconds(seconds);
        return date;
    }

    /**
     * Asserts that the captured log holds the fixed rejection text and no material of the rejected token.
     *
     * @param rejectionText the fixed text the rejection line must contain
     * @param token the rejected token
     * @param jwtId the token's {@code jti} claim value, or {@code null} for a token without one
     */
    private static void assertRejectedWithoutTokenInLog(StdErr stdErr,
            String rejectionText,
            String token,
            @Nullable String jwtId) {
        var log = stdErr.capturedString();
        assertTrue(log.contains(rejectionText), "The fixed rejection line must be logged");
        assertFalse(log.contains(token), "The rejected token must never be logged");
        var segments = token.split("\\.", -1);
        if (segments.length > 1) {
            assertFalse(log.contains(segments[1]), "The payload of a rejected token must never be logged");
        }
        if (jwtId != null) {
            assertFalse(log.contains(jwtId), "The JWT ID of a rejected token must never be logged");
        }
        assertFalse(log.contains("claims->"), "The claims of a rejected token must never be logged");
    }

    /**
     * Builds a request for the given path. {@link JWTValidator#authorize} dereferences the path info without a null
     * check, so every request carries a path.
     *
     * @param pathInfo the servlet path info, never {@code null}
     * @param authorization the {@code Authorization} header value, or {@code null} for a request without it
     */
    private static HttpServletRequest request(String pathInfo, @Nullable String authorization) {
        var request = new MockHttpServletRequest();
        request.setPathInfo(pathInfo);
        if (authorization != null) {
            request.addHeader("Authorization", authorization);
        }
        return request;
    }
}

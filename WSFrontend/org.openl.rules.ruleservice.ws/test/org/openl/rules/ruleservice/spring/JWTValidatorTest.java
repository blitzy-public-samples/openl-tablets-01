package org.openl.rules.ruleservice.spring;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Answers.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;

import org.jose4j.http.Get;
import org.jose4j.http.SimpleResponse;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.ReservedClaimNames;
import org.jose4j.jwt.consumer.ErrorCodeValidator;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.mockito.MockedConstruction;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import org.slf4j.simple.SimpleLogger;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Covers V2: once JWT authentication is enabled, only {@code /admin/healthcheck/}, {@code /admin/info/} and
 * {@code /admin/config/} bypass the token check among the {@code /admin/} paths, while service OpenAPI documents
 * outside {@code /admin/} stay public.
 * <p>
 * Every key and token is generated at run time. The only file written is a JWKS holding the trusted public key.
 * Methods that present a token capture {@code System.err}, where the test logger writes, and every one of them asserts
 * through one shared guard that no token material reaches the log: neither the token, its payload nor its signature.
 * Accepted-token methods also assert the intended authorized line. Rejected-token methods also assert the fixed
 * rejection line and that neither the JWT ID nor the claims are logged. A negative control proves the guard detects a
 * leaked token, payload or signature in synthetic log text. Assertion messages are fixed, so a failure never prints
 * token material.
 * <p>
 * Level tests lower the validator's logger only while they call it and restore it afterwards: with INFO disabled a
 * valid token is still accepted and no authorized line or JWT ID is logged; with WARN disabled rejected tokens are
 * still rejected and no rejection line is logged; a JWT ID that is not a string is rejected whether INFO is enabled or
 * not. With a mocked consumer, they also verify that the JWT ID is read at every level and that the error codes of a
 * rejected token are collected only while WARN is enabled.
 */
class JWTValidatorTest {

    private static final String ISSUER = "itest";
    private static final String AUDIENCE = "https://openl-tablets.org";
    private static final String ISS_PROPERTY = "ruleservice.authentication.iss";
    private static final String AUD_PROPERTY = "ruleservice.authentication.aud";
    private static final String JWKS_PROPERTY = "ruleservice.authentication.jwks";
    private static final String REJECTED_TOKEN_LOG = "JWT rejected, jose4j error codes";
    private static final String UNEXPECTED_FAILURE_LOG = "JWT rejected, unexpected";
    private static final String AUTHORIZED_LOG = "Authorized for JWT ID=";

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
        assertSingleAuthorizedLine(stdErr.capturedString());
        assertNoTokenMaterialInLog(stdErr.capturedString(), token);
    }

    @Test
    @StdIo
    void validToken_withLowerCaseBearerScheme_isAllowed(StdErr stdErr) throws JoseException {
        var token = sign(trusted, AUDIENCE, inSeconds(300));
        assertTrue(validator.authorize(request("/admin/deploy", "bearer " + token)));
        assertSingleAuthorizedLine(stdErr.capturedString());
        assertNoTokenMaterialInLog(stdErr.capturedString(), token);
    }

    @Test
    @StdIo
    void validToken_withoutJwtId_isAllowed(StdErr stdErr) throws JoseException {
        var token = sign(trusted, ISSUER, AUDIENCE, inSeconds(300), null);
        assertTrue(validator.authorize(request("/admin/deploy", "Bearer " + token)));
        assertTrue(stdErr.capturedString().contains(AUTHORIZED_LOG + "null"),
                "A token without a JWT ID must be logged as authorized");
        assertNoTokenMaterialInLog(stdErr.capturedString(), token);
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
        assertNoTokenMaterialInLog(stdErr.capturedString(), token);
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
        assertNoTokenMaterialInLog(log, token);
    }

    @Test
    void containsTokenMaterial_detectsTokenPayloadAndSignature() throws JoseException {
        // Negative control for the log guard: synthetic log text that leaks a real token, or one of its secret
        // segments, must be detected, and the guard's own failure message must carry no token material.
        var jwtId = UUID.randomUUID().toString();
        var token = sign(trusted, ISSUER, AUDIENCE, inSeconds(300), jwtId);
        var segments = token.split("\\.", -1);
        assertEquals(3, segments.length, "A signed token must have a header, a payload and a signature");
        var prefix = "[main] INFO " + JWTValidator.class.getName() + " - ";
        var clean = prefix + AUTHORIZED_LOG + jwtId + System.lineSeparator();

        assertTrue(containsTokenMaterial(clean + prefix + token, token), "A leaked token must be detected");
        assertTrue(containsTokenMaterial(clean + prefix + segments[1], token), "A leaked payload must be detected");
        assertTrue(containsTokenMaterial(clean + prefix + segments[2], token), "A leaked signature must be detected");
        assertFalse(containsTokenMaterial(clean, token), "A log without token material must pass the guard");
        assertDoesNotThrow(() -> assertNoTokenMaterialInLog(clean, token), "A clean log must pass the assertion");
        var failure = assertThrows(AssertionError.class,
                () -> assertNoTokenMaterialInLog(clean + prefix + segments[1], token),
                "A leaked payload must fail the assertion");
        assertFalse(containsTokenMaterial(String.valueOf(failure.getMessage()), token),
                "The assertion failure message must carry no token material");

        // A token without dots has no segments, so only the whole value counts, and an empty signature segment of an
        // unsigned token never matches on its own.
        var opaque = UUID.randomUUID().toString();
        assertTrue(containsTokenMaterial(prefix + opaque, opaque), "A leaked token without dots must be detected");
        assertFalse(containsTokenMaterial(clean, opaque), "A token without dots must not match a clean log");
        var unsigned = segments[0] + "." + segments[1] + ".";
        assertFalse(containsTokenMaterial(clean, unsigned), "An empty segment must not match a clean log");
        assertTrue(containsTokenMaterial(clean + prefix + segments[1], unsigned),
                "The payload of an unsigned token must be detected");
    }

    @Test
    @StdIo
    void validToken_withInfoDisabled_isAllowedWithoutAuthorizedLine(StdErr stdErr) throws Throwable {
        // The control character would be escaped if the authorized line were formatted while INFO is disabled.
        var head = UUID.randomUUID().toString();
        var jwtId = head + '\u0007' + UUID.randomUUID();
        var token = sign(trusted, ISSUER, AUDIENCE, inSeconds(300), jwtId);
        withValidatorLogLevel(Level.WARN,
                () -> assertTrue(validator.authorize(request("/admin/deploy", "Bearer " + token))));

        var log = stdErr.capturedString();
        assertFalse(log.contains(AUTHORIZED_LOG), "No authorized line may be logged while INFO is disabled");
        assertFalse(log.contains(head), "No JWT ID may be logged while INFO is disabled");
        assertNoTokenMaterialInLog(log, token);
    }

    @Test
    @StdIo
    void rejectedTokens_withWarnDisabled_areRejectedWithoutRejectionLine(StdErr stdErr) throws Throwable {
        // Ten minutes in the past is well beyond the 30 seconds of allowed clock skew.
        var expired = sign(trusted, ISSUER, AUDIENCE, inSeconds(-600), UUID.randomUUID().toString());
        var untrustedToken = sign(untrusted, ISSUER, AUDIENCE, inSeconds(300), UUID.randomUUID().toString());
        withValidatorLogLevel(Level.ERROR, () -> {
            assertFalse(validator.authorize(request("/admin/deploy", "Bearer " + expired)));
            assertFalse(validator.authorize(request("/simple/ping", "Bearer " + untrustedToken)));
        });

        var log = stdErr.capturedString();
        assertFalse(log.contains("JWT rejected"), "No rejection line may be logged while WARN is disabled");
        assertNoTokenMaterialInLog(log, expired);
        assertNoTokenMaterialInLog(log, untrustedToken);
    }

    @Test
    @StdIo
    void disabledLogLevels_stillReadJwtId_andSkipErrorCodes(StdErr stdErr) throws Throwable {
        // Controlled collaborators make the guarded work observable: the JWT ID is read at every level, while the
        // error codes of a rejected token are collected only when WARN is enabled.
        var accepted = UUID.randomUUID().toString();
        var rejected = UUID.randomUUID().toString();
        var claims = mock(JwtClaims.class);
        when(claims.getJwtId()).thenReturn(UUID.randomUUID().toString());
        var invalid = mock(InvalidJwtException.class);
        when(invalid.getErrorDetails()).thenReturn(List.of(new ErrorCodeValidator.Error(ErrorCodes.EXPIRED, "")));
        var consumer = mock(JwtConsumer.class);
        when(consumer.processToClaims(accepted)).thenReturn(claims);
        when(consumer.processToClaims(rejected)).thenThrow(invalid);
        try (MockedConstruction<JwtConsumerBuilder> ignored = mockConstruction(JwtConsumerBuilder.class,
                withSettings().defaultAnswer(RETURNS_SELF),
                (builder, context) -> when(builder.build()).thenReturn(consumer))) {
            var controlled = new JWTValidator(env(jwksUrl));
            withValidatorLogLevel(Level.WARN,
                    () -> assertTrue(controlled.authorize(request("/admin/deploy", "Bearer " + accepted))));
            verify(claims).getJwtId();
            withValidatorLogLevel(Level.ERROR,
                    () -> assertFalse(controlled.authorize(request("/admin/deploy", "Bearer " + rejected))));
            verify(invalid, never()).getErrorDetails();
            withValidatorLogLevel(Level.WARN,
                    () -> assertFalse(controlled.authorize(request("/admin/deploy", "Bearer " + rejected))));
            verify(invalid).getErrorDetails();
        }

        var log = stdErr.capturedString();
        assertFalse(log.contains(AUTHORIZED_LOG), "No authorized line may be logged while INFO is disabled");
        assertEquals(1, log.lines().filter(line -> line.contains(REJECTED_TOKEN_LOG)).count(),
                "Only the rejection while WARN is enabled may be logged");
        assertTrue(log.contains(REJECTED_TOKEN_LOG + " [" + ErrorCodes.EXPIRED + "]"),
                "The rejection line must name the jose4j error code");
        assertNoTokenMaterialInLog(log, accepted);
        assertNoTokenMaterialInLog(log, rejected);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    @StdIo
    void tokenWithNumericJwtId_isRejectedAtEveryLogLevel(boolean infoEnabled, StdErr stdErr) throws Throwable {
        // jose4j rejects a JWT ID that is not a string as a malformed claim while it processes the token.
        var jwtId = new SecureRandom().nextLong(1_000_000_000_000L, Long.MAX_VALUE);
        var claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(AUDIENCE);
        claims.setExpirationTime(inSeconds(300));
        claims.setIssuedAtToNow();
        claims.setClaim(ReservedClaimNames.JWT_ID, jwtId);
        var token = sign(trusted, claims);
        withValidatorLogLevel(infoEnabled ? Level.INFO : Level.WARN,
                () -> assertFalse(validator.authorize(request("/admin/deploy", "Bearer " + token))));

        assertRejectedWithoutTokenInLog(stdErr, REJECTED_TOKEN_LOG, token, String.valueOf(jwtId));
        var log = stdErr.capturedString();
        assertTrue(log.contains(REJECTED_TOKEN_LOG + " [" + ErrorCodes.MALFORMED_CLAIM + "]"),
                "A JWT ID that is not a string must be rejected as a malformed claim");
        assertFalse(log.contains(AUTHORIZED_LOG), "A rejected token must never be logged as authorized");
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
    @StdIo
    void constructor_withHttpsJwks_fetchesKeysOnFirstVerificationOnly(StdErr stdErr) throws Exception {
        // The HTTP client that the HTTPS key resolver creates is replaced by a mock that serves the trusted public
        // JWKS, so no connection is ever made; the reserved .invalid host could not be resolved anyway. Because the
        // mock answers from the start, an eager fetch would succeed silently and only the interaction checks catch it.
        var url = "https://" + UUID.randomUUID() + ".invalid/jwks.json";
        var token = sign(trusted, AUDIENCE, inSeconds(300));
        var response = mock(SimpleResponse.class);
        when(response.getStatusCode()).thenReturn(200);
        var publicJwks = new JsonWebKeySet(trusted).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        when(response.getBody()).thenReturn(publicJwks);
        try (MockedConstruction<Get> gets = mockConstruction(Get.class,
                (get, context) -> when(get.get(url)).thenReturn(response))) {
            var lazy = new JWTValidator(env(url));
            assertEquals(1, gets.constructed().size(), "The validator must create one HTTP client for its JWKS");
            var get = gets.constructed().get(0);
            verifyNoInteractions(get);

            // Decisions that need no key are made without fetching the JWKS.
            assertTrue(lazy.authorize(request("/admin/healthcheck/readiness", null)),
                    "A public admin path must be allowed before any key is fetched");
            assertFalse(lazy.authorize(request("/admin/deploy", null)),
                    "A request without a token must be rejected before any key is fetched");
            verifyNoInteractions(get);

            assertTrue(lazy.authorize(request("/admin/deploy", "Bearer " + token)),
                    "A valid token must be accepted with the fetched keys");
            verify(get).get(url);
            assertSingleAuthorizedLine(stdErr.capturedString());

            // A later verification uses the cached keys instead of fetching them again.
            assertTrue(lazy.authorize(request("/simple/ping", "Bearer " + token)),
                    "A valid token must be accepted with the cached keys");
            verify(get).get(url);
            verifyNoMoreInteractions(get);
        }
        assertNoTokenMaterialInLog(stdErr.capturedString(), token);
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
        return sign(key, claims);
    }

    /**
     * Signs the given claims with RS256 and the given key, naming its key ID in the header.
     */
    private static String sign(RsaJsonWebKey key, JwtClaims claims) throws JoseException {
        var jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setKeyIdHeaderValue(key.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        return jws.getCompactSerialization();
    }

    /**
     * Runs a body with the validator's logger at the given level and restores the previous level afterwards, even
     * when the body fails. The test logger is slf4j-simple, which has no public level API: {@link LoggerFactory}
     * returns the one cached {@link SimpleLogger} that {@link JWTValidator} also logs through, and its protected
     * {@code currentLogLevel} field decides every {@code isXxxEnabled} check, so the field is set reflectively. The
     * slf4j-simple level values equal {@link Level#toInt()}.
     *
     * @param level the lowest level that is logged while the body runs
     * @param body the code to run at that level
     */
    private static void withValidatorLogLevel(Level level, Executable body) throws Throwable {
        var logger = LoggerFactory.getLogger(JWTValidator.class);
        assertInstanceOf(SimpleLogger.class, logger, "The test logger must be slf4j-simple to change its level");
        var currentLogLevel = SimpleLogger.class.getDeclaredField("currentLogLevel");
        currentLogLevel.setAccessible(true);
        int previous = currentLogLevel.getInt(logger);
        currentLogLevel.setInt(logger, level.toInt());
        try {
            body.execute();
        } finally {
            currentLogLevel.setInt(logger, previous);
        }
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
        assertFalse(containsTokenMaterial(log, token), "No material of a rejected token may be logged");
        if (jwtId != null) {
            assertFalse(log.contains(jwtId), "The JWT ID of a rejected token must never be logged");
        }
        assertFalse(log.contains("claims->"), "The claims of a rejected token must never be logged");
    }

    /**
     * Asserts that a captured log holds no material of a presented token, as {@link #containsTokenMaterial} defines
     * it. The message is fixed, so a failure never prints the log or the token.
     *
     * @param log the captured log text
     * @param token the token presented to the validator
     */
    private static void assertNoTokenMaterialInLog(String log, String token) {
        assertFalse(containsTokenMaterial(log, token), "No material of a presented token may be logged");
    }

    /**
     * Tells whether a text holds material of a token: the whole compact serialization, its payload segment (the
     * claims) or its signature segment. The header is not looked for, since it names only the algorithm and key ID.
     * A token without dots, such as a malformed one, has no segments, so only the whole value is looked for. An empty
     * segment, such as the signature of an unsigned token, is skipped because every text contains it.
     *
     * @param text the text to search, typically a captured log
     * @param token the token whose material must not appear
     * @return {@code true} if the text holds the token, its payload or its signature
     */
    private static boolean containsTokenMaterial(String text, String token) {
        if (text.contains(token)) {
            return true;
        }
        var segments = token.split("\\.", -1);
        // Index 1 is the payload and index 2 the signature of a compact JWS; a token without dots has one segment.
        for (int i = 1; i < Math.min(segments.length, 3); i++) {
            if (!segments[i].isEmpty() && text.contains(segments[i])) {
                return true;
            }
        }
        return false;
    }

    /**
     * Asserts that a captured log holds exactly one authorized line, the one the validator writes on success.
     *
     * @param log the captured log text
     */
    private static void assertSingleAuthorizedLine(String log) {
        assertEquals(1, log.lines().filter(line -> line.contains(AUTHORIZED_LOG)).count(),
                "Exactly one authorized line must be logged");
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

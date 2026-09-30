package org.openl.rules.ruleservice.spring;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.jose4j.lang.JoseException;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Covers V2: once JWT authentication is enabled, only {@code /admin/healthcheck/}, {@code /admin/info/} and
 * {@code /admin/config/} bypass the token check among the {@code /admin/} paths, while service OpenAPI documents
 * outside {@code /admin/} stay public.
 * <p>
 * Every key and token is generated at run time. The only file written is a JWKS holding the trusted public key.
 * Methods that present a rejected token capture {@code System.err}, because {@link JWTValidator} logs the jose4j
 * exception of a rejected token, and that text can carry the token's claims.
 */
class JWTValidatorTest {

    private static final String ISSUER = "itest";
    private static final String AUDIENCE = "https://openl-tablets.org";
    private static final String ISS_PROPERTY = "ruleservice.authentication.iss";
    private static final String AUD_PROPERTY = "ruleservice.authentication.aud";
    private static final String JWKS_PROPERTY = "ruleservice.authentication.jwks";

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
            "/admin/healthcheck"})
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
    void servicePath_withoutAuthorizationHeader_isRejected() {
        assertFalse(validator.authorize(request("/simple/ping", null)));
    }

    // The credential checks below run on a protected admin path and on a service path. Before the V2 fix the admin
    // path skipped the token check, so there only the service-path cases pass; after it both must reject.

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
        var token = sign(trusted, AUDIENCE, inSeconds(-600));
        assertFalse(validator.authorize(request(path, "Bearer " + token)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/deploy", "/simple/ping"})
    @StdIo
    void tokenForAnotherAudience_isRejected(String path, StdErr stdErr) throws JoseException {
        var token = sign(trusted, "https://" + UUID.randomUUID(), inSeconds(300));
        assertFalse(validator.authorize(request(path, "Bearer " + token)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/deploy", "/simple/ping"})
    @StdIo
    void tokenSignedByUntrustedKey_isRejected(String path, StdErr stdErr) throws JoseException {
        var token = sign(untrusted, AUDIENCE, inSeconds(300));
        assertFalse(validator.authorize(request(path, "Bearer " + token)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/deploy", "/simple/ping"})
    @StdIo
    void malformedToken_isRejected(String path, StdErr stdErr) {
        assertFalse(validator.authorize(request(path, "Bearer " + UUID.randomUUID())));
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
        var claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(audience);
        claims.setExpirationTime(exp);
        claims.setIssuedAtToNow();
        claims.setGeneratedJwtId();

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

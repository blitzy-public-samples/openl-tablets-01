package org.openl.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.openl.itest.core.JettyServer;

/**
 * V2: with JWT authentication and the deployer enabled, every /admin/ path except health, info and config requires
 * a valid token.
 *
 * <p>The signing key and the token are generated for each run, and only the public key is written to disk. This is a
 * class of its own, so the {@code jwt} suite of {@link JWTValidatorTest} keeps its fixtures unchanged.
 */
class JwtDeployAuthorizationTest {

    // The Rule Services default of ruleservice.authentication.aud, which the jwt-deploy profile does not override.
    private static final String AUDIENCE = "https://openl-tablets.org";
    // The ruleservice.authentication.iss of the jwt-deploy profile.
    private static final String ISSUER = "itest";
    // The ruleservice.authentication.jwks of the jwt-deploy profile, file:target/jwt-deploy/jwks.json, relative to
    // the module directory the tests run in. JWTValidator reads it once, when the webapp starts.
    private static final Path JWKS = Path.of("target", "jwt-deploy", "jwks.json");
    private static final String TEST_RESOURCES = "test-resources-jwt-deploy";
    // V2: the request fixtures of TEST_RESOURCES, each without its .req extension.
    private static final List<String> REQUESTS = List.of("010-deploy-no-token",
            "020-deploy-openapi-no-token",
            "030-services-no-token",
            "040-deploy-with-token",
            "050-healthcheck",
            "060-info-sys",
            "070-config",
            "080-service-openapi",
            "900-delete");

    private static String token;

    /**
     * Generates an RSA key pair, publishes its public half as the JWKS the webapp trusts, and signs a token that
     * carries the expiration, issuer and audience the validator requires.
     */
    @BeforeAll
    static void createKeyAndToken() throws Exception {
        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId(UUID.randomUUID().toString());

        Files.createDirectories(JWKS.getParent());
        Files.writeString(JWKS,
                new JsonWebKeySet(jwk).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);

        var claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(AUDIENCE);
        claims.setExpirationTimeMinutesInTheFuture(5);
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();

        var jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(jwk.getPrivateKey());
        jws.setKeyIdHeaderValue(jwk.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        token = jws.getCompactSerialization();
    }

    @Test
    void test() throws Exception {
        // V2: HttpClient.test passes on a folder that holds no requests, so this check stops the class passing
        // without its fixtures. It runs before the server starts.
        var missing = REQUESTS.stream()
                .map(name -> name + ".req")
                .filter(file -> !Files.isRegularFile(Path.of(TEST_RESOURCES, file)))
                .toList();
        assertEquals(List.of(), missing, "Request fixtures missing from " + TEST_RESOURCES);

        try (var client = JettyServer.get().withProfile("jwt-deploy").start()) {
            // The fixtures send the token as Authorization: Bearer ${JWT_TOKEN}.
            client.localEnv.put("JWT_TOKEN", token);
            client.test(TEST_RESOURCES);
        }
    }

    /**
     * Fails when a response body saved for a mismatch holds the generated token. The message names the files only.
     */
    @AfterAll
    static void noTokenInSavedResponses() throws IOException {
        var responses = System.getProperty("server.responses");
        if (token == null || responses == null) {
            return;
        }
        var dir = Path.of(responses);
        if (!Files.isDirectory(dir)) {
            return;
        }
        List<Path> saved;
        try (Stream<Path> files = Files.walk(dir)) {
            saved = files.filter(Files::isRegularFile).toList();
        }
        var offending = new ArrayList<Path>();
        for (var file : saved) {
            if (new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1).contains(token)) {
                offending.add(file);
            }
        }
        assertEquals(0, offending.size(), "Saved responses contain the generated token: " + offending);
    }
}

package org.openl.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Stream;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jspecify.annotations.Nullable;
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
            // V2: dot-segment paths that resolve into a public path still need a token.
            "081-deploy-dot-segment-no-token",
            "082-info-dot-segment-no-token",
            "900-delete");

    private static String token;
    // V2: the private members of the signing key (d, p, q, dp, dq, qi), keyed by JWK member name.
    private static Map<String, String> privateKeyMembers = Map.of();

    /**
     * Generates an RSA key pair, publishes its public half as the JWKS the webapp trusts, and signs a token that
     * carries the expiration, issuer and audience the validator requires.
     */
    @BeforeAll
    static void createKeyAndToken() throws Exception {
        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId(UUID.randomUUID().toString());
        privateKeyMembers = privateMembers(jwk);

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
        // V2: fail before the server starts when a request fixture is missing.
        // HttpClient.test passes on a folder that holds no requests; this check stops the class passing without them.
        var missing = REQUESTS.stream()
                .map(name -> name + ".req")
                .filter(file -> !Files.isRegularFile(Path.of(TEST_RESOURCES, file)))
                .toList();
        assertEquals(List.of(), missing, "Request fixtures missing from " + TEST_RESOURCES);

        // V2: both console streams are copied while the server runs and scanned for the token and private key members.
        // The capture is the first try resource, so it is restored only after the server has stopped, then scanned.
        var console = new ConsoleCapture();
        try (console; var client = JettyServer.get().withProfile("jwt-deploy").start()) {
            // The fixtures send the token as Authorization: Bearer ${JWT_TOKEN}.
            client.localEnv.put("JWT_TOKEN", token);
            client.test(TEST_RESOURCES);
        } catch (Throwable e) {
            // V2: every failure, an Error included, stays the reported one: a console finding is attached to it
            var printed = tokenPrinted(console);
            if (printed != null) {
                e.addSuppressed(printed);
            }
            throw e;
        }
        var printed = tokenPrinted(console); // V2: the run passed, so a console finding is the reported failure
        if (printed != null) {
            throw printed;
        }
    }

    // V2: the failure, naming the labels and never the values, when the copied console output holds a generated secret.
    // The generated secrets are the token and the private members of the signing key.
    private static @Nullable AssertionError tokenPrinted(ConsoleCapture console) {
        var secrets = new LinkedHashMap<String, String>();
        secrets.put("JWT_TOKEN", token);
        privateKeyMembers.forEach((member, value) -> secrets.put("private key member " + member, value));
        var names = console.printed(secrets);
        return names.isEmpty() ? null
                : new AssertionError("Generated credentials found in the console output: " + names);
    }

    /**
     * Fails when a response body saved for a mismatch holds the generated token or a private member of the generated
     * signing key. The message names the kind of secret and the files only, never the matched content.
     */
    @AfterAll
    static void noGeneratedSecretInSavedResponses() throws IOException {
        var responses = System.getProperty("server.responses");
        // V2: every value this class generates and must never find in a saved response, keyed by its kind.
        var generated = new LinkedHashMap<String, String>();
        if (token != null) {
            generated.put("token", token);
        }
        privateKeyMembers.forEach((member, value) -> generated.put("private key member " + member, value));
        if (generated.isEmpty() || responses == null) {
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
        var offending = new TreeMap<String, List<Path>>();
        for (var file : saved) {
            var content = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1);
            generated.forEach((kind, value) -> {
                if (content.contains(value)) {
                    offending.computeIfAbsent(kind, k -> new ArrayList<>()).add(file);
                }
            });
        }
        assertEquals(0, offending.size(), "Saved responses contain generated secrets: " + offending);
    }

    /**
     * Returns the members that the private form of a JWK adds to its public form, which are its private key material.
     *
     * @param jwk the generated signing key
     * @return each private member's base64url value, keyed by its JWK member name
     */
    private static Map<String, String> privateMembers(RsaJsonWebKey jwk) {
        var publicMembers = jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY).keySet();
        var members = new TreeMap<String, String>();
        jwk.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE).forEach((member, value) -> {
            if (!publicMembers.contains(member) && value instanceof String text && !text.isEmpty()) {
                members.put(member, text);
            }
        });
        return members;
    }

    // V2: while open, System.out and System.err pass everything on to the console and keep a copy for the token scan.
    // The harness progress and a mismatching response are therefore still shown.
    // Closing restores both streams; a second close does nothing.
    private static final class ConsoleCapture implements AutoCloseable {
        private final PrintStream originalOut = System.out;
        private final PrintStream originalErr = System.err;
        private final ByteArrayOutputStream outCopy = new ByteArrayOutputStream();
        private final ByteArrayOutputStream errCopy = new ByteArrayOutputStream();
        private final PrintStream out = tee(originalOut, outCopy);
        private final PrintStream err = tee(originalErr, errCopy);
        private boolean closed;

        ConsoleCapture() {
            System.setOut(out);
            System.setErr(err);
        }

        // V2: writes every byte to the console stream and to the copy, encoding characters as the console does
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

        // V2: the text System.out received while open, decoded with the charset of the console stream
        String out() {
            return outCopy.toString(originalOut.charset());
        }

        // V2: the text System.err received while open, decoded with the charset of the console stream
        String err() {
            return errCopy.toString(originalErr.charset());
        }

        // V2: the sorted names whose non-empty value either stream received.
        // Each value is searched for as that stream's charset encodes it.
        Set<String> printed(Map<String, String> secrets) {
            var outText = out();
            var errText = err();
            var names = new TreeSet<String>();
            for (var entry : secrets.entrySet()) {
                var value = entry.getValue();
                if (!value.isEmpty() && (outText.contains(encoded(value, originalOut.charset()))
                        || errText.contains(encoded(value, originalErr.charset())))) {
                    names.add(entry.getKey());
                }
            }
            return names;
        }

        // V2: the text as a stream of this charset gives it back, characters it cannot encode replaced
        private static String encoded(String text, Charset charset) {
            return new String(text.getBytes(charset), charset);
        }

        @Override
        public void close() {
            if (closed) {
                return;
            }
            closed = true;
            out.flush();
            err.flush();
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }
}

package org.openl.itest;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.TreeSet;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import org.openl.itest.core.JettyServer;

class WebStudioTest {

    // V7: generator of the runtime credentials; alphanumeric values are embedded in JSON bodies without escaping
    // The helpers stay private to this runner: each suite generates its own credentials, with no shared helper file
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final int PASSWORD_LENGTH = 16;
    private static final String BASIC_PREFIX = "Basic ";

    @Test
    void multi() throws Exception {
        // V7: the users the fixtures create get policy-compliant passwords generated per run, never literals
        var secrets = new LinkedHashMap<String, String>();
        putUser(secrets, "EPBDS_12683");
        putUser(secrets, "EPBDS_12973");
        putUser(secrets, "EPBDS_12973_2");
        putUser(secrets, "EPBDS_12973_3");
        // Every EPBDS-12819 request is rejected for its user name, so it only needs a compliant password
        secrets.put("EPBDS_12819_PASSWORD", password());
        var adminAuth = adminAuthorization();

        // V7: the suite runs with the runtime credentials, then the saved responses are scanned for them
        Throwable failure = null;
        try (var client = JettyServer.get().start()) {
            client.localEnv.put("ADMIN_AUTH_TOCKEN", adminAuth);
            client.localEnv.putAll(secrets);
            client.test("test-resources");
        } catch (Throwable e) {
            // V7: every failure, an Error included, is recorded so that a scan error cannot replace it
            failure = e;
            throw e;
        } finally {
            assertNotSaved(secrets, failure);
        }
    }

    // V7: puts <user>_PASSWORD, a generated password, and <user>_BASIC, its HTTP Basic header value
    private static void putUser(Map<String, String> env, String user) {
        var password = password();
        env.put(user + "_PASSWORD", password);
        env.put(user + "_BASIC", basic(user, password));
    }

    // V7: a random alphanumeric password that the local password policy accepts
    private static String password() {
        var builder = new StringBuilder(PASSWORD_LENGTH);
        for (int i = 0; i < PASSWORD_LENGTH; i++) {
            builder.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return builder.toString();
    }

    // V7: HTTP Basic header value, UTF-8 encoded as Spring's BasicAuthenticationFilter decodes it
    private static String basic(String user, String password) {
        return BASIC_PREFIX + Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    // V7: the administrator header is derived from the configured administrator instead of a literal
    private static String adminAuthorization() throws IOException {
        var path = Path.of("openl-repository", "application.properties");
        var properties = new Properties();
        try (var reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        var name = properties.getProperty("security.administrators", "").split(",", -1)[0].trim();
        if (name.isEmpty()) {
            throw new IllegalStateException("security.administrators is not set in " + path);
        }
        // AdminUsers seeds each configured administrator with its user name as the password
        return basic(name, name);
    }

    // V7: fails, naming the variables only, when a generated credential reached a saved mismatching response.
    // A scan error is suppressed onto the suite failure, and thrown only when the suite itself passed.
    private static void assertNotSaved(Map<String, String> secrets, @Nullable Throwable failure) throws IOException {
        var root = Path.of(System.getProperty("server.responses", "target/responses"));
        if (!Files.exists(root)) {
            return;
        }
        var names = new TreeSet<String>();
        IOException readError = null;
        try (var walk = Files.walk(root)) {
            for (var file : walk.filter(Files::isRegularFile).toList()) {
                // ISO-8859-1 maps every byte to one character, so any saved body can be searched
                var content = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1);
                for (var entry : secrets.entrySet()) {
                    var value = entry.getValue();
                    var encoded = value.startsWith(BASIC_PREFIX) ? value.substring(BASIC_PREFIX.length()) : value;
                    if (content.contains(value) || content.contains(encoded)) {
                        names.add(entry.getKey());
                    }
                }
            }
        } catch (UncheckedIOException e) {
            // The directory stream reports a failed traversal step unchecked
            readError = e.getCause();
        } catch (IOException e) {
            readError = e;
        }
        if (readError != null) {
            if (failure == null) {
                throw readError;
            }
            failure.addSuppressed(readError);
            return;
        }
        if (!names.isEmpty()) {
            var error = new AssertionError("Generated credentials found under " + root + ": " + names);
            if (failure == null) {
                throw error;
            }
            failure.addSuppressed(error);
        }
    }
}

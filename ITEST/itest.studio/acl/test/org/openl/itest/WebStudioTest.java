package org.openl.itest;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.TreeSet;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import org.openl.itest.core.HttpClient;
import org.openl.itest.core.JettyServer;

class WebStudioTest {

    // V7: the local users the acl fixtures create; each gets a generated password that meets the policy
    private static final String[] USERS = {"EPBDS_14474", "EPBDS_14584", "EPBDS_14670", "jsmith", "jdoe",
            "jane.doe", "EPBDS_16253"};
    private static final String ADMIN_ENV = "ADMIN_AUTH_TOCKEN";
    private static final String BASIC_PREFIX = "Basic ";
    private static final String PASSWORD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final int PASSWORD_LENGTH = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    void acl() throws Exception {
        // V7: start the server directly so the generated credentials reach localEnv
        var env = new HashMap<String, String>();
        Throwable failure = null;
        try (var client = JettyServer.get().start()) {
            putCredentials(client);
            env.putAll(client.localEnv);
            client.test("test-resources");
        } catch (Throwable e) {
            failure = e;
            throw e;
        } finally {
            assertNoSecretSaved(env, failure);
        }
    }

    // V7: runtime credentials for the ${…} placeholders of the acl fixtures
    static void putCredentials(HttpClient client) throws IOException {
        // Studio seeds each configured administrator with its user name as the password.
        var admin = administrator();
        client.localEnv.put(ADMIN_ENV, basic(admin, admin));
        for (var user : USERS) {
            var key = user.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]", "_");
            var password = generatePassword();
            client.localEnv.put(key + "_PASSWORD", password);
            client.localEnv.put(key + "_BASIC", basic(user, password));
        }
    }

    // V7: fail if a generated credential was saved with a mismatching response body
    static void assertNoSecretSaved(Map<String, String> env, @Nullable Throwable failure) throws IOException {
        var root = Path.of(System.getProperty("server.responses", "target/responses"));
        if (env.isEmpty() || !Files.isDirectory(root)) {
            return;
        }
        var leaked = new TreeSet<String>();
        IOException readError = null;
        try (var walk = Files.walk(root)) {
            for (var file : walk.filter(Files::isRegularFile).toList()) {
                var content = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1);
                for (var entry : env.entrySet()) {
                    var secret = secretOf(entry.getKey(), entry.getValue());
                    if (secret != null && content.contains(secret)) {
                        leaked.add(entry.getKey());
                    }
                }
            }
        } catch (UncheckedIOException e) {
            // The directory stream reports a failed traversal step unchecked.
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
        if (!leaked.isEmpty()) {
            // Names only: neither a value nor the content of a saved response is reported.
            var error = new AssertionError("Generated credentials were saved in the server responses: " + leaked);
            if (failure == null) {
                throw error;
            }
            failure.addSuppressed(error);
        }
    }

    /** The secret part of a generated variable, or {@code null} for a variable that holds none. */
    private static @Nullable String secretOf(String key, String value) {
        if (ADMIN_ENV.equals(key) || value == null || value.isEmpty()) {
            return null;
        }
        if (key.endsWith("_BASIC")) {
            var encoded = value.startsWith(BASIC_PREFIX) ? value.substring(BASIC_PREFIX.length()) : value;
            return encoded.isEmpty() ? null : encoded;
        }
        return key.endsWith("_PASSWORD") ? value : null;
    }

    /** The first administrator configured in the suite's {@code openl-repository/application.properties}. */
    private static String administrator() throws IOException {
        var path = Path.of("openl-repository", "application.properties");
        var properties = new Properties();
        try (var reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        var administrators = properties.getProperty("security.administrators");
        var admin = administrators == null ? "" : administrators.split(",", 2)[0].trim();
        if (admin.isEmpty()) {
            throw new IllegalStateException(
                    "security.administrators is not set in openl-repository/application.properties");
        }
        return admin;
    }

    private static String generatePassword() {
        var password = new StringBuilder(PASSWORD_LENGTH);
        for (int i = 0; i < PASSWORD_LENGTH; i++) {
            password.append(PASSWORD_ALPHABET.charAt(RANDOM.nextInt(PASSWORD_ALPHABET.length())));
        }
        return password.toString();
    }

    private static String basic(String user, String password) {
        return BASIC_PREFIX + Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }
}

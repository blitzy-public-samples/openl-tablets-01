package org.openl.itest;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import org.openl.itest.core.HttpClient;
import org.openl.itest.core.JettyServer;

class WebStudioTest {

    // V1: generator for runtime test credentials; alphanumeric so fixtures can embed the values unescaped
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    @Test
    void repos() throws Exception {
        // V1: runtime credentials, then a scan of saved responses for generated secrets
        Map<String, String> generated = new HashMap<>();
        Throwable failure = null;
        try (var client = JettyServer.get().start()) {
            putAdminCredentials(client);
            putPasswordPolicyValues(client, generated); // V7: generated local-user passwords
            putLockoutValues(client, generated); // V9: generated lockout-scenario credentials
            client.test("test-resources");
        } catch (Throwable t) {
            failure = t;
            throw t;
        } finally {
            try {
                assertNoSecretsSaved(generated);
            } catch (AssertionError scan) {
                if (failure != null) {
                    failure.addSuppressed(scan);
                } else {
                    throw scan;
                }
            }
        }
    }

    // V1: the administrator header, derived from the configured administrator instead of a literal in itest.env
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
        // More than 25 code points, so the former 25-character maximum rejects this accepted value.
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

    // V1: fails, naming only the keys, when a generated secret appears in a saved mismatching response
    static void assertNoSecretsSaved(Map<String, String> generated) {
        Path dir = Path.of(System.getProperty("server.responses", "target/responses"));
        if (!Files.exists(dir) || generated.isEmpty()) {
            return;
        }
        Set<String> names = new TreeSet<>();
        List<Path> files;
        try (Stream<Path> walk = Files.walk(dir)) {
            files = walk.filter(Files::isRegularFile).toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        for (Path file : files) {
            String content;
            try {
                content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
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

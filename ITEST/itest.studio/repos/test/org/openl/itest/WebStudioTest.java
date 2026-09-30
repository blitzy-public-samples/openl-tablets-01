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

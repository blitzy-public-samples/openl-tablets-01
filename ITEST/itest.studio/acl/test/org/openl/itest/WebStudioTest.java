package org.openl.itest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.Charset;
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
        // V7: copy both console streams while the server runs, so its output is searched for the credentials too
        var capture = ConsoleCapture.start();
        try (var client = JettyServer.get().start()) {
            putCredentials(client);
            env.putAll(client.localEnv);
            client.test("test-resources");
        } catch (Throwable e) {
            failure = e;
            throw e;
        } finally {
            // V7: the server has stopped here, so the capture is complete when it is restored and searched
            assertNoSecretLeaked(env, capture, failure);
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

    // V7: restore the console, then search the captured output and the saved responses for the credentials
    static void assertNoSecretLeaked(Map<String, String> env, ConsoleCapture capture, @Nullable Throwable failure)
            throws IOException {
        capture.close();
        try {
            assertNoSecretPrinted(env, capture, failure);
        } catch (AssertionError printed) {
            // Thrown only without a primary failure, so the saved-response result is attached to it.
            assertNoSecretSaved(env, printed);
            throw printed;
        }
        assertNoSecretSaved(env, failure);
    }

    // V7: fail if a generated credential reached System.out or System.err while the capture was installed
    static void assertNoSecretPrinted(Map<String, String> env, ConsoleCapture capture, @Nullable Throwable failure) {
        var out = capture.out();
        var err = capture.err();
        var leaked = new TreeSet<String>();
        for (var entry : env.entrySet()) {
            var secret = secretOf(entry.getKey(), entry.getValue());
            if (secret != null && (out.contains(secret) || err.contains(secret))) {
                leaked.add(entry.getKey());
            }
        }
        if (!leaked.isEmpty()) {
            // Names only: neither a value nor the captured output is reported.
            var error = new AssertionError("Generated credentials were printed to the console: " + leaked);
            if (failure == null) {
                throw error;
            }
            failure.addSuppressed(error);
        }
    }

    /**
     * The secret part of a generated or derived credential variable, or {@code null} for a variable that holds none.
     * Basic header values, the administrator's included, are reduced to their Base64 credential.
     */
    private static @Nullable String secretOf(String key, String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        // V7: the derived administrator header is scanned too, by its Base64 part; its bare user name is not a secret
        if (ADMIN_ENV.equals(key) || key.endsWith("_BASIC")) {
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

    // V7: a tee rather than a redirect, so the harness output stays on the console while a copy is kept to search
    static final class ConsoleCapture implements AutoCloseable {
        private final PrintStream originalOut = System.out;
        private final PrintStream originalErr = System.err;
        private final ByteArrayOutputStream copyOut = new ByteArrayOutputStream();
        private final ByteArrayOutputStream copyErr = new ByteArrayOutputStream();
        private final PrintStream teeOut = tee(originalOut, copyOut);
        private final PrintStream teeErr = tee(originalErr, copyErr);
        private boolean closed;

        private ConsoleCapture() {
        }

        /** Puts copying streams in place of the current {@code System.out} and {@code System.err}. */
        static ConsoleCapture start() {
            var capture = new ConsoleCapture();
            System.setOut(capture.teeOut);
            System.setErr(capture.teeErr);
            return capture;
        }

        /** What was written to {@code System.out} while the capture was installed. */
        Captured out() {
            return new Captured(copyOut.toString(originalOut.charset()), originalOut.charset());
        }

        /** What was written to {@code System.err} while the capture was installed. */
        Captured err() {
            return new Captured(copyErr.toString(originalErr.charset()), originalErr.charset());
        }

        /** Flushes the copying streams and puts the original ones back; a later call does nothing. */
        @Override
        public void close() {
            if (closed) {
                return;
            }
            closed = true;
            teeOut.flush();
            teeErr.flush();
            System.setOut(originalOut);
            System.setErr(originalErr);
        }

        /** A stream that encodes as {@code console} does and writes every byte both to it and to {@code copy}. */
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

        /** Text copied from one console stream, decoded with the charset that stream encodes with. */
        record Captured(String text, Charset charset) {

            /** Whether the text holds {@code needle} as the stream encoded it, an unmappable character included. */
            boolean contains(String needle) {
                return text.contains(new String(needle.getBytes(charset), charset));
            }
        }
    }
}

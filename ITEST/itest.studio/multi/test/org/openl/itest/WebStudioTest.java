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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
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
        // V7: the scan also covers the derived administrator header, matched by its value and its Base64 part
        var scanned = new LinkedHashMap<String, String>(secrets);
        scanned.put("ADMIN_AUTH_TOCKEN", adminAuth);

        // V7: the suite runs with the runtime credentials while both console streams are copied for the scan
        // The capture is the first resource, so it is restored only after the server has stopped; then the copied
        // output and the saved responses are scanned for the credentials.
        var console = new ConsoleCapture();
        try (console; var client = JettyServer.get().start()) {
            client.localEnv.put("ADMIN_AUTH_TOCKEN", adminAuth);
            client.localEnv.putAll(secrets);
            client.test("test-resources");
        } catch (Throwable e) {
            // V7: every failure, an Error included, stays the reported one: each scan failure is attached to it
            try {
                assertNotLeaked(console, scanned, e);
            } catch (IOException | RuntimeException scan) {
                e.addSuppressed(scan);
            }
            throw e;
        }
        assertNotLeaked(console, scanned, null); // V7: the suite passed, so a scan failure is the reported one
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

    // V7: the administrator header is derived at runtime from the first configured administrator
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

    // V7: fails, naming the variables only, when a generated credential reached the console copy or a saved response
    // Given a suite failure, both scans attach their failures to it; otherwise a console finding is thrown with the
    // saved-response scan's failure attached.
    private static void assertNotLeaked(ConsoleCapture console, Map<String, String> secrets,
            @Nullable Throwable failure) throws IOException {
        var names = console.printed(secrets);
        if (names.isEmpty()) {
            assertNotSaved(secrets, failure);
            return;
        }
        var printed = new AssertionError("Generated credentials found in the console output: " + names);
        if (failure != null) {
            failure.addSuppressed(printed);
            assertNotSaved(secrets, failure);
            return;
        }
        try {
            assertNotSaved(secrets, printed);
        } catch (IOException | RuntimeException e) {
            printed.addSuppressed(e);
        }
        throw printed;
    }

    // V7: fails, naming the variables only, when a generated credential reached a saved mismatching response.
    // A scan error is suppressed onto the given failure, the suite's or the console scan's, and thrown only without
    // one.
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

    // V7: while open, tees System.out and System.err to the console and keeps a copy of both for the credential scan
    // The harness progress and a mismatching response are therefore still shown. Closing restores both streams; a
    // second close does nothing.
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

        // V7: writes every byte to the console stream and to the copy, encoding characters as the console does
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

        // V7: the text System.out received while open, decoded with the charset of the console stream
        String out() {
            return outCopy.toString(originalOut.charset());
        }

        // V7: the text System.err received while open, decoded with the charset of the console stream
        String err() {
            return errCopy.toString(originalErr.charset());
        }

        // V7: the sorted variables whose value, or the Base64 part of a Basic value, either stream received
        // Each is searched for as that stream's charset encodes it
        Set<String> printed(Map<String, String> secrets) {
            var outText = out();
            var errText = err();
            var names = new TreeSet<String>();
            for (var entry : secrets.entrySet()) {
                var value = entry.getValue();
                var needle = value.startsWith(BASIC_PREFIX) ? value.substring(BASIC_PREFIX.length()) : value;
                if (!needle.isEmpty() && (outText.contains(encoded(needle, originalOut.charset()))
                        || errText.contains(encoded(needle, originalErr.charset())))) {
                    names.add(entry.getKey());
                }
            }
            return names;
        }

        // V7: the text as a stream of this charset gives it back, characters it cannot encode replaced
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

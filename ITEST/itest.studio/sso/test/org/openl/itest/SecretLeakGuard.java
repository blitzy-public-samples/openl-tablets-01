package org.openl.itest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * V3: the secret-leak proof of the Keycloak SSO suite. It keeps, by kind, every credential the suite generates and
 * every credential the IdP or Studio issues to a test class, and fails a test whose output contains one of them and
 * a test class whose saved responses do. Either also fails on a Studio session cookie printed with its value, as
 * {@code JSESSIONID=<value>}, because the ITEST harness client keeps its sessions to itself.
 *
 * <p>During each test, {@code System.out} and {@code System.err} are teed: the console still receives everything,
 * and a copy is scanned after the test, once its Studio server and containers have stopped, whether the test passed
 * or failed. JUnit adds that failure to a failed test as a suppressed exception, so the primary failure is kept. A
 * test that takes the streams over with JUnit Pioneer {@code @StdIo} hands its captures to {@link #scanAlso}.
 *
 * <p>Every failure message names only kinds of secret, the test and relative paths; never a value or the text
 * around it.
 */
final class SecretLeakGuard implements BeforeAllCallback, BeforeEachCallback, AfterEachCallback {

    private static final String STUDIO_SESSION_ID = "Studio session ID";
    // A Studio session cookie printed with its value, as the ITEST harness prints the Set-Cookie header of every
    // response that does not match its fixture. The harness keeps those sessions to itself, so they are found by
    // their form, not by their value. The cookie name must not be the tail of another one, such as the fixtures'
    // NO_JSESSIONID, and an empty value or the fixtures' *** mask is no session.
    private static final Pattern STUDIO_SESSION_COOKIE = Pattern.compile(
            "(?<![\\w!#$%&'*+.^`|~-])JSESSIONID=(?!\\*\\*\\*(?![^\\s;,\"']))[^\\s;,\"']",
            Pattern.CASE_INSENSITIVE);

    // value -> kind of the credentials generated once per JVM, scanned for in every test class
    private final Map<String, String> retained = new LinkedHashMap<>();
    // value -> kind of the credentials issued while the current test class runs
    private final Map<String, String> issued = new LinkedHashMap<>();
    private @Nullable Capture capture;

    /**
     * Keeps {@code values} under {@code kind} for every test class of this JVM. Blank values are ignored.
     *
     * @return this guard
     */
    synchronized SecretLeakGuard retain(String kind, Collection<String> values) {
        for (String value : values) {
            keep(retained, kind, value);
        }
        return this;
    }

    /**
     * Keeps a credential issued to the current test class under {@code kind}. A {@code null} or blank value is
     * ignored, and a value kept already keeps its first kind.
     */
    synchronized void register(String kind, @Nullable String value) {
        if (value != null && !retained.containsKey(value)) {
            keep(issued, kind, value);
        }
    }

    /**
     * Returns a snapshot of every credential kept, mapped to its kind.
     */
    synchronized Map<String, String> secrets() {
        Map<String, String> secrets = new LinkedHashMap<>(retained);
        issued.forEach(secrets::putIfAbsent);
        return secrets;
    }

    /**
     * Forgets the credentials issued to the previous test class; the generated ones stay.
     */
    synchronized void resetIssued() {
        issued.clear();
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        resetIssued();
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        startCapture();
    }

    @Override
    public void afterEach(ExtensionContext context) {
        finishCapture(context.getRequiredTestClass().getSimpleName() + "." + context.getRequiredTestMethod().getName());
    }

    /**
     * Replaces {@code System.out} and {@code System.err} with tees that copy everything written to them.
     *
     * @throws IllegalStateException if a capture is already active
     */
    synchronized void startCapture() {
        if (capture != null) {
            throw new IllegalStateException("The output of a previous test is still being captured");
        }
        var started = new Capture(System.out, System.err);
        capture = started;
        System.setOut(started.teeOut);
        System.setErr(started.teeErr);
    }

    /**
     * Adds text captured outside the tees, such as JUnit Pioneer {@code StdOut} or {@code StdErr}, to the scan run
     * when the current test finishes. The supplier is read only then.
     *
     * @throws IllegalStateException if no capture is active
     */
    synchronized void scanAlso(Supplier<String> captured) {
        var current = capture;
        if (current == null) {
            throw new IllegalStateException("No test output is being captured");
        }
        current.handedOver.add(captured);
    }

    /**
     * Restores the streams that were in place when the capture started, then scans everything captured for every
     * credential kept and for a Studio session cookie printed with its value. Does nothing if no capture is active.
     *
     * @param test the test name used in the failure message
     * @throws AssertionError naming the kinds found, if any captured text contains a credential
     */
    void finishCapture(String test) {
        Capture current;
        synchronized (this) {
            current = capture;
            capture = null;
        }
        if (current == null) {
            return;
        }
        System.setOut(current.originalOut);
        System.setErr(current.originalErr);
        var secrets = secrets();
        Set<String> kinds = new TreeSet<>();
        kinds.addAll(kindsIn(current.out.toString(current.originalOut.charset()), secrets));
        kinds.addAll(kindsIn(current.err.toString(current.originalErr.charset()), secrets));
        for (Supplier<String> handedOver : current.handedOver) {
            kinds.addAll(kindsIn(handedOver.get(), secrets));
        }
        if (!kinds.isEmpty()) {
            throw new AssertionError("Generated or issued secrets found in the output captured during " + test + ": "
                    + kinds);
        }
    }

    /**
     * Scans every regular file under {@code dir}, where the ITEST harness saves the body of each response that did
     * not match its fixture, for every credential kept and for a Studio session cookie written with its value. A
     * missing directory holds nothing to scan.
     *
     * @throws AssertionError naming each kind found with the file's path relative to {@code dir}, or if a file
     *                        cannot be listed or read
     */
    void assertNoSecretsSaved(Path dir) {
        var secrets = secrets();
        if (!Files.isDirectory(dir)) {
            return;
        }
        List<Path> files;
        try (Stream<Path> walk = Files.walk(dir)) {
            files = walk.filter(Files::isRegularFile).sorted().toList();
        } catch (IOException | UncheckedIOException e) {
            // The directory stream reports a failed traversal step unchecked.
            throw new AssertionError("Cannot list the saved responses under " + dir, e);
        }
        Set<String> found = new TreeSet<>();
        for (Path file : files) {
            String content;
            try {
                content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new AssertionError("Cannot read the saved response " + dir.relativize(file), e);
            }
            for (String kind : kindsIn(content, secrets)) {
                found.add(kind + " in " + dir.relativize(file));
            }
        }
        if (!found.isEmpty()) {
            throw new AssertionError("Generated or issued secrets found in the saved responses under " + dir + ": "
                    + found);
        }
    }

    // the kinds of the secrets that occur in text, and of a Studio session cookie printed with its value
    private static Set<String> kindsIn(String text, Map<String, String> secrets) {
        Set<String> kinds = new TreeSet<>();
        for (Map.Entry<String, String> secret : secrets.entrySet()) {
            if (text.contains(secret.getKey())) {
                kinds.add(secret.getValue());
            }
        }
        if (STUDIO_SESSION_COOKIE.matcher(text).find()) {
            kinds.add(STUDIO_SESSION_ID);
        }
        return kinds;
    }

    private static void keep(Map<String, String> secrets, String kind, String value) {
        if (!value.isBlank()) {
            secrets.putIfAbsent(value, kind);
        }
    }

    // the streams a capture replaced, its tees and their copies, and the captures handed over by the test
    private static final class Capture {

        private final PrintStream originalOut;
        private final PrintStream originalErr;
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private final ByteArrayOutputStream err = new ByteArrayOutputStream();
        private final PrintStream teeOut;
        private final PrintStream teeErr;
        private final List<Supplier<String>> handedOver = new ArrayList<>();

        Capture(PrintStream originalOut, PrintStream originalErr) {
            this.originalOut = originalOut;
            this.originalErr = originalErr;
            this.teeOut = new PrintStream(new Tee(originalOut, out), true, originalOut.charset());
            this.teeErr = new PrintStream(new Tee(originalErr, err), true, originalErr.charset());
        }
    }

    // writes every byte to the console stream and to its copy; closing it closes neither
    private static final class Tee extends OutputStream {

        private final PrintStream console;
        private final ByteArrayOutputStream copy;

        Tee(PrintStream console, ByteArrayOutputStream copy) {
            this.console = console;
            this.copy = copy;
        }

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
    }
}

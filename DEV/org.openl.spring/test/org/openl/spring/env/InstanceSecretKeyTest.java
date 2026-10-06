package org.openl.spring.env;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.channels.ClosedByInterruptException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;

/**
 * Tests of {@link InstanceSecretKey}, the key file that encrypts secret settings when {@code secret.key} is blank
 * (V6).
 *
 * <p>Every key is generated at run time. Keys are compared through {@link #assertSameKey} and
 * {@link #assertNoKey}, which fail with a fixed message, so a failing assertion never prints a key into the test
 * report.
 */
class InstanceSecretKeyTest {

    private static final int KEY_BYTES = 32;
    private static final int KEY_TEXT_LENGTH = 44;
    private static final String BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * The threads that race for one key file in a round, and the rounds, each on a fresh directory.
     */
    private static final int CALLERS = 8;
    private static final int ROUNDS = 50;
    /**
     * The copies of {@link InstanceSecretKey}, each in its own class loader, that race the class of this test.
     */
    private static final int COPIES = 3;
    private static final long TIMEOUT_SECONDS = 30;
    /**
     * How long a key file stays empty before its writer completes it: well within the wait of a reader.
     */
    private static final Duration WRITE_DELAY = Duration.ofMillis(100);
    /**
     * Text that imitates a log record, which a hostile directory name places after a line break.
     */
    private static final String FORGED_RECORD = "2026-10-06 10:53:42,902 INFO OpenL.config - forged record";

    @BeforeAll
    static void initLog() {
        // ConfigLog prints the OpenL info block from its static initializer. Loading it here keeps that block out of
        // the output a test captures.
        ConfigLog.LOG.isDebugEnabled();
    }

    @Test
    void createsKeyAndMissingParentDirectories(@TempDir Path dir) throws IOException {
        Path directory = dir.resolve("missing/parent");

        String key = requireKey(InstanceSecretKey.get(directory, true));

        Path file = directory.resolve(InstanceSecretKey.FILE_NAME);
        assertTrue(Files.isRegularFile(file), "The key file must be created together with its missing parents");
        assertEquals(KEY_BYTES, Base64.getDecoder().decode(key).length);
        assertSameKey(Files.readString(file).trim(), key, "The returned key must be the content of the key file");
    }

    @Test
    void reusesExistingKey(@TempDir Path dir) throws IOException {
        String first = requireKey(InstanceSecretKey.get(dir, true));
        Path file = dir.resolve(InstanceSecretKey.FILE_NAME);
        byte[] written = Files.readAllBytes(file);

        String second = InstanceSecretKey.get(dir, true);
        String readOnly = InstanceSecretKey.get(dir, false);

        assertSameKey(first, second, "A second get(dir, true) must return the existing key");
        assertSameKey(first, readOnly, "get(dir, false) must return the existing key");
        assertTrue(Arrays.equals(written, Files.readAllBytes(file)), "An existing key file must not be rewritten");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void createsFileReadableByOwnerOnly(@TempDir Path dir) throws IOException {
        requireKey(InstanceSecretKey.get(dir, true));

        Path file = dir.resolve(InstanceSecretKey.FILE_NAME);
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(file));
    }

    @Test
    void neverOverwritesExistingFile(@TempDir Path dir) throws IOException {
        String existing = generatedKey();
        // A trailing line break, as a key file written by hand usually ends, is not part of the key.
        Path file = Files.writeString(dir.resolve(InstanceSecretKey.FILE_NAME), existing + "\n");
        byte[] before = Files.readAllBytes(file);

        String key = InstanceSecretKey.get(dir, true);

        assertSameKey(existing, key, "The key of an existing file must be returned as it is");
        assertTrue(Arrays.equals(before, Files.readAllBytes(file)), "An existing key file must never be overwritten");
    }

    @Test
    void returnsNullWithoutCreation(@TempDir Path dir) throws IOException {
        assertNoKey(InstanceSecretKey.get(dir, false), "An absent key must be reported as null");
        assertFalse(Files.exists(dir.resolve(InstanceSecretKey.FILE_NAME)), "No key file may be created");

        Path missing = dir.resolve("missing");
        assertNoKey(InstanceSecretKey.get(missing, false), "An absent directory must be reported as no key");
        assertFalse(Files.exists(missing), "No directory may be created without create");
    }

    @Test
    void rejectsBlankFile(@TempDir Path dir) throws IOException {
        String content = "  \n";
        Path file = Files.writeString(dir.resolve(InstanceSecretKey.FILE_NAME), content);
        byte[] before = Files.readAllBytes(file);

        long checked = System.nanoTime();
        IOException e = assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, true, checked));
        // Checked again under the lock, the unchanged file fails from memory; a read-only lookup fails without a check.
        assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, true, checked));
        assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, false, checked));

        String message = e.getMessage();
        assertNotNull(message, "The failure must name the key file");
        assertNotEquals(content, message);
        assertFalse(message.contains(content), "The failure must not quote the file content");
        assertTrue(message.contains(InstanceSecretKey.FILE_NAME), "The failure must name the key file");
        assertTrue(Arrays.equals(before, Files.readAllBytes(file)), "A blank key file must not be replaced");
    }

    @Test
    void noticesDeletedFile(@TempDir Path dir) throws IOException {
        String key = requireKey(InstanceSecretKey.get(dir, true));
        Path file = dir.resolve(InstanceSecretKey.FILE_NAME);

        Files.delete(file);

        assertNoKey(InstanceSecretKey.get(dir, false, afterRecheckInterval()),
                "A deleted key file must count as absent, whatever is cached");
        assertFalse(Files.exists(file), "Reading must not recreate the key file");
        String recreated = requireKey(InstanceSecretKey.get(dir, true));
        assertFalse(key.equals(recreated), "A deleted key must be replaced by a new key, not by the cached one");
    }

    @Test
    void readsReplacedFileAgain(@TempDir Path dir) throws IOException {
        String original = requireKey(InstanceSecretKey.get(dir, true));
        Path file = dir.resolve(InstanceSecretKey.FILE_NAME);
        FileTime created = Files.getLastModifiedTime(file);
        String replacement = generatedKey();

        Files.writeString(file, replacement);
        // A later timestamp makes the replacement visible even where the file system's timestamps are coarse.
        Files.setLastModifiedTime(file, FileTime.fromMillis(created.toMillis() + 60_000));

        String key = InstanceSecretKey.get(dir, false, afterRecheckInterval());
        assertSameKey(replacement, key, "A replaced key file must be read again");
        assertFalse(original.equals(key), "The cached key of the replaced file must not be returned");
    }

    @ParameterizedTest(name = "create = {0}")
    @ValueSource(booleans = {false, true})
    void readsAtomicReplacementWithSameTimeAndSize(boolean create, @TempDir Path dir) throws IOException {
        long checked = System.nanoTime();
        String original = requireKey(InstanceSecretKey.get(dir, true, checked));
        Path file = dir.resolve(InstanceSecretKey.FILE_NAME);
        BasicFileAttributes before = Files.readAttributes(file, BasicFileAttributes.class);
        String replacement = generatedKey();

        // A key written beside the file, given the file's modification time and moved over it, as a restore does.
        Path staged = Files.writeString(dir.resolve("replacement-key"), replacement);
        Files.setLastModifiedTime(staged, before.lastModifiedTime());
        Files.move(staged, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        assertSameTimeAndSize(before, file);

        assertSameKey(original, InstanceSecretKey.get(dir, false, checked),
                "A read within the recheck interval must be served from memory");
        // A lookup that may create checks the file at once; a read-only one once the recheck interval has passed.
        long due = create ? checked : checked + InstanceSecretKey.RECHECK_INTERVAL_NANOS;
        String key = InstanceSecretKey.get(dir, create, due);
        assertSameKey(replacement, key, "A key file replaced with the same time and size must be read again");
        assertFalse(original.equals(key), "The cached key of the replaced file must not be returned");
        assertSameKey(replacement, InstanceSecretKey.get(dir, true), "A save must use the key that is in the file");
        assertTrue(Arrays.equals(ascii(replacement), Files.readAllBytes(file)),
                "A replaced key file must not be overwritten");
    }

    @ParameterizedTest(name = "create = {0}")
    @ValueSource(booleans = {false, true})
    void readsInPlaceRewriteWithSameTimeAndSize(boolean create, @TempDir Path dir) throws IOException {
        long checked = System.nanoTime();
        String original = requireKey(InstanceSecretKey.get(dir, true, checked));
        Path file = dir.resolve(InstanceSecretKey.FILE_NAME);
        BasicFileAttributes before = Files.readAttributes(file, BasicFileAttributes.class);
        String replacement = generatedKey();

        // The same file, rewritten and given back its modification time: no attribute tells the contents apart.
        Files.writeString(file, replacement);
        Files.setLastModifiedTime(file, before.lastModifiedTime());
        BasicFileAttributes after = assertSameTimeAndSize(before, file);
        assertEquals(before.fileKey(), after.fileKey(), "A file rewritten in place must keep its file key");

        // A lookup that may create checks the file at once; a read-only one once the recheck interval has passed.
        long due = create ? checked : checked + InstanceSecretKey.RECHECK_INTERVAL_NANOS;
        String key = InstanceSecretKey.get(dir, create, due);
        assertSameKey(replacement, key, "A key file rewritten with the same time and size must be read again");
        assertFalse(original.equals(key), "The cached key of the rewritten file must not be returned");
        assertTrue(Arrays.equals(ascii(replacement), Files.readAllBytes(file)),
                "A rewritten key file must not be overwritten");
    }

    @Test
    void rejectsInPlaceRewriteWithoutKey(@TempDir Path dir) throws IOException {
        requireKey(InstanceSecretKey.get(dir, true));
        Path file = dir.resolve(InstanceSecretKey.FILE_NAME);
        BasicFileAttributes before = Files.readAttributes(file, BasicFileAttributes.class);
        String invalid = "*" + generatedKey().substring(1);

        Files.writeString(file, invalid);
        Files.setLastModifiedTime(file, before.lastModifiedTime());
        assertSameTimeAndSize(before, file);

        // The remembered key is no longer in the file, so a save must not encrypt with it.
        IOException e = assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, true));
        assertNamesFileOnly(e, invalid);
        assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, false, afterRecheckInterval()));
        assertTrue(Arrays.equals(ascii(invalid), Files.readAllBytes(file)),
                "A file without a valid key must not be replaced");
    }

    @Test
    void unchangedFileWithoutKeyIsNotWaitedForAgain(@TempDir Path dir) throws IOException {
        String unfinished = generatedKey().substring(0, KEY_TEXT_LENGTH - 1);
        Path file = Files.writeString(dir.resolve(InstanceSecretKey.FILE_NAME), unfinished);
        // The first check waits for the file to be completed, in vain.
        assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, false));

        // With the interrupt status set, a further wait fails with InterruptedIOException, so a plain failure proves
        // that the unchanged file was read without waiting for it again.
        Thread.currentThread().interrupt();
        try {
            IOException e = assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, true));
            assertFalse(e instanceof InterruptedIOException, "An unchanged file must not be waited for again");
            assertNamesFileOnly(e, unfinished);
            IOException later = assertThrows(IOException.class,
                    () -> InstanceSecretKey.get(dir, false, afterRecheckInterval()));
            assertFalse(later instanceof InterruptedIOException, "An unchanged file must not be waited for again");
            assertTrue(Thread.interrupted(), "The interrupt status must be kept");
        } finally {
            // Clear the status so that nothing after this test runs interrupted.
            Thread.interrupted();
        }

        assertSameKey(unfinished, Files.readString(file), "An unfinished key file must not be replaced");
    }

    @Test
    void createsKeyOnFileSystemWithoutPosixPermissions(@TempDir Path dir) throws IOException {
        try (FileSystem zip = FileSystems.newFileSystem(dir.resolve("shared.zip"), Map.of("create", "true"))) {
            assertFalse(zip.supportedFileAttributeViews().contains("posix"),
                    "The ZIP file system must not support POSIX permissions for this test");
            Path directory = zip.getPath("/shared");

            String key = requireKey(InstanceSecretKey.get(directory, true));

            Path file = directory.resolve(InstanceSecretKey.FILE_NAME);
            assertTrue(Files.isRegularFile(file), "The key file must be created without permission attributes");
            assertEquals(KEY_BYTES, Base64.getDecoder().decode(key).length);
            assertSameKey(Files.readString(file).trim(), key, "The returned key must be the content of the key file");
            assertSameKey(key, InstanceSecretKey.get(directory, false), "The created key must be read back");
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void neverWritesThroughLinkAtKeyPath(@TempDir Path dir) throws IOException {
        Path target = Files.createDirectories(dir.resolve("elsewhere")).resolve("stolen-key");
        Path link = Files.createSymbolicLink(dir.resolve(InstanceSecretKey.FILE_NAME), target);

        // The dangling link reads as absent, and the exclusive creation refuses to replace or follow it.
        assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, true));

        assertFalse(Files.exists(target, LinkOption.NOFOLLOW_LINKS), "A key must never be written through a link");
        assertTrue(Files.isSymbolicLink(link), "The link at the key path must be left as it is");
    }

    @Test
    void removesPartlyWrittenFile(@TempDir Path dir) throws IOException {
        Path file = dir.resolve(InstanceSecretKey.FILE_NAME);

        // With the interrupt status set, the file channel fails the write after the file has been created, which
        // is a real write failure of the key file.
        Thread.currentThread().interrupt();
        try {
            assertThrows(ClosedByInterruptException.class, () -> InstanceSecretKey.get(dir, true));
        } finally {
            // Clear the status so that nothing after this test runs interrupted.
            Thread.interrupted();
        }

        assertFalse(Files.exists(file, LinkOption.NOFOLLOW_LINKS), "A failed write must not leave a key file behind");
        String key = requireKey(InstanceSecretKey.get(dir, true));
        assertEquals(KEY_BYTES, Base64.getDecoder().decode(key).length);
    }

    @Test
    @StdIo
    void creationLogsPathNotKey(StdErr stdErr, @TempDir Path dir) throws IOException {
        int mark = stdErr.capturedString().length();

        String key = requireKey(InstanceSecretKey.get(dir, true));
        InstanceSecretKey.get(dir, true);
        InstanceSecretKey.get(dir, false);

        String keyFile = dir.resolve(InstanceSecretKey.FILE_NAME).toAbsolutePath().toString();
        long infoLines = stdErr.capturedString()
                .substring(mark)
                .lines()
                .filter(line -> line.contains("INFO") && line.contains(keyFile))
                .count();
        assertEquals(1, infoLines, "Creating the key must log one INFO line naming the key file");
        assertFalse(stdErr.capturedString().contains(key), "The key must never be logged");
    }

    @Test
    @StdIo
    @DisabledOnOs(OS.WINDOWS)
    void creationLogsControlCharactersOfPathEscaped(StdErr stdErr, @TempDir Path dir) throws IOException {
        // A POSIX directory name may hold every character but '/' and NUL, so also a line break and a forged record.
        Path directory = dir.resolve("shared\n" + FORGED_RECORD + "\rreturn\ttab\u001Bescape");

        assertCreationLoggedOnOneLine(stdErr,
                directory,
                dir.toAbsolutePath() + "/shared\\u000A" + FORGED_RECORD + "\\u000Dreturn\\u0009tab\\u001Bescape/"
                        + InstanceSecretKey.FILE_NAME);
    }

    @Test
    @StdIo
    void creationLogsLineSeparatorsOfPathEscaped(StdErr stdErr, @TempDir Path dir) throws IOException {
        // The ZIP file system stores names in UTF-8, whatever encoding the platform uses for file names.
        try (FileSystem zip = FileSystems.newFileSystem(dir.resolve("shared.zip"), Map.of("create", "true"))) {
            Path directory = zip.getPath("/shared\u2028" + FORGED_RECORD + "\u2029paragraph\u0085next-line");

            assertCreationLoggedOnOneLine(stdErr,
                    directory,
                    "/shared\\u2028" + FORGED_RECORD + "\\u2029paragraph\\u0085next-line/"
                            + InstanceSecretKey.FILE_NAME);
        }
    }

    @Test
    void concurrentCallersShareOneKey(@TempDir Path dir) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(CALLERS);
        try {
            for (int round = 0; round < ROUNDS; round++) {
                Path directory = dir.resolve("round-" + round);
                List<Callable<@Nullable String>> creators = new ArrayList<>();
                List<Callable<@Nullable String>> readers = new ArrayList<>();
                for (int i = 0; i < CALLERS; i++) {
                    creators.add(() -> InstanceSecretKey.get(directory, true));
                    // Past the recheck interval, every reader goes for the lock and the first one checks the file.
                    readers.add(() -> InstanceSecretKey.get(directory, false, afterRecheckInterval()));
                }

                String key = assertOneKey(directory, race(executor, creators));
                assertSameKey(key, assertOneKey(directory, race(executor, readers)),
                        "Concurrent readers must get the created key");
            }
        } finally {
            shutdown(executor);
        }
    }

    @Test
    void classLoadersRacingForTheKeyShareOneKey(@TempDir Path dir) throws Exception {
        // Each copy has its own class lock and memory, as the class has in another web application of the same JVM.
        List<Method> copies = new ArrayList<>();
        for (int i = 0; i < COPIES; i++) {
            ClassLoader loader = new CopyingClassLoader(InstanceSecretKeyTest.class.getClassLoader());
            Class<?> copy = Class.forName(InstanceSecretKey.class.getName(), true, loader);
            assertFalse(copy == InstanceSecretKey.class, "The class loader must define its own copy of the class");
            Method get = copy.getDeclaredMethod("get", Path.class, boolean.class);
            get.setAccessible(true);
            copies.add(get);
        }

        ExecutorService executor = Executors.newFixedThreadPool(CALLERS);
        try {
            for (int round = 0; round < ROUNDS; round++) {
                Path directory = dir.resolve("round-" + round);
                List<Callable<@Nullable String>> creators = new ArrayList<>();
                for (int i = 0; i < CALLERS; i++) {
                    // Half of the callers use the class of this test, the other half its copies.
                    if (i % 2 == 0) {
                        creators.add(() -> InstanceSecretKey.get(directory, true));
                    } else {
                        Method copy = copies.get(i / 2 % COPIES);
                        creators.add(() -> invoke(copy, directory));
                    }
                }

                assertOneKey(directory, race(executor, creators));
            }
        } finally {
            shutdown(executor);
        }
    }

    @ParameterizedTest(name = "create = {0}")
    @ValueSource(booleans = {false, true})
    void waitsForKeyBeingWritten(boolean create, @TempDir Path dir) throws Exception {
        // Another creator has created the file and has not written its key yet.
        Path file = Files.createFile(dir.resolve(InstanceSecretKey.FILE_NAME));
        String written = generatedKey();

        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<?> writer = executor.submit(() -> {
                Thread.sleep(WRITE_DELAY);
                Files.writeString(file, written);
                return null;
            });

            String key = InstanceSecretKey.get(dir, create);

            writer.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            assertSameKey(written, key, "A reader must wait for the key of a file still being written");
            assertTrue(Arrays.equals(written.getBytes(StandardCharsets.US_ASCII), Files.readAllBytes(file)),
                    "A key file still being written must not be rewritten");
        } finally {
            shutdown(executor);
        }
    }

    @Test
    void rejectsUnfinishedFileAfterBoundedWait(@TempDir Path dir) throws IOException {
        // The unpadded text of a key, which the JDK decoder reads as the same 32 bytes, is never completed.
        String unfinished = generatedKey().substring(0, KEY_TEXT_LENGTH - 1);
        assertEquals(KEY_BYTES, Base64.getDecoder().decode(unfinished).length);
        Path file = Files.writeString(dir.resolve(InstanceSecretKey.FILE_NAME), unfinished);

        long started = System.nanoTime();
        IOException e = assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, false));
        Duration waited = Duration.ofNanos(System.nanoTime() - started);

        assertTrue(waited.compareTo(Duration.ofMillis(500)) >= 0,
                "A file that may still be written must be given time to complete");
        assertNamesFileOnly(e, unfinished);
        assertSameKey(unfinished, Files.readString(file), "An unfinished key file must not be replaced");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("nonCanonicalKeys")
    void rejectsNonCanonicalKey(String kind, byte[] content, @TempDir Path dir) throws IOException {
        Path file = Files.write(dir.resolve(InstanceSecretKey.FILE_NAME), content);
        FileTime written = Files.getLastModifiedTime(file);

        IOException e = assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, true));
        assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, false));

        assertNamesFileOnly(e, new String(content, StandardCharsets.US_ASCII));
        assertTrue(Arrays.equals(content, Files.readAllBytes(file)), "A file without a valid key must not be replaced");

        // The rejected content was not remembered as a key: a valid key written over it is read.
        String replacement = generatedKey();
        Files.writeString(file, replacement);
        Files.setLastModifiedTime(file, FileTime.fromMillis(written.toMillis() + 60_000));
        assertSameKey(replacement, InstanceSecretKey.get(dir, true),
                "A valid key written over the rejected content must be read");
    }

    static Stream<Arguments> nonCanonicalKeys() {
        String key = generatedKey();
        // The last data character of a 32-byte key carries 2 unused low bits; the JDK decoder ignores them.
        char[] unusedBitsSet = key.toCharArray();
        int last = KEY_TEXT_LENGTH - 2;
        unusedBitsSet[last] = BASE64_ALPHABET.charAt(BASE64_ALPHABET.indexOf(unusedBitsSet[last]) ^ 0b11);
        String altered = new String(unusedBitsSet);
        assertTrue(Arrays.equals(Base64.getDecoder().decode(key), Base64.getDecoder().decode(altered)),
                "The altered text must decode to the bytes of the key");

        byte[] binary = new byte[KEY_TEXT_LENGTH + 4];
        RANDOM.nextBytes(binary);
        for (int i = 0; i < binary.length; i++) {
            binary[i] |= (byte) 0x80;
        }

        return Stream.of(Arguments.of("unused bits set", ascii(altered)),
                Arguments.of("31 bytes", ascii(encodedRandom(KEY_BYTES - 1))),
                Arguments.of("33 bytes", ascii(encodedRandom(KEY_BYTES + 1))),
                Arguments.of("non-Base64 character", ascii("*" + key.substring(1))),
                Arguments.of("binary", binary));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("oversizedFiles")
    void rejectsOversizedFileWithoutWaiting(String kind, byte[] content, @TempDir Path dir) throws IOException {
        Path file = Files.write(dir.resolve(InstanceSecretKey.FILE_NAME), content);

        // With the interrupt status set, a wait for the file to be completed fails with InterruptedIOException, so
        // a plain failure proves that the file was rejected without that wait.
        Thread.currentThread().interrupt();
        try {
            IOException e = assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, true));
            assertFalse(e instanceof InterruptedIOException, "An oversized file must not be waited for");
            assertNamesFileOnly(e, new String(content, StandardCharsets.US_ASCII));
            IOException later = assertThrows(IOException.class,
                    () -> InstanceSecretKey.get(dir, false, afterRecheckInterval()));
            assertFalse(later instanceof InterruptedIOException, "An oversized file must not be waited for");
            assertTrue(Thread.interrupted(), "The interrupt status must be kept");
        } finally {
            // Clear the status so that nothing after this test runs interrupted.
            Thread.interrupted();
        }

        assertTrue(Arrays.equals(content, Files.readAllBytes(file)), "An oversized key file must not be replaced");
    }

    static Stream<Arguments> oversizedFiles() {
        // Trimmed, either file is a valid key; only its size makes it hold none.
        return Stream.of(
                Arguments.of("one byte past the bound",
                        ascii(padded(generatedKey(), InstanceSecretKey.MAX_FILE_BYTES + 1))),
                Arguments.of("1 MiB", ascii(padded(generatedKey(), 1024 * 1024))));
    }

    @Test
    void acceptsKeyWithWhitespaceUpToTheBound(@TempDir Path dir) throws IOException {
        String key = generatedKey();
        byte[] content = ascii(padded(key, InstanceSecretKey.MAX_FILE_BYTES));
        Path file = Files.write(dir.resolve(InstanceSecretKey.FILE_NAME), content);

        assertSameKey(key, InstanceSecretKey.get(dir, true), "Whitespace within the bound must not hide the key");
        assertSameKey(key,
                InstanceSecretKey.get(dir, false, afterRecheckInterval()),
                "Whitespace within the bound must not hide the key");
        assertTrue(Arrays.equals(content, Files.readAllBytes(file)), "An existing key file must never be overwritten");
    }

    @Test
    void interruptedWhileWaitingKeepsInterruptStatus(@TempDir Path dir) throws IOException {
        Path file = Files.createFile(dir.resolve(InstanceSecretKey.FILE_NAME));

        Thread.currentThread().interrupt();
        try {
            InterruptedIOException e = assertThrows(InterruptedIOException.class,
                    () -> InstanceSecretKey.get(dir, false));
            assertTrue(Thread.interrupted(), "The interrupt status must be kept");
            assertNamesFileOnly(e, "");
        } finally {
            // Clear the status so that nothing after this test runs interrupted.
            Thread.interrupted();
        }

        // The interrupted wait was not remembered as a file without a key.
        String written = generatedKey();
        Files.writeString(file, written);
        assertSameKey(written, InstanceSecretKey.get(dir, false), "The completed key must be read");
    }

    @Test
    void readsServedFromMemoryWithinRecheckInterval(@TempDir Path dir) throws IOException {
        long checked = System.nanoTime();
        String key = requireKey(InstanceSecretKey.get(dir, true, checked));

        Files.delete(dir.resolve(InstanceSecretKey.FILE_NAME));

        assertSameKey(key, InstanceSecretKey.get(dir, false, checked),
                "A read within the recheck interval must be served from memory");
        assertSameKey(key, InstanceSecretKey.get(dir, false, checked + InstanceSecretKey.RECHECK_INTERVAL_NANOS - 1),
                "A read must be served from memory up to the end of the recheck interval");
        assertNoKey(InstanceSecretKey.get(dir, false, checked + InstanceSecretKey.RECHECK_INTERVAL_NANOS),
                "A read after the recheck interval must check the file again");
        String recreated = requireKey(InstanceSecretKey.get(dir, true));
        assertFalse(key.equals(recreated), "A deleted key must be replaced by a new key, not by the remembered one");
    }

    @Test
    void absenceRememberedWithinRecheckInterval(@TempDir Path dir) throws IOException {
        Path reading = Files.createDirectories(dir.resolve("reading"));
        long checked = System.nanoTime();
        assertNoKey(InstanceSecretKey.get(reading, false, checked), "An absent key must be reported as null");

        String written = generatedKey();
        Files.writeString(reading.resolve(InstanceSecretKey.FILE_NAME), written);

        assertNoKey(InstanceSecretKey.get(reading, false, checked),
                "An absent file must be remembered within the recheck interval");
        assertSameKey(written,
                InstanceSecretKey.get(reading, false, checked + InstanceSecretKey.RECHECK_INTERVAL_NANOS),
                "A key file written elsewhere must be read after the recheck interval");

        Path creating = Files.createDirectories(dir.resolve("creating"));
        long absent = System.nanoTime();
        assertNoKey(InstanceSecretKey.get(creating, false, absent), "An absent key must be reported as null");

        String existing = generatedKey();
        Path file = Files.writeString(creating.resolve(InstanceSecretKey.FILE_NAME), existing);

        assertSameKey(existing, InstanceSecretKey.get(creating, true, absent),
                "A lookup that may create must check the file, whatever is remembered");
        assertTrue(Arrays.equals(existing.getBytes(StandardCharsets.US_ASCII), Files.readAllBytes(file)),
                "An existing key file must never be overwritten");
    }

    /**
     * A {@link System#nanoTime()} reading at which every check made so far is due again.
     */
    private static long afterRecheckInterval() {
        return System.nanoTime() + InstanceSecretKey.RECHECK_INTERVAL_NANOS;
    }

    /**
     * Runs {@code callers} on the threads of {@code executor}, released together once every one is ready, and returns
     * their results in order. A failure of a caller fails the test with its exception.
     */
    private static List<@Nullable String> race(ExecutorService executor,
            List<Callable<@Nullable String>> callers) throws Exception {
        CountDownLatch ready = new CountDownLatch(callers.size());
        CountDownLatch start = new CountDownLatch(1);
        List<Future<@Nullable String>> results = new ArrayList<>();
        for (Callable<@Nullable String> caller : callers) {
            results.add(executor.submit(() -> {
                ready.countDown();
                assertTrue(start.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "The race must start");
                return caller.call();
            }));
        }
        assertTrue(ready.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "Every caller must be ready for the race");
        start.countDown();

        List<@Nullable String> keys = new ArrayList<>();
        for (Future<@Nullable String> result : results) {
            keys.add(result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
        }
        return keys;
    }

    private static void shutdown(ExecutorService executor) throws InterruptedException {
        executor.shutdownNow();
        assertTrue(executor.awaitTermination(TIMEOUT_SECONDS, TimeUnit.SECONDS), "The test threads must stop");
    }

    /**
     * Calls {@code get(directory, true)} of a copy of {@link InstanceSecretKey}, failing with what the copy throws.
     */
    private static @Nullable String invoke(Method get, Path directory) throws Exception {
        try {
            return (String) get.invoke(null, directory, true);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof Exception failure) {
                throw failure;
            }
            throw e;
        }
    }

    /**
     * Asserts that every caller got the same key, which is the content of the key file in {@code directory} and
     * decodes to 32 bytes, and returns it.
     */
    private static String assertOneKey(Path directory, List<@Nullable String> keys) throws IOException {
        String key = requireKey(keys.get(0));
        for (String other : keys) {
            assertSameKey(key, other, "Every concurrent caller must get the same key");
        }
        Path file = directory.resolve(InstanceSecretKey.FILE_NAME);
        assertSameKey(Files.readString(file).trim(), key, "The shared key must be the content of the key file");
        assertEquals(KEY_BYTES, Base64.getDecoder().decode(key).length);
        return key;
    }

    /**
     * Asserts that {@code file} has the modification time and size {@code before} describes, and returns its
     * attributes.
     */
    private static BasicFileAttributes assertSameTimeAndSize(BasicFileAttributes before, Path file) throws IOException {
        BasicFileAttributes after = Files.readAttributes(file, BasicFileAttributes.class);
        assertEquals(before.lastModifiedTime(), after.lastModifiedTime(), "The new content must keep the file's time");
        assertEquals(before.size(), after.size(), "The new content must keep the file's size");
        return after;
    }

    /**
     * Asserts that {@code e} names the key file and does not quote {@code content}.
     */
    private static void assertNamesFileOnly(IOException e, String content) {
        String message = e.getMessage();
        assertNotNull(message, "The failure must name the key file");
        assertTrue(message.contains(InstanceSecretKey.FILE_NAME), "The failure must name the key file");
        String quoted = content.trim();
        assertTrue(quoted.isEmpty() || !message.contains(quoted), "The failure must not quote the file content");
    }

    /**
     * Creates the key in {@code directory} and asserts what is logged meanwhile: whole records only, none holding a
     * raw control character or line separator; one INFO record naming the key file as {@code rendered}, the only
     * record that holds {@link #FORGED_RECORD}; and never the key.
     */
    private static void assertCreationLoggedOnOneLine(StdErr stdErr, Path directory, String rendered)
            throws IOException {
        int mark = stdErr.capturedString().length();

        String key = requireKey(InstanceSecretKey.get(directory, true));

        // Each record ends with the line separator of the platform, so any other break would start a forged record.
        List<String> records = List
                .of(stdErr.capturedString().substring(mark).split(Pattern.quote(System.lineSeparator())));
        assertTrue(records.stream().flatMapToInt(String::chars).noneMatch(InstanceSecretKeyTest::breaksLine),
                "No logged record may hold a raw control character or line separator");
        List<String> created = records.stream()
                .filter(line -> line.contains("INFO")
                        && line.contains("Created the instance secret key '" + rendered + "'."))
                .toList();
        assertEquals(1, created.size(), "Creating the key must log one INFO line naming the escaped key file");
        assertEquals(created,
                records.stream().filter(line -> line.contains(FORGED_RECORD)).toList(),
                "A directory name must not forge a log record");
        assertFalse(stdErr.capturedString().contains(key), "The key must never be logged");
    }

    private static boolean breaksLine(int c) {
        int type = Character.getType(c);
        return Character.isISOControl(c) || type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR;
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * {@code key} between surrounding whitespace, {@code length} characters in all.
     */
    private static String padded(String key, int length) {
        String leading = " \t\r\n";
        return leading + key + " ".repeat(length - leading.length() - key.length() - 1) + "\n";
    }

    private static String encodedRandom(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static String generatedKey() {
        return encodedRandom(KEY_BYTES);
    }

    private static String requireKey(@Nullable String key) {
        assertNotNull(key, "A key was expected");
        return key;
    }

    private static void assertSameKey(String expected, @Nullable String actual, String message) {
        assertTrue(expected.equals(actual), message);
    }

    private static void assertNoKey(@Nullable String key, String message) {
        assertTrue(key == null, message);
    }

    /**
     * Defines its own copies of {@link InstanceSecretKey}, its nested classes and {@link ConfigLog}, which it reaches
     * package-privately, from the class files of its parent, and leaves every other class to the parent.
     */
    private static final class CopyingClassLoader extends ClassLoader {
        private static final String KEY_CLASS = InstanceSecretKey.class.getName();

        private CopyingClassLoader(ClassLoader parent) {
            super(parent);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (!isCopied(name)) {
                return super.loadClass(name, resolve);
            }
            synchronized (getClassLoadingLock(name)) {
                Class<?> type = findLoadedClass(name);
                if (type == null) {
                    type = copy(name);
                }
                if (resolve) {
                    resolveClass(type);
                }
                return type;
            }
        }

        private static boolean isCopied(String name) {
            return name.equals(KEY_CLASS) || name.startsWith(KEY_CLASS + "$") || name.equals(ConfigLog.class.getName());
        }

        private Class<?> copy(String name) throws ClassNotFoundException {
            String resource = name.replace('.', '/') + ".class";
            try (InputStream in = getParent().getResourceAsStream(resource)) {
                if (in == null) {
                    throw new ClassNotFoundException(name);
                }
                byte[] bytes = in.readAllBytes();
                return defineClass(name, bytes, 0, bytes.length);
            } catch (IOException e) {
                throw new ClassNotFoundException(name, e);
            }
        }
    }
}

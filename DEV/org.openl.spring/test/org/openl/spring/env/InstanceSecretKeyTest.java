package org.openl.spring.env;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.channels.ClosedByInterruptException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
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
    private static final SecureRandom RANDOM = new SecureRandom();

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

        IOException e = assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, true));
        assertThrows(IOException.class, () -> InstanceSecretKey.get(dir, false));

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

        assertNoKey(InstanceSecretKey.get(dir, false), "A deleted key file must count as absent, whatever is cached");
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

        String key = InstanceSecretKey.get(dir, false);
        assertSameKey(replacement, key, "A replaced key file must be read again");
        assertFalse(original.equals(key), "The cached key of the replaced file must not be returned");
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

    private static String generatedKey() {
        byte[] bytes = new byte[KEY_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
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
}

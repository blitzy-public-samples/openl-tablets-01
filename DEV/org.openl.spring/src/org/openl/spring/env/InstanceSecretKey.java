package org.openl.spring.env;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

/**
 * The per-installation key that encrypts secret settings when {@code secret.key} is blank (V6).
 *
 * <p>Settings whose names end in {@code password}, {@code secret} or {@code token} are always stored encrypted.
 * {@code secret.key} keeps its blank default, and a key derived from an empty string would be known to everyone. So
 * when no {@code secret.key} is configured, {@link DynamicPropertySource} encrypts those settings with a random key of
 * this installation instead. The key lives in its own file, {@code ${openl.home.shared}/.openl-secret-key}, beside the
 * settings file, so the settings file itself never holds a plain-text secret. A configured {@code secret.key} always
 * takes precedence; the caller decides which key to use.
 *
 * <p>The key is 32 bytes from {@link SecureRandom}, stored Base64-encoded. The file is created once,
 * with {@link StandardOpenOption#CREATE_NEW}, and is never overwritten. Where the file system supports POSIX
 * permissions, it is created readable and writable by its owner only ({@code rw-------}); the permissions are applied
 * when the file is created, and a umask can only narrow them.
 *
 * <p>Operational constraints:
 * <ul>
 * <li>Moving the settings file to another installation requires moving this file too, or configuring
 * {@code secret.key} before the first save.</li>
 * <li>Values written with this key are unreadable once the file is lost.</li>
 * </ul>
 *
 * <p>The key and the file content never appear in a log line or an exception message; both name the path only.
 *
 * <p>All access is serialized on the class lock, so concurrent callers of one JVM always get the same key. When another
 * process creates the file first, its key is read and used.
 */
final class InstanceSecretKey {

    /**
     * The name of the key file inside {@code ${openl.home.shared}}.
     */
    static final String FILE_NAME = ".openl-secret-key";

    private static final int KEY_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * The last key read or created, with its file and that file's modification time. Guarded by the class lock. It
     * starts as {@link CachedKey#NONE}, which matches no key file, so a lookup needs no null check.
     */
    private static CachedKey cache = CachedKey.NONE;

    private InstanceSecretKey() {
    }

    /**
     * Returns the instance key stored in {@code directory}, creating it first when it is absent and {@code create} is
     * {@code true}.
     *
     * <p>The file is checked on every call: a deleted file counts as absent, and a replaced file is read again. An
     * unchanged file is served from memory.
     *
     * @param directory the directory that holds the key file, normally {@code ${openl.home.shared}}
     * @param create    {@code true} to create the key when it is absent; {@code false} to only read an existing one
     * @return the key, or {@code null} when the file is absent and {@code create} is {@code false}
     * @throws IOException when the file cannot be read or created, or holds no key
     */
    static synchronized @Nullable String get(Path directory, boolean create) throws IOException {
        Objects.requireNonNull(directory, "directory");
        Path file = directory.resolve(FILE_NAME).toAbsolutePath();
        String key = readIfExists(file);
        if (key != null || !create) {
            return key;
        }
        return create(directory, file);
    }

    private static @Nullable String readIfExists(Path file) throws IOException {
        try {
            return read(file);
        } catch (NoSuchFileException e) {
            // Absence is an expected state: the key is created on the first save that needs it.
            return null;
        }
    }

    private static String read(Path file) throws IOException {
        FileTime modified = Files.getLastModifiedTime(file);
        CachedKey cached = cache;
        if (cached.matches(file, modified)) {
            return cached.key;
        }
        String key = Files.readString(file, StandardCharsets.UTF_8).trim();
        if (key.isEmpty()) {
            throw new IOException("The instance secret key file '" + file + "' holds no key.");
        }
        cache = new CachedKey(file, modified, key);
        return key;
    }

    private static String create(Path directory, Path file) throws IOException {
        Files.createDirectories(directory);
        byte[] random = new byte[KEY_BYTES];
        RANDOM.nextBytes(random);
        String key = Base64.getEncoder().encodeToString(random);
        Arrays.fill(random, (byte) 0);

        SeekableByteChannel channel;
        try {
            channel = Files.newByteChannel(file,
                    EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                    ownerOnly(directory));
        } catch (FileAlreadyExistsException e) {
            // Another process created the key after the check above. Its key wins, so that every process of the
            // installation encrypts with the same key.
            return read(file);
        }
        try (channel) {
            ByteBuffer content = ByteBuffer.wrap(key.getBytes(StandardCharsets.US_ASCII));
            while (content.hasRemaining()) {
                channel.write(content);
            }
        } catch (IOException | RuntimeException e) {
            // A partly written file would be read as a different key, or as no key, from then on.
            deleteQuietly(file, e);
            throw e;
        }
        cache = new CachedKey(file, Files.getLastModifiedTime(file), key);
        ConfigLog.LOG.info("Created the instance secret key '{}'.", file);
        return key;
    }

    /**
     * Owner-only permissions where the file system of the key file supports POSIX permissions, none otherwise.
     */
    private static FileAttribute<?>[] ownerOnly(Path directory) {
        if (directory.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            return new FileAttribute<?>[]{
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))};
        }
        return new FileAttribute<?>[0];
    }

    private static void deleteQuietly(Path file, Exception failure) {
        try {
            Files.deleteIfExists(file);
        } catch (IOException e) {
            failure.addSuppressed(e);
        }
    }

    /**
     * A key with the file it was read from. It keeps {@link Object#toString()}, so the key cannot reach a log line.
     */
    private static final class CachedKey {
        /**
         * Matches no key file: the file it names is empty and relative, while every key file looked up is absolute.
         */
        private static final CachedKey NONE = new CachedKey(Path.of(""), FileTime.fromMillis(0), "");

        private final Path file;
        private final FileTime modified;
        private final String key;

        private CachedKey(Path file, FileTime modified, String key) {
            this.file = file;
            this.modified = modified;
            this.key = key;
        }

        private boolean matches(Path otherFile, FileTime otherModified) {
            return file.equals(otherFile) && modified.equals(otherModified);
        }
    }
}

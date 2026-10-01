package org.openl.spring.env;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Duration;
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
 * <p>The key is 32 bytes from {@link SecureRandom}, stored as their canonical, padded Base64 text of 44 characters.
 * That text, not the decoded bytes, is the key material. A file holding anything else, surrounding whitespace aside,
 * holds no valid key and is never used as one. The file is created once, with {@link StandardOpenOption#CREATE_NEW},
 * and is never overwritten. Where the file system supports POSIX permissions, it is created readable and writable by
 * its owner only ({@code rw-------}); the permissions are applied when the file is created, and a umask can only
 * narrow them.
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
 * <p>The class lock serializes every check and creation of the file by the callers of one class loader, so they always
 * get the same key; a read-only lookup answered from memory needs no lock. Other class loaders, such as another web
 * application in the same JVM, and other processes coordinate through the file: it is created exclusively and never
 * overwritten, so the key of the first creator is the one every caller reads, and a reader that finds the file still
 * being written waits briefly for the complete key.
 */
final class InstanceSecretKey {

    /**
     * The name of the key file inside {@code ${openl.home.shared}}.
     */
    static final String FILE_NAME = ".openl-secret-key";

    private static final int KEY_BYTES = 32;
    /**
     * The length of the padded Base64 text of {@link #KEY_BYTES} bytes.
     */
    private static final int KEY_TEXT_LENGTH = 4 * ((KEY_BYTES + 2) / 3);
    private static final String BASE64_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    /**
     * How often, and how long apart, a key file that may still be written is read before it counts as holding no key:
     * about a second in all.
     */
    private static final int PUBLICATION_ATTEMPTS = 20;
    private static final Duration PUBLICATION_PAUSE = Duration.ofMillis(50);
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * How long a read-only lookup is answered from the last check of the key file without touching the file.
     */
    static final long RECHECK_INTERVAL_NANOS = Duration.ofSeconds(1).toNanos();

    /**
     * The last check of a key file. Written under the class lock, and read without it by read-only lookups. It starts
     * as {@link Observation#NONE}, which describes no key file, so a lookup needs no null check.
     */
    private static volatile Observation observation = Observation.NONE;

    private InstanceSecretKey() {
    }

    /**
     * Returns the instance key stored in {@code directory}, creating it first when it is absent and {@code create} is
     * {@code true}.
     *
     * <p>A lookup that may create always checks the file. A read-only lookup is served from memory for up to one
     * second after the last check, so a deletion or replacement made elsewhere reaches reads within that time. When the
     * file is checked, a deleted file counts as absent and a replaced file is read again, while an unchanged file, with
     * the same modification time and size, is served from memory.
     *
     * @param directory the directory that holds the key file, normally {@code ${openl.home.shared}}
     * @param create    {@code true} to create the key when it is absent; {@code false} to only read an existing one
     * @return the key, or {@code null} when the file is absent and {@code create} is {@code false}
     * @throws IOException when the file cannot be read or created, or holds no valid key
     */
    static @Nullable String get(Path directory, boolean create) throws IOException {
        return get(directory, create, System.nanoTime());
    }

    /**
     * {@link #get(Path, boolean)} at the moment {@code nanoTime}.
     *
     * @param nanoTime a {@link System#nanoTime()} reading taken for this call
     */
    static @Nullable String get(Path directory, boolean create, long nanoTime) throws IOException {
        Objects.requireNonNull(directory, "directory");
        Path file = directory.resolve(FILE_NAME).toAbsolutePath();
        if (!create) {
            Observation last = observation;
            if (last.isRecent(file, nanoTime)) {
                return last.answer();
            }
        }
        return lookup(directory, file, create, nanoTime);
    }

    private static synchronized @Nullable String lookup(Path directory, Path file, boolean create, long nanoTime)
            throws IOException {
        if (!create) {
            Observation last = observation;
            if (last.isRecent(file, nanoTime)) {
                // Another caller checked the file while this one waited for the lock.
                return last.answer();
            }
        }
        String key = readIfExists(file, nanoTime);
        if (key != null || !create) {
            return key;
        }
        return create(directory, file, nanoTime);
    }

    private static @Nullable String readIfExists(Path file, long nanoTime) throws IOException {
        try {
            return read(file, nanoTime);
        } catch (NoSuchFileException e) {
            // Absence is an expected state: the key is created on the first save that needs it.
            observation = Observation.absent(file, nanoTime);
            return null;
        }
    }

    private static String read(Path file, long nanoTime) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(file, BasicFileAttributes.class);
        Observation last = observation;
        // The attributes are taken before the content, so a file that changes meanwhile is read again next time.
        Observation current = last.describes(file, attributes)
                ? last.recheckedAt(nanoTime)
                : Observation.existing(file, attributes, nanoTime, readKey(file));
        observation = current;
        String key = current.key;
        if (key == null) {
            // Until the file changes, it fails at once without being read again.
            throw invalidKey(file);
        }
        return key;
    }

    /**
     * Reads the key from {@code file}. Content that may be a key still being written by another creator is read again
     * after a short pause, for about a second at most.
     *
     * @return the key, or {@code null} when the file holds no valid key
     * @throws InterruptedIOException when the thread is interrupted while waiting; its interrupt status is kept
     */
    private static @Nullable String readKey(Path file) throws IOException {
        for (int attempt = 1;; attempt++) {
            byte[] content = Files.readAllBytes(file);
            // Any byte outside ASCII decodes to a replacement character, which no key contains.
            String text = new String(content, StandardCharsets.US_ASCII);
            Arrays.fill(content, (byte) 0);
            String key = text.trim();
            if (isKey(key)) {
                return key;
            }
            if (attempt >= PUBLICATION_ATTEMPTS || !mayBeUnfinished(text)) {
                return null;
            }
            pause(file);
        }
    }

    /**
     * Whether {@code text} is a key: the canonical, padded Base64 text of exactly 32 bytes. The JDK decoder also
     * accepts unpadded text and text whose unused low bits are set, and 31, 32 and 33 bytes all encode to 44
     * characters, so only re-encoding the decoded bytes proves the canonical form.
     */
    private static boolean isKey(String text) {
        if (text.length() != KEY_TEXT_LENGTH) {
            return false;
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            return false;
        }
        try {
            return decoded.length == KEY_BYTES && Base64.getEncoder().encodeToString(decoded).equals(text);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    /**
     * Whether {@code text} may be a key that its creator is still writing: shorter than a key and made of Base64
     * characters only. An empty file qualifies. A blank one does not, since a key is written without whitespace.
     */
    private static boolean mayBeUnfinished(String text) {
        if (text.length() >= KEY_TEXT_LENGTH) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            if (BASE64_CHARACTERS.indexOf(text.charAt(i)) < 0) {
                return false;
            }
        }
        return true;
    }

    private static void pause(Path file) throws InterruptedIOException {
        try {
            Thread.sleep(PUBLICATION_PAUSE);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            InterruptedIOException interrupted = new InterruptedIOException(
                    "Interrupted while waiting for the instance secret key file '" + file + "' to be written.");
            interrupted.initCause(e);
            throw interrupted;
        }
    }

    private static IOException invalidKey(Path file) {
        return new IOException("The instance secret key file '" + file + "' does not hold a valid key.");
    }

    private static String create(Path directory, Path file, long nanoTime) throws IOException {
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
            // Another process or class loader created the file after the check above and may still be writing it.
            // Its key wins, so that every process of the installation encrypts with the same key.
            return read(file, nanoTime);
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
        observation = Observation.existing(file, Files.readAttributes(file, BasicFileAttributes.class), nanoTime, key);
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
     * One check of a key file: when it was made, the modification time and size the file had, and the key it held. It
     * keeps {@link Object#toString()}, so the key cannot reach a log line.
     */
    private static final class Observation {
        /**
         * Describes no key file: the file it names is empty and relative, while every key file looked up is absolute.
         */
        private static final Observation NONE = new Observation(Path.of(""), 0, null, -1, null);

        private final Path file;
        /**
         * The {@link System#nanoTime()} reading of the check.
         */
        private final long checkedAt;
        /**
         * The modification time of the file, or {@code null} when the file was absent.
         */
        private final @Nullable FileTime modified;
        private final long size;
        /**
         * The key of the file, or {@code null} when the file was absent or holds no valid key.
         */
        private final @Nullable String key;

        private Observation(Path file, long checkedAt, @Nullable FileTime modified, long size, @Nullable String key) {
            this.file = file;
            this.checkedAt = checkedAt;
            this.modified = modified;
            this.size = size;
            this.key = key;
        }

        private static Observation absent(Path file, long checkedAt) {
            return new Observation(file, checkedAt, null, -1, null);
        }

        private static Observation existing(Path file,
                BasicFileAttributes attributes,
                long checkedAt,
                @Nullable String key) {
            return new Observation(file, checkedAt, attributes.lastModifiedTime(), attributes.size(), key);
        }

        private Observation recheckedAt(long nanoTime) {
            return new Observation(file, nanoTime, modified, size, key);
        }

        /**
         * Whether this is a check of {@code otherFile} made less than {@link #RECHECK_INTERVAL_NANOS} before
         * {@code nanoTime}. Subtracting the readings, rather than comparing them, keeps it right when
         * {@link System#nanoTime()} overflows.
         */
        private boolean isRecent(Path otherFile, long nanoTime) {
            return file.equals(otherFile) && nanoTime - checkedAt < RECHECK_INTERVAL_NANOS;
        }

        /**
         * Whether this is a check of {@code otherFile} as it still is: present, with the same modification time and
         * size.
         */
        private boolean describes(Path otherFile, BasicFileAttributes attributes) {
            return file.equals(otherFile) && modified != null && modified.equals(attributes.lastModifiedTime())
                    && size == attributes.size();
        }

        /**
         * The key, {@code null} for an absent file, or the failure of a file that holds no valid key.
         */
        private @Nullable String answer() throws IOException {
            if (modified != null && key == null) {
                throw invalidKey(file);
            }
            return key;
        }
    }
}

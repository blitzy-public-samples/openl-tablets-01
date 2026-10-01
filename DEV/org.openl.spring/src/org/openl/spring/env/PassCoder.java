package org.openl.spring.env;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.jspecify.annotations.Nullable;

import org.openl.util.HashingUtils;
import org.openl.util.StringUtils;

/**
 * Encrypts and decrypts the values of secret settings.
 * <p>
 * The legacy {@link #decode} reads existing {@code ENC(...)} values: its key is the first 16 bytes of the SHA-1 of
 * {@code secret.key}, its cipher is the configured {@code secret.cipher} ({@code AES/CBC/PKCS5Padding} by default),
 * and its IV is zero. The legacy {@link #encode} is no longer used to write settings. Settings are written in the v2
 * format of {@link #encodeV2} and {@link #decodeV2}: AES-256-GCM, a PBKDF2-derived key, and a random salt and nonce
 * per value.
 *
 * @author Pavel Tarasevich
 */
final class PassCoder {
    private static final byte[] bytes = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    private static final IvParameterSpec algorithmParameterSpec = new IvParameterSpec(bytes);

    // V6: parameters of the v2 format: AES-256-GCM, PBKDF2-HMAC-SHA256 key, random salt and nonce per value.
    /**
     * Marks the content of {@code ENC(...)} written in the v2 format. Standard Base64 never contains {@code :}, so
     * the prefix cannot occur at the start of a legacy value.
     */
    static final String V2_PREFIX = "v2:";
    private static final String V2_CIPHER = "AES/GCM/NoPadding";
    private static final String V2_KDF = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 600_000;
    private static final int KEY_BITS = 256;
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    // Binds each ciphertext to its format version: a v2 payload cannot be decrypted under another AAD.
    private static final byte[] AAD = "openl-enc-v2".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();
    // Reads decode on every property access; the cache keeps them from repeating the 600,000 PBKDF2 iterations.
    private static final KeyCache KEYS = new KeyCache(256);

    private PassCoder() {
    }

    static String encode(String strToEncrypt, String privateKey, String c) throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidAlgorithmParameterException {
        if (StringUtils.isBlank(strToEncrypt)) {
            return strToEncrypt;
        }
        if (StringUtils.isBlank(privateKey)) {
            return strToEncrypt;
        }
        Cipher cipher = Cipher.getInstance(c);

        SecretKeySpec secretKey = getKey(privateKey);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);
        var toEncrypt = strToEncrypt.getBytes(StandardCharsets.UTF_8);
        var encrypted = cipher.doFinal(toEncrypt);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    static String decode(String strToDecrypt, String privateKey, String c) throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidAlgorithmParameterException {
        if (StringUtils.isBlank(strToDecrypt)) {
            return strToDecrypt;
        }
        if (StringUtils.isBlank(privateKey)) {
            return strToDecrypt;
        }

        Cipher cipher = Cipher.getInstance(c);
        SecretKeySpec secretKey = getKey(privateKey);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec);
        var toDecrypt = Base64.getDecoder().decode(strToDecrypt);
        var decripted = cipher.doFinal(toDecrypt);
        return new String(decripted, StandardCharsets.UTF_8);
    }

    private static SecretKeySpec getKey(String privateKey) {
        var key = HashingUtils.sha1(privateKey);
        key = Arrays.copyOf(key, 16); // use only first 128 bit

        return new SecretKeySpec(key, "AES");
    }

    // V6: writes a value in the v2 format; a fresh salt and nonce per call make every encoding unique.
    /**
     * Encrypts a value in the v2 format.
     * <p>
     * The result is the content of the {@code ENC(...)} wrapper, without the wrapper itself:
     * {@code v2:} followed by the Base64 of the 16-byte salt, the 12-byte nonce and the ciphertext with its 16-byte
     * tag, in that order. An empty value is encrypted as well.
     *
     * @param value the plain text to encrypt; may be empty, must not be {@code null}
     * @param keyMaterial the secret the AES-256 key is derived from; must not be blank
     * @return the v2 form of the value
     * @throws NullPointerException if the value is {@code null}
     * @throws IllegalArgumentException if the key material is blank
     * @throws GeneralSecurityException if the JDK cannot provide the cipher or the key derivation
     */
    static String encodeV2(String value, String keyMaterial) throws GeneralSecurityException {
        Objects.requireNonNull(value, "The value must not be null.");
        if (StringUtils.isBlank(keyMaterial)) {
            throw new IllegalArgumentException("The key material must not be blank.");
        }
        var salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        var nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);

        var cipher = Cipher.getInstance(V2_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(keyMaterial, salt), new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(AAD);
        var encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));

        var payload = new byte[SALT_BYTES + NONCE_BYTES + encrypted.length];
        System.arraycopy(salt, 0, payload, 0, SALT_BYTES);
        System.arraycopy(nonce, 0, payload, SALT_BYTES, NONCE_BYTES);
        System.arraycopy(encrypted, 0, payload, SALT_BYTES + NONCE_BYTES, encrypted.length);
        return V2_PREFIX + Base64.getEncoder().encodeToString(payload);
    }

    // V6: reads a v2 value; a wrong key or any modified byte fails authentication instead of yielding plain text.
    /**
     * Decrypts a value written by {@link #encodeV2(String, String)}.
     * <p>
     * Exception messages never contain the value or the key material.
     *
     * @param value the content of the {@code ENC(...)} wrapper, starting with {@link #V2_PREFIX}
     * @param keyMaterial the secret the AES-256 key is derived from; must not be blank
     * @return the plain text
     * @throws IllegalArgumentException if the value is {@code null}, lacks the v2 prefix, is not valid Base64 or is
     *             shorter than a salt, a nonce and a tag, or if the key material is blank
     * @throws javax.crypto.AEADBadTagException if the key is wrong or the salt, nonce, ciphertext or tag was modified
     * @throws GeneralSecurityException if the JDK cannot provide the cipher or the key derivation
     */
    static String decodeV2(String value, String keyMaterial) throws GeneralSecurityException {
        if (value == null) {
            throw new IllegalArgumentException("The value must not be null.");
        }
        if (!value.startsWith(V2_PREFIX)) {
            throw new IllegalArgumentException("The value is not in the v2 format.");
        }
        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(value.substring(V2_PREFIX.length()));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The v2 value is not valid Base64.", e);
        }
        if (payload.length < SALT_BYTES + NONCE_BYTES + TAG_BITS / Byte.SIZE) {
            throw new IllegalArgumentException("The v2 value is too short.");
        }
        if (StringUtils.isBlank(keyMaterial)) {
            throw new IllegalArgumentException("The key material must not be blank.");
        }
        var salt = Arrays.copyOfRange(payload, 0, SALT_BYTES);
        var nonce = Arrays.copyOfRange(payload, SALT_BYTES, SALT_BYTES + NONCE_BYTES);
        var encrypted = Arrays.copyOfRange(payload, SALT_BYTES + NONCE_BYTES, payload.length);

        var cipher = Cipher.getInstance(V2_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(keyMaterial, salt), new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(AAD);
        return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
    }

    // V6: derives the AES-256 key of a key material and salt once, then serves it from the cache.
    /**
     * Returns the PBKDF2-HMAC-SHA256 key for the key material and salt, from the cache when present.
     * <p>
     * The cache is keyed by the SHA-256 of the key material and the salt, so the raw key material is never stored.
     * Threads that miss the same key material and salt at the same time share one derivation: one thread derives,
     * and the others wait for its key. A derived key is cached whether or not a decryption then accepts it, so a
     * wrong candidate key is cached too; its lookup is cheap next time and it still fails authentication.
     */
    private static SecretKey deriveKey(String keyMaterial, byte[] salt) throws GeneralSecurityException {
        var cacheKey = HashingUtils.sha256Hex(keyMaterial) + ":" + Base64.getEncoder().encodeToString(salt);
        // V6: concurrent misses for one cache key run a single derivation and all receive its key.
        return KEYS.getOrDerive(cacheKey, () -> pbkdf2(keyMaterial, salt));
    }

    // V6: runs the PBKDF2-HMAC-SHA256 iterations and wipes the copies of the key material and the key it made.
    private static SecretKey pbkdf2(String keyMaterial, byte[] salt) throws GeneralSecurityException {
        var spec = new PBEKeySpec(keyMaterial.toCharArray(), salt, ITERATIONS, KEY_BITS);
        try {
            var encoded = SecretKeyFactory.getInstance(V2_KDF).generateSecret(spec).getEncoded();
            SecretKey key = new SecretKeySpec(encoded, "AES");
            Arrays.fill(encoded, (byte) 0); // SecretKeySpec keeps its own copy
            return key;
        } finally {
            spec.clearPassword();
        }
    }

    // V6: the computation of a key that the cache runs on a miss.
    /** Computes the key of a cache entry; it runs without the lock of the {@link KeyCache}. */
    @FunctionalInterface
    interface KeyDerivation {
        SecretKey derive() throws GeneralSecurityException;
    }

    // V6: bounded least-recently-used store of derived keys, safe for concurrent property reads.
    /**
     * A least-recently-used cache of derived keys that holds at most {@code capacity} entries; the entry accessed
     * longest ago is evicted first. A capacity below 1 keeps nothing.
     * <p>
     * {@link #getOrDerive} runs one derivation per cache key at a time: the first thread that misses derives the key,
     * and every thread that misses the same cache key meanwhile waits for that key instead of deriving its own. The
     * lock of the cache is never held while a key is derived. A failed derivation is not cached, so the next call
     * derives again.
     */
    static final class KeyCache {
        private final Map<String, SecretKey> keys;
        // V6: the derivation in progress per cache key, guarded by the same lock as the keys.
        private final Map<String, FutureTask<SecretKey>> pending = new HashMap<>();

        KeyCache(int capacity) {
            this.keys = new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, SecretKey> eldest) {
                    return size() > capacity;
                }
            };
        }

        // V6: a miss returns null.
        synchronized @Nullable SecretKey get(String cacheKey) {
            return keys.get(cacheKey);
        }

        synchronized void put(String cacheKey, SecretKey key) {
            keys.put(cacheKey, key);
        }

        // V6: a cached key is returned at once; otherwise one caller derives it and the others wait for its result.
        /**
         * Returns the cached key of the cache key, or derives it once however many threads miss it at the same time.
         * <p>
         * The lookup and the registration of a new derivation happen under one lock, as do the caching of the
         * derived key and the end of its derivation, so a caller either finds the key, joins the derivation in
         * progress, or starts the only one. An interrupt does not end the wait for a derivation; the interrupt
         * status of the thread is restored once the key or the failure is there.
         *
         * @param cacheKey the key of the entry
         * @param derivation computes the key on a miss; it runs in the calling thread, without the lock
         * @return the cached or derived key
         * @throws GeneralSecurityException if the derivation this caller started or waited for failed with it
         */
        SecretKey getOrDerive(String cacheKey, KeyDerivation derivation) throws GeneralSecurityException {
            FutureTask<SecretKey> task;
            boolean owner = false;
            synchronized (this) {
                var cached = get(cacheKey);
                if (cached != null) {
                    return cached;
                }
                var running = pending.get(cacheKey);
                if (running == null) {
                    running = new FutureTask<>(derivation::derive);
                    pending.put(cacheKey, running);
                    owner = true;
                }
                task = running;
            }
            if (owner) {
                try {
                    task.run();
                } finally {
                    finish(cacheKey, task);
                }
            }
            return await(task);
        }

        // V6: ends a derivation; its key is cached on success, and the cache key is free for the next derivation.
        private synchronized void finish(String cacheKey, FutureTask<SecretKey> task) {
            pending.remove(cacheKey, task);
            if (task.state() == Future.State.SUCCESS) {
                put(cacheKey, task.resultNow());
            }
        }

        // V6: waits for a derivation through interrupts, restores the interrupt status and rethrows its failure.
        private static SecretKey await(FutureTask<SecretKey> task) throws GeneralSecurityException {
            boolean interrupted = false;
            try {
                while (true) {
                    try {
                        return task.get();
                    } catch (InterruptedException e) {
                        interrupted = true;
                    }
                }
            } catch (ExecutionException e) {
                var cause = e.getCause();
                if (cause instanceof GeneralSecurityException securityFailure) {
                    throw securityFailure;
                }
                if (cause instanceof RuntimeException uncheckedFailure) {
                    throw uncheckedFailure;
                }
                if (cause instanceof Error error) {
                    throw error;
                }
                throw new IllegalStateException("The key derivation failed.", cause);
            } finally {
                if (interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
}

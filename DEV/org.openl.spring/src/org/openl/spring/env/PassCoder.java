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
    // V6: the keys of live ciphertexts stay as long as the configuration holds them, apart from 256 candidates.
    /**
     * The derived keys of the v2 values. It keeps at most 256 candidates, the keys of salts that no key has
     * authenticated, and one group per {@code ENC(v2:...)} ciphertext the current configuration holds, with the
     * key that authenticated it and at most {@value KeyCache#REJECTED_PER_SALT} keys it rejected.
     * {@link DynamicPropertySource} drops the group of every ciphertext its settings replace or remove through
     * {@link #forget(String)}. No plain text is cached; see {@link KeyCache}.
     */
    static final KeyCache KEYS = new KeyCache(256);

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

        var slot = slotOf(keyMaterial, salt);
        var key = deriveKey(slot, keyMaterial, salt);
        var cipher = Cipher.getInstance(V2_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(AAD);
        var plain = value.getBytes(StandardCharsets.UTF_8);

        // V6: the ciphertext and its tag are written straight behind the salt and the nonce, without a second copy.
        int header = SALT_BYTES + NONCE_BYTES;
        var payload = new byte[header + cipher.getOutputSize(plain.length)];
        System.arraycopy(salt, 0, payload, 0, SALT_BYTES);
        System.arraycopy(nonce, 0, payload, SALT_BYTES, NONCE_BYTES);
        int written = cipher.doFinal(plain, 0, plain.length, payload, header);
        // V6: the key made this ciphertext, so the reads of the saved value find it among the authenticated keys.
        KEYS.prove(slot, key);
        if (header + written < payload.length) {
            // getOutputSize may reserve more than a provider writes.
            payload = Arrays.copyOf(payload, header + written);
        }
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
        // V6: only the salt is copied, for the key derivation; the nonce and the ciphertext are read in place.
        var salt = Arrays.copyOfRange(payload, 0, SALT_BYTES);
        int header = SALT_BYTES + NONCE_BYTES;

        var slot = slotOf(keyMaterial, salt);
        var key = deriveKey(slot, keyMaterial, salt);
        var cipher = Cipher.getInstance(V2_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, payload, SALT_BYTES, NONCE_BYTES));
        cipher.updateAAD(AAD);
        var plain = cipher.doFinal(payload, header, payload.length - header);
        // V6: only a key that authenticated the value is proven; a key the GCM tag rejected stays a candidate or a
        // rejected key of the salt.
        KEYS.prove(slot, key);
        return new String(plain, StandardCharsets.UTF_8);
    }

    // V6: drops the cached keys of a v2 value once the configuration no longer holds it.
    /**
     * Drops every cached key of the salt of a v2 value: the group of the ciphertext and the candidates of its salt.
     * A value that is {@code null}, lacks the v2 prefix, is not valid Base64 or is shorter than a salt, a nonce and a
     * tag has no cached key, since {@link #decodeV2} rejects it before deriving one; it is ignored without an
     * exception and without a log line.
     *
     * @param v2Value the content of an {@code ENC(...)} wrapper, starting with {@link #V2_PREFIX}
     */
    static void forget(@Nullable String v2Value) {
        if (v2Value == null || !v2Value.startsWith(V2_PREFIX)) {
            return;
        }
        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(v2Value.substring(V2_PREFIX.length()));
        } catch (IllegalArgumentException e) {
            // Not Base64, so decodeV2 never derived a key for it.
            return;
        }
        if (payload.length < SALT_BYTES + NONCE_BYTES + TAG_BITS / Byte.SIZE) {
            return;
        }
        KEYS.forget(Base64.getEncoder().encodeToString(Arrays.copyOf(payload, SALT_BYTES)));
    }

    // V6: the cache slot of a key material and salt; it holds the SHA-256 of the key material, never the material.
    private static KeySlot slotOf(String keyMaterial, byte[] salt) {
        return new KeySlot(Base64.getEncoder().encodeToString(salt), HashingUtils.sha256Hex(keyMaterial));
    }

    // V6: derives the AES-256 key of a key material and salt once, then serves it from the cache.
    /**
     * Returns the PBKDF2-HMAC-SHA256 key for the key material and salt, from the cache when present.
     * <p>
     * The cache is keyed by the SHA-256 of the key material and the salt, so the raw key material is never stored.
     * Threads that miss the same key material and salt at the same time share one derivation: one thread derives,
     * and the others wait for its key. A derived key is cached whether or not a decryption then accepts it, so a
     * wrong candidate key is cached too; its lookup is cheap next time and it still fails authentication. Only the
     * keys proven with {@link KeyCache#prove} are authenticated, apart from the bounded candidates and rejected keys.
     */
    private static SecretKey deriveKey(KeySlot slot, String keyMaterial, byte[] salt) throws GeneralSecurityException {
        // V6: concurrent misses for one cache key run a single derivation and all receive its key.
        return KEYS.getOrDerive(slot, () -> pbkdf2(keyMaterial, salt));
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

    // V6: identifies a derived key in the cache by its salt and the SHA-256 of its key material.
    /**
     * The cache key of a derived key. It never holds the key material itself.
     *
     * @param salt the standard Base64 of the 16-byte salt of a ciphertext
     * @param material the hex SHA-256 of the key material
     */
    record KeySlot(String salt, String material) {
    }

    // V6: two-tier store of derived keys, safe for concurrent property reads: bounded candidates of unauthenticated
    // salts, and per authenticated salt its authenticated keys apart from the few keys it rejected.
    /**
     * A cache of derived keys in two tiers. It holds keys only, never a plain text or a decoded value, and a lookup
     * needs the key material itself, so a value whose key material is lost, or not yet available early in startup,
     * fails to decrypt exactly as it would without the cache.
     * <ul>
     * <li><b>Candidates</b> are the keys of salts that no key has authenticated: just derived, or rejected by the GCM
     * tag. They share one least-recently-used store of at most {@code capacity} keys; the key accessed longest ago is
     * evicted first. A capacity below 1 keeps no candidate. A candidate never evicts a group.</li>
     * <li><b>Groups</b> hold the keys of one salt, that is of one ciphertext, from the moment {@link #prove} records
     * that a key encrypted a value or authenticated a decryption with it. A group keeps its <i>authenticated</i> keys
     * until {@link #forget} drops it, and apart from them at most {@value #REJECTED_PER_SALT} <i>rejected</i> keys,
     * the wrong keys most recently tried against the salt, such as a configured {@code secret.key} tried before the
     * instance key. The first proof of a salt turns its candidates into rejected keys, and a key derived later for
     * the salt is a rejected key until it is proven, so a rejected key never displaces an authenticated one.</li>
     * </ul>
     * No group is evicted by count or by time; its lifetime is that of its ciphertext in the configuration. Only a
     * genuine ciphertext creates a group, and {@link DynamicPropertySource} forgets the salt of every
     * {@code ENC(v2:...)} value its settings replace or remove, so the cache holds at most {@code capacity}
     * candidates and one group per {@code ENC(v2:...)} ciphertext of the current configuration. A read that decrypts
     * a value while a save replaces that value can prove the replaced ciphertext again after it was forgotten, which
     * keeps at most one more group per value replaced that way.
     * <p>
     * A changed {@code secret.key} or a replaced instance key has another SHA-256, so the keys of the old material
     * never serve the new one, and a deleted instance key leaves no material to look a key up with.
     * <p>
     * {@link #getOrDerive} runs one derivation per cache key at a time: the first thread that misses derives the key,
     * and every thread that misses the same cache key meanwhile waits for that key instead of deriving its own. The
     * lock of the cache is never held while a key is derived. A failed derivation is not cached, so the next call
     * derives again.
     */
    static final class KeyCache {
        /** The most rejected keys a group keeps: the wrong keys most recently tried against its salt. */
        static final int REJECTED_PER_SALT = 3;

        private final Map<KeySlot, SecretKey> candidates;
        // V6: the group of every authenticated salt, kept until forget drops it; never evicted by count or by time.
        private final Map<String, Group> groups = new HashMap<>();
        // V6: the derivation in progress per cache key, guarded by the same lock as the keys.
        private final Map<KeySlot, FutureTask<SecretKey>> pending = new HashMap<>();

        /**
         * @param capacity the most candidates kept; below 1 no candidate is kept
         */
        KeyCache(int capacity) {
            this.candidates = new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<KeySlot, SecretKey> eldest) {
                    return size() > capacity;
                }
            };
        }

        // V6: a miss returns null; the authenticated keys of a salt are looked up before its rejected ones.
        synchronized @Nullable SecretKey get(KeySlot slot) {
            var group = groups.get(slot.salt());
            if (group == null) {
                return candidates.get(slot);
            }
            var key = group.authenticated.get(slot.material());
            return key != null ? key : group.rejected.get(slot.material());
        }

        // V6: whether the key of the slot authenticated its salt; unlike a lookup, the query changes no order.
        synchronized boolean isAuthenticated(KeySlot slot) {
            var group = groups.get(slot.salt());
            return group != null && group.authenticated.containsKey(slot.material());
        }

        // V6: whether the key of the slot is kept as one its authenticated salt rejected; the query changes no order.
        synchronized boolean isRejected(KeySlot slot) {
            var group = groups.get(slot.salt());
            return group != null && group.rejected.containsKey(slot.material());
        }

        // V6: a key that encrypted a value or authenticated a decryption becomes an authenticated key of its salt.
        /**
         * Records that the key of the slot encrypted a value or authenticated a decryption. The first proof of a salt
         * creates its group and turns the other candidates of that salt into its rejected keys.
         *
         * @param slot the cache key of the key
         * @param key the key; a key already authenticated for the slot is kept
         */
        synchronized void prove(KeySlot slot, SecretKey key) {
            var group = groups.get(slot.salt());
            if (group == null) {
                group = new Group();
                // V6: the wrong keys tried against this salt become its rejected keys, least recently used first.
                var iterator = candidates.entrySet().iterator();
                while (iterator.hasNext()) {
                    var candidate = iterator.next();
                    var candidateSlot = candidate.getKey();
                    if (candidateSlot.salt().equals(slot.salt())) {
                        if (!candidateSlot.material().equals(slot.material())) {
                            group.rejected.put(candidateSlot.material(), candidate.getValue());
                        }
                        iterator.remove();
                    }
                }
                groups.put(slot.salt(), group);
            } else {
                // V6: a key derived for the salt after its first proof was a rejected key until now.
                group.rejected.remove(slot.material());
            }
            group.authenticated.putIfAbsent(slot.material(), key);
        }

        // V6: drops every key of a salt; the configuration no longer holds its ciphertext.
        /**
         * Drops the group of the salt and the candidates of the salt. A derivation still running for the salt caches
         * its key as a candidate.
         *
         * @param salt the standard Base64 of the 16-byte salt of a ciphertext
         */
        synchronized void forget(String salt) {
            groups.remove(salt);
            candidates.keySet().removeIf(slot -> slot.salt().equals(salt));
        }

        // V6: a cached key is returned at once; otherwise one caller derives it and the others wait for its result.
        /**
         * Returns the cached key of the cache key, or derives it once however many threads miss it at the same time.
         * <p>
         * The lookup and the registration of a new derivation happen under one lock, as do the caching of the
         * derived key and the end of its derivation, so a caller either finds the key, joins the derivation in
         * progress, or starts the only one. An interrupt does not end the wait for a derivation; the interrupt
         * status of the thread is restored once the key or the failure is there. A derived key is a rejected key of
         * its salt when a key has authenticated that salt, and a candidate otherwise, until {@link #prove} records it.
         *
         * @param slot the key of the entry
         * @param derivation computes the key on a miss; it runs in the calling thread, without the lock
         * @return the cached or derived key
         * @throws GeneralSecurityException if the derivation this caller started or waited for failed with it
         */
        SecretKey getOrDerive(KeySlot slot, KeyDerivation derivation) throws GeneralSecurityException {
            FutureTask<SecretKey> task;
            boolean owner = false;
            synchronized (this) {
                var cached = get(slot);
                if (cached != null) {
                    return cached;
                }
                var running = pending.get(slot);
                if (running == null) {
                    running = new FutureTask<>(derivation::derive);
                    pending.put(slot, running);
                    owner = true;
                }
                task = running;
            }
            if (owner) {
                try {
                    task.run();
                } finally {
                    finish(slot, task);
                }
            }
            return await(task);
        }

        // V6: ends a derivation; its key is cached on success, and the cache key is free for the next derivation.
        private synchronized void finish(KeySlot slot, FutureTask<SecretKey> task) {
            pending.remove(slot, task);
            if (task.state() == Future.State.SUCCESS) {
                store(slot, task.resultNow());
            }
        }

        // V6: a key derived for an authenticated salt is one of its rejected keys unless it authenticated the salt
        // meanwhile; any other key is a candidate.
        private void store(KeySlot slot, SecretKey key) {
            var group = groups.get(slot.salt());
            if (group == null) {
                candidates.put(slot, key);
            } else if (!group.authenticated.containsKey(slot.material())) {
                group.rejected.put(slot.material(), key);
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

        // V6: the keys of one salt by the SHA-256 of their key material: those that authenticated its ciphertext, and
        // apart from them the rejected ones, least recently used first.
        private static final class Group {
            private final Map<String, SecretKey> authenticated = new HashMap<>();
            private final Map<String, SecretKey> rejected = new LinkedHashMap<>(8, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, SecretKey> eldest) {
                    return size() > REJECTED_PER_SALT;
                }
            };
        }
    }
}

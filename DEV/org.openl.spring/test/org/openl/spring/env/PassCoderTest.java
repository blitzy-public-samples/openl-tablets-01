package org.openl.spring.env;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import java.util.stream.Stream;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * @author Pavel Tarasevich
 */

class PassCoderTest {

    private static final String CIPHER = "AES/CBC/PKCS5Padding";

    // V6: the value and the keys are generated per run, so no credential is written into the source.
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String PASS = random(16);
    private static final String KEY = random(32);
    // V6: a random wrong key passes the CBC padding check about once in 256 runs and yields garbage instead of an
    // exception, so only a candidate that is proven to fail the legacy decoding is used.
    private static final String WRONG_KEY = wrongKey();

    @Test
    void testPassCodingEncoding() {
        var codedPass = assertDoesNotThrow(() -> PassCoder.encode(PASS, KEY, CIPHER));

        assertNotNull(codedPass);

        String decodedPass = null;

        try {
            decodedPass = PassCoder.decode(codedPass, WRONG_KEY, CIPHER);
        } catch (Exception e) {
            // skip exception which wrong key
        }

        // V6: the decoded values are compared through booleans, so a failure message never holds plain text.
        assertTrue(decodedPass == null, "A wrong key must not decode the value");

        decodedPass = assertDoesNotThrow(() -> PassCoder.decode(codedPass, KEY, CIPHER));

        assertSamePlain(PASS, decodedPass, "The legacy decoding must return the encoded value");
    }

    @Test
    void testEmpty() throws Exception {
        // V6: the generated PASS and KEY replace the literal value and key; PASS is compared without being printed.
        assertSamePlain(PASS, PassCoder.encode(PASS, "", CIPHER), "An empty key must leave the value as it is");
        assertSamePlain(PASS, PassCoder.encode(PASS, " ", CIPHER), "A blank key must leave the value as it is");
        assertSamePlain(PASS, PassCoder.encode(PASS, null, CIPHER), "A null key must leave the value as it is");
        assertEquals("", PassCoder.encode("", KEY, CIPHER));
        assertEquals(" ", PassCoder.encode(" ", KEY, CIPHER));
        assertNull(PassCoder.encode(null, KEY, CIPHER));
        assertEquals("", PassCoder.encode("", "", CIPHER));

        assertSamePlain(PASS, PassCoder.decode(PASS, "", CIPHER), "An empty key must leave the value as it is");
        assertSamePlain(PASS, PassCoder.decode(PASS, " ", CIPHER), "A blank key must leave the value as it is");
        assertSamePlain(PASS, PassCoder.decode(PASS, null, CIPHER), "A null key must leave the value as it is");
        assertEquals("", PassCoder.decode("", KEY, CIPHER));
        assertEquals(" ", PassCoder.decode(" ", KEY, CIPHER));
        assertNull(PassCoder.decode(null, KEY, CIPHER));
        assertEquals("", PassCoder.decode("", "", CIPHER));
    }

    // V6: the tests below prove the legacy format unchanged and cover the v2 format (AES-256-GCM with a
    // PBKDF2-derived key). Each v2 encoding derives a key through 600,000 PBKDF2 iterations, so the class reuses
    // one shared encoding wherever a test only needs some valid v2 value.

    /**
     * Recomputes the legacy format with the JDK alone: AES-128-CBC, PKCS5 padding, a zero IV and the first 16 bytes
     * of the SHA-1 of the key, in standard Base64. Existing {@code ENC(...)} values stay readable only while this
     * holds. The non-ASCII case pins the UTF-8 bytes of the key and of the value.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("legacyKnownAnswers")
    void legacyFormatKnownAnswer(String key, String value) throws Exception {
        byte[] k = Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest(key.getBytes(StandardCharsets.UTF_8)), 16);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"), new IvParameterSpec(new byte[16]));
        String expected = Base64.getEncoder().encodeToString(c.doFinal(value.getBytes(StandardCharsets.UTF_8)));

        // V6: a broken encoder could return the value itself, so the result is compared without being printed.
        assertSamePlain(expected, PassCoder.encode(value, key, CIPHER), "The legacy encoding must match the JDK one");
        assertSamePlain(value, PassCoder.decode(expected, key, CIPHER), "The legacy decoding must return the value");
    }

    static Stream<Arguments> legacyKnownAnswers() {
        // V6: an ASCII and a non-ASCII key and value; Named arguments keep them out of the display names and reports.
        return Stream.of(Arguments.of(Named.of("ascii", KEY), Named.of("ascii value", PASS)),
            Arguments.of(Named.of("non-ascii", random(8) + "\u0416\u4E2D"),
                Named.of("non-ascii value", random(8) + "\u0416\u4E2D")));
    }

    /** One v2 encoding of {@link #PASS} under {@link #KEY}, shared by the tests that need any valid value. */
    private static String encoded;

    @BeforeAll
    static void encodeOnce() throws GeneralSecurityException {
        encoded = PassCoder.encodeV2(PASS, KEY);
    }

    // V6: decrypts the shared v2 value with the JDK alone, so a change of any v2 parameter or of the layout fails.
    /**
     * Recomputes the v2 format with the JDK alone: {@code v2:} followed by the standard Base64 of a 16-byte salt, a
     * 12-byte nonce and the ciphertext with its 16-byte tag; the key is PBKDF2WithHmacSHA256 with 600,000 iterations
     * and 256 bits, and the cipher is AES/GCM/NoPadding with a 128-bit tag and the AAD {@code openl-enc-v2}. Stored
     * {@code ENC(v2:...)} values stay readable only while this holds.
     */
    @Test
    void v2FormatKnownAnswer() throws Exception {
        assertTrue(encoded.startsWith("v2:"), "A v2 value must start with its prefix");
        var text = encoded.substring("v2:".length());
        assertFalse(text.contains(":"), "Only the prefix of a v2 value may contain a colon");
        var payload = Base64.getDecoder().decode(text);
        assertEquals(16 + 12 + PASS.getBytes(StandardCharsets.UTF_8).length + 16, payload.length);

        var salt = Arrays.copyOfRange(payload, 0, 16);
        var nonce = Arrays.copyOfRange(payload, 16, 28);
        var spec = new PBEKeySpec(KEY.toCharArray(), salt, 600_000, 256);
        byte[] k = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        spec.clearPassword();
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD("openl-enc-v2".getBytes(StandardCharsets.UTF_8));
        var plain = new String(c.doFinal(payload, 28, payload.length - 28), StandardCharsets.UTF_8);

        assertSamePlain(PASS, plain, "The JDK decryption of a v2 value must return the value");
    }

    static Stream<Named<String>> v2Values() {
        // Named arguments keep the generated values out of the test display names and reports.
        return Stream.of(Named.of("ascii", random(16)),
            Named.of("unicode", random(8) + "\uD83D\uDD10" + "\u4E2D\u6587" + "\u0416\u044E"),
            Named.of("empty", ""));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("v2Values")
    void v2RoundTrip(String value) throws Exception {
        var v2 = PassCoder.encodeV2(value, KEY);

        assertTrue(v2.startsWith(PassCoder.V2_PREFIX));
        assertSamePlain(value, PassCoder.decodeV2(v2, KEY), "The v2 decoding must return the encoded value");
    }

    @Test
    void v2EncodingsOfTheSameValueDiffer() throws Exception {
        var again = PassCoder.encodeV2(PASS, KEY);

        assertTrue(encoded.startsWith(PassCoder.V2_PREFIX));
        assertTrue(again.startsWith(PassCoder.V2_PREFIX));
        assertNotEquals(encoded, again);
        assertSamePlain(PASS, PassCoder.decodeV2(again, KEY), "Each v2 encoding must decode to the value");
    }

    @Test
    void v2ModifiedBytesFailAuthentication() throws Exception {
        var payload = Base64.getDecoder().decode(encoded.substring(PassCoder.V2_PREFIX.length()));

        // The salt, the nonce, the first byte after the nonce and the last byte of the tag.
        for (int offset : new int[]{0, 20, 28, payload.length - 1}) {
            var modified = payload.clone();
            modified[offset] ^= 0x01;
            var tampered = PassCoder.V2_PREFIX + Base64.getEncoder().encodeToString(modified);

            assertThrows(AEADBadTagException.class,
                () -> PassCoder.decodeV2(tampered, KEY),
                "Modified byte at offset " + offset);
        }
        assertSamePlain(PASS, PassCoder.decodeV2(encoded, KEY), "The unmodified v2 value must still decode");
    }

    @Test
    void v2WrongKeyFailsAuthentication() {
        assertThrows(AEADBadTagException.class, () -> PassCoder.decodeV2(encoded, WRONG_KEY));
    }

    @Test
    @SuppressWarnings("NullAway") // passes null on purpose to check the null contract of decodeV2
    void v2RejectsMalformedValues() {
        var withoutPrefix = random(16);
        var invalidBase64 = PassCoder.V2_PREFIX + "%%%";
        var tooShort = PassCoder.V2_PREFIX + Base64.getEncoder().encodeToString(new byte[43]);

        assertThrows(IllegalArgumentException.class, () -> PassCoder.decodeV2(withoutPrefix, KEY));
        assertThrows(IllegalArgumentException.class, () -> PassCoder.decodeV2(null, KEY));
        assertThrows(IllegalArgumentException.class, () -> PassCoder.decodeV2(invalidBase64, KEY));
        assertThrows(IllegalArgumentException.class, () -> PassCoder.decodeV2(tooShort, KEY));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", " "})
    void v2RejectsBlankKeyMaterial(String keyMaterial) {
        assertThrows(IllegalArgumentException.class, () -> PassCoder.encodeV2(PASS, keyMaterial));
        assertThrows(IllegalArgumentException.class, () -> PassCoder.decodeV2(encoded, keyMaterial));
    }

    @Test
    @SuppressWarnings("NullAway") // passes null on purpose to check the null contract of encodeV2
    void v2RejectsNullValue() {
        assertThrows(NullPointerException.class, () -> PassCoder.encodeV2(null, KEY));
    }

    @Test
    void keyCacheReturnsTheStoredKey() {
        var cache = new PassCoder.KeyCache(2);
        var key = new SecretKeySpec(new byte[32], "AES");

        assertNull(cache.get("a"));
        cache.put("a", key);

        assertSame(key, cache.get("a"));
        assertNull(cache.get("b"));
    }

    @Test
    void keyCacheEvictsTheLeastRecentlyUsedKey() {
        var cache = new PassCoder.KeyCache(2);
        var a = new SecretKeySpec(new byte[32], "AES");
        var b = new SecretKeySpec(new byte[32], "AES");
        var c = new SecretKeySpec(new byte[32], "AES");

        cache.put("a", a);
        cache.put("b", b);
        cache.put("c", c);

        assertNull(cache.get("a"));
        assertSame(b, cache.get("b"));
        assertSame(c, cache.get("c"));
    }

    @Test
    void keyCacheGetRefreshesTheAccessOrder() {
        var cache = new PassCoder.KeyCache(2);
        var a = new SecretKeySpec(new byte[32], "AES");
        var b = new SecretKeySpec(new byte[32], "AES");
        var c = new SecretKeySpec(new byte[32], "AES");

        cache.put("a", a);
        cache.put("b", b);
        assertSame(a, cache.get("a"));
        cache.put("c", c);

        assertNull(cache.get("b"));
        assertSame(a, cache.get("a"));
        assertSame(c, cache.get("c"));
    }

    @Test
    void keyCacheWithoutCapacityKeepsNothing() {
        var cache = new PassCoder.KeyCache(0);

        cache.put("a", new SecretKeySpec(new byte[32], "AES"));

        assertNull(cache.get("a"));
    }

    // V6: callers that miss one cache key together run one derivation, and every caller receives its key.
    @Test
    void keyCacheDerivesOnceForConcurrentMisses() throws Exception {
        int threads = 8;
        var cache = new PassCoder.KeyCache(2);
        var derivations = new AtomicInteger();
        var start = new CountDownLatch(1);
        var arrived = new CountDownLatch(threads);
        var callers = new ConcurrentLinkedQueue<Thread>();
        PassCoder.KeyDerivation derivation = () -> {
            derivations.incrementAndGet();
            // Holds the derivation until every other caller has missed the key and waits for this derivation.
            assertTrue(assertDoesNotThrow(() -> arrived.await(10, TimeUnit.SECONDS)), "Not every caller arrived");
            awaitWaiting(callers);
            return new SecretKeySpec(new byte[32], "AES");
        };
        var pool = daemonPool(threads);
        try {
            var results = new ArrayList<Future<SecretKey>>();
            for (int i = 0; i < threads; i++) {
                results.add(pool.submit(() -> {
                    callers.add(Thread.currentThread());
                    assertTrue(start.await(10, TimeUnit.SECONDS), "The callers were not released");
                    arrived.countDown();
                    return cache.getOrDerive("k", derivation);
                }));
            }
            start.countDown();

            var key = results.get(0).get(30, TimeUnit.SECONDS);
            for (var result : results) {
                assertSame(key, result.get(30, TimeUnit.SECONDS));
            }
            assertSame(key, cache.get("k"));
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, derivations.get());
    }

    // V6: a failed derivation reaches the caller as it is, is not cached, and the next call derives again.
    @Test
    void keyCacheDoesNotCacheAFailedDerivation() throws Exception {
        var cache = new PassCoder.KeyCache(2);
        var failure = new GeneralSecurityException("The derivation failed.");
        var key = new SecretKeySpec(new byte[32], "AES");
        var derivations = new AtomicInteger();

        var thrown = assertThrows(GeneralSecurityException.class, () -> cache.getOrDerive("k", () -> {
            derivations.incrementAndGet();
            throw failure;
        }));
        assertSame(failure, thrown);
        assertNull(cache.get("k"));

        assertSame(key, cache.getOrDerive("k", () -> {
            derivations.incrementAndGet();
            return key;
        }));
        assertEquals(2, derivations.get());
        // A cached key is returned without running the derivation.
        assertSame(key, cache.getOrDerive("k", () -> {
            throw failure;
        }));
    }

    // V6: unchecked failures of a derivation reach the caller as they are; an undeclared checked one is wrapped.
    @Test
    void keyCachePassesOnOtherFailures() {
        var cache = new PassCoder.KeyCache(2);
        var unchecked = new IllegalArgumentException("The derivation failed.");
        var error = new InternalError("The derivation failed.");
        var undeclared = new IOException("The derivation failed.");

        assertSame(unchecked, assertThrows(IllegalArgumentException.class, () -> cache.getOrDerive("k", () -> {
            throw unchecked;
        })));
        assertSame(error, assertThrows(InternalError.class, () -> cache.getOrDerive("k", () -> {
            throw error;
        })));
        var wrapped = assertThrows(IllegalStateException.class,
            () -> cache.getOrDerive("k", () -> sneakyThrow(undeclared)));
        assertSame(undeclared, wrapped.getCause());
        assertNull(cache.get("k"));
    }

    // V6: an interrupted caller still waits for the running derivation, receives its key and stays interrupted.
    @Test
    void keyCacheWaiterKeepsItsInterruptStatus() throws Exception {
        var cache = new PassCoder.KeyCache(2);
        var key = new SecretKeySpec(new byte[32], "AES");
        var waiter = Thread.currentThread();
        var deriving = new CountDownLatch(1);
        var pool = daemonPool(1);
        try {
            var owner = pool.submit(() -> cache.getOrDerive("k", () -> {
                deriving.countDown();
                // Holds the derivation until the interrupted test thread waits for it.
                awaitWaiting(List.of(waiter));
                return key;
            }));
            assertTrue(deriving.await(10, TimeUnit.SECONDS), "The derivation did not start");

            waiter.interrupt();
            SecretKey waited;
            boolean keptInterrupt;
            try {
                waited = cache.getOrDerive("k", () -> {
                    throw new GeneralSecurityException("A waiting caller must not derive.");
                });
            } finally {
                // Clears the status so that nothing after this test runs interrupted.
                keptInterrupt = Thread.interrupted();
            }

            assertTrue(keptInterrupt, "The waiting caller must keep its interrupt status");
            assertSame(key, waited);
            assertSame(key, owner.get(10, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
    }

    /** A pool of daemon threads, so that a caller stuck in a failed test never keeps the test JVM alive. */
    private static ExecutorService daemonPool(int threads) {
        return Executors.newFixedThreadPool(threads, task -> {
            var thread = new Thread(task);
            thread.setDaemon(true);
            return thread;
        });
    }

    /**
     * Waits up to ten seconds until every given thread other than the current one is parked without a timeout, as a
     * caller waiting for a derivation is.
     */
    private static void awaitWaiting(Collection<Thread> threads) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        for (var thread : threads) {
            while (!thread.equals(Thread.currentThread()) && thread.getState() != Thread.State.WAITING) {
                assertTrue(System.nanoTime() - deadline < 0, "A caller did not wait for the running derivation");
                LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
            }
        }
    }

    /** Throws a checked exception the caller does not declare, as a misbehaving security provider could. */
    @SuppressWarnings("unchecked")
    private static <T extends Throwable> SecretKey sneakyThrow(Throwable failure) throws T {
        throw (T) failure;
    }

    private static String random(int bytes) {
        var buffer = new byte[bytes];
        RANDOM.nextBytes(buffer);
        return HexFormat.of().formatHex(buffer);
    }

    // V6: compares plain values without handing them to the assertion, so a failure prints only the fixed message.
    private static void assertSamePlain(String expected, @Nullable String actual, String message) {
        assertTrue(expected.equals(actual), message);
    }

    /**
     * Returns a generated key that differs from {@link #KEY} and whose legacy decoding of an encoding under
     * {@link #KEY} throws, trying at most 100 candidates.
     */
    private static String wrongKey() {
        String coded;
        try {
            coded = PassCoder.encode(PASS, KEY, CIPHER);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("The legacy cipher is not available.", e);
        }
        for (int i = 0; i < 100; i++) {
            var candidate = random(32);
            if (!candidate.equals(KEY) && legacyDecodingFails(coded, candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("No generated key failed the legacy decoding.");
    }

    private static boolean legacyDecodingFails(String coded, String candidate) {
        try {
            PassCoder.decode(coded, candidate, CIPHER);
            return false;
        } catch (Exception e) {
            // The same failure the wrong-key assertion of testPassCodingEncoding relies on.
            return true;
        }
    }
}

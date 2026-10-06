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
import java.util.stream.IntStream;
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

        // V6: the first byte of the salt, then every byte of the nonce, of the ciphertext and of the tag in turn.
        for (int offset : IntStream.concat(IntStream.of(0), IntStream.range(16, payload.length)).toArray()) {
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

    // V6: encodeV2 proves the key it encrypted with, so the reads of a saved value find it among the authenticated
    // keys.
    @Test
    void v2EncodingProvesItsKey() {
        var payload = Base64.getDecoder().decode(encoded.substring(PassCoder.V2_PREFIX.length()));

        assertTrue(PassCoder.KEYS.isAuthenticated(slotOf(KEY, Arrays.copyOfRange(payload, 0, 16))),
            "The key that encrypted a value must be authenticated");
    }

    // V6: decodeV2 proves a key only after the GCM tag accepted it; every rejection leaves the salt unproven.
    @Test
    void v2DecodingProvesOnlyTheKeyThatAuthenticated() throws Exception {
        // Encrypted with the JDK alone, so no PassCoder call has seen its salt yet.
        var salt = new byte[16];
        RANDOM.nextBytes(salt);
        var nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        var spec = new PBEKeySpec(KEY.toCharArray(), salt, 600_000, 256);
        byte[] k = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        spec.clearPassword();
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD("openl-enc-v2".getBytes(StandardCharsets.UTF_8));
        var encrypted = c.doFinal(PASS.getBytes(StandardCharsets.UTF_8));
        var payload = new byte[28 + encrypted.length];
        System.arraycopy(salt, 0, payload, 0, 16);
        System.arraycopy(nonce, 0, payload, 16, 12);
        System.arraycopy(encrypted, 0, payload, 28, encrypted.length);
        var value = PassCoder.V2_PREFIX + Base64.getEncoder().encodeToString(payload);
        var tamperedPayload = payload.clone();
        tamperedPayload[payload.length - 1] ^= 0x01;
        var tampered = PassCoder.V2_PREFIX + Base64.getEncoder().encodeToString(tamperedPayload);
        var right = slotOf(KEY, salt);
        var wrong = slotOf(WRONG_KEY, salt);

        assertThrows(AEADBadTagException.class, () -> PassCoder.decodeV2(tampered, KEY));
        assertFalse(PassCoder.KEYS.isAuthenticated(right), "The right key of a modified value must not be proven");
        assertThrows(AEADBadTagException.class, () -> PassCoder.decodeV2(value, WRONG_KEY));
        assertFalse(PassCoder.KEYS.isAuthenticated(wrong), "A key the GCM tag rejected must not be proven");
        assertFalse(PassCoder.KEYS.isAuthenticated(right), "A rejection of another key must not prove the right one");

        assertSamePlain(PASS, PassCoder.decodeV2(value, KEY), "The v2 decoding must return the encrypted value");
        assertTrue(PassCoder.KEYS.isAuthenticated(right), "The key that authenticated the value must be proven");
        assertTrue(PassCoder.KEYS.isRejected(wrong), "The candidates of a proven salt must become its rejected keys");
        assertFalse(PassCoder.KEYS.isAuthenticated(wrong), "A rejected key must never count as authenticated");
    }

    // V6: wrong keys tried against a live value never evict the key that authenticated it, so the next read of the
    // value derives nothing.
    @Test
    void v2RejectedKeysNeverEvictTheAuthenticatedKey() throws Exception {
        var keyMaterial = random(32);
        var plain = random(16);
        var value = PassCoder.encodeV2(plain, keyMaterial);
        var right = slotOfValue(value, keyMaterial);
        var authenticated = PassCoder.KEYS.get(right);
        assertNotNull(authenticated, "The key that encrypted the value must be cached");

        var wrongKeys = new ArrayList<String>();
        for (int i = 0; i < PassCoder.KeyCache.REJECTED_PER_SALT + 2; i++) {
            var wrongKey = random(32);
            wrongKeys.add(wrongKey);
            assertThrows(AEADBadTagException.class, () -> PassCoder.decodeV2(value, wrongKey));
        }

        assertSame(authenticated, PassCoder.KEYS.get(right), "No rejected key may evict the authenticated one");
        assertSamePlain(plain, PassCoder.decodeV2(value, keyMaterial), "The value must decrypt with its key");
        assertSame(authenticated, PassCoder.KEYS.get(right), "The read must use the cached key, not derive one");
        assertTrue(PassCoder.KEYS.isAuthenticated(right), "The key of the value must stay authenticated");
        for (int i = 0; i < wrongKeys.size(); i++) {
            var wrong = slotOfValue(value, wrongKeys.get(i));
            assertFalse(PassCoder.KEYS.isAuthenticated(wrong), "A wrong key must never count as authenticated");
            assertEquals(i >= wrongKeys.size() - PassCoder.KeyCache.REJECTED_PER_SALT,
                PassCoder.KEYS.isRejected(wrong),
                "Only the most recent wrong keys are kept, at most " + PassCoder.KeyCache.REJECTED_PER_SALT);
        }
    }

    // V6: forgetting a v2 value drops every key of its salt; a value that cannot have a cached key is ignored.
    @Test
    void v2ForgetDropsTheKeysOfTheValueOnly() throws Exception {
        var plain = random(16);
        var value = PassCoder.encodeV2(plain, KEY);
        var right = slotOfValue(value, KEY);
        assertThrows(AEADBadTagException.class, () -> PassCoder.decodeV2(value, WRONG_KEY));
        var wrong = slotOfValue(value, WRONG_KEY);
        var other = slotOfValue(encoded, KEY);
        assertTrue(PassCoder.KEYS.isAuthenticated(right), "The key of the value must be authenticated");
        assertTrue(PassCoder.KEYS.isRejected(wrong), "The wrong key of the value must be rejected");
        assertTrue(PassCoder.KEYS.isAuthenticated(other), "The key of another value must be authenticated");

        // Null, without the prefix, not Base64, and shorter than a salt, a nonce and a tag, though it starts with
        // the salt of the value.
        var payload = Base64.getDecoder().decode(value.substring(PassCoder.V2_PREFIX.length()));
        var tooShort = PassCoder.V2_PREFIX + Base64.getEncoder().encodeToString(Arrays.copyOf(payload, 43));
        for (var malformed : Arrays.asList(null, value.substring(PassCoder.V2_PREFIX.length()), "v2:%%%", tooShort)) {
            assertDoesNotThrow(() -> PassCoder.forget(malformed), "A malformed value must be ignored");
        }
        assertTrue(PassCoder.KEYS.isAuthenticated(right), "A malformed value must not drop any key");
        assertTrue(PassCoder.KEYS.isRejected(wrong), "A malformed value must not drop any key");

        PassCoder.forget(value);

        assertNull(PassCoder.KEYS.get(right), "The key of a forgotten value must be dropped");
        assertNull(PassCoder.KEYS.get(wrong), "The wrong key of a forgotten value must be dropped");
        assertTrue(PassCoder.KEYS.isAuthenticated(other), "The key of another value must be kept");
        assertSamePlain(plain, PassCoder.decodeV2(value, KEY), "A forgotten value must still decrypt");
        assertTrue(PassCoder.KEYS.isAuthenticated(right), "A forgotten value read again is authenticated again");
    }

    @Test
    void keyCacheReturnsTheStoredKey() throws Exception {
        var cache = cache(2);
        var key = newKey();

        assertNull(cache.get(slot("s", "a")));
        assertSame(key, cache.getOrDerive(slot("s", "a"), () -> key));

        assertSame(key, cache.get(slot("s", "a")));
        assertNull(cache.get(slot("s", "b")));
        assertNull(cache.get(slot("t", "a")));
        assertFalse(cache.isAuthenticated(slot("s", "a")), "A derived key must stay unproven until it is proven");
        assertFalse(cache.isRejected(slot("s", "a")), "A key of an unproven salt must be a candidate");
    }

    @Test
    void keyCacheEvictsTheLeastRecentlyUsedCandidate() throws Exception {
        var cache = cache(2);
        var a = newKey();
        var b = newKey();
        var c = newKey();

        cache.getOrDerive(slot("a", "m"), () -> a);
        cache.getOrDerive(slot("b", "m"), () -> b);
        cache.getOrDerive(slot("c", "m"), () -> c);

        assertNull(cache.get(slot("a", "m")));
        assertSame(b, cache.get(slot("b", "m")));
        assertSame(c, cache.get(slot("c", "m")));
    }

    @Test
    void keyCacheGetRefreshesTheAccessOrder() throws Exception {
        var cache = cache(2);
        var a = newKey();
        var b = newKey();
        var c = newKey();

        cache.getOrDerive(slot("a", "m"), () -> a);
        cache.getOrDerive(slot("b", "m"), () -> b);
        assertSame(a, cache.get(slot("a", "m")));
        cache.getOrDerive(slot("c", "m"), () -> c);

        assertNull(cache.get(slot("b", "m")));
        assertSame(a, cache.get(slot("a", "m")));
        assertSame(c, cache.get(slot("c", "m")));
    }

    // V6: without capacity no unproven key is kept, while a proven key still is.
    @Test
    void keyCacheWithoutCapacityKeepsNoUnprovenKey() throws Exception {
        var cache = cache(0);
        var key = newKey();

        assertSame(key, cache.getOrDerive(slot("s", "m"), () -> key));
        assertNull(cache.get(slot("s", "m")));

        cache.prove(slot("s", "m"), key);
        assertSame(key, cache.get(slot("s", "m")));
        assertTrue(cache.isAuthenticated(slot("s", "m")), "A proven key must be kept without candidate capacity");
    }

    // V6: a working set of live ciphertexts larger than the capacity is derived once, however often it is read.
    @Test
    void keyCacheDerivesALiveWorkingSetAboveItsCapacityOnce() throws Exception {
        var cache = cache(256);
        var derivations = new AtomicInteger();

        for (int round = 0; round < 3; round++) {
            for (int i = 0; i < 300; i++) {
                read(cache, slot("salt" + i, "right"), derivations);
            }
        }

        assertEquals(300, derivations.get());
    }

    // V6: the keys of live ciphertexts stay however many further values are saved, since a group lives as long as
    // its ciphertext is configured.
    @Test
    void keyCacheKeepsALiveWorkingSetWhateverIsSavedAfterIt() throws Exception {
        var cache = cache(256);
        var derivations = new AtomicInteger();
        for (int i = 0; i < 300; i++) {
            read(cache, slot("live" + i, "right"), derivations);
        }
        // Each save encrypts a new value under a new salt and proves its key.
        for (int i = 0; i < 1000; i++) {
            read(cache, slot("saved" + i, "right"), derivations);
        }
        assertEquals(1300, derivations.get());

        for (int i = 0; i < 300; i++) {
            read(cache, slot("live" + i, "right"), derivations);
        }

        assertEquals(1300, derivations.get(), "Rereading the live values must not derive any key");
    }

    // V6: the wrong keys tried against a live salt, before or after it is proven, are derived once as well.
    @ParameterizedTest(name = "wrong key tried from the first round: {0}")
    @ValueSource(booleans = {true, false})
    void keyCacheDerivesTheWrongKeysOfALiveWorkingSetOnce(boolean wrongFromTheFirstRound) throws Exception {
        var cache = cache(256);
        var derivations = new AtomicInteger();

        for (int round = 0; round < 3; round++) {
            for (int i = 0; i < 300; i++) {
                if (wrongFromTheFirstRound || round > 0) {
                    // Rejected by the GCM tag, as the configured secret.key is for a value of the instance key.
                    cache.getOrDerive(slot("salt" + i, "wrong"), counting(derivations));
                }
                read(cache, slot("salt" + i, "right"), derivations);
            }
        }

        assertEquals(600, derivations.get());
        assertTrue(cache.isRejected(slot("salt0", "wrong")), "The wrong key of a proven salt must be rejected");
    }

    // V6: arbitrary keys of salts no key has proven evict only one another, never a proven key.
    @Test
    void keyCacheUnprovenSaltsNeverEvictProvenKeys() throws Exception {
        int capacity = 256;
        var cache = cache(capacity);
        var proven = new AtomicInteger();
        var unproven = new AtomicInteger();
        for (int i = 0; i < 300; i++) {
            read(cache, slot("live" + i, "right"), proven);
        }

        for (int i = 0; i < 1000; i++) {
            cache.getOrDerive(slot("foreign" + i, "any"), counting(unproven));
            read(cache, slot("live" + i % 300, "right"), proven);
        }

        assertEquals(300, proven.get(), "The arbitrary salts must not evict a proven key");
        assertEquals(1000, unproven.get());
        // Only the most recent candidates are kept, and none of them is proven.
        assertNull(cache.get(slot("foreign" + (1000 - capacity - 1), "any")));
        for (int i = 1000 - capacity; i < 1000; i++) {
            assertNotNull(cache.get(slot("foreign" + i, "any")));
            assertFalse(cache.isAuthenticated(slot("foreign" + i, "any")), "An unproven salt must stay unproven");
        }
    }

    // V6: wrong keys tried against an authenticated salt are kept apart from its key, at most REJECTED_PER_SALT of
    // them, and never displace the key or a candidate of another salt.
    @Test
    void keyCacheRejectedKeysNeverDisplaceTheAuthenticatedKey() throws Exception {
        int rejected = PassCoder.KeyCache.REJECTED_PER_SALT;
        var cache = cache(1);
        var right = newKey();
        var other = newKey();
        cache.prove(slot("s", "right"), right);
        cache.getOrDerive(slot("t", "other"), () -> other);
        var derivations = new AtomicInteger();

        for (int i = 0; i < 10; i++) {
            cache.getOrDerive(slot("s", "wrong" + i), counting(derivations));
        }

        assertEquals(10, derivations.get());
        assertSame(right, cache.getOrDerive(slot("s", "right"), counting(derivations)));
        assertEquals(10, derivations.get(), "The authenticated key must be returned without a derivation");
        assertTrue(cache.isAuthenticated(slot("s", "right")), "The authenticated key must stay authenticated");
        for (int i = 0; i < 10; i++) {
            var wrong = slot("s", "wrong" + i);
            assertFalse(cache.isAuthenticated(wrong), "A wrong key must never count as authenticated");
            if (i < 10 - rejected) {
                assertNull(cache.get(wrong), "Only the " + rejected + " most recent wrong keys may be kept");
            } else {
                assertTrue(cache.isRejected(wrong), "The most recent wrong keys must be kept as rejected");
            }
        }
        assertSame(other, cache.get(slot("t", "other")), "The keys of a proven salt must not evict a candidate");
    }

    // V6: the first proof of a salt turns its other candidates into rejected keys and leaves the other salts alone.
    @Test
    void keyCacheProofMovesTheCandidatesOfItsSalt() throws Exception {
        var cache = cache(3);
        var wrong = newKey();
        var other = newKey();
        var right = newKey();
        cache.getOrDerive(slot("s", "wrong"), () -> wrong);
        cache.getOrDerive(slot("t", "other"), () -> other);
        cache.getOrDerive(slot("s", "right"), () -> right);

        cache.prove(slot("s", "right"), right);
        // A second proof keeps the key it already holds.
        cache.prove(slot("s", "right"), newKey());

        assertSame(right, cache.get(slot("s", "right")));
        assertTrue(cache.isAuthenticated(slot("s", "right")), "The proven key must be authenticated");
        assertFalse(cache.isRejected(slot("s", "right")), "The proven key must not be kept as rejected too");
        assertSame(wrong, cache.get(slot("s", "wrong")));
        assertTrue(cache.isRejected(slot("s", "wrong")), "A candidate of a proven salt must become a rejected key");
        assertFalse(cache.isRejected(slot("t", "other")), "A candidate of another salt must stay a candidate");
        for (int i = 0; i < 3; i++) {
            cache.getOrDerive(slot("n" + i, "m"), PassCoderTest::newKey);
        }
        assertNull(cache.get(slot("t", "other")), "A candidate must still be evicted by newer candidates");
        assertSame(wrong, cache.get(slot("s", "wrong")), "A rejected key must not be evicted with the candidates");
    }

    // V6: a key derived for a salt after its first proof is a rejected key until it authenticates the salt too.
    @Test
    void keyCacheLaterProofAuthenticatesARejectedKey() throws Exception {
        var cache = cache(1);
        var first = newKey();
        var later = newKey();
        cache.prove(slot("s", "first"), first);
        cache.getOrDerive(slot("s", "later"), () -> later);
        assertTrue(cache.isRejected(slot("s", "later")), "A key derived for a proven salt must be rejected first");

        cache.prove(slot("s", "later"), later);

        assertTrue(cache.isAuthenticated(slot("s", "later")), "A proven key must be authenticated");
        assertFalse(cache.isRejected(slot("s", "later")), "A proven key must no longer be kept as rejected");
        assertSame(first, cache.get(slot("s", "first")));
        assertSame(later, cache.get(slot("s", "later")));
    }

    // V6: a derivation that ends after its key authenticated the salt meanwhile keeps the authenticated key.
    @Test
    void keyCacheDerivationKeepsAKeyAuthenticatedMeanwhile() throws Exception {
        var cache = cache(1);
        var authenticated = newKey();
        cache.prove(slot("s", "other"), newKey());

        var derived = cache.getOrDerive(slot("s", "m"), () -> {
            // Another reader proves the same key while this derivation runs.
            cache.prove(slot("s", "m"), authenticated);
            return newKey();
        });

        assertNotNull(derived);
        assertSame(authenticated, cache.get(slot("s", "m")), "The authenticated key must be kept");
        assertFalse(cache.isRejected(slot("s", "m")), "An authenticated key must not be kept as rejected too");
    }

    // V6: forgetting a salt drops its group and its candidates, and only those.
    @Test
    void keyCacheForgetDropsTheKeysOfASalt() throws Exception {
        var cache = cache(4);
        var kept = newKey();
        var candidate = newKey();
        cache.prove(slot("s", "right"), newKey());
        cache.getOrDerive(slot("s", "wrong"), PassCoderTest::newKey);
        cache.getOrDerive(slot("u", "any"), PassCoderTest::newKey);
        cache.prove(slot("t", "right"), kept);
        cache.getOrDerive(slot("v", "any"), () -> candidate);

        cache.forget("s");
        cache.forget("u");
        cache.forget("unknown");

        assertNull(cache.get(slot("s", "right")), "The authenticated key of a forgotten salt must be dropped");
        assertFalse(cache.isAuthenticated(slot("s", "right")), "A forgotten salt must not stay authenticated");
        assertNull(cache.get(slot("s", "wrong")), "The rejected key of a forgotten salt must be dropped");
        assertNull(cache.get(slot("u", "any")), "The candidate of a forgotten salt must be dropped");
        assertSame(kept, cache.get(slot("t", "right")), "The group of another salt must be kept");
        assertSame(candidate, cache.get(slot("v", "any")), "The candidate of another salt must be kept");

        // A forgotten salt read again is derived once and authenticated again.
        var derivations = new AtomicInteger();
        read(cache, slot("s", "right"), derivations);
        read(cache, slot("s", "right"), derivations);
        assertEquals(1, derivations.get());
        assertTrue(cache.isAuthenticated(slot("s", "right")), "A salt read again must be authenticated again");
    }

    // V6: callers that miss one cache key together run one derivation, and every caller receives its key.
    @Test
    void keyCacheDerivesOnceForConcurrentMisses() throws Exception {
        int threads = 8;
        var cache = cache(2);
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
                    return cache.getOrDerive(K, derivation);
                }));
            }
            start.countDown();

            var key = results.get(0).get(30, TimeUnit.SECONDS);
            for (var result : results) {
                assertSame(key, result.get(30, TimeUnit.SECONDS));
            }
            assertSame(key, cache.get(K));
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, derivations.get());
    }

    // V6: a failed derivation reaches the caller as it is, is not cached, and the next call derives again.
    @Test
    void keyCacheDoesNotCacheAFailedDerivation() throws Exception {
        var cache = cache(2);
        var failure = new GeneralSecurityException("The derivation failed.");
        var key = new SecretKeySpec(new byte[32], "AES");
        var derivations = new AtomicInteger();

        var thrown = assertThrows(GeneralSecurityException.class, () -> cache.getOrDerive(K, () -> {
            derivations.incrementAndGet();
            throw failure;
        }));
        assertSame(failure, thrown);
        assertNull(cache.get(K));

        assertSame(key, cache.getOrDerive(K, () -> {
            derivations.incrementAndGet();
            return key;
        }));
        assertEquals(2, derivations.get());
        // A cached key is returned without running the derivation.
        assertSame(key, cache.getOrDerive(K, () -> {
            throw failure;
        }));
    }

    // V6: unchecked failures of a derivation reach the caller as they are; an undeclared checked one is wrapped.
    @Test
    void keyCachePassesOnOtherFailures() {
        var cache = cache(2);
        var unchecked = new IllegalArgumentException("The derivation failed.");
        var error = new InternalError("The derivation failed.");
        var undeclared = new IOException("The derivation failed.");

        assertSame(unchecked, assertThrows(IllegalArgumentException.class, () -> cache.getOrDerive(K, () -> {
            throw unchecked;
        })));
        assertSame(error, assertThrows(InternalError.class, () -> cache.getOrDerive(K, () -> {
            throw error;
        })));
        var wrapped = assertThrows(IllegalStateException.class,
            () -> cache.getOrDerive(K, () -> sneakyThrow(undeclared)));
        assertSame(undeclared, wrapped.getCause());
        assertNull(cache.get(K));
    }

    // V6: an interrupted caller still waits for the running derivation, receives its key and stays interrupted.
    @Test
    void keyCacheWaiterKeepsItsInterruptStatus() throws Exception {
        var cache = cache(2);
        var key = new SecretKeySpec(new byte[32], "AES");
        var waiter = Thread.currentThread();
        var deriving = new CountDownLatch(1);
        var pool = daemonPool(1);
        try {
            var owner = pool.submit(() -> cache.getOrDerive(K, () -> {
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
                waited = cache.getOrDerive(K, () -> {
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

    /** The cache key the concurrency tests share. */
    private static final PassCoder.KeySlot K = slot("s", "k");

    private static PassCoder.KeyCache cache(int capacity) {
        return new PassCoder.KeyCache(capacity);
    }

    private static PassCoder.KeySlot slot(String salt, String material) {
        return new PassCoder.KeySlot(salt, material);
    }

    /** The slot PassCoder uses for a key material and salt, computed with the JDK alone. */
    private static PassCoder.KeySlot slotOf(String keyMaterial, byte[] salt) {
        try {
            var digest = MessageDigest.getInstance("SHA-256").digest(keyMaterial.getBytes(StandardCharsets.UTF_8));
            return slot(Base64.getEncoder().encodeToString(salt), HexFormat.of().formatHex(digest));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is not available.", e);
        }
    }

    private static SecretKey newKey() {
        return new SecretKeySpec(new byte[32], "AES");
    }

    /** A derivation that counts its runs and makes a new key each time. */
    private static PassCoder.KeyDerivation counting(AtomicInteger derivations) {
        return () -> {
            derivations.incrementAndGet();
            return newKey();
        };
    }

    /** Reads a value as decodeV2 does when the key authenticates it: finds or derives the key, then proves it. */
    private static void read(PassCoder.KeyCache cache,
            PassCoder.KeySlot slot,
            AtomicInteger derivations) throws GeneralSecurityException {
        cache.prove(slot, cache.getOrDerive(slot, counting(derivations)));
    }

    /** The slot PassCoder uses for a v2 value under a key material. */
    private static PassCoder.KeySlot slotOfValue(String v2, String keyMaterial) {
        var payload = Base64.getDecoder().decode(v2.substring(PassCoder.V2_PREFIX.length()));
        return slotOf(keyMaterial, Arrays.copyOf(payload, 16));
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

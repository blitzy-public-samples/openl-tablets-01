package org.openl.spring.env;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.stream.Stream;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
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

        assertNull(decodedPass);

        decodedPass = assertDoesNotThrow(() -> PassCoder.decode(codedPass, KEY, CIPHER));

        assertEquals(PASS, decodedPass);
    }

    @Test
    void testEmpty() throws Exception {
        // V6: the generated PASS and KEY replace the literal value and key; the assertions are unchanged.
        assertEquals(PASS, PassCoder.encode(PASS, "", CIPHER));
        assertEquals(PASS, PassCoder.encode(PASS, " ", CIPHER));
        assertEquals(PASS, PassCoder.encode(PASS, null, CIPHER));
        assertEquals("", PassCoder.encode("", KEY, CIPHER));
        assertEquals(" ", PassCoder.encode(" ", KEY, CIPHER));
        assertNull(PassCoder.encode(null, KEY, CIPHER));
        assertEquals("", PassCoder.encode("", "", CIPHER));

        assertEquals(PASS, PassCoder.decode(PASS, "", CIPHER));
        assertEquals(PASS, PassCoder.decode(PASS, " ", CIPHER));
        assertEquals(PASS, PassCoder.decode(PASS, null, CIPHER));
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
     * holds.
     */
    @Test
    void legacyFormatKnownAnswer() throws Exception {
        byte[] k = Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest(KEY.getBytes(StandardCharsets.UTF_8)), 16);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"), new IvParameterSpec(new byte[16]));
        String expected = Base64.getEncoder().encodeToString(c.doFinal(PASS.getBytes(StandardCharsets.UTF_8)));

        assertEquals(expected, PassCoder.encode(PASS, KEY, CIPHER));
        assertEquals(PASS, PassCoder.decode(expected, KEY, CIPHER));
    }

    /** One v2 encoding of {@link #PASS} under {@link #KEY}, shared by the tests that need any valid value. */
    private static String encoded;

    @BeforeAll
    static void encodeOnce() throws GeneralSecurityException {
        encoded = PassCoder.encodeV2(PASS, KEY);
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
        assertEquals(value, PassCoder.decodeV2(v2, KEY));
    }

    @Test
    void v2EncodingsOfTheSameValueDiffer() throws Exception {
        var again = PassCoder.encodeV2(PASS, KEY);

        assertTrue(encoded.startsWith(PassCoder.V2_PREFIX));
        assertTrue(again.startsWith(PassCoder.V2_PREFIX));
        assertNotEquals(encoded, again);
        assertEquals(PASS, PassCoder.decodeV2(again, KEY));
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
        assertEquals(PASS, PassCoder.decodeV2(encoded, KEY));
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

    private static String random(int bytes) {
        var buffer = new byte[bytes];
        RANDOM.nextBytes(buffer);
        return HexFormat.of().formatHex(buffer);
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

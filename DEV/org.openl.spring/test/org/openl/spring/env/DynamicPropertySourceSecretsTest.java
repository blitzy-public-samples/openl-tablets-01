package org.openl.spring.env;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.mockito.Mockito;
import org.slf4j.simple.SimpleLogger;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;

import org.openl.info.OpenLVersion;
import org.openl.util.HashingUtils;
import org.openl.util.PropertiesUtils;

/**
 * Tests of how {@link DynamicPropertySource} stores and reads the secrets of V6: values given to {@code save()} are
 * plain text whatever they look like, stored values keep their reading contract, readers keep the stored settings
 * while secrets are encrypted, and a v2 value that cannot be decrypted reads as {@code ""} with one ERROR that names
 * the property and the cause.
 *
 * <p>Each test uses its own {@code openl.home.shared}. Every key, value and ciphertext is generated at run time.
 * Secrets are compared through {@link #assertSecret}, which fails with a fixed message, so a failing assertion never
 * prints a secret into the test report, and every test that captures the log asserts that none of its generated
 * values, ciphertexts or keys was logged.
 */
class DynamicPropertySourceSecretsTest {

    private static final String APP = "test-app";
    private static final String CIPHER = "AES/CBC/PKCS5Padding";
    private static final String V2_STORED = "ENC(v2:";
    private static final SecureRandom RANDOM = new SecureRandom();

    // V6: characters that could end a log line or pass for another one, each with the rendering a log line or a
    // message gives it: CR, LF, CRLF, NEL, the line and paragraph separators, a format character (the right-to-left
    // override), the quotes and the backslash.
    private static final List<Hostile> HOSTILE = List.of(new Hostile("\r", "\\u000D"),
            new Hostile("\n", "\\u000A"),
            new Hostile("\r\n", "\\u000D\\u000A"),
            new Hostile("\u0085", "\\u0085"),
            new Hostile("\u2028", "\\u2028"),
            new Hostile("\u2029", "\\u2029"),
            new Hostile("\u202E", "\\u202E"),
            new Hostile("'", "\\u0027"),
            new Hostile("\"", "\\u0022"),
            new Hostile("\\", "\\u005C"));
    // V6: the end of every hostile name, after its hostile characters.
    private static final String HOSTILE_TAIL = "b.password";

    private DynamicPropertySource previous;

    @BeforeAll
    static void initLog() {
        // ConfigLog prints the OpenL info block from its static initializer. Loading it here keeps that block out of
        // the output a test captures.
        ConfigLog.LOG.isDebugEnabled();
    }

    @BeforeEach
    void rememberRegisteredSource() {
        previous = DynamicPropertySource.get();
    }

    @AfterEach
    void restoreRegisteredSource() {
        DynamicPropertySource.register(previous);
    }

    // A value given to save() is plain text, even when it looks like a stored ENC(...) value.
    @Test
    @StdIo
    void givenValuesShapedLikeEncAreEncryptedWithConfiguredKey(StdErr err, @TempDir Path home) throws IOException {
        var legacyShaped = hex();
        var v2Shaped = v2Inner();
        assertGivenValuesEncrypted(err,
                home,
                key(),
                List.of(new Given("x.password", legacyShaped, "ENC(" + legacyShaped + ")"),
                        new Given("y.secret", v2Shaped, "ENC(" + v2Shaped + ")")));
    }

    // The same with the blank secret.key, which encrypts with the instance key.
    @Test
    @StdIo
    void givenValuesShapedLikeEncAreEncryptedWithInstanceKey(StdErr err, @TempDir Path home) throws IOException {
        var legacyShaped = hex();
        var v2Shaped = v2Inner();
        assertGivenValuesEncrypted(err,
                home,
                null,
                List.of(new Given("x.password", legacyShaped, "ENC(" + legacyShaped + ")"),
                        new Given("y.secret", v2Shaped, "ENC(" + v2Shaped + ")")));
    }

    // An ENC-looking value with surrounding blanks is plain text too, and reads back exactly as given.
    @Test
    @StdIo
    void paddedEncLookingValuesAreEncryptedWithConfiguredKey(StdErr err, @TempDir Path home) throws IOException {
        var legacyShaped = hex();
        var v2Shaped = v2Inner();
        assertGivenValuesEncrypted(err,
                home,
                key(),
                List.of(new Given("x.password", legacyShaped, " ENC(" + legacyShaped + ") "),
                        new Given("y.token", v2Shaped, "ENC(" + v2Shaped + ")\t")));
    }

    // The same with the blank secret.key.
    @Test
    @StdIo
    void paddedEncLookingValuesAreEncryptedWithInstanceKey(StdErr err, @TempDir Path home) throws IOException {
        var legacyShaped = hex();
        var v2Shaped = v2Inner();
        assertGivenValuesEncrypted(err,
                home,
                null,
                List.of(new Given("x.password", legacyShaped, " ENC(" + legacyShaped + ") "),
                        new Given("y.token", v2Shaped, "ENC(" + v2Shaped + ")\t")));
    }

    // A padded legacy ciphertext of the default is a different plain text, so it is not removed as the
    // default; an unchanged second save keeps its ciphertext.
    @Test
    @StdIo
    void paddedLegacyCiphertextOfTheDefaultIsNotTheDefault(StdErr err, @TempDir Path home) throws Exception {
        var secretKey = key();
        var plain = hex();
        var legacy = PassCoder.encode(plain, secretKey, CIPHER);
        var given = " ENC(" + legacy + ") ";
        var source = open(home, secretKey, Map.of("x.password", plain));

        source.save(Map.of("x.password", given));

        var stored = stored(source, "x.password");
        assertTrue(stored.startsWith(V2_STORED), "The given value must be stored in the v2 format");
        assertFalse(stored.contains(legacy), "The stored value must not hold the given text");
        assertSecret(given, source.getProperty("x.password"), "The given value must read back exactly");

        var file = settingsFile(home);
        var before = Files.readString(file);
        source.save(Map.of("x.password", given));
        assertTrue(stored.equals(stored(source, "x.password")), "An unchanged secret must keep its ciphertext");
        assertTrue(before.equals(Files.readString(file)), "An unchanged save must not rewrite the file");

        assertNoneLogged(err.capturedString(), List.of(secretKey, plain, legacy, stored));
    }

    // Stored values are read as before: trimmed, then unwrapped; legacy values are re-encrypted on the next
    // save and v2 values are kept as they are.
    @Test
    @StdIo
    void storedValuesKeepTheirReadingContract(StdErr err, @TempDir Path home) throws Exception {
        var secretKey = key();
        var first = hex();
        var second = hex();
        var third = hex();
        var firstLegacy = PassCoder.encode(first, secretKey, CIPHER);
        var secondLegacy = PassCoder.encode(second, secretKey, CIPHER);
        var thirdV2 = "ENC(" + PassCoder.encodeV2(third, secretKey) + ")";
        var plainStored = hex();
        writeSettings(home,
                "a.password=ENC(" + firstLegacy + ")",
                "b.password=ENC(" + secondLegacy + ")\\t",
                "c.password=" + thirdV2,
                "d.password=" + plainStored,
                "e.password=");
        var source = open(home, secretKey, Map.of());
        assertTrue(("ENC(" + secondLegacy + ")\t").equals(stored(source, "b.password")),
                "The escaped trailing tab must be part of the stored value");

        assertSecret(first, source.getProperty("a.password"), "A stored legacy value must decrypt");
        assertSecret(second, source.getProperty("b.password"), "A stored legacy value with a tab must decrypt");
        assertSecret(third, source.getProperty("c.password"), "A stored v2 value must decrypt");
        assertSecret(plainStored, source.getProperty("d.password"), "A stored plain-text value must read as it is");

        source.save(Map.of("unrelated.name", hex()));

        var firstStored = stored(source, "a.password");
        var secondStored = stored(source, "b.password");
        var plainEncrypted = stored(source, "d.password");
        assertTrue(firstStored.startsWith(V2_STORED), "A stored legacy value must be re-encrypted in the v2 format");
        assertTrue(secondStored.startsWith(V2_STORED), "A stored legacy value must be re-encrypted in the v2 format");
        assertFalse(secondStored.contains(secondLegacy), "The legacy ciphertext must not be kept");
        assertTrue(thirdV2.equals(stored(source, "c.password")), "A stored v2 value must be kept as it is");
        assertTrue(plainEncrypted.startsWith(V2_STORED), "A stored plain-text value must be encrypted");
        // V6: a blank secret is encrypted too, and still reads as empty.
        var blankEncrypted = stored(source, "e.password");
        assertTrue(blankEncrypted.startsWith(V2_STORED), "A stored blank value must be encrypted");
        assertEquals("", source.getProperty("e.password"), "An encrypted blank value must read as empty");
        assertSecret(first, source.getProperty("a.password"), "A re-encrypted value must read as before");
        assertSecret(second, source.getProperty("b.password"), "A re-encrypted value must read as before");
        assertSecret(third, source.getProperty("c.password"), "A kept v2 value must read as before");
        assertSecret(plainStored, source.getProperty("d.password"), "An encrypted value must read as before");

        var reopened = open(home, secretKey, Map.of());
        assertSecret(first, reopened.getProperty("a.password"), "A re-encrypted value must read from the file");
        assertSecret(second, reopened.getProperty("b.password"), "A re-encrypted value must read from the file");
        assertSecret(third, reopened.getProperty("c.password"), "A kept v2 value must read from the file");
        assertSecret(plainStored, reopened.getProperty("d.password"), "An encrypted value must read from the file");
        assertFalse(Files.readString(settingsFile(home)).contains(plainStored), "No plain-text secret may be stored");

        var log = err.capturedString();
        assertFalse(log.contains("Cannot re-encrypt"), "Every stored legacy value must be re-encrypted");
        assertNoneLogged(log,
                List.of(secretKey,
                        first,
                        second,
                        third,
                        plainStored,
                        firstLegacy,
                        secondLegacy,
                        thirdV2,
                        firstStored,
                        secondStored,
                        plainEncrypted,
                        // V6: the ciphertext of the blank value.
                        blankEncrypted));
    }

    // A stored secret is compared with its default by its decrypted value; one that no key decrypts is never taken
    // for its default, and a legacy value that cannot be parsed is kept with a WARN and reads as "".
    @Test
    @StdIo
    void storedSecretsAreComparedWithTheirDefaultsByTheirPlainText(StdErr err, @TempDir Path home) throws Exception {
        var secretKey = key();
        var legacyDefault = hex();
        var v2Default = hex();
        var undecryptableDefault = hex();
        var legacy = "ENC(" + PassCoder.encode(legacyDefault, secretKey, CIPHER) + ")";
        var v2 = "ENC(" + PassCoder.encodeV2(v2Default, secretKey) + ")";
        var undecryptable = "ENC(" + v2Inner() + ")";
        var previousLegacy = "ENC(" + PassCoder.encode(hex(), secretKey, CIPHER) + ")";
        writeSettings(home,
                "a.password=" + legacy,
                "b.password=" + v2,
                "c.password=" + undecryptable,
                "bad.password=ENC(!!!)",
                "e.password=" + previousLegacy);
        var source = open(home,
                secretKey,
                Map.of("a.password", legacyDefault, "b.password", v2Default, "c.password", undecryptableDefault));
        var changed = hex();

        source.save(Map.of("e.password", changed));

        assertFalse(source.containsProperty("a.password"), "A legacy value equal to its default must be removed");
        assertFalse(source.containsProperty("b.password"), "A v2 value equal to its default must be removed");
        assertTrue(undecryptable.equals(stored(source, "c.password")), "An undecryptable value must be kept");
        assertEquals("ENC(!!!)", stored(source, "bad.password"), "An unparsable legacy value must be kept");
        assertEquals("", source.getProperty("bad.password"), "An unparsable legacy value must read as empty");
        var changedStored = stored(source, "e.password");
        assertTrue(changedStored.startsWith(V2_STORED), "A changed secret must be stored in the v2 format");
        assertSecret(changed, source.getProperty("e.password"), "A changed secret must read back exactly");

        var log = err.capturedString();
        assertEquals(1, count(log, "WARN", "Cannot re-encrypt legacy encoded property 'bad.password'"));
        assertNoneLogged(log,
                List.of(secretKey,
                        legacyDefault,
                        v2Default,
                        undecryptableDefault,
                        legacy,
                        v2,
                        undecryptable,
                        previousLegacy,
                        changed,
                        changedStored));
    }

    // A secret equal to its default is removed before encryption, so it never creates the instance key.
    @Test
    void secretEqualToItsDefaultIsRemovedWithoutCreatingTheInstanceKey(@TempDir Path home) throws IOException {
        var plain = hex();
        var source = open(home, null, Map.of("x.password", plain));

        source.save(Map.of("x.password", plain));

        assertFalse(source.containsProperty("x.password"), "A secret equal to its default must be removed");
        assertFalse(Files.exists(settingsFile(home)), "Nothing is left to store, so the file must not exist");
        assertFalse(Files.exists(home.resolve(InstanceSecretKey.FILE_NAME)), "No instance key may be created");
    }

    // A save keeps the cached key of an unchanged secret, and drops the key of a ciphertext it replaces or removes,
    // also when it deletes the file.
    @Test
    void savesDropTheCachedKeysOfTheSecretsTheyReplace(@TempDir Path home) throws IOException {
        var secretKey = key();
        var first = hex();
        var second = hex();
        var source = open(home, secretKey, Map.of());
        source.save(Map.of("x.password", first));
        var firstStored = stored(source, "x.password");
        var firstSlot = slotOf(firstStored, secretKey);
        assertTrue(PassCoder.KEYS.isAuthenticated(firstSlot), "The key of a saved secret must be cached");

        source.save(Map.of("x.password", first));

        assertTrue(firstStored.equals(stored(source, "x.password")), "An unchanged secret must keep its ciphertext");
        assertTrue(PassCoder.KEYS.isAuthenticated(firstSlot), "An unchanged save must keep the cached key");

        source.save(Map.of("x.password", second));

        var secondStored = stored(source, "x.password");
        var secondSlot = slotOf(secondStored, secretKey);
        assertNull(PassCoder.KEYS.get(firstSlot), "The key of a replaced ciphertext must no longer be cached");
        assertTrue(PassCoder.KEYS.isAuthenticated(secondSlot), "The key of the new ciphertext must be cached");
        assertSecret(second, source.getProperty("x.password"), "The replaced secret must read the new value");

        var removal = new HashMap<String, String>();
        removal.put("x.password", null);
        source.save(removal);

        assertFalse(Files.exists(settingsFile(home)), "Nothing is left to store, so the file must be deleted");
        assertNull(PassCoder.KEYS.get(secondSlot), "The key of a removed ciphertext must no longer be cached");
    }

    // A reload of a file someone else rewrote drops the cached key of every ciphertext the file no longer holds, and
    // keeps the keys of the ciphertexts it still holds, read as getProperty reads them.
    @Test
    void reloadDropsTheCachedKeysOfTheSecretsTheFileNoLongerHolds(@TempDir Path home) throws Exception {
        var secretKey = key();
        var keptPlain = hex();
        var replacedPlain = hex();
        var replacementPlain = hex();
        var kept = "ENC(" + PassCoder.encodeV2(keptPlain, secretKey) + ")";
        var replaced = "ENC(" + PassCoder.encodeV2(replacedPlain, secretKey) + ")";
        var legacy = "ENC(" + PassCoder.encode(hex(), secretKey, CIPHER) + ")";
        writeSettings(home,
                "a.password=" + kept,
                "b.password=" + replaced,
                "c.password=" + legacy,
                "plain.name=" + hex());
        var source = open(home, secretKey, Map.of());
        assertSecret(keptPlain, source.getProperty("a.password"), "A stored v2 value must decrypt");
        assertSecret(replacedPlain, source.getProperty("b.password"), "A stored v2 value must decrypt");
        var keptSlot = slotOf(kept, secretKey);
        var replacedSlot = slotOf(replaced, secretKey);
        assertTrue(PassCoder.KEYS.isAuthenticated(replacedSlot), "The key of a read secret must be cached");

        var replacement = "ENC(" + PassCoder.encodeV2(replacementPlain, secretKey) + ")";
        var file = settingsFile(home);
        var modified = Files.getLastModifiedTime(file).toMillis();
        // The kept value gains an escaped trailing tab, which getProperty trims.
        writeSettings(home,
                "a.password=" + kept + "\\t",
                "b.password=" + replacement,
                "c.password=" + legacy,
                "plain.name=" + hex());
        Files.setLastModifiedTime(file, FileTime.fromMillis(modified + 10_000));

        assertTrue(source.reloadIfModified(), "The rewritten file must be met as a change");

        assertNull(PassCoder.KEYS.get(replacedSlot), "The key of a replaced ciphertext must no longer be cached");
        assertTrue(PassCoder.KEYS.isAuthenticated(keptSlot), "The key of a ciphertext still stored must be kept");
        assertSecret(keptPlain, source.getProperty("a.password"), "A kept value must read as before");
        assertSecret(replacementPlain, source.getProperty("b.password"), "A replacement must read its value");
    }

    // V6: the same for a blank secret equal to its blank default, whether given, stored as plain text or stored as the
    // legacy ENC() of an empty value.
    @Test
    void blankSecretEqualToItsBlankDefaultIsRemovedWithoutCreatingTheInstanceKey(@TempDir Path home)
            throws IOException {
        var other = hex();
        writeSettings(home, "stored.password=", "legacy.secret=ENC()", "other.name=" + other);
        var source = open(home, null, Map.of("stored.password", "", "legacy.secret", "", "given.token", ""));

        source.save(Map.of("given.token", ""));

        for (var name : List.of("stored.password", "legacy.secret", "given.token")) {
            assertFalse(source.containsProperty(name), "A blank secret equal to its blank default must be removed");
        }
        assertEquals(other, source.getProperty("other.name"), "The other setting must stay stored");
        assertFalse(Files.exists(home.resolve(InstanceSecretKey.FILE_NAME)), "No instance key may be created");
    }

    // V6: a blank secret is stored as ENC(v2:...) like any other: a given one as it is, a stored plain-text one
    // trimmed and a legacy ENC() as the empty value it decrypts to. Each reads as before, and an unchanged second save
    // keeps every ciphertext and the file.
    @Test
    @StdIo
    void blankSecretsAreEncryptedWithConfiguredKey(StdErr err, @TempDir Path home) throws IOException {
        var secretKey = key();

        var generated = assertBlankSecretsEncrypted(err, home, secretKey);

        assertFalse(Files.exists(home.resolve(InstanceSecretKey.FILE_NAME)),
                "A configured secret.key must not create the instance key file");
        generated.add(secretKey);
        assertNoneLogged(err.capturedString(), generated);
    }

    // V6: the same with the blank secret.key, which encrypts with the instance key.
    @Test
    @StdIo
    void blankSecretsAreEncryptedWithInstanceKey(StdErr err, @TempDir Path home) throws IOException {
        var generated = assertBlankSecretsEncrypted(err, home, null);

        var keyFile = home.resolve(InstanceSecretKey.FILE_NAME);
        assertTrue(Files.isRegularFile(keyFile), "The blank secret.key must create the instance key file");
        generated.add(Files.readString(keyFile).trim());
        assertNoneLogged(err.capturedString(), generated);
    }

    // The settings are hidden only from the thread of save() while it reads the defaults, so readers on other threads
    // never meet them absent, also while secrets are encrypted.
    @Test
    // V6: a backstop for a save that blocks; the reader in absentReadsDuring has shorter bounds of its own.
    @Timeout(value = 300, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    void readersKeepTheStoredSettingsWhileSecretsAreEncrypted(@TempDir Path home) throws Exception {
        var source = open(home, key(), Map.of());
        var setting = hex();
        source.save(Map.of("some.setting", setting));

        var absent = absentReadsDuring(source,
                "some.setting",
                () -> source.save(Map.of("first.password", hex(), "second.secret", hex(), "third.token", hex())));

        assertEquals(0, absent, "A stored setting must never read as absent while a save runs");
        assertEquals(setting, source.getProperty("some.setting"));
        for (var name : List.of("first.password", "second.secret", "third.token")) {
            assertTrue(stored(source, name).startsWith(V2_STORED), "Every new secret must be stored in v2");
        }
    }

    // Reading a default may decrypt an ENC(v2:...) value of the application properties and derive its key for the
    // first time; readers on other threads keep the stored settings meanwhile, and the decrypted default still
    // decides whether a secret equals its default.
    @Test
    // V6: a backstop for a save that blocks; the reader in absentReadsDuring has shorter bounds of its own.
    @Timeout(value = 300, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    void readersKeepTheStoredSettingsWhileEncryptedDefaultsAreRead(@TempDir Path home) throws Exception {
        var secretKey = key();
        var names = List.of("first.password", "second.secret");
        var defaults = new HashMap<String, String>();
        var lines = new ArrayList<String>();
        for (var name : names) {
            var plain = hex();
            defaults.put(name, plain);
            // Encrypted apart from PassCoder, so no key of these values is cached before the save reads them.
            lines.add(name + "=ENC(" + independentV2(plain, secretKey) + ")");
        }
        var conf = Files.createDirectories(home.resolve("conf"));
        Files.write(conf.resolve("application.properties"), lines, StandardCharsets.UTF_8);
        var values = new HashMap<String, Object>();
        values.put(DynamicPropertySource.OPENL_HOME_SHARED, home.toString());
        values.put("secret.cipher", CIPHER);
        values.put("secret.key", secretKey);
        var location = conf.toUri().toString();
        values.put("openl.config.location", location.endsWith("/") ? location : location + "/");
        values.put("openl.config.name", "application.properties");
        var sources = new MutablePropertySources();
        sources.addLast(new MapPropertySource("defaults", values));
        var resolver = new FirewallPropertyResolver(sources);
        sources.addFirst(new ApplicationPropertySource(resolver, APP));
        var source = new DynamicPropertySource(APP, resolver);
        sources.addFirst(source);
        DynamicPropertySource.register(source);
        var setting = hex();
        source.save(Map.of("some.setting", setting));

        var absent = absentReadsDuring(source,
                "some.setting",
                () -> source.save(Map.of("first.password", hex(), "second.secret", hex())));

        assertEquals(0, absent, "A stored setting must never read as absent while encrypted defaults are read");
        for (var name : names) {
            assertTrue(stored(source, name).startsWith(V2_STORED), "A secret other than its default must be stored");
        }
        source.save(Map.of("first.password", defaults.get("first.password")));
        assertFalse(source.containsProperty("first.password"), "A secret equal to its encrypted default is removed");
        assertTrue(source.containsProperty("second.secret"), "A secret other than its default must be kept");
        assertEquals(setting, source.getProperty("some.setting"));
    }

    // An ENC(v2:...) secret.key would need itself to be decrypted; it reads as "" instead of recursing.
    @Test
    @StdIo
    void encryptedSecretKeyReadsAsEmptyInsteadOfRecursing(StdErr err, @TempDir Path home) throws IOException {
        var keyInner = v2Inner();
        var passwordInner = v2Inner();
        writeSettings(home, "secret.key=ENC(" + keyInner + ")", "x.password=ENC(" + passwordInner + ")");
        var source = open(home, null, Map.of());

        assertEquals("", assertDoesNotThrow(() -> source.getProperty("x.password")));

        var log = err.capturedString();
        assertEquals(1, count(log, "ERROR", "The ENC(v2:...) value of property 'secret.key' cannot be decrypted"));
        assertEquals(1, count(log, "ERROR", "The ENC(v2:...) value of property 'x.password' cannot be decrypted"));

        var other = hex();
        assertDoesNotThrow(() -> source.save(Map.of("other.name", other)));
        assertEquals(other, source.getProperty("other.name"));
        assertTrue(("ENC(" + keyInner + ")").equals(stored(source, "secret.key")), "secret.key must be kept");
        assertTrue(("ENC(" + passwordInner + ")").equals(stored(source, "x.password")), "A v2 value must be kept");
        assertNoneLogged(err.capturedString(), List.of(keyInner, passwordInner));
    }

    // An unreadable instance key file is reported as the cause, with its path.
    @Test
    @StdIo
    void unreadableInstanceKeyFileIsReportedAsTheCause(StdErr err, @TempDir Path home) throws IOException {
        var keyFile = home.resolve(InstanceSecretKey.FILE_NAME);
        Files.createDirectory(keyFile);
        var inner = v2Inner();
        writeSettings(home, "x.password=ENC(" + inner + ")");
        var source = open(home, null, Map.of());

        assertEquals("", source.getProperty("x.password"));

        var log = err.capturedString();
        // V6: the cause is named by its type, without the text of the exception.
        assertEquals(1,
                count(log,
                        "ERROR",
                        "The ENC(v2:...) value of property 'x.password' cannot be decrypted: the instance key file '"
                                + keyFile + "' cannot be read; an empty value is used."));
        assertFalse(log.contains("IOException"), "The exception itself must not be logged");
        assertFalse(log.contains("does not decrypt it"), "An unreadable key file is not a wrong key");
        assertNoneLogged(log, List.of(inner));
    }

    // A malformed value is reported with the reason it cannot be parsed, not as a wrong key.
    @Test
    @StdIo
    void malformedValueIsReportedAsTheCause(StdErr err, @TempDir Path home) throws IOException {
        var secretKey = key();
        // Both keys are tried; the first cause found is the one reported.
        var instanceKey = writeInstanceKey(home);
        writeSettings(home, "x.password=ENC(v2:!!!)");
        var source = open(home, secretKey, Map.of());

        assertEquals("", source.getProperty("x.password"));

        var log = err.capturedString();
        // V6: the cause is named by its type, without the text of the exception.
        assertEquals(1,
                count(log,
                        "ERROR",
                        "The ENC(v2:...) value of property 'x.password' cannot be decrypted: the value is not a"
                                + " well-formed ENC(v2:...) value; an empty value is used."));
        assertFalse(log.contains("IllegalArgumentException"), "The exception itself must not be logged");
        assertFalse(log.contains("does not decrypt it"), "A malformed value is not a wrong key");
        assertNoneLogged(log, List.of(secretKey, instanceKey));
    }

    // A value written under another key, with the blank secret.key and an instance key that is not its key.
    @Test
    @StdIo
    void wrongInstanceKeyIsReported(StdErr err, @TempDir Path home) throws Exception {
        var instanceKey = writeInstanceKey(home);
        var foreignKey = key();
        var plain = hex();
        var inner = PassCoder.encodeV2(plain, foreignKey);
        writeSettings(home, "x.password=ENC(" + inner + ")");
        var source = open(home, null, Map.of());

        assertEquals("", source.getProperty("x.password"));

        var log = err.capturedString();
        assertEquals(1,
                count(log,
                        "ERROR",
                        "The ENC(v2:...) value of property 'x.password' cannot be decrypted: 'secret.key' is blank, and"
                                + " the instance key file '" + home.resolve(InstanceSecretKey.FILE_NAME)
                                + "' does not decrypt it; an empty value is used."));
        assertNoneLogged(log, List.of(instanceKey, foreignKey, plain, inner));
    }

    // A value written under another key, with a configured secret.key and no instance key file.
    @Test
    @StdIo
    void wrongConfiguredKeyWithoutKeyFileIsReported(StdErr err, @TempDir Path home) throws Exception {
        var secretKey = key();
        var foreignKey = key();
        var plain = hex();
        var inner = PassCoder.encodeV2(plain, foreignKey);
        writeSettings(home, "x.password=ENC(" + inner + ")");
        var source = open(home, secretKey, Map.of());

        assertEquals("", source.getProperty("x.password"));

        var log = err.capturedString();
        assertEquals(1,
                count(log,
                        "ERROR",
                        "The ENC(v2:...) value of property 'x.password' cannot be decrypted: 'secret.key' does not"
                                + " decrypt it, and the instance key file '" + home.resolve(InstanceSecretKey.FILE_NAME)
                                + "' does not exist; an empty value is used."));
        assertNoneLogged(log, List.of(secretKey, foreignKey, plain, inner));
    }

    // No key at all.
    @Test
    @StdIo
    void missingKeysAreReported(StdErr err, @TempDir Path home) throws IOException {
        var inner = v2Inner();
        writeSettings(home, "x.password=ENC(" + inner + ")");
        var source = open(home, null, Map.of());

        assertEquals("", source.getProperty("x.password"));

        var log = err.capturedString();
        assertEquals(1,
                count(log,
                        "ERROR",
                        "The ENC(v2:...) value of property 'x.password' cannot be decrypted: 'secret.key' is blank, and"
                                + " the instance key file '" + home.resolve(InstanceSecretKey.FILE_NAME)
                                + "' does not exist; an empty value is used."));
        assertNoneLogged(log, List.of(inner));
    }

    // V6: every distinct failing value is reported once while it is among the most recently failing distinct values,
    // however often it is read; one that as many newer failing values pushed out is reported once more.
    @Test
    @StdIo
    void failingValuesAreReportedOnceWhileTheyAreAmongTheMostRecent(StdErr err, @TempDir Path home)
            throws IOException {
        var storedInner = v2Inner();
        writeSettings(home, "x.password=ENC(" + storedInner + ")");
        var source = open(home, null, Map.of());
        var cap = DynamicPropertySource.REPORTED_V2_FAILURES_CAP;
        // Malformed contents and no key at all, so no key is derived for any of them.
        var values = new ArrayList<String>();
        for (var i = 0; i <= cap; i++) {
            var value = "ENC(v2:!" + hex() + ")";
            values.add(value);
            assertEquals("", DynamicPropertySource.decode(value));
        }
        // Counted by the subject only, so the count does not depend on the cause the line gives.
        var unnamed = "An ENC(v2:...) property value";
        assertEquals(cap + 1,
                count(err.capturedString(), "ERROR", unnamed),
                "Each distinct failing value must be reported once");

        assertEquals("", DynamicPropertySource.decode(values.get(cap)));
        assertEquals(cap + 1,
                count(err.capturedString(), "ERROR", unnamed),
                "A recent value must not be reported again");

        // The first value was pushed out by the cap newer ones; reporting it again pushes out the second.
        assertEquals("", DynamicPropertySource.decode(values.get(0)));
        assertEquals(cap + 2,
                count(err.capturedString(), "ERROR", unnamed),
                "A value pushed out by as many newer ones must be reported once more");
        assertEquals("", DynamicPropertySource.decode(values.get(0)));
        assertEquals(cap + 2,
                count(err.capturedString(), "ERROR", unnamed),
                "A value reported once more must not be reported again while it is recent");
        assertEquals("", DynamicPropertySource.decode(values.get(1)));
        assertEquals(cap + 3,
                count(err.capturedString(), "ERROR", unnamed),
                "The value pushed out by the one reported again must be reported once more");
        assertEquals("", DynamicPropertySource.decode(values.get(cap)));
        assertEquals(cap + 3,
                count(err.capturedString(), "ERROR", unnamed),
                "A recent value must not be reported again");

        assertEquals("", source.getProperty("x.password"));
        assertEquals("", source.getProperty("x.password"));
        var log = err.capturedString();
        assertEquals(1, count(log, "ERROR", "property 'x.password' cannot be decrypted"));
        values.add(storedInner);
        assertNoneLogged(log, values);
    }

    // The ERROR names the property, never the value, its ciphertext or its fingerprint.
    @Test
    @StdIo
    void errorNamesThePropertyNeverTheValue(StdErr err, @TempDir Path home) throws IOException {
        var inner = v2Inner();
        var unnamedInner = v2Inner();
        writeSettings(home, "db.password=ENC(" + inner + ")");
        var source = open(home, null, Map.of());

        assertEquals("", source.getProperty("db.password"));
        assertEquals("", DynamicPropertySource.decode("ENC(" + unnamedInner + ")"));

        var log = err.capturedString();
        assertEquals(1, count(log, "ERROR", "The ENC(v2:...) value of property 'db.password' cannot be decrypted"));
        assertEquals(1, count(log, "ERROR", "An ENC(v2:...) property value cannot be decrypted"));
        assertNoneLogged(log,
                List.of(inner,
                        inner.substring(PassCoder.V2_PREFIX.length()),
                        HashingUtils.sha256Hex(inner),
                        unnamedInner,
                        HashingUtils.sha256Hex(unnamedInner)));
    }

    // A value read before any source is registered is reported once, without a name.
    @Test
    @StdIo
    void earlyStartUpReadIsReportedOnce(StdErr err) throws ReflectiveOperationException {
        var inner = v2Inner();
        unregister();

        assertEquals("", DynamicPropertySource.decode("ENC(" + inner + ")"));
        assertEquals("", DynamicPropertySource.decode("ENC(" + inner + ")"));

        var log = err.capturedString();
        assertEquals(1,
                count(log,
                        "ERROR",
                        "An ENC(v2:...) property value is read before the settings are loaded, so no key can decrypt"
                                + " it; an empty value is used."));
        assertNoneLogged(log, List.of(inner, HashingUtils.sha256Hex(inner)));
    }

    // V6: with ERROR disabled, a value no key decrypts reads as "" and logs nothing, yet counts as reported: once
    // ERROR is enabled again, that value is not reported, while a distinct value is reported once. This holds for a
    // named read, for a secret.key that is itself ENC(v2:...) and for a read before the settings are loaded.
    @Test
    @StdIo
    void valueReadWhileErrorIsDisabledCountsAsReported(StdErr err, @TempDir Path home) throws Throwable {
        var keyInner = v2Inner();
        var passwordInner = v2Inner();
        var otherInner = v2Inner();
        var earlyInner = v2Inner();
        var otherEarlyInner = v2Inner();
        writeSettings(home,
                "secret.key=ENC(" + keyInner + ")",
                "x.password=ENC(" + passwordInner + ")",
                "y.password=ENC(" + otherInner + ")");
        var source = open(home, null, Map.of());
        // Loading the settings logs their path; only what the reads log is checked.
        var mark = err.capturedString().length();

        withConfigLogDisabled(() -> {
            // Fails the secret.key, which is ENC(v2:...) itself, and then x.password.
            assertEquals("", source.getProperty("x.password"), "A value no key decrypts must read as empty");
            unregister();
            assertEquals("", DynamicPropertySource.decode("ENC(" + earlyInner + ")"), "An early read must be empty");
            DynamicPropertySource.register(source);
        });
        assertTrue(err.capturedString().substring(mark).isEmpty(), "Nothing may be logged while ERROR is disabled");

        assertEquals("", source.getProperty("x.password"), "A value no key decrypts must read as empty");
        unregister();
        assertEquals("", DynamicPropertySource.decode("ENC(" + earlyInner + ")"), "An early read must be empty");
        DynamicPropertySource.register(source);
        assertEquals(0,
                count(err.capturedString().substring(mark), "ERROR"),
                "A value read while ERROR was disabled must not be reported later");

        assertEquals("", source.getProperty("y.password"), "A value no key decrypts must read as empty");
        unregister();
        assertEquals("", DynamicPropertySource.decode("ENC(" + otherEarlyInner + ")"), "An early read must be empty");
        DynamicPropertySource.register(source);
        var log = err.capturedString().substring(mark);
        assertEquals(1,
                count(log, "ERROR", "The ENC(v2:...) value of property 'y.password' cannot be decrypted"),
                "A distinct value must be reported once");
        assertEquals(1,
                count(log, "ERROR", "An ENC(v2:...) property value is read before the settings are loaded"),
                "A distinct early value must be reported once");
        assertEquals(2, count(log, "ERROR"), "Only the distinct values may be reported");
        assertNoneLogged(err.capturedString(),
                List.of(keyInner, passwordInner, otherInner, earlyInner, otherEarlyInner));
    }

    // V6: a secret that cannot be encrypted fails the save: the stored v2 value is not replaced, the new secret is not
    // dropped silently, and neither the settings this source holds nor the file change.
    @Test
    @StdIo
    void failedEncryptionFailsTheSaveAndKeepsTheStoredSettings(StdErr err, @TempDir Path home) throws IOException {
        var keyFile = Files.createDirectory(home.resolve(InstanceSecretKey.FILE_NAME));
        var previousInner = v2Inner();
        writeSettings(home, "kept.password=ENC(" + previousInner + ")");
        var source = open(home, null, Map.of());
        var before = Map.copyOf(source.getProperties());
        var file = Files.readAllBytes(settingsFile(home));
        var fresh = hex();
        var changed = hex();

        var failure = assertThrows(IOException.class,
                () -> source.save(Map.of("new.password", fresh, "kept.password", changed)));

        // The secrets are encrypted in the order of their names, so the changed one fails first.
        var expected = "Cannot encrypt the value of property 'kept.password' (the instance key file '" + keyFile
                + "' cannot be read or created); the settings are not saved.";
        assertSecret(expected, failure.getMessage(), "The failure must name the property and the cause");
        assertNull(failure.getCause(), "The failure must not carry its cause, whose text may be unsafe in a log");
        assertTrue(before.equals(source.getProperties()), "The settings must stay as they were");
        assertFalse(source.containsProperty("new.password"), "A secret that cannot be encrypted must not be stored");
        assertTrue(Arrays.equals(file, Files.readAllBytes(settingsFile(home))), "The file must stay as it was");
        var log = err.capturedString();
        assertEquals(1, count(log, "ERROR", expected));
        assertNoneLogged(log, List.of(fresh, changed, previousInner));
        assertNoneLogged(String.valueOf(failure.getMessage()), List.of(fresh, changed, previousInner));
    }

    // V6: a settings file written before V6 holds a secret in plain text. When it cannot be encrypted, a save of an
    // unrelated setting fails, so the plain text is not written again and nothing of the save is published.
    @Test
    @StdIo
    void plainTextSecretThatCannotBeEncryptedFailsAnUnrelatedSave(StdErr err, @TempDir Path home) throws IOException {
        var keyFile = Files.createDirectory(home.resolve(InstanceSecretKey.FILE_NAME));
        var plain = hex();
        writeSettings(home, "security.oauth2.client-secret=" + plain);
        var source = open(home, null, Map.of());
        var before = Map.copyOf(source.getProperties());
        var version = source.version();
        var file = Files.readAllBytes(settingsFile(home));
        var modified = Files.getLastModifiedTime(settingsFile(home));
        var unrelated = hex();

        var failure = assertThrows(IOException.class, () -> source.save(Map.of("unrelated.name", unrelated)));

        var expected = "Cannot encrypt the value of property 'security.oauth2.client-secret' (the instance key file '"
                + keyFile + "' cannot be read or created); the settings are not saved.";
        assertSecret(expected, failure.getMessage(), "The failure must name the property and the cause");
        assertTrue(before.equals(source.getProperties()), "The settings must stay as they were");
        assertNull(source.getProperty("unrelated.name"), "Nothing of a failed save may be published");
        assertSecret(plain, source.getProperty("security.oauth2.client-secret"), "The stored secret must read as before");
        assertEquals(version, source.version(), "A failed save must keep the version of the settings");
        assertTrue(Arrays.equals(file, Files.readAllBytes(settingsFile(home))), "The file must stay as it was");
        assertEquals(modified, Files.getLastModifiedTime(settingsFile(home)), "A failed save must not write the file");
        var log = err.capturedString();
        assertEquals(1, count(log, "ERROR", expected));
        assertNoneLogged(log, List.of(plain, unrelated));
        assertNoneLogged(String.valueOf(failure.getMessage()), List.of(plain, unrelated));
    }

    // V6: a new secret that cannot be encrypted fails the save instead of being dropped, and nothing is written.
    @Test
    @StdIo
    void newSecretThatCannotBeEncryptedFailsTheSave(StdErr err, @TempDir Path home) throws IOException {
        var keyFile = Files.createDirectory(home.resolve(InstanceSecretKey.FILE_NAME));
        var source = open(home, null, Map.of());
        var fresh = hex();
        var other = hex();

        var failure = assertThrows(IOException.class,
                () -> source.save(Map.of("new.token", fresh, "other.name", other)));

        var expected = "Cannot encrypt the value of property 'new.token' (the instance key file '" + keyFile
                + "' cannot be read or created); the settings are not saved.";
        assertSecret(expected, failure.getMessage(), "The failure must name the property and the cause");
        assertTrue(source.getProperties().isEmpty(), "Nothing of a failed save may be published");
        assertFalse(Files.exists(settingsFile(home)), "A failed save must not write the file");
        var log = err.capturedString();
        assertEquals(1, count(log, "ERROR", expected));
        assertNoneLogged(log, List.of(fresh, other));
        assertNoneLogged(String.valueOf(failure.getMessage()), List.of(fresh, other));
    }

    // V6: a save that fails on a later secret drops the cached keys of the ciphertexts it made and never published.
    @Test
    @StdIo
    void failedSaveDropsTheCachedKeysOfTheCiphertextsItMade(StdErr err, @TempDir Path home) throws Exception {
        var source = open(home, null, Map.of());
        var instanceKey = key();
        var material = HashingUtils.sha256Hex(instanceKey);
        var first = hex();
        var second = hex();
        var causeText = hex();
        var calls = new AtomicInteger();
        var made = new ArrayList<String>();
        IOException failure;
        // The instance key serves the first secret; the lookup for the second fails once the first is encrypted.
        try (var keys = Mockito.mockStatic(InstanceSecretKey.class)) {
            keys.when(() -> InstanceSecretKey.get(any(Path.class), eq(true))).thenAnswer(call -> {
                if (calls.incrementAndGet() == 1) {
                    return instanceKey;
                }
                made.addAll(saltsAuthenticatedBy(material));
                throw new IOException(causeText);
            });

            failure = assertThrows(IOException.class,
                    () -> source.save(Map.of("a.password", first, "b.password", second)));
        }

        assertEquals(2, calls.get(), "Both secrets must be encrypted, in the order of their names");
        assertEquals(1, made.size(), "The first secret must be encrypted, proving its key, before the second fails");
        var slot = new PassCoder.KeySlot(made.get(0), material);
        assertNull(PassCoder.KEYS.get(slot), "The key of a ciphertext a failed save made must no longer be cached");
        assertTrue(saltsAuthenticatedBy(material).isEmpty(), "No key of a failed save may stay cached");
        var expected = "Cannot encrypt the value of property 'b.password' (the instance key file '"
                + home.resolve(InstanceSecretKey.FILE_NAME)
                + "' cannot be read or created); the settings are not saved.";
        assertSecret(expected, failure.getMessage(), "The failure must name the property and the cause");
        assertNull(failure.getCause(), "The failure must not carry its cause, whose text may be unsafe in a log");
        assertTrue(source.getProperties().isEmpty(), "Nothing of a failed save may be published");
        assertFalse(Files.exists(settingsFile(home)), "A failed save must not write the file");
        var log = err.capturedString();
        assertEquals(1, count(log, "ERROR"), "A failed save must log one ERROR");
        assertEquals(1, count(log, "ERROR", expected), "The ERROR must name the property and the cause");
        assertNoneLogged(log, List.of(first, second, instanceKey, causeText));
        assertNoneLogged(String.valueOf(failure.getMessage()), List.of(first, second, instanceKey, causeText));
    }

    // V6: the cause of a failed encryption is named by the type of the failure, never by its text, and logged once.
    @Test
    @StdIo
    void encryptionFailureNamesItsCauseByType(StdErr err, @TempDir Path home) {
        var keyFile = home.resolve(InstanceSecretKey.FILE_NAME);
        var text = hex();
        var prefix = "Cannot encrypt the value of property 'x.password' (";
        var suffix = "); the settings are not saved.";

        assertSecret(prefix + "the instance key file '" + keyFile + "' cannot be read or created" + suffix,
                DynamicPropertySource.cannotEncrypt("x.password", new IOException(text), keyFile).getMessage(),
                "An I/O failure is a key file that cannot be read or created");
        assertSecret(prefix + "the JDK does not provide the cipher or the key derivation" + suffix,
                DynamicPropertySource.cannotEncrypt("x.password", new NoSuchAlgorithmException(text), keyFile)
                        .getMessage(),
                "A security failure is a cipher or a key derivation the JDK does not provide");
        assertSecret(prefix + "the encryption failed unexpectedly" + suffix,
                DynamicPropertySource.cannotEncrypt("x.password", new IllegalStateException(text), keyFile)
                        .getMessage(),
                "Any other failure is unexpected");

        var log = err.capturedString();
        assertEquals(3, count(log, "ERROR", prefix));
        assertNoneLogged(log, List.of(text));
    }

    // V6: the cause of a failed decryption is named by the type of the failure, never by its text.
    @Test
    void decryptionFailureNamesItsCauseByType(@TempDir Path home) {
        var keyFile = home.resolve(InstanceSecretKey.FILE_NAME);
        var text = hex();

        assertSecret("the instance key file '" + keyFile + "' cannot be read",
                DynamicPropertySource.decryptionCause(new IOException(text), keyFile),
                "An I/O failure is a key file that cannot be read");
        assertSecret("the value is not a well-formed ENC(v2:...) value",
                DynamicPropertySource.decryptionCause(new IllegalArgumentException(text), keyFile),
                "An illegal argument is a value that is not well-formed");
        assertSecret("the JDK does not provide the cipher or the key derivation",
                DynamicPropertySource.decryptionCause(new NoSuchAlgorithmException(text), keyFile),
                "A security failure is a cipher or a key derivation the JDK does not provide");
    }

    // V6: a property name cannot forge a log line: the WARN of a kept legacy value renders it on one line.
    @Test
    @StdIo
    void hostileNameInTheLegacyWarningStaysOnOneLine(StdErr err, @TempDir Path home) throws Exception {
        var legacyKey = key();
        var settings = new LinkedHashMap<String, String>();
        var generated = new ArrayList<>(List.of(legacyKey));
        for (var i = 0; i < HOSTILE.size(); i++) {
            var plain = hex();
            var legacy = "ENC(" + PassCoder.encode(plain, legacyKey, CIPHER) + ")";
            settings.put(hostileName(i, HOSTILE.get(i).raw()), legacy);
            generated.add(plain);
            generated.add(legacy);
        }
        PropertiesUtils.store(settingsFile(home), settings.entrySet());
        // The blank secret.key cannot decrypt the legacy values, so each is kept with a WARN.
        var source = open(home, null, Map.of());

        source.save(Map.of("other.name", hex()));

        var log = err.capturedString();
        for (var i = 0; i < HOSTILE.size(); i++) {
            var name = hostileName(i, HOSTILE.get(i).raw());
            assertTrue(stored(source, name).equals(settings.get(name)), "An undecryptable legacy value must be kept");
            assertEquals(1,
                    count(log,
                            "WARN",
                            "Cannot re-encrypt legacy encoded property '" + hostileName(i, HOSTILE.get(i).escaped())
                                    + "'; the stored value is kept."),
                    "The WARN must render the name on one line");
        }
        assertOneLinePerRecord(log, "Cannot re-encrypt legacy encoded property '");
        assertNoneLogged(log, generated);
    }

    // V6: the ERROR of a v2 value that cannot be decrypted renders the name of its property on one line.
    @Test
    @StdIo
    void hostileNameInTheDecryptionErrorStaysOnOneLine(StdErr err, @TempDir Path home) throws IOException {
        var settings = new LinkedHashMap<String, String>();
        for (var i = 0; i < HOSTILE.size(); i++) {
            settings.put(hostileName(i, HOSTILE.get(i).raw()), "ENC(" + v2Inner() + ")");
        }
        PropertiesUtils.store(settingsFile(home), settings.entrySet());
        var source = open(home, null, Map.of());

        for (var name : settings.keySet()) {
            assertEquals("", source.getProperty(name), "A value no key decrypts must read as empty");
        }

        var log = err.capturedString();
        for (var i = 0; i < HOSTILE.size(); i++) {
            assertEquals(1,
                    count(log,
                            "ERROR",
                            "The ENC(v2:...) value of property '" + hostileName(i, HOSTILE.get(i).escaped())
                                    + "' cannot be decrypted: 'secret.key' is blank, and the instance key file '"
                                    + home.resolve(InstanceSecretKey.FILE_NAME)
                                    + "' does not exist; an empty value is used."),
                    "The ERROR must render the name on one line");
        }
        assertOneLinePerRecord(log, "The ENC(v2:...) value of property '");
        assertNoneLogged(log, List.copyOf(settings.values()));
    }

    // V6: the failure of a save renders the name of the secret that cannot be encrypted on one line, in its message
    // and in its ERROR. Names given to save() may also hold unpaired surrogates and characters outside the BMP: a
    // format character is escaped unit by unit, any other is kept.
    @Test
    @StdIo
    void hostileNameInTheEncryptionFailureStaysOnOneLine(StdErr err, @TempDir Path home) throws IOException {
        var keyFile = Files.createDirectory(home.resolve(InstanceSecretKey.FILE_NAME));
        var source = open(home, null, Map.of());
        var labels = new ArrayList<>(HOSTILE);
        labels.add(new Hostile("\uD800", "\\uD800"));
        labels.add(new Hostile("\uDC00", "\\uDC00"));
        labels.add(new Hostile("\uDB40\uDC01", "\\uDB40\\uDC01"));
        labels.add(new Hostile("\uD83D\uDE00", "\uD83D\uDE00"));
        var values = new ArrayList<String>();

        for (var i = 0; i < labels.size(); i++) {
            var name = hostileName(i, labels.get(i).raw());
            var value = hex();
            values.add(value);

            var failure = assertThrows(IOException.class, () -> source.save(Map.of(name, value)));

            var expected = "Cannot encrypt the value of property '" + hostileName(i, labels.get(i).escaped())
                    + "' (the instance key file '" + keyFile + "' cannot be read or created); the settings are not"
                    + " saved.";
            assertSecret(expected, failure.getMessage(), "The message must render the name on one line");
            assertEquals(1, count(err.capturedString(), "ERROR", expected), "The ERROR must render the name too");
        }

        assertTrue(source.getProperties().isEmpty(), "Nothing of a failed save may be published");
        assertOneLinePerRecord(err.capturedString(), "Cannot encrypt the value of property '");
        assertNoneLogged(err.capturedString(), values);
    }

    // V6: a path cannot forge a log line either. The instance key file is named on one line in the ERROR of a read and
    // in the failure of a save, here in an openl.home.shared whose name holds a line feed.
    @Test
    @StdIo
    @DisabledOnOs(value = OS.WINDOWS, disabledReason = "A Windows file name cannot hold a line feed")
    void hostileKeyFilePathStaysOnOneLine(StdErr err, @TempDir Path temp) throws IOException {
        var shared = Files.createDirectory(temp.resolve("a\nb"));
        var keyFile = Files.createDirectory(shared.resolve(InstanceSecretKey.FILE_NAME));
        var rendered = keyFile.toString().replace("\n", "\\u000A");
        var inner = v2Inner();
        writeSettings(shared, "x.password=ENC(" + inner + ")");
        var source = open(shared, null, Map.of());
        // Loading the settings logs their path before any key file is named; only the lines that follow are checked.
        var mark = err.capturedString().length();
        var value = hex();

        assertEquals("", source.getProperty("x.password"), "A value no key decrypts must read as empty");
        var failure = assertThrows(IOException.class, () -> source.save(Map.of("y.password", value)));

        var expectedSave = "Cannot encrypt the value of property 'y.password' (the instance key file '" + rendered
                + "' cannot be read or created); the settings are not saved.";
        assertSecret(expectedSave, failure.getMessage(), "The message must render the path on one line");
        var log = err.capturedString().substring(mark);
        assertEquals(1,
                count(log,
                        "ERROR",
                        "The ENC(v2:...) value of property 'x.password' cannot be decrypted: the instance key file '"
                                + rendered + "' cannot be read; an empty value is used."),
                "The ERROR of the read must render the path on one line");
        assertEquals(1, count(log, "ERROR", expectedSave), "The ERROR of the save must render the path on one line");
        assertTrue(log.lines()
                .filter(line -> line.contains("b/" + InstanceSecretKey.FILE_NAME))
                .allMatch(line -> line.contains("ERROR")), "A path must not start a log line of its own");
        assertNoneLogged(log, List.of(inner, value));
    }

    // A stored legacy value that no key decrypts is kept, with a WARN that names the property only.
    @Test
    @StdIo
    void undecryptableLegacyValueIsKeptWithWarning(StdErr err, @TempDir Path home) throws Exception {
        var legacyKey = key();
        var plain = hex();
        var legacy = "ENC(" + PassCoder.encode(plain, legacyKey, CIPHER) + ")";
        writeSettings(home, "a.password=" + legacy);
        var source = open(home, null, Map.of());

        source.save(Map.of("other.name", hex()));

        assertTrue(legacy.equals(stored(source, "a.password")), "An undecryptable legacy value must be kept");
        assertFalse(Files.exists(home.resolve(InstanceSecretKey.FILE_NAME)), "No instance key may be created");
        var log = err.capturedString();
        assertEquals(1, count(log, "WARN", "Cannot re-encrypt legacy encoded property 'a.password'"));
        assertNoneLogged(log, List.of(legacyKey, plain, legacy));
    }

    @Test
    void secretNamesAreTheThreeSuffixesExceptSecretKey() {
        assertTrue(DynamicPropertySource.isSecretName("repository.design.password"));
        assertTrue(DynamicPropertySource.isSecretName("security.oauth2.client-secret"));
        assertTrue(DynamicPropertySource.isSecretName("some.service.token"));
        assertFalse(DynamicPropertySource.isSecretName("secret.key"));
        assertFalse(DynamicPropertySource.isSecretName("repository.s3.secret-key"));
        assertFalse(DynamicPropertySource.isSecretName("repository.azure.account-key"));
        assertFalse(DynamicPropertySource.isSecretName("security.saml.local-key"));
        assertFalse(DynamicPropertySource.isSecretName("db.Password"));
        assertFalse(DynamicPropertySource.isSecretName("password.policy"));
        assertFalse(DynamicPropertySource.isSecretName(null));
    }

    // The settings around the secrets: defaults are not stored, a null value removes a property, an empty result
    // deletes the file, and the file written is met as a change.
    @Test
    void settingsLifecycle(@TempDir Path home) throws IOException {
        var source = open(home, null, Map.of("default.name", "default"));
        assertNull(source.getProperty(DynamicPropertySource.OPENL_HOME));
        assertNull(source.getProperty(DynamicPropertySource.OPENL_HOME_SHARED));
        assertNull(source.getProperty("missing.name"));
        assertEquals(OpenLVersion.getVersion(), source.version());

        var unclosed = "ENC(" + hex();
        source.save(Map.of("plain.name", "value", "default.name", "default", "unclosed.name", unclosed));

        assertEquals(unclosed, source.getProperty("unclosed.name"), "A value without the closing ')' is plain text");
        assertTrue(source.containsProperty("plain.name"));
        assertFalse(source.containsProperty("default.name"), "A value equal to its default must not be stored");
        assertTrue(Arrays.asList(source.getPropertyNames()).contains("plain.name"));
        assertEquals("value", source.getProperty("plain.name"));
        assertTrue(Files.exists(settingsFile(home)));
        assertTrue(source.reloadIfModified(), "The written file must be met as a change");
        assertFalse(source.reloadIfModified(), "An unchanged file is not a change");
        assertEquals("value", source.getProperty("plain.name"));

        var removal = new HashMap<String, String>();
        removal.put("plain.name", null);
        removal.put("unclosed.name", null);
        source.save(removal);

        assertFalse(source.containsProperty("plain.name"));
        assertFalse(Files.exists(settingsFile(home)), "Nothing is left to store, so the file must be deleted");
    }

    private void assertGivenValuesEncrypted(StdErr err,
            Path home,
            @Nullable String secretKey,
            List<Given> given) throws IOException {
        var source = open(home, secretKey, Map.of());
        var config = new HashMap<String, String>();
        given.forEach(g -> config.put(g.name(), g.value()));

        source.save(config);

        var generated = new ArrayList<String>();
        var file = Files.readString(settingsFile(home));
        for (var g : given) {
            var stored = stored(source, g.name());
            assertTrue(stored.startsWith(V2_STORED), "A given value must be stored in the v2 format: " + g.name());
            assertFalse(stored.contains(g.core()), "The stored value must not hold the given text: " + g.name());
            assertFalse(file.contains(g.core()), "The file must not hold the given text: " + g.name());
            assertSecret(g.value(), source.getProperty(g.name()), "A given value must read back exactly: " + g.name());
            generated.add(g.core());
            generated.add(stored.substring(V2_STORED.length(), stored.length() - 1));
        }
        var reopened = open(home, secretKey, Map.of());
        for (var g : given) {
            assertSecret(g.value(),
                    reopened.getProperty(g.name()),
                    "A given value must read from the file: " + g.name());
        }

        var keyFile = home.resolve(InstanceSecretKey.FILE_NAME);
        if (secretKey == null) {
            assertTrue(Files.isRegularFile(keyFile), "The blank secret.key must create the instance key file");
            generated.add(Files.readString(keyFile).trim());
        } else {
            assertFalse(Files.exists(keyFile), "A configured secret.key must not create the instance key file");
            generated.add(secretKey);
        }
        var log = err.capturedString();
        assertFalse(log.contains("Cannot re-encrypt"), "A given value must never be read as a stored ENC(...) value");
        // V6: the ERROR of a secret that cannot be encrypted.
        assertFalse(log.contains("Cannot encrypt"), "Every given value must be encrypted");
        assertNoneLogged(log, generated);
    }

    /**
     * V6: stores blank secrets in {@code home} with the given {@code secret.key}: a stored empty plain-text value, a
     * stored tab, a stored legacy {@code ENC()}, a given empty value and a given space, and asserts that each is stored
     * as {@code ENC(v2:...)}, also in the file, that each reads as before, and that an unchanged second save keeps
     * every ciphertext and does not write the file.
     *
     * @return the ciphertexts, which the log must never hold
     */
    private List<String> assertBlankSecretsEncrypted(StdErr err,
            Path home,
            @Nullable String secretKey) throws IOException {
        writeSettings(home, "stored.password=", "tab.secret=\\t", "legacy.token=ENC()");
        var source = open(home, secretKey, Map.of());
        var reads = Map.of("stored.password",
                "",
                "tab.secret",
                "",
                "legacy.token",
                "",
                "given.password",
                "",
                "given.secret",
                " ");

        source.save(Map.of("given.password", "", "given.secret", " "));

        var generated = new ArrayList<String>();
        var reopened = open(home, secretKey, Map.of());
        for (var read : reads.entrySet()) {
            var name = read.getKey();
            var stored = stored(source, name);
            assertTrue(stored.startsWith(V2_STORED), "A blank secret must be stored as ENC(v2:...): " + name);
            assertTrue(stored.equals(stored(reopened, name)), "The file must hold the ciphertext: " + name);
            assertSecret(read.getValue(), source.getProperty(name), "A blank secret must read as before: " + name);
            assertSecret(read.getValue(), reopened.getProperty(name), "A blank secret must read from the file: " + name);
            generated.add(stored.substring(V2_STORED.length(), stored.length() - 1));
        }

        var file = Files.readAllBytes(settingsFile(home));
        var modified = Files.getLastModifiedTime(settingsFile(home));
        var kept = Map.copyOf(reopened.getProperties());
        reopened.save(Map.of("given.password", "", "given.secret", " ", "stored.password", ""));
        assertTrue(kept.equals(reopened.getProperties()), "An unchanged save must keep every ciphertext");
        assertTrue(Arrays.equals(file, Files.readAllBytes(settingsFile(home))), "An unchanged save must keep the file");
        assertEquals(modified, Files.getLastModifiedTime(settingsFile(home)), "An unchanged save must not write the file");

        var log = err.capturedString();
        assertFalse(log.contains("Cannot re-encrypt"), "A legacy ENC() must be re-encrypted");
        assertFalse(log.contains("Cannot encrypt"), "Every blank secret must be encrypted");
        return generated;
    }

    /**
     * Opens the settings of {@code home} as the application does: this source first, then the defaults, and makes it
     * the registered source that {@link DynamicPropertySource#decode(String)} uses.
     */
    private static DynamicPropertySource open(Path home, @Nullable String secretKey, Map<String, String> defaults) {
        var values = new HashMap<String, Object>(defaults);
        values.put(DynamicPropertySource.OPENL_HOME_SHARED, home.toString());
        values.put("secret.cipher", CIPHER);
        if (secretKey != null) {
            values.put("secret.key", secretKey);
        }
        var sources = new MutablePropertySources();
        sources.addLast(new MapPropertySource("defaults", values));
        var resolver = new FirewallPropertyResolver(sources);
        var source = new DynamicPropertySource(APP, resolver);
        sources.addFirst(source);
        DynamicPropertySource.register(source);
        return source;
    }

    /**
     * Runs {@code save} while another thread reads {@code name} from {@code source} in a loop, and returns how many of
     * those reads found the property absent.
     *
     * <p>Every wait on the reader is bounded: a reader that does not read, or does not stop, in time fails the test
     * with a fixed message instead of hanging the build.
     */
    private static long absentReadsDuring(DynamicPropertySource source,
            String name,
            Saving save) throws IOException, InterruptedException {
        // V6: bounded waits on the reader, generous for a loaded build host, so a blocked reader fails the test.
        var readerLimitMillis = TimeUnit.SECONDS.toMillis(30);
        var interruptedReaderLimitMillis = TimeUnit.SECONDS.toMillis(5);
        var stop = new AtomicBoolean();
        var reads = new AtomicLong();
        var absent = new AtomicLong();
        var readerFailure = new AtomicReference<Throwable>();
        var reader = new Thread(() -> {
            try {
                while (!stop.get()) {
                    if (source.getProperty(name) == null) {
                        absent.incrementAndGet();
                    }
                    reads.incrementAndGet();
                }
            } catch (RuntimeException | Error e) {
                readerFailure.set(e);
            }
        }, "settings-reader");
        reader.setDaemon(true);
        reader.start();
        long readsDuring;
        try {
            var deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(readerLimitMillis);
            while (reads.get() == 0 && reader.isAlive()) {
                assertTrue(System.nanoTime() - deadline < 0, "The reader must read within the time limit");
                Thread.onSpinWait();
            }
            // Only the type of a failure is named, never its message.
            var failure = readerFailure.get();
            assertTrue(reads.get() > 0,
                    failure == null ? "The reader must read before the save runs"
                                    : "The reader must not fail before its first read: " + failure.getClass().getName());
            var readsBefore = reads.get();
            save.run();
            readsDuring = reads.get() - readsBefore;
        } finally {
            // No assertion here, so a failure of the save is never masked; a reader still alive fails below.
            stop.set(true);
            try {
                reader.join(readerLimitMillis);
            } finally {
                if (reader.isAlive()) {
                    reader.interrupt();
                    reader.join(interruptedReaderLimitMillis);
                }
            }
        }
        assertFalse(reader.isAlive(), "The reader must stop within the time limit");
        assertNull(readerFailure.get(), "The reader must not fail");
        assertTrue(readsDuring > 0, "The reader must read while the save runs");
        return absent.get();
    }

    /**
     * Encrypts a value in the v2 format with the JDK alone, as the format is specified: PBKDF2-HMAC-SHA256 with
     * 600,000 iterations over a random 16-byte salt gives the AES-256 key, and AES-GCM with a random 12-byte nonce, a
     * 128-bit tag and the AAD {@code openl-enc-v2} encrypts; the result is {@code v2:} and the Base64 of the salt, the
     * nonce and the ciphertext with its tag.
     */
    private static String independentV2(String plain, String keyMaterial) throws GeneralSecurityException {
        var salt = new byte[16];
        RANDOM.nextBytes(salt);
        var nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        var spec = new PBEKeySpec(keyMaterial.toCharArray(), salt, 600_000, 256);
        var key = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec)
                .getEncoded(), "AES");
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        cipher.updateAAD("openl-enc-v2".getBytes(StandardCharsets.UTF_8));
        var encrypted = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        var payload = new byte[salt.length + nonce.length + encrypted.length];
        System.arraycopy(salt, 0, payload, 0, salt.length);
        System.arraycopy(nonce, 0, payload, salt.length, nonce.length);
        System.arraycopy(encrypted, 0, payload, salt.length + nonce.length, encrypted.length);
        return "v2:" + Base64.getEncoder().encodeToString(payload);
    }

    /**
     * V6: runs {@code reads} with every level of {@code OpenL.config} disabled, ERROR included, and then restores its
     * level, whether or not {@code reads} fails. slf4j-simple fixes the level of a logger when it creates the logger
     * and has no API to change it, so the level is set through the field the logger checks.
     */
    private static void withConfigLogDisabled(Executable reads) throws Throwable {
        var logger = assertInstanceOf(SimpleLogger.class, ConfigLog.LOG, "The tests must log through slf4j-simple");
        var level = SimpleLogger.class.getDeclaredField("currentLogLevel");
        level.setAccessible(true);
        var off = SimpleLogger.class.getDeclaredField("LOG_LEVEL_OFF");
        off.setAccessible(true);
        var enabled = level.getInt(logger);
        level.setInt(logger, off.getInt(null));
        try {
            assertFalse(ConfigLog.LOG.isErrorEnabled(), "ERROR must be disabled");
            reads.execute();
        } finally {
            level.setInt(logger, enabled);
        }
        assertTrue(ConfigLog.LOG.isErrorEnabled(), "ERROR must be enabled again");
    }

    /**
     * The state of early start-up: no source is registered yet.
     */
    private static void unregister() throws ReflectiveOperationException {
        DynamicPropertySource.class.getDeclaredMethod("register", DynamicPropertySource.class)
                .invoke(null, (Object) null);
    }

    private static Path settingsFile(Path home) {
        return home.resolve(APP + ".properties");
    }

    private static void writeSettings(Path home, String... lines) throws IOException {
        Files.writeString(settingsFile(home), String.join("\n", lines) + "\n", StandardCharsets.UTF_8);
    }

    /**
     * Writes an instance key file as {@link InstanceSecretKey} creates one: the Base64 of 32 random bytes, readable by
     * its owner only where the file system supports POSIX permissions.
     */
    private static String writeInstanceKey(Path home) throws IOException {
        var instanceKey = key();
        var file = home.resolve(InstanceSecretKey.FILE_NAME);
        Files.writeString(file, instanceKey, StandardCharsets.US_ASCII);
        if (home.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        }
        return instanceKey;
    }

    /**
     * The slot under which {@link PassCoder#KEYS} caches the key of a stored {@code ENC(v2:...)} value: its salt and
     * the SHA-256 of the key material, never the material itself.
     */
    private static PassCoder.KeySlot slotOf(String stored, String keyMaterial) {
        var payload = Base64.getDecoder().decode(stored.substring(V2_STORED.length(), stored.length() - 1));
        return new PassCoder.KeySlot(Base64.getEncoder().encodeToString(Arrays.copyOf(payload, 16)),
                HashingUtils.sha256Hex(keyMaterial));
    }

    /**
     * V6: the salts whose group in {@link PassCoder#KEYS} holds the key of the given material as authenticated, read
     * under the lock of the cache from its private map of groups.
     *
     * @param material the hex SHA-256 of a key material
     */
    private static List<String> saltsAuthenticatedBy(String material) throws ReflectiveOperationException {
        var groups = PassCoder.KeyCache.class.getDeclaredField("groups");
        groups.setAccessible(true);
        var salts = new ArrayList<String>();
        synchronized (PassCoder.KEYS) {
            for (var salt : ((Map<?, ?>) groups.get(PassCoder.KEYS)).keySet()) {
                var slot = new PassCoder.KeySlot((String) salt, material);
                if (PassCoder.KEYS.isAuthenticated(slot)) {
                    salts.add(slot.salt());
                }
            }
        }
        return salts;
    }

    private static String stored(DynamicPropertySource source, String name) {
        var value = source.getProperties().get(name);
        assertNotNull(value, "The property must be stored: " + name);
        return value;
    }

    private static long count(String log, String... parts) {
        return log.lines().filter(line -> Arrays.stream(parts).allMatch(line::contains)).count();
    }

    /**
     * V6: a secret name that holds {@code part} between a prefix unique to {@code index} and {@link #HOSTILE_TAIL}.
     */
    private static String hostileName(int index, String part) {
        return "h" + index + "a" + part + HOSTILE_TAIL;
    }

    /**
     * V6: asserts that every log line holding the end of a hostile name is a record that starts with {@code head}, so
     * that no name ended its line early or started a line of its own, and that the log holds none of the line and
     * paragraph separators and format characters themselves.
     */
    private static void assertOneLinePerRecord(String log, String head) {
        assertTrue(log.lines().filter(line -> line.contains(HOSTILE_TAIL)).allMatch(line -> line.contains(head)),
                "A hostile name must not start a log line of its own");
        for (var character : List.of("\u0085", "\u2028", "\u2029", "\u202E")) {
            assertFalse(log.contains(character), "A separator or a format character must never be logged");
        }
    }

    private static void assertSecret(String expected, @Nullable String actual, String message) {
        assertTrue(expected.equals(actual), message);
    }

    private static void assertNoneLogged(String log, List<String> generated) {
        for (var value : generated) {
            assertFalse(log.contains(value), "A generated value, ciphertext or key must never be logged");
        }
    }

    private static String hex() {
        var bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    private static String key() {
        var bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * The content of a well-formed {@code ENC(v2:...)} value that no key wrote: a salt, a nonce and a tag of random
     * bytes, so every key fails its authentication.
     */
    private static String v2Inner() {
        var bytes = new byte[48];
        RANDOM.nextBytes(bytes);
        return PassCoder.V2_PREFIX + Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * A value given to {@code save()}: its property, the random text a stored value, the file or the log must never
     * hold, and the value itself.
     */
    private record Given(String name, String core, String value) {
    }

    /**
     * V6: characters of a property name or a path, and how a log line or a message renders them.
     */
    private record Hostile(String raw, String escaped) {
    }

    /**
     * A save that a reader thread runs beside.
     */
    @FunctionalInterface
    private interface Saving {
        void run() throws IOException;
    }
}

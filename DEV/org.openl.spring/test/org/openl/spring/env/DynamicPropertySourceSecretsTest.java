package org.openl.spring.env;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
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
import org.junit.jupiter.api.io.TempDir;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;

import org.openl.info.OpenLVersion;
import org.openl.util.HashingUtils;

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
        assertEquals("", stored(source, "e.password"), "A blank secret holds nothing to encrypt");
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
                        plainEncrypted));
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

    // The settings are hidden only from the thread of save() while it reads the defaults, so readers on other threads
    // never meet them absent, also while secrets are encrypted.
    @Test
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
        assertEquals(1,
                count(log,
                        "ERROR",
                        "The ENC(v2:...) value of property 'x.password' cannot be decrypted: the instance key file '"
                                + keyFile + "' cannot be read (",
                        "IOException"));
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
        assertEquals(1,
                count(log,
                        "ERROR",
                        "The ENC(v2:...) value of property 'x.password' cannot be decrypted:"
                                + " java.lang.IllegalArgumentException"));
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

    // Every distinct failing value is reported once, however many there are, and never again.
    @Test
    @StdIo
    void eachFailingValueIsReportedOnceForTheLifeOfTheJvm(StdErr err, @TempDir Path home) throws IOException {
        var storedInner = v2Inner();
        writeSettings(home, "x.password=ENC(" + storedInner + ")");
        var source = open(home, null, Map.of());
        var values = new ArrayList<String>();
        for (var i = 0; i < 1_001; i++) {
            var value = "ENC(" + v2Inner() + ")";
            values.add(value);
            assertEquals("", DynamicPropertySource.decode(value));
        }
        // Counted by the subject only, so the count does not depend on the cause the line gives.
        var unnamed = "An ENC(v2:...) property value";
        assertEquals(1_001, count(err.capturedString(), "ERROR", unnamed));

        assertEquals("", DynamicPropertySource.decode(values.get(0)));
        assertEquals(1_001,
                count(err.capturedString(), "ERROR", unnamed),
                "An earlier value must not be reported again");

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

    // A secret that cannot be encrypted keeps its previous value, or is not stored; it never reaches the file.
    @Test
    @StdIo
    void failedEncryptionNeverStoresPlainText(StdErr err, @TempDir Path home) throws IOException {
        Files.createDirectory(home.resolve(InstanceSecretKey.FILE_NAME));
        var previousInner = v2Inner();
        writeSettings(home, "kept.password=ENC(" + previousInner + ")");
        var source = open(home, null, Map.of());
        var fresh = hex();
        var changed = hex();

        source.save(Map.of("new.password", fresh, "kept.password", changed));

        assertFalse(source.containsProperty("new.password"), "A secret that cannot be encrypted must not be stored");
        assertTrue(("ENC(" + previousInner + ")").equals(stored(source, "kept.password")),
                "A secret that cannot be encrypted must keep its previous value");
        var file = Files.readString(settingsFile(home));
        assertFalse(file.contains(fresh), "A plain-text secret must never reach the file");
        assertFalse(file.contains(changed), "A plain-text secret must never reach the file");
        var log = err.capturedString();
        assertEquals(1, count(log, "ERROR", "Error when setting password property: new.password"));
        assertEquals(1, count(log, "ERROR", "Error when setting password property: kept.password"));
        assertNoneLogged(log, List.of(fresh, changed, previousInner));
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
        assertFalse(log.contains("Error when setting password property"), "Every given value must be encrypted");
        assertNoneLogged(log, generated);
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
     */
    private static long absentReadsDuring(DynamicPropertySource source,
            String name,
            Saving save) throws IOException, InterruptedException {
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
            while (reads.get() == 0 && reader.isAlive()) {
                Thread.onSpinWait();
            }
            var readsBefore = reads.get();
            save.run();
            readsDuring = reads.get() - readsBefore;
        } finally {
            stop.set(true);
            reader.join();
        }
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

    private static String stored(DynamicPropertySource source, String name) {
        var value = source.getProperties().get(name);
        assertNotNull(value, "The property must be stored: " + name);
        return value;
    }

    private static long count(String log, String... parts) {
        return log.lines().filter(line -> Arrays.stream(parts).allMatch(line::contains)).count();
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
     * A save that a reader thread runs beside.
     */
    @FunctionalInterface
    private interface Saving {
        void run() throws IOException;
    }
}

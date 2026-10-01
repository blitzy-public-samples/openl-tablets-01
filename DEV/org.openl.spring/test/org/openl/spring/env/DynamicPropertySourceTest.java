package org.openl.spring.env;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

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

import org.openl.util.PropertiesUtils;

/**
 * V6: how {@link DynamicPropertySource} stores secret settings.
 *
 * <p>A setting whose name ends in {@code password}, {@code secret} or {@code token}, except {@code secret.key}, must be
 * stored as {@code ENC(v2:...)}, with a fresh ciphertext per value, whether {@code secret.key} is configured or keeps
 * its blank default. Legacy {@code ENC(...)} values must keep decrypting and must be re-encrypted on the next save; a
 * legacy value that cannot be decrypted is kept with a WARN, and a value whose key is lost reads as {@code ""} with one
 * ERROR.
 *
 * <p>The class compiles against the source as it was before V6, so it reproduces the finding there: it uses only the
 * public settings API, the legacy {@link PassCoder#encode} and the package-private constructors and
 * {@link DynamicPropertySource#register}. The name of the instance key file and the v2 prefix are therefore spelled out
 * as literals.
 *
 * <p>Every key and value is generated at run time. Secrets are compared through assertions with fixed messages, so a
 * failing assertion never prints a secret or a ciphertext into the test report, and every test that captures the log
 * asserts that none of its secrets, ciphertexts or keys was logged.
 */
class DynamicPropertySourceTest {

    private static final String APP = "test-app";
    private static final String CIPHER = "AES/CBC/PKCS5Padding";
    private static final String V2 = "ENC(v2:";
    private static final String KEY_FILE = ".openl-secret-key";
    private static final SecureRandom RANDOM = new SecureRandom();

    @TempDir
    Path home;

    private DynamicPropertySource previous;

    @BeforeAll
    static void initLog() {
        // ConfigLog prints the OpenL info block from its static initializer; loading it here keeps that block out of
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

    @Test
    void legacyValueDecodesAndIsReEncrypted() throws Exception {
        var key = random();
        var plain = random();
        var legacy = legacy(plain, key);
        var conf = Files.createDirectories(home.resolve("conf"));
        var location = conf.toUri().toString();
        if (!location.endsWith("/")) {
            location += "/";
        }
        PropertiesUtils.store(conf.resolve("application.properties"), Map.of("repo.password", legacy).entrySet());
        writeSettings(Map.of("repo.password", legacy));
        var fixture = open(Map.of("secret.key",
                key,
                "openl.config.location",
                location,
                "openl.config.name",
                "application.properties"));
        var source = fixture.source();

        assertSecret(plain, source.getProperty("repo.password"), "A stored legacy value must decrypt");
        var application = new ApplicationPropertySource(fixture.resolver(), APP);
        assertSecret(plain,
                application.getProperty("repo.password"),
                "A legacy value of the application properties must decrypt");

        source.save(Map.of("other.name", random()));

        var rewritten = assertV2(stored().get("repo.password"), plain, "repo.password");
        assertFalse(legacy.equals(rewritten), "The legacy value must be replaced");
        assertSecret(plain, source.getProperty("repo.password"), "The re-encrypted value must decrypt");
        assertSecret(plain,
                open(Map.of("secret.key", key)).source().getProperty("repo.password"),
                "The re-encrypted value must decrypt from the file");
    }

    @Test
    @StdIo
    void noPlainTextSecretsWithKey(StdErr err) throws IOException {
        var key = random();

        var logged = assertNoPlainTextSecrets(key);

        assertFalse(Files.exists(keyFile()), "A configured secret.key must not create the instance key file");
        logged.add(key);
        assertNoneLogged(err.capturedString(), logged);
    }

    @Test
    @StdIo
    void noPlainTextSecretsWithBlankKey(StdErr err) throws IOException {
        var logged = assertNoPlainTextSecrets("");

        assertTrue(Files.isRegularFile(keyFile()), "A blank secret.key must create the instance key file");
        logged.add(Files.readString(keyFile()).trim());
        assertNoneLogged(err.capturedString(), logged);
    }

    @Test
    void sameValueDifferentCiphertexts() throws IOException {
        var key = random();
        var plain = random();
        var source = open(Map.of("secret.key", key)).source();

        source.save(Map.of("a.password", plain, "b.password", plain));

        // Compared before the format checks, so a deterministic encoding fails on this assertion whatever its format.
        var stored = stored();
        assertTrue(stored.containsKey("a.password") && stored.containsKey("b.password"), "Both values must be stored");
        assertFalse(Objects.equals(stored.get("a.password"), stored.get("b.password")),
                "Two encryptions of the same value must differ");
        assertV2(stored.get("a.password"), plain, "a.password");
        assertV2(stored.get("b.password"), plain, "b.password");
        assertSecret(plain, source.getProperty("a.password"), "The first ciphertext must decrypt");
        assertSecret(plain, source.getProperty("b.password"), "The second ciphertext must decrypt");
    }

    @Test
    void secretKeyIsNeverEncrypted() throws IOException {
        var key = random();
        var source = open(Map.of("secret.key", "")).source();

        source.save(Map.of("secret.key", key));

        assertSecret(key, stored().get("secret.key"), "secret.key must be stored as it is");
        assertSecret(key, source.getProperty("secret.key"), "secret.key must read as it is");
        assertFalse(Files.exists(keyFile()), "Storing secret.key must not create the instance key file");
    }

    @Test
    void noChurnOnUnchangedSave() throws IOException {
        var key = random();
        var plain = random();
        var source = open(Map.of("secret.key", key)).source();
        source.save(Map.of("repo.password", plain));
        var before = stored();
        var bytes = Files.readAllBytes(settingsFile());
        var modified = Files.getLastModifiedTime(settingsFile());

        source.save(Map.of("repo.password", plain));

        assertTrue(before.equals(stored()), "An unchanged save must keep the stored ciphertext");
        assertTrue(Arrays.equals(bytes, Files.readAllBytes(settingsFile())), "An unchanged save must keep the file");
        assertEquals(modified, Files.getLastModifiedTime(settingsFile()), "An unchanged save must not write the file");
        assertSecret(plain, source.getProperty("repo.password"), "The kept ciphertext must decrypt");
    }

    @Test
    void valueEqualToDefaultIsRemoved() throws IOException {
        var plain = random();
        var source = open(Map.of("secret.key", "", "x.password", plain)).source();

        source.save(Map.of("x.password", plain));

        assertFalse(source.getProperties().containsKey("x.password"), "A value equal to its default must be removed");
        assertFalse(stored().containsKey("x.password"), "A value equal to its default must not be stored");
        assertFalse(Files.exists(keyFile()), "A value equal to its default must not create the instance key file");
    }

    @Test
    @StdIo
    void undecryptableLegacyValueIsKept(StdErr err) throws Exception {
        // A blank secret.key cannot decrypt a legacy value. A wrong configured key is no reliable fixture: the
        // legacy cipher sometimes finds valid padding under a wrong key and yields garbage instead of failing.
        var plain = random();
        var foreignKey = random();
        var legacy = legacy(plain, foreignKey);
        writeSettings(Map.of("repo.password", legacy));
        var source = open(Map.of("secret.key", "")).source();

        source.save(Map.of("other.name", random()));

        assertTrue(legacy.equals(stored().get("repo.password")), "An undecryptable legacy value must be kept");
        assertFalse(Files.exists(keyFile()), "Nothing was encrypted, so no instance key file must be created");
        var log = err.capturedString();
        assertTrue(log.lines().anyMatch(line -> line.contains("WARN") && line.contains("repo.password")),
                "A WARN must name the property whose legacy value is kept");
        assertNoneLogged(log, List.of(inner(legacy), plain, foreignKey));
    }

    @Test
    @StdIo
    void legacyValueWithoutCipherIsKept(StdErr err) throws Exception {
        var key = random();
        var plain = random();
        var legacy = legacy(plain, key);
        writeSettings(Map.of("repo.password", legacy));
        var source = open(Map.of("secret.key", key, "secret.cipher", "")).source();

        source.save(Map.of("other.name", random()));

        assertTrue(legacy.equals(stored().get("repo.password")),
                "A legacy value must be kept when secret.cipher is blank");
        var log = err.capturedString();
        assertTrue(log.lines().anyMatch(line -> line.contains("WARN") && line.contains("repo.password")),
                "A WARN must name the property whose legacy value is kept");
        assertNoneLogged(log, List.of(inner(legacy), plain, key));
    }

    @Test
    @StdIo
    void lostInstanceKeyYieldsEmptyWithOneError(StdErr err) throws Exception {
        var plain = random();
        var source = open(Map.of("secret.key", "")).source();
        source.save(Map.of("repo.password", plain));
        var stored = assertV2(stored().get("repo.password"), plain, "repo.password");
        assertSecret(plain, source.getProperty("repo.password"), "The value must decrypt while the key file exists");
        var instanceKey = Files.readString(keyFile()).trim();

        Files.delete(keyFile());
        var mark = err.capturedString().length();

        var first = readUntilEmpty(source, "repo.password");
        var second = source.getProperty("repo.password");

        assertTrue("".equals(first), "A value whose key file is lost must read as empty");
        assertTrue("".equals(second), "A value whose key file is lost must keep reading as empty");
        assertEquals(1,
                err.capturedString().substring(mark).lines().filter(line -> line.contains(" ERROR ")).count(),
                "One ERROR must be logged for the value, however often it is read");
        assertNoneLogged(err.capturedString(), List.of(plain, inner(stored), instanceKey));
    }

    @Test
    void nonSecretNamesAndNullRemoval() throws IOException {
        var url = random();
        var other = random();
        var source = open(Map.of("secret.key", "")).source();

        source.save(Map.of("some.url", url, "other.name", other));

        assertEquals(url, stored().get("some.url"), "A non-secret value must be stored as given");
        assertEquals(url, source.getProperty("some.url"), "A non-secret value must read as given");

        var removal = new HashMap<String, String>();
        removal.put("some.url", null);
        source.save(removal);

        assertFalse(source.getProperties().containsKey("some.url"), "A null value must remove the property");
        assertFalse(stored().containsKey("some.url"), "A null value must remove the property from the file");
        assertEquals(other, stored().get("other.name"), "The other property must stay stored");

        removal.clear();
        removal.put("other.name", null);
        source.save(removal);

        assertTrue(source.getProperties().isEmpty(), "Removing the last property must leave no settings");
        assertFalse(Files.exists(settingsFile()), "Removing the last property must delete the file");
        assertFalse(Files.exists(keyFile()), "Non-secret settings must not create the instance key file");
    }

    @Test
    void plainTextSecretReplacedByNewValueIsEncrypted() throws IOException {
        // A settings file written while secret.key was blank holds its secrets in plain text.
        var key = random();
        var oldPlain = random();
        var newPlain = random();
        writeSettings(Map.of("repo.password", oldPlain));
        var source = open(Map.of("secret.key", key)).source();
        assertSecret(oldPlain, source.getProperty("repo.password"), "A stored plain-text value must read as it is");

        source.save(Map.of("repo.password", newPlain));

        assertV2(stored().get("repo.password"), newPlain, "repo.password");
        var file = raw();
        assertFalse(file.contains(oldPlain), "The settings file must not keep the replaced plain value");
        assertFalse(file.contains(newPlain), "The settings file must not hold the new plain value");
        assertSecret(newPlain, source.getProperty("repo.password"), "The new value must decrypt");
    }


    /**
     * Saves one generated value under a {@code password}, a {@code secret} and a {@code token} name with the given
     * {@code secret.key}, and asserts that each is stored as {@code ENC(v2:...)}, that the file holds none of the plain
     * values, and that each reads back as given.
     *
     * @return the plain values and the stored ciphertexts, which the log must never hold
     */
    private List<String> assertNoPlainTextSecrets(String key) throws IOException {
        var values = new LinkedHashMap<String, String>();
        values.put("repo.password", random());
        values.put("security.oauth2.client-secret", random());
        values.put("api.token", random());
        var source = open(Map.of("secret.key", key)).source();

        source.save(values);

        var stored = stored();
        var file = raw();
        // Checked for every name before the format checks, so a plain-text value fails here whatever the others hold.
        values.forEach((name, plain) -> assertFalse(file.contains(plain),
                "The settings file must not hold the plain value of " + name));
        var logged = new ArrayList<String>();
        for (var entry : values.entrySet()) {
            var name = entry.getKey();
            var plain = entry.getValue();
            var value = assertV2(stored.get(name), plain, name);
            assertSecret(plain, source.getProperty(name), "The stored value must decrypt: " + name);
            logged.add(plain);
            logged.add(inner(value));
        }
        return logged;
    }

    /**
     * Opens the settings in {@code home} as the application does: this source first, then the defaults, and registers
     * it as the source that decodes {@code ENC(...)} values.
     *
     * @param extra defaults beside {@code openl.home.shared} and {@code secret.cipher}, such as {@code secret.key}
     */
    private Fixture open(Map<String, String> extra) {
        var defaults = new HashMap<String, Object>();
        defaults.put("openl.home.shared", home.toString());
        defaults.put("secret.cipher", CIPHER);
        defaults.putAll(extra);
        var sources = new MutablePropertySources();
        sources.addLast(new MapPropertySource("test", defaults));
        var resolver = new FirewallPropertyResolver(sources);
        var source = new DynamicPropertySource(APP, resolver);
        sources.addFirst(source);
        DynamicPropertySource.register(source);
        return new Fixture(source, resolver);
    }

    /**
     * Reads the property until it reads as {@code ""}, for ten seconds at most, and returns the last value read. Reads
     * may answer from the last check of the instance key file for up to a second, so its deletion reaches them only
     * after that.
     */
    private static String readUntilEmpty(DynamicPropertySource source, String name) throws InterruptedException {
        var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        var value = source.getProperty(name);
        while (!"".equals(value) && System.nanoTime() - deadline < 0) {
            TimeUnit.MILLISECONDS.sleep(50);
            value = source.getProperty(name);
        }
        return value;
    }

    private Path settingsFile() {
        return home.resolve(APP + ".properties");
    }

    private Path keyFile() {
        return home.resolve(KEY_FILE);
    }

    private void writeSettings(Map<String, String> settings) throws IOException {
        PropertiesUtils.store(settingsFile(), settings.entrySet());
    }

    /**
     * The settings as the file holds them, or none when there is no file.
     */
    private Map<String, String> stored() throws IOException {
        var stored = new LinkedHashMap<String, String>();
        if (Files.exists(settingsFile())) {
            PropertiesUtils.load(settingsFile(), stored::put);
        }
        return stored;
    }

    private String raw() throws IOException {
        return Files.readString(settingsFile());
    }

    /**
     * A value in the legacy format: AES-128-CBC with a zero IV and a SHA-1-derived key.
     */
    private static String legacy(String plain, String key) throws Exception {
        return "ENC(" + PassCoder.encode(plain, key, CIPHER) + ")";
    }

    /**
     * The content of an {@code ENC(...)} value.
     */
    private static String inner(String value) {
        return value.substring("ENC(".length(), value.length() - 1);
    }

    /**
     * Asserts that a stored value is in the v2 format and does not hold its plain value, and returns it.
     */
    private static String assertV2(@Nullable String value, String plain, String name) {
        if (value == null) {
            return fail("The property must be stored: " + name);
        }
        assertTrue(value.startsWith(V2) && value.endsWith(")"), "The property must be stored as ENC(v2:...): " + name);
        assertFalse(value.contains(plain), "The stored value must not hold the plain value: " + name);
        return value;
    }

    /**
     * Compares a secret with a fixed failure message, so a failure never prints the secret.
     */
    private static void assertSecret(String expected, @Nullable Object actual, String message) {
        assertTrue(expected.equals(actual), message);
    }

    private static void assertNoneLogged(String log, List<String> secrets) {
        for (var secret : secrets) {
            assertFalse(log.contains(secret), "A secret, a ciphertext or a key must never be logged");
        }
    }

    private static String random() {
        var bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    /**
     * An opened settings source and the resolver of its defaults.
     */
    private record Fixture(DynamicPropertySource source, FirewallPropertyResolver resolver) {
    }
}

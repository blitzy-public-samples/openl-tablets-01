package org.openl.spring.env;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicReference;

import org.jspecify.annotations.Nullable;
import org.springframework.core.env.EnumerablePropertySource;

import org.openl.info.OpenLVersion;
import org.openl.util.FileUtils;
import org.openl.util.HashingUtils;
import org.openl.util.PropertiesUtils;
import org.openl.util.StringUtils;

/**
 * Loads always actual properties from an external file located in ${openl.home} directory.
 *
 * @author Yury Molchan
 */
public class DynamicPropertySource extends EnumerablePropertySource<Object> {
    public static final String PROPS_NAME = "Dynamic properties";

    public static final String OPENL_HOME = "openl.home";
    public static final String OPENL_HOME_SHARED = "openl.home.shared";

    private static final String PROP_VERSION = ".version";

    // V6: fingerprints of the undecryptable ENC(v2:...) values already reported, so each is logged once. Bounded,
    // because the values come from configuration files an administrator can edit at any time.
    private static final int MAX_REPORTED_V2_FAILURES = 1_000;
    private static final Set<String> REPORTED_V2_FAILURES = new HashSet<>();

    private final FirewallPropertyResolver resolver;
    private final String appName;

    private final AtomicReference<Map<String, String>> settings = new AtomicReference<>();
    private volatile String version;
    private volatile long timestamp;

    public DynamicPropertySource(String appName, FirewallPropertyResolver resolver) {
        super(PROPS_NAME);
        this.resolver = resolver;
        this.appName = appName;
        loadProperties();
    }

    @Override
    public String[] getPropertyNames() {
        return settings.get().keySet().toArray(StringUtils.EMPTY_STRING_ARRAY);
    }

    @Override
    public boolean containsProperty(String name) {
        return settings.get().containsKey(name);
    }

    public boolean reloadIfModified() {
        var l = getFile().lastModified();
        var modified = l != timestamp;
        if (modified) {
            loadProperties();
        }
        return modified;
    }

    private synchronized void loadProperties() {
        var file = getFile();
        var properties = new LinkedHashMap<String, String>();
        var lastModified = file.lastModified();
        if (file.exists()) {
            try {
                PropertiesUtils.load(file.toPath(), properties::put);
                ConfigLog.LOG.info("+       Load: '{}' ({} properties)", getFile(), properties.size());
            } catch (IOException e) {
                ConfigLog.LOG.error("!     Error:", e);
            }
            version = properties.get(PROP_VERSION);
        } else {
            // If the file does not exist, then it is default settings for the current version.
            version = OpenLVersion.getVersion();
        }
        settings.set(properties);
        timestamp = lastModified;
    }

    private File getFile() {
        var property = resolver.getProperty(OPENL_HOME_SHARED);
        return new File(property, appName + ".properties");
    }

    // V6: the folder of the settings file, ${openl.home.shared}, which also holds the instance key file.
    private Path sharedDir() {
        return getFile().getAbsoluteFile().getParentFile().toPath();
    }

    @Override
    public String getProperty(String name) {
        if (OPENL_HOME.equals(name) || OPENL_HOME_SHARED.equals(name)) {
            // prevent cycled call
            return null;
        }
        var property = settings.get().get(name);
        if (property == null) {
            return null;
        }
        property = StringUtils.trimToEmpty(property);
        return decode(property);
    }

    private static DynamicPropertySource THE;

    public static DynamicPropertySource get() {
        return THE;
    }

    /**
     * Makes the given source the one {@link #get()} returns.
     */
    static void register(DynamicPropertySource source) {
        THE = source;
    }

    /**
     * Returns the OpenL version of these properties.
     */
    public String version() {
        return version;
    }

    /**
     * Stores the given settings, keeping only what differs from the application defaults.
     *
     * <p>A property with a {@code null} value is removed, and settings that leave nothing to store delete the
     * file.
     *
     * <p>A property whose name ends in {@code password}, {@code secret} or {@code token}, except {@code secret.key}
     * itself, is stored as {@code ENC(v2:...)}: AES-256-GCM with a PBKDF2-derived key, and a random salt and nonce
     * per value. Such a property is compared with its default by its decrypted value, so a value equal to its default
     * is removed and is never encrypted. Legacy {@code ENC(...)} and plain-text values of such properties are
     * re-encrypted on save; a legacy value that cannot be decrypted is kept as it is. An unchanged value keeps its
     * ciphertext, so a save that changes nothing does not rewrite the file. The key is {@code secret.key} when it is
     * configured; when it is blank, the key is the instance key in {@code ${openl.home.shared}/.openl-secret-key},
     * created on first need. A secret that cannot be encrypted keeps its previously stored value, or is not stored.
     *
     * <p>The stored file stays newer than what this source has read, so the running application meets it as a
     * change on its next {@link #reloadIfModified()} and reloads its configuration. A caller that stores
     * settings the application already holds — during start-up, for instance — calls {@link #reloadIfModified()}
     * itself right after, otherwise its own write is taken for a change someone made.
     *
     * @param config settings to store, a {@code null} value removing the property
     */
    public synchronized void save(Map<String, String> config) throws IOException {
        // V6: read the key first; secret.key may be stored in this very file, which is hidden from the resolver below.
        var configuredKey = getSecretKey();
        var cipher = getCipher();
        final var properties = new TreeMap<>(settings.get());
        for (Map.Entry<String, String> pair : config.entrySet()) {
            var propertyName = pair.getKey();
            var value = pair.getValue();
            if (value == null) {
                properties.remove(propertyName);
            } else {
                // V6: secrets are encrypted after the clean-up from default values below, not while merging.
                properties.put(propertyName, value);
            }
        }
        var origin = settings.get();

        // 'unconfigure' settings for matching with defaults. to get settings not from a file
        settings.set(Map.of());

        // Do clean up from default values
        // V6: a secret is compared with its default by its decrypted value.
        properties.entrySet()
                .removeIf(e -> isSecretName(e.getKey())
                        ? isSecretDefault(e.getKey(), e.getValue(), configuredKey, cipher)
                        : Objects.equals(resolver.getRawProperty(e.getKey()), e.getValue()));

        // V6: every secret left to store is written in the v2 format. The origin is never null once the source has
        // loaded; requireNonNull states that for NullAway.
        encryptSecrets(properties, Objects.requireNonNull(origin), configuredKey, cipher);

        // Remove version for correct determining of properties to save
        properties.remove(PROP_VERSION);

        var noPropsToSave = properties.isEmpty();

        version = OpenLVersion.getVersion();
        settings.set(properties);

        if (noPropsToSave) {
            // Nothing to save. Delete old settings.
            var settingsFile = getFile();
            FileUtils.deleteQuietly(settingsFile);
            return;
        }

        // Mark version of the settings for migration purposes.
        properties.put(PROP_VERSION, OpenLVersion.getVersion());

        if (!origin.equals(properties)) {
            // Save the difference only
            writeSettings(properties);
        }
    }

    // V6: replaces the former endsWith("password") check of save(). Here and in the helpers below, jspecify
    // @Nullable marks the inputs and results that may be null, so NullAway raises no new warning.
    /**
     * Tells whether a property is stored encrypted: its name ends in {@code password}, {@code secret} or
     * {@code token}, and it is not {@code secret.key}, the key the others are encrypted with. The match is
     * case-sensitive. Names ending in {@code secret-key}, {@code account-key} or {@code local-key} do not match.
     *
     * @param name the property name, may be {@code null}
     * @return {@code true} when a value of the property is stored as {@code ENC(v2:...)}
     */
    static boolean isSecretName(@Nullable String name) {
        return name != null && !"secret.key".equals(name)
                && (name.endsWith("password") || name.endsWith("secret") || name.endsWith("token"));
    }

    // V6: normalization of the secrets left after the clean-up from default values.
    /**
     * Stores every secret of {@code properties} in the v2 format: a plain-text value is encrypted, a legacy
     * {@code ENC(...)} value is decrypted and encrypted again, and a v2 value is kept as it is. A plain-text value
     * equal to the decrypted v2 value previously stored keeps that ciphertext, so an unchanged save writes nothing. A
     * value that fails to encrypt is replaced by the previously stored value, or removed when there is none, so a new
     * plain-text value never reaches the file. No exception escapes, so the caller always completes the save.
     */
    private void encryptSecrets(Map<String, String> properties,
            Map<String, String> origin,
            String configuredKey,
            String cipher) {
        for (var iterator = properties.entrySet().iterator(); iterator.hasNext();) {
            var entry = iterator.next();
            var name = entry.getKey();
            var value = entry.getValue();
            if (!isSecretName(name) || StringUtils.isBlank(value)) {
                continue;
            }
            var inner = encInner(value);
            if (inner != null && inner.startsWith(PassCoder.V2_PREFIX)) {
                // Already in the v2 format; kept even when it cannot be decrypted, so that nothing is lost.
                continue;
            }
            var previous = origin.get(name);
            try {
                if (inner != null) {
                    var plain = legacyPlain(inner, configuredKey, cipher);
                    if (plain == null) {
                        ConfigLog.LOG.warn("Cannot re-encrypt legacy encoded property '{}'; the stored value is kept.",
                                name);
                    } else {
                        entry.setValue(encodePassword(plain, configuredKey));
                    }
                } else if (isSameSecret(value, previous, configuredKey)) {
                    entry.setValue(previous);
                } else {
                    entry.setValue(encodePassword(value, configuredKey));
                }
            } catch (Exception e) {
                ConfigLog.LOG.error("Error when setting password property: {}", name, e);
                if (previous == null) {
                    iterator.remove();
                } else {
                    entry.setValue(previous);
                }
            }
        }
    }

    // V6: whether the previously stored v2 ciphertext holds exactly this plain text, so it can be kept as it is.
    private boolean isSameSecret(String plain, @Nullable String previous, String configuredKey) {
        var previousInner = encInner(previous);
        return previousInner != null && previousInner.startsWith(PassCoder.V2_PREFIX)
                && plain.equals(tryDecodeV2(previousInner, configuredKey));
    }

    // V6: an undecryptable stored secret never counts as its default, so it is never dropped by the clean-up.
    private boolean isSecretDefault(String name, String value, String configuredKey, String cipher) {
        var storedPlain = plainOf(value, configuredKey, cipher);
        return storedPlain != null
                && storedPlain.equals(plainOf(resolver.getRawProperty(name), configuredKey, cipher));
    }

    // V6: always the v2 format; secret.key takes precedence, and a blank secret.key no longer means plain text.
    /**
     * Encrypts a secret in the v2 format.
     *
     * @param value the plain text; a blank value is returned unchanged
     * @param configuredKey {@code secret.key}, or {@code null} when it is blank; the instance key is used then, and
     *            created on first need
     * @return {@code ENC(v2:...)}, or the blank value
     * @throws IOException when the instance key file cannot be read or created
     */
    private String encodePassword(String value, String configuredKey) throws GeneralSecurityException, IOException {
        if (StringUtils.isBlank(value)) {
            return value;
        }
        var writeKey = StringUtils.isNotBlank(configuredKey)
                ? configuredKey
                : Objects.requireNonNull(InstanceSecretKey.get(sharedDir(), true), "No instance secret key created.");
        return "ENC(" + PassCoder.encodeV2(value, writeKey) + ")";
    }

    // V6: v2 decryption with the configured key first, then the instance key.
    /**
     * Decrypts the content of an {@code ENC(v2:...)} value with {@code secret.key} when it is configured, and
     * otherwise, or when that fails, with the instance key when its file exists. The GCM tag tells which key wrote the
     * value. Never logs.
     *
     * @return the plain text, or {@code null} when there is no key or no key decrypts the value
     */
    private @Nullable String tryDecodeV2(String inner, String configuredKey) {
        if (StringUtils.isNotBlank(configuredKey)) {
            var plain = decodeV2Quietly(inner, configuredKey);
            if (plain != null) {
                return plain;
            }
        }
        String instanceKey;
        try {
            instanceKey = InstanceSecretKey.get(sharedDir(), false);
        } catch (IOException e) {
            // An unreadable key file counts as no instance key; the caller reports the value it cannot decrypt.
            return null;
        }
        return instanceKey == null ? null : decodeV2Quietly(inner, instanceKey);
    }

    // V6: a wrong key fails the GCM tag and a malformed value fails parsing; both mean "not this key".
    private static @Nullable String decodeV2Quietly(String inner, String key) {
        try {
            return PassCoder.decodeV2(inner, key);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return null;
        }
    }

    // V6: the legacy AES-128-CBC decryption, or null when there is no key or cipher or the value does not decrypt.
    private static @Nullable String legacyPlain(String inner, String configuredKey, String cipher) {
        // Guarded explicitly: with a blank key the legacy decoder returns the ciphertext itself as the plain text.
        if (StringUtils.isBlank(configuredKey) || StringUtils.isBlank(cipher)) {
            return null;
        }
        try {
            return PassCoder.decode(inner, configuredKey, cipher);
        } catch (Exception e) {
            return null;
        }
    }

    // V6: the plain text of a stored or default value, or null when it is null or cannot be decrypted.
    private @Nullable String plainOf(@Nullable String value, String configuredKey, String cipher) {
        var inner = encInner(value);
        if (inner == null) {
            return value;
        }
        if (inner.startsWith(PassCoder.V2_PREFIX)) {
            return tryDecodeV2(inner, configuredKey);
        }
        return legacyPlain(inner, configuredKey, cipher);
    }

    // V6: the content of an ENC(...) wrapper, or null when the value is not wrapped.
    private static @Nullable String encInner(@Nullable String value) {
        if (value == null) {
            return null;
        }
        var trimmed = value.trim();
        if (trimmed.startsWith("ENC(") && trimmed.endsWith(")")) {
            return trimmed.substring(4, trimmed.length() - 1);
        }
        return null;
    }

    private void writeSettings(Map<String, String> properties) throws IOException {
        var settingsFile = getFile();
        var parent = settingsFile.getParentFile();
        if (!parent.mkdirs() && !parent.exists()) {
            throw new FileNotFoundException("The folder cannot be created. " + parent.getAbsolutePath());
        }
        PropertiesUtils.store(settingsFile.toPath(), properties.entrySet());
    }

    static String decode(String value) {
        if (value != null && value.startsWith("ENC(") && value.endsWith(")")) {
            // V6: the v2 format goes to its own decoder; legacy values keep the unchanged path below.
            if (value.startsWith("ENC(" + PassCoder.V2_PREFIX)) {
                return decodeV2Value(value.substring(4, value.length() - 1));
            }
            try {
                return PassCoder.decode(value.substring(4, value.length() - 1),
                        DynamicPropertySource.get().getSecretKey(),
                        DynamicPropertySource.get().getCipher());
            } catch (Exception e) {
                return "";
            }
        } else {
            return value;
        }
    }

    // V6: an undecryptable v2 value reads as "", the existing failure contract, and is reported once per value.
    private static String decodeV2Value(String inner) {
        // Null during early start-up: the application properties are read before this source is registered.
        var source = get();
        if (source != null) {
            var plain = source.tryDecodeV2(inner, source.getSecretKey());
            if (plain != null) {
                return plain;
            }
        }
        if (isFirstV2Failure(inner)) {
            // Names the key file only; the value, its ciphertext and its fingerprint never reach the log.
            if (source != null) {
                ConfigLog.LOG.error("An ENC(v2:...) property value matches neither 'secret.key' nor the instance key"
                        + " file '{}'; an empty value is used.",
                        source.sharedDir().resolve(InstanceSecretKey.FILE_NAME));
            } else {
                ConfigLog.LOG.error("An ENC(v2:...) property value is read before the settings are loaded, so no key"
                        + " can decrypt it; an empty value is used.");
            }
        }
        return "";
    }

    // V6: true once per distinct value; the set is cleared when full, so it never grows without bound.
    private static boolean isFirstV2Failure(String inner) {
        var fingerprint = HashingUtils.sha256Hex(inner);
        synchronized (REPORTED_V2_FAILURES) {
            if (REPORTED_V2_FAILURES.size() >= MAX_REPORTED_V2_FAILURES
                    && !REPORTED_V2_FAILURES.contains(fingerprint)) {
                REPORTED_V2_FAILURES.clear();
            }
            return REPORTED_V2_FAILURES.add(fingerprint);
        }
    }

    public Map<String, String> getProperties() {
        return settings.get();
    }

    private String getSecretKey() {
        return StringUtils.trimToNull(resolver.getProperty("secret.key"));
    }

    private String getCipher() {
        return StringUtils.trimToNull(resolver.getProperty("secret.cipher"));
    }

}

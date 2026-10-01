package org.openl.spring.env;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.AEADBadTagException;

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

    // V6: fingerprints of the undecryptable ENC(v2:...) values already reported, so each is logged once for the life
    // of the JVM. The set grows only with the distinct undecryptable ENC(v2:...) values present in the configuration,
    // which only administrators write; it holds fingerprints, never values.
    private static final Set<String> REPORTED_V2_FAILURES = ConcurrentHashMap.newKeySet();

    // V6: set while the keys of an ENC(v2:...) value are resolved on this thread, so that a key which is itself
    // ENC(v2:...) reads as "" instead of recursing without end.
    private static final ThreadLocal<Boolean> RESOLVING_V2_KEYS = new ThreadLocal<>();

    private final FirewallPropertyResolver resolver;
    private final String appName;

    private final AtomicReference<Map<String, String>> settings = new AtomicReference<>();
    // V6: set on the thread of save() while it reads the defaults; only that thread then meets no settings here.
    private final ThreadLocal<Boolean> readingDefaults = new ThreadLocal<>();
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
        // V6: the settings of the calling thread.
        return visibleSettings().keySet().toArray(StringUtils.EMPTY_STRING_ARRAY);
    }

    @Override
    public boolean containsProperty(String name) {
        // V6: the settings of the calling thread.
        return visibleSettings().containsKey(name);
    }

    // V6: none for the thread of save() while it reads the defaults, the stored settings for every other thread, so
    // reading a default, which may derive the key of an ENC(v2:...) value, never hides the settings from readers.
    private Map<String, String> visibleSettings() {
        return readingDefaults.get() != null ? Map.of() : Objects.requireNonNull(settings.get());
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
        // V6: the settings of the calling thread.
        var property = visibleSettings().get(name);
        if (property == null) {
            return null;
        }
        property = StringUtils.trimToEmpty(property);
        // V6: the name only labels the ERROR of a value that cannot be decrypted.
        return decode(name, property);
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
     * per value. A value given here is plain text and is encrypted as it is, even when it looks like
     * {@code ENC(...)}. Such a property is compared with its default by its decrypted value, so a value equal to its
     * default is removed and is never encrypted. Stored legacy {@code ENC(...)} and plain-text values of such
     * properties are re-encrypted on save; a legacy value that cannot be decrypted is kept as it is, and so is a
     * stored {@code ENC(v2:...)} value. A given value equal to the stored one keeps its ciphertext, so a save that
     * changes nothing does not rewrite the file. The key is {@code secret.key} when it is configured; when it is
     * blank, the key is the instance key in {@code ${openl.home.shared}/.openl-secret-key}, created on first need. A
     * secret that cannot be encrypted keeps its previously stored value, or is not stored. Readers on other threads
     * meet the previously stored settings until the new ones are in place, also while the defaults are read and while
     * the secrets are decrypted and encrypted.
     *
     * <p>The stored file stays newer than what this source has read, so the running application meets it as a
     * change on its next {@link #reloadIfModified()} and reloads its configuration. A caller that stores
     * settings the application already holds — during start-up, for instance — calls {@link #reloadIfModified()}
     * itself right after, otherwise its own write is taken for a change someone made.
     *
     * @param config settings to store, a {@code null} value removing the property; the values are plain text, and a
     *            value is never read as {@code ENC(...)}
     */
    public synchronized void save(Map<String, String> config) throws IOException {
        // V6: read the key first; secret.key may be stored in this very file, which is hidden from the resolver below.
        var configuredKey = getSecretKey();
        var cipher = getCipher();
        final var properties = new TreeMap<>(settings.get());
        // V6: the names whose values come from the caller; those values are plain text, whatever they look like.
        var supplied = new HashSet<String>();
        for (Map.Entry<String, String> pair : config.entrySet()) {
            var propertyName = pair.getKey();
            var value = pair.getValue();
            if (value == null) {
                properties.remove(propertyName);
            } else {
                // V6: secrets are encrypted after the clean-up from default values below, not while merging.
                properties.put(propertyName, value);
                supplied.add(propertyName);
            }
        }
        var origin = settings.get();

        // 'unconfigure' settings for matching with defaults. to get settings not from a file
        // V6: for this thread only; readers on other threads keep the stored settings for the whole save.
        readingDefaults.set(Boolean.TRUE);
        var secretDefaults = new HashMap<String, @Nullable String>();
        try {
            // V6: the defaults of the secrets are only read here; they are decrypted afterwards.
            for (var propertyName : properties.keySet()) {
                if (isSecretName(propertyName)) {
                    secretDefaults.put(propertyName, resolver.getRawProperty(propertyName));
                }
            }

            // Do clean up from default values
            // V6: secrets are compared with their defaults below, by their decrypted values.
            properties.entrySet()
                    .removeIf(e -> !isSecretName(e.getKey())
                            && Objects.equals(resolver.getRawProperty(e.getKey()), e.getValue()));
        } finally {
            readingDefaults.remove();
        }

        // V6: a secret equal to its default is removed before encryption, so it never creates the instance key.
        properties.entrySet()
                .removeIf(e -> secretDefaults.containsKey(e.getKey())
                        && isSecretDefault(e.getKey(),
                                e.getValue(),
                                supplied,
                                secretDefaults.get(e.getKey()),
                                configuredKey,
                                cipher));

        // V6: every secret left to store is written in the v2 format. The origin is never null once the source has
        // loaded.
        encryptSecrets(properties, supplied, Objects.requireNonNull(origin), configuredKey, cipher);

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
    // @Nullable marks the inputs and results that may be null.
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
     * Stores every secret of {@code properties} in the v2 format. A value whose name is in {@code supplied} came from
     * the caller and is plain text: it is encrypted as it is, whatever it looks like, unless it equals the decrypted
     * v2 value previously stored, whose ciphertext is then kept, so an unchanged save writes nothing. A stored value
     * is read as {@link #getProperty(String)} reads it: a plain-text value is encrypted, a legacy {@code ENC(...)}
     * value is decrypted and encrypted again, and a v2 value is kept as it is. A value that fails to encrypt is
     * replaced by the previously stored value, or removed when there is none, so a new plain-text value never reaches
     * the file. No exception escapes, so the caller always completes the save.
     */
    private void encryptSecrets(Map<String, String> properties,
            Set<String> supplied,
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
            var previous = origin.get(name);
            try {
                if (supplied.contains(name)) {
                    // V6: a value from the caller is plain text and is encrypted as it is, even when it looks like
                    // ENC(...).
                    entry.setValue(isSameSecret(value, previous, configuredKey)
                            ? previous
                            : encodePassword(value, configuredKey));
                    continue;
                }
                // V6: a stored value is read as getProperty reads it: trimmed, then unwrapped from ENC(...). A value
                // already in the v2 format is kept as it is, even when it cannot be decrypted, so that nothing is lost.
                var stored = StringUtils.trimToEmpty(value);
                var inner = encInner(stored);
                if (inner == null) {
                    entry.setValue(encodePassword(stored, configuredKey));
                } else if (!inner.startsWith(PassCoder.V2_PREFIX)) {
                    var plain = legacyPlain(inner, configuredKey, cipher);
                    if (plain == null) {
                        ConfigLog.LOG.warn("Cannot re-encrypt legacy encoded property '{}'; the stored value is kept.",
                                name);
                    } else {
                        entry.setValue(encodePassword(plain, configuredKey));
                    }
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
        if (previous == null) {
            return false;
        }
        // V6: the stored value is read as getProperty reads it.
        var previousInner = encInner(StringUtils.trimToEmpty(previous));
        return previousInner != null && previousInner.startsWith(PassCoder.V2_PREFIX)
                && plain.equals(tryDecodeV2(previousInner, configuredKey));
    }

    // V6: an undecryptable stored secret never counts as its default, so it is never dropped by the clean-up. A value
    // from the caller is plain text; a stored value is read as getProperty reads it. A secret without a default is
    // not decrypted at all.
    private boolean isSecretDefault(String name,
            String value,
            Set<String> supplied,
            @Nullable String defaultValue,
            String configuredKey,
            String cipher) {
        var defaultPlain = plainOf(defaultValue, configuredKey, cipher);
        if (defaultPlain == null) {
            return false;
        }
        var plain = supplied.contains(name) ? value : plainOf(StringUtils.trimToEmpty(value), configuredKey, cipher);
        return defaultPlain.equals(plain);
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
        // V6: saves compare and keep ciphertexts silently, so why a value does not decrypt is not kept.
        return tryDecodeV2(inner, configuredKey, new V2Failure());
    }

    // V6: as above, and records in failure why no key decrypts the value, so that a read can report the cause.
    private @Nullable String tryDecodeV2(String inner, String configuredKey, V2Failure failure) {
        if (StringUtils.isNotBlank(configuredKey)) {
            var plain = decodeV2Quietly(inner, configuredKey, failure);
            if (plain != null) {
                return plain;
            }
            failure.configuredKeyRejected = true;
        }
        var directory = sharedDir();
        failure.keyFile = directory.resolve(InstanceSecretKey.FILE_NAME);
        String instanceKey;
        try {
            instanceKey = InstanceSecretKey.get(directory, false);
        } catch (IOException e) {
            // V6: an unreadable key file counts as no instance key; its exception, which names the path only, is
            // the cause the caller reports.
            failure.fail(e);
            return null;
        }
        if (instanceKey == null) {
            failure.instanceKeyAbsent = true;
            return null;
        }
        return decodeV2Quietly(inner, instanceKey, failure);
    }

    // V6: a wrong key fails the GCM tag, which means "not this key"; a malformed value or a missing algorithm is
    // recorded in failure as the cause.
    private static @Nullable String decodeV2Quietly(String inner, String key, V2Failure failure) {
        try {
            return PassCoder.decodeV2(inner, key);
        } catch (AEADBadTagException e) {
            return null;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            failure.fail(e);
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

    // V6: the content of an ENC(...) wrapper, or null when the value is not wrapped. The one recogniser of the wrapper
    // for reads and saves: the value must start with "ENC(" and end with ")" exactly, without surrounding blanks.
    private static @Nullable String encInner(@Nullable String value) {
        if (value != null && value.startsWith("ENC(") && value.endsWith(")")) {
            return value.substring(4, value.length() - 1);
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
        // V6: a value read without its property name, as the application properties read theirs.
        return decode(null, value);
    }

    // V6: the name, when it is known, only labels the ERROR of a v2 value that cannot be decrypted.
    private static String decode(@Nullable String name, String value) {
        var inner = encInner(value);
        if (inner != null) {
            // V6: the v2 format goes to its own decoder; legacy values keep the unchanged path below.
            if (inner.startsWith(PassCoder.V2_PREFIX)) {
                return decodeV2Value(name, inner);
            }
            try {
                return PassCoder.decode(inner,
                        DynamicPropertySource.get().getSecretKey(),
                        DynamicPropertySource.get().getCipher());
            } catch (Exception e) {
                return "";
            }
        } else {
            return value;
        }
    }

    // V6: an undecryptable v2 value reads as "", the existing failure contract, and is reported once per value. The
    // ERROR names the property when it is known and the cause; the value, its ciphertext and its fingerprint never
    // reach the log.
    private static String decodeV2Value(@Nullable String name, String inner) {
        var subject = name != null
                ? "The ENC(v2:...) value of property '" + name + "'"
                : "An ENC(v2:...) property value";
        // Null during early start-up: the application properties are read before this source is registered.
        var source = get();
        if (source == null) {
            if (isFirstV2Failure(inner)) {
                ConfigLog.LOG.error("{} is read before the settings are loaded, so no key can decrypt it; an empty"
                        + " value is used.", subject);
            }
            return "";
        }
        if (RESOLVING_V2_KEYS.get() != null) {
            // secret.key or openl.home.shared is itself ENC(v2:...); decrypting it would need itself.
            if (isFirstV2Failure(inner)) {
                ConfigLog.LOG.error("{} cannot be decrypted: it is read while the keys of another ENC(v2:...) value"
                        + " are resolved, and 'secret.key' and 'openl.home.shared' cannot be ENC(v2:...) themselves;"
                        + " an empty value is used.", subject);
            }
            return "";
        }
        var failure = new V2Failure();
        String plain;
        RESOLVING_V2_KEYS.set(Boolean.TRUE);
        try {
            plain = source.tryDecodeV2(inner, source.getSecretKey(), failure);
        } finally {
            RESOLVING_V2_KEYS.remove();
        }
        if (plain != null) {
            return plain;
        }
        if (isFirstV2Failure(inner)) {
            var error = failure.error;
            // toString() gives the class and the message only, without a stack trace or causes; the messages name a
            // path or a fixed text.
            if (error instanceof IOException) {
                ConfigLog.LOG.error("{} cannot be decrypted: the instance key file '{}' cannot be read ({}); an empty"
                        + " value is used.", subject, failure.keyFile, error.toString());
            } else if (error != null) {
                ConfigLog.LOG.error("{} cannot be decrypted: {}; an empty value is used.", subject, error.toString());
            } else {
                ConfigLog.LOG.error("{} cannot be decrypted: {}, and the instance key file '{}' {}; an empty value is"
                        + " used.",
                        subject,
                        failure.configuredKeyRejected ? "'secret.key' does not decrypt it" : "'secret.key' is blank",
                        failure.keyFile,
                        failure.instanceKeyAbsent ? "does not exist" : "does not decrypt it");
            }
        }
        return "";
    }

    // V6: true once per distinct value; a reported value is never reported again.
    private static boolean isFirstV2Failure(String inner) {
        return REPORTED_V2_FAILURES.add(HashingUtils.sha256Hex(inner));
    }

    // V6: why no key decrypts an ENC(v2:...) value, for the ERROR of its read. It holds a path and exceptions whose
    // messages name a path or a fixed text, never a value, a ciphertext or a key.
    private static final class V2Failure {
        // secret.key is configured and does not decrypt the value
        private boolean configuredKeyRejected;
        // the instance key file does not exist
        private boolean instanceKeyAbsent;
        // the instance key file looked up
        private @Nullable Path keyFile;
        // the first failure other than a wrong key: an unreadable key file, a malformed value or a missing algorithm
        private @Nullable Exception error;

        private void fail(Exception e) {
            if (error == null) {
                error = e;
            }
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

package org.openl.spring.env;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
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

    // V6: how many fingerprints of reported ENC(v2:...) values are remembered at most.
    static final int REPORTED_V2_FAILURES_CAP = 1_000;

    // V6: fingerprints, never values, of the reported undecryptable ENC(v2:...) values, by their last failing read.
    // A value is reported once while it stays among the REPORTED_V2_FAILURES_CAP distinct values that failed most
    // recently, however often it is read; once that many other values have failed after its last failing read, it is
    // forgotten and its next failing read reports it once more.
    private static final Set<String> REPORTED_V2_FAILURES = Collections
            .synchronizedSet(Collections.newSetFromMap(new LinkedHashMap<String, Boolean>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                    return size() > REPORTED_V2_FAILURES_CAP;
                }
            }));

    // V6: set while this thread resolves the keys of a v2 value; a key that is itself ENC(v2:...) then reads as "".
    // This keeps the decryption of such a key from recursing without end.
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

    // V6: no settings for the thread of save() while it reads the defaults, the stored settings for every other thread.
    // So reading a default, which may derive the key of an ENC(v2:...) value, never hides the settings from readers.
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
        // V6: a reload drops the cached keys of the ENC(v2:...) values the file no longer holds.
        replaceSettings(properties);
        timestamp = lastModified;
    }

    // V6: puts the settings in place and drops the PassCoder keys of the replaced ENC(v2:...) values they do not hold.
    private void replaceSettings(Map<String, String> properties) {
        var previous = settings.getAndSet(properties);
        if (previous == null) {
            return;
        }
        var kept = new HashSet<String>();
        for (var value : properties.values()) {
            // V6: a value is read as getProperty reads it: trimmed, then unwrapped from ENC(...).
            var inner = encInner(StringUtils.trimToEmpty(value));
            if (inner != null && inner.startsWith(PassCoder.V2_PREFIX)) {
                kept.add(inner);
            }
        }
        for (var value : previous.values()) {
            var inner = encInner(StringUtils.trimToEmpty(value));
            if (inner != null && inner.startsWith(PassCoder.V2_PREFIX) && !kept.contains(inner)) {
                PassCoder.forget(inner);
            }
        }
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
     * secret that cannot be encrypted fails the save before anything is stored, so the settings this source holds and
     * the file stay as they were. Readers on other threads meet the previously stored settings until the new ones are
     * in place, also while the defaults are read and while the secrets are decrypted and encrypted.
     *
     * <p>The stored file stays newer than what this source has read, so the running application meets it as a
     * change on its next {@link #reloadIfModified()} and reloads its configuration. A caller that stores
     * settings the application already holds — during start-up, for instance — calls {@link #reloadIfModified()}
     * itself right after, otherwise its own write is taken for a change someone made.
     *
     * @param config settings to store, a {@code null} value removing the property; the values are plain text, and a
     *            value is never read as {@code ENC(...)}
     * @throws IOException when a secret cannot be encrypted, with a message that names the property and the cause and
     *             never a value, or when the settings file cannot be written
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

        // V6: every secret left is written as v2; a failure throws here, before anything is published or written.
        // The origin is never null once the source has loaded.
        encryptSecrets(properties, supplied, Objects.requireNonNull(origin), configuredKey, cipher);

        // Remove version for correct determining of properties to save
        properties.remove(PROP_VERSION);

        var noPropsToSave = properties.isEmpty();

        version = OpenLVersion.getVersion();
        // V6: a save drops the cached keys of the ENC(v2:...) values it replaces or removes.
        replaceSettings(properties);

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

    // V6: a setting whose name ends in password, secret or token is encrypted, except secret.key; null never matches.
    // Here and in the helpers below, jspecify @Nullable marks the inputs and results that may be null.
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
     * value is decrypted and encrypted again, and a v2 value is kept as it is. A legacy value that no key decrypts is
     * kept as it is, with a WARN. A value that fails to encrypt fails the whole save: the caller has published and
     * written nothing yet, so neither a plain-text value nor the loss of a given one can follow from it. The failed
     * save also drops the cached {@link PassCoder} keys of the ciphertexts it made, since none of them is published.
     *
     * @throws IOException when a secret cannot be encrypted; the message names the property and the cause in fixed
     *             words, never the value, and the failure is not kept as its cause
     */
    private void encryptSecrets(Map<String, String> properties,
            Set<String> supplied,
            Map<String, String> origin,
            String configuredKey,
            String cipher) throws IOException {
        // V6: the ciphertexts made here; a failed save publishes none of them, so it drops their cached keys.
        var made = new ArrayList<String>();
        // V6: no entry is removed here; a secret that cannot be encrypted fails the save instead.
        for (var entry : properties.entrySet()) {
            var name = entry.getKey();
            var value = entry.getValue();
            // V6: a blank secret is encrypted too, so every secret written is ENC(v2:...).
            if (!isSecretName(name)) {
                continue;
            }
            var previous = origin.get(name);
            try {
                if (supplied.contains(name)) {
                    // V6: a caller's value is plain text and is encrypted as it is, even when it looks like ENC(...).
                    if (isSameSecret(value, previous, configuredKey)) {
                        entry.setValue(previous);
                    } else {
                        entry.setValue(encodePassword(value, configuredKey));
                        made.add(entry.getValue());
                    }
                    continue;
                }
                // V6: a stored value is read as getProperty reads it: trimmed, then unwrapped from ENC(...).
                // A v2 value is kept as it is, even when it cannot be decrypted, so that nothing is lost.
                var stored = StringUtils.trimToEmpty(value);
                var inner = encInner(stored);
                if (inner == null) {
                    entry.setValue(encodePassword(stored, configuredKey));
                    made.add(entry.getValue());
                } else if (!inner.startsWith(PassCoder.V2_PREFIX)) {
                    var plain = legacyPlain(inner, configuredKey, cipher);
                    if (plain == null) {
                        // V6: the name is rendered on one line, so that it cannot forge another log line.
                        ConfigLog.LOG.warn("Cannot re-encrypt legacy encoded property '{}'; the stored value is kept.",
                                safeLabel(name));
                    } else {
                        entry.setValue(encodePassword(plain, configuredKey));
                        made.add(entry.getValue());
                    }
                }
            } catch (IOException | GeneralSecurityException | RuntimeException e) {
                // V6: never the previous value, which may be plain text, and never a silent drop of a given one.
                for (var ciphertext : made) {
                    PassCoder.forget(encInner(ciphertext));
                }
                throw cannotEncrypt(name, e, sharedDir().resolve(InstanceSecretKey.FILE_NAME));
            }
        }
    }

    // V6: the failure of a save whose secret cannot be encrypted, also logged as one ERROR line.
    // The cause is given in fixed words by the type of the failure: the failure's own text may hold anything, and it
    // is neither logged nor kept as the cause, since the callers log the returned exception with its causes.
    /**
     * Describes why the secret {@code name} cannot be encrypted, logs it as an ERROR and returns it as the exception
     * that fails the save.
     *
     * @param name the property of the secret
     * @param failure why it cannot be encrypted: an {@link IOException} of the instance key file, a
     *            {@link GeneralSecurityException} of the JDK, or any other unexpected failure
     * @param keyFile the instance key file, named when it is the cause
     * @return the exception to throw; its message names the property and the cause, never a value
     */
    static IOException cannotEncrypt(String name, Exception failure, Path keyFile) {
        String cause;
        if (failure instanceof IOException) {
            cause = "the instance key file '" + safeLabel(keyFile) + "' cannot be read or created";
        } else if (failure instanceof GeneralSecurityException) {
            cause = "the JDK does not provide the cipher or the key derivation";
        } else {
            cause = "the encryption failed unexpectedly";
        }
        var message = "Cannot encrypt the value of property '" + safeLabel(name) + "' (" + cause
                + "); the settings are not saved.";
        ConfigLog.LOG.error("{}", message);
        return new IOException(message);
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

    // V6: an undecryptable stored secret never counts as its default, so the clean-up never drops it.
    // A value from the caller is plain text; a stored value is read as getProperty reads it. A secret without a
    // default is not decrypted at all.
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

    // V6: always the v2 format, with secret.key when configured and otherwise the instance key, created on first need.
    /**
     * Encrypts a secret in the v2 format.
     *
     * @param value the plain text; a blank value is encrypted as well
     * @param configuredKey {@code secret.key}, or {@code null} when it is blank; the instance key is used then, and
     *            created on first need
     * @return {@code ENC(v2:...)}, also for a blank value
     * @throws IOException when the instance key file cannot be read or created
     */
    private String encodePassword(String value, String configuredKey) throws GeneralSecurityException, IOException {
        // V6: no blank value is returned as plain text; the v2 format encrypts an empty value too.
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
            // V6: an unreadable key file counts as no instance key; the caller reports it by its exception type.
            // That report renders the path on one line.
            failure.fail(e);
            return null;
        }
        if (instanceKey == null) {
            failure.instanceKeyAbsent = true;
            return null;
        }
        return decodeV2Quietly(inner, instanceKey, failure);
    }

    // V6: a failed GCM tag means "not this key"; a malformed value or a missing algorithm is recorded as the cause.
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
        // V6: the legacy format stores a blank value as it is, so a blank content is its plain text under any key.
        if (StringUtils.isBlank(inner)) {
            return inner;
        }
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
    // It is the one recogniser of the wrapper for reads and saves: the value must start with "ENC(" and end with ")"
    // exactly, without surrounding blanks.
    private static @Nullable String encInner(@Nullable String value) {
        if (value != null && value.startsWith("ENC(") && value.endsWith(")")) {
            return value.substring(4, value.length() - 1);
        }
        return null;
    }

    // V6: the one rendering of a property name or a path in a log line or an exception message of the secrets.
    /**
     * Renders a property name or a path on one line, so that it can neither end the log line it is written in nor
     * pass for another one. Each UTF-16 unit of an ISO control character (U+0000 to U+001F and U+007F to U+009F, CR,
     * LF and NEL among them), of the line separator U+2028, of the paragraph separator U+2029, of a Unicode format
     * character such as U+202E, of an unpaired surrogate, and of the quotes {@code '} and {@code "} and the
     * backslash, which delimit the rendering and start its escapes, is written as a backslash, the letter {@code u}
     * and the four upper-case hexadecimal digits of the unit. Every other character is kept as it is.
     *
     * @param label the property name or the path; {@code null} is rendered as {@code null}
     * @return the label on one line
     */
    private static String safeLabel(@Nullable Object label) {
        var text = String.valueOf(label);
        var hex = HexFormat.of().withUpperCase();
        var safe = new StringBuilder(text.length());
        text.codePoints().forEach(codePoint -> {
            if (isUnsafeInLabel(codePoint)) {
                for (var unit : Character.toChars(codePoint)) {
                    safe.append("\\u").append(hex.toHexDigits(unit));
                }
            } else {
                safe.appendCodePoint(codePoint);
            }
        });
        return safe.toString();
    }

    // V6: the characters safeLabel escapes; an unpaired surrogate is a code point of its own type.
    private static boolean isUnsafeInLabel(int codePoint) {
        return switch (Character.getType(codePoint)) {
            case Character.CONTROL, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR, Character.FORMAT,
                    Character.SURROGATE -> true;
            default -> codePoint == '\'' || codePoint == '"' || codePoint == '\\';
        };
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

    // V6: an undecryptable v2 value reads as "", the existing failure contract, with an ERROR that holds no value.
    // The ERROR is deduplicated while the value's fingerprint stays among the REPORTED_V2_FAILURES_CAP remembered
    // ones, and a value pushed out of them is reported again. It names the property when it is known and the cause;
    // the value, its ciphertext and its fingerprint never reach the log.
    private static String decodeV2Value(@Nullable String name, String inner) {
        // Null during early start-up: the application properties are read before this source is registered.
        var source = get();
        if (source == null) {
            if (isFirstV2Failure(inner) && ConfigLog.LOG.isErrorEnabled()) {
                // V6: counted as reported even with ERROR off; the subject is built only for an ERROR that is logged.
                ConfigLog.LOG.error("{} is read before the settings are loaded, so no key can decrypt it; an empty"
                        + " value is used.", v2Subject(name));
            }
            return "";
        }
        if (RESOLVING_V2_KEYS.get() != null) {
            // secret.key or openl.home.shared is itself ENC(v2:...); decrypting it would need itself.
            if (isFirstV2Failure(inner) && ConfigLog.LOG.isErrorEnabled()) {
                // V6: counted as reported even with ERROR off; the subject is built only for an ERROR that is logged.
                ConfigLog.LOG.error("{} cannot be decrypted: it is read while the keys of another ENC(v2:...) value"
                        + " are resolved, and 'secret.key' and 'openl.home.shared' cannot be ENC(v2:...) themselves;"
                        + " an empty value is used.", v2Subject(name));
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
        if (isFirstV2Failure(inner) && ConfigLog.LOG.isErrorEnabled()) {
            // V6: counted as reported even with ERROR off; the subject and cause are built only for a logged ERROR.
            var subject = v2Subject(name);
            var error = failure.error;
            // V6: the cause is named in fixed words by its type, and the path is rendered on one line.
            // The text of the failure itself never reaches the log.
            if (error != null) {
                ConfigLog.LOG.error("{} cannot be decrypted: {}; an empty value is used.",
                        subject,
                        decryptionCause(error, failure.keyFile));
            } else {
                ConfigLog.LOG.error("{} cannot be decrypted: {}, and the instance key file '{}' {}; an empty value is"
                        + " used.",
                        subject,
                        failure.configuredKeyRejected ? "'secret.key' does not decrypt it" : "'secret.key' is blank",
                        safeLabel(failure.keyFile),
                        failure.instanceKeyAbsent ? "does not exist" : "does not decrypt it");
            }
        }
        return "";
    }

    // V6: the subject of the ERROR of an undecryptable ENC(v2:...) value: its property, or an unnamed value.
    // The name is rendered on one line, so that it cannot forge another log line.
    private static String v2Subject(@Nullable String name) {
        return name != null
                ? "The ENC(v2:...) value of property '" + safeLabel(name) + "'"
                : "An ENC(v2:...) property value";
    }

    // V6: why no key decrypts an ENC(v2:...) value, in fixed words by the type of the failure.
    /**
     * Describes the failure that keeps an {@code ENC(v2:...)} value from being decrypted, without its own text.
     *
     * @param failure an {@link IOException} of the instance key file, an {@link IllegalArgumentException} of a value
     *            that is not well-formed, or a {@link GeneralSecurityException} of the JDK
     * @param keyFile the instance key file, named when it is the cause
     * @return the cause, for the ERROR of the read
     */
    static String decryptionCause(Exception failure, @Nullable Path keyFile) {
        if (failure instanceof IOException) {
            return "the instance key file '" + safeLabel(keyFile) + "' cannot be read";
        }
        if (failure instanceof IllegalArgumentException) {
            return "the value is not a well-formed ENC(v2:...) value";
        }
        return "the JDK does not provide the cipher or the key derivation";
    }

    // V6: true when the value is not among the remembered reported ones; each call counts as a failing read of it.
    private static boolean isFirstV2Failure(String inner) {
        return REPORTED_V2_FAILURES.add(HashingUtils.sha256Hex(inner));
    }

    // V6: why no key decrypts an ENC(v2:...) value, for the ERROR of its read; never a value, a ciphertext or a key.
    // It holds a path and the first failure. The ERROR gives only the type of the failure, in fixed words, and the
    // path rendered on one line.
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

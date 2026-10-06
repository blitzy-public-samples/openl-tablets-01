package org.openl.rules.webstudio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junitpioneer.jupiter.RestoreSystemProperties;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.mock.web.MockServletContext;

import org.openl.info.OpenLVersion;
import org.openl.rules.dataformat.yaml.YamlMapperFactory;
import org.openl.rules.project.impl.local.MetainfoRegistry;
import org.openl.rules.project.impl.local.ProjectMetainfo;
import org.openl.rules.webstudio.web.Props;
import org.openl.rules.webstudio.web.install.KeyPairCertUtils;
import org.openl.rules.workspace.dtr.impl.ProjectIndex;
import org.openl.rules.workspace.dtr.impl.ProjectInfo;
import org.openl.spring.env.PropertySourcesLoader;
import org.openl.util.PropertiesUtils;

/**
 * Tests of {@link Migrator#migrate()}, the start-up migration of the settings and files a previous installation left:
 * the version guards, the property migrations of 5.24.0, 5.26.0, 5.26.1, 6.0.0 and 6.4.0, the 5.24.0 move of the
 * project paths, the non-flat project settings and the project locks, the generated SAML key and certificate, and the
 * failures each of them logs instead of breaking the start-up.
 *
 * <p>The settings are loaded as the application loads them: {@link PropertySourcesLoader} reads
 * {@code ${openl.home.shared}/webstudio.properties} for the {@code /webstudio} context path, and the {@code .version}
 * property of that file is the version the migrations start from. Each test points {@code openl.home},
 * {@code openl.home.shared} and {@code user.workspace.home} at its own temporary folder, and checks the saved settings
 * file and the files on disk. Unit tests log through slf4j-simple to {@link System#err}, so {@link StdIo} captures
 * the logged failures; the assertions match message substrings only.
 */
@RestoreSystemProperties
class MigratorSettingsTest {

    private static final String LEGACY_SETTINGS = ".version=5.23.1\n";
    private static final String DEFAULT_PRODUCTION_URI = "jdbc:h2:mem:repo;DB_CLOSE_DELAY=-1";
    private static final String CHANGED_PRODUCTION_URI = "jdbc:postgresql://db.example.com/openl";
    private static final String CONFIGS = "production-repository-configs";
    private static final String NAME = "repository.production.name";
    private static final String REF = "repository.production.$ref";
    private static final String BASE_PATH = "repository.production.base.path.$ref";
    private static final String URI = "repository.production.uri";
    private static final String DEFAULT_BASE_PATH = "repo-default.production.base.path";
    private static final String PROJECT_LIST = """
            project.1.name=Bank Rating
            project.1.path=DESIGN/rules/Banking/Bank Rating
            project.2.name=Auto Policy
            project.2.path=DESIGN/rules/Insurance/Auto Policy
            """;
    private static final List<String> REMOVED_SAML_PROPERTIES = List.of("security.saml.app-url",
            "security.saml.authentication-contexts",
            "security.saml.local-logout",
            "security.saml.is-app-after-balancer",
            "security.saml.scheme",
            "security.saml.server-name",
            "security.saml.server-port",
            "security.saml.include-server-port-in-request-url",
            "security.saml.context-path",
            "security.saml.max-authentication-age",
            "security.saml.metadata-trust-check",
            "security.saml.request-timeout",
            "security.saml.keystore-file-path",
            "security.saml.keystore-password",
            "security.saml.keystore-sp-alias",
            "security.saml.keystore-sp-password");

    @TempDir
    Path home;

    private Environment previousEnvironment;

    @BeforeEach
    void setUp() throws IOException {
        // The environment found here is restored after the test, so no test reads the settings another installed.
        previousEnvironment = Props.getEnvironment();
        System.setProperty("openl.home", home.toString());
        System.setProperty("openl.home.shared", home.toString());
        // An existing workspace, as the application creates it, keeps the 5.24.0 walk of it from failing.
        System.setProperty("user.workspace.home", Files.createDirectories(workspace()).toString());
        // Multi-user mode keeps the single-user workspace move out of the tests that do not check it.
        System.setProperty("user.mode", "multi");
    }

    @AfterEach
    void tearDown() {
        Props.setEnvironment(previousEnvironment);
    }

    @Test
    void settingsWithoutVersionAreMigratedFromTheFirstVersion() throws IOException {
        writeSettings("test.run.parallel=false\n");

        assertEquals("5.23.1", migrate(), "Settings without a version are migrated as written by 5.23.1.");

        var saved = savedSettings();
        assertEquals("1", saved.get("test.run.thread.count"), "The 5.24.0 migration runs.");
        assertFalse(saved.containsKey("test.run.parallel"), "The 5.24.0 migration removes the parallel switch.");
        assertEquals(OpenLVersion.getVersion(),
                saved.get(".version"),
                "The settings are saved as the running version.");
    }

    @Test
    void anInstallationWithoutSettingsIsNotMigrated() throws IOException {
        writeProjectList(home.resolve("design-repository"), PROJECT_LIST);
        writeLock(workspace().resolve(".locks/rules"), "Bank Rating", "user=jdoe");

        assertEquals(OpenLVersion.getVersion(),
                migrate(),
                "Without a settings file the settings are the defaults of the running version.");

        assertFalse(Files.exists(settingsFile()), "Nothing is saved.");
        assertFalse(Files.exists(projectIndex()), "The 5.24.0 project paths migration does not run.");
        assertFalse(Files.exists(workspace().resolve(".locks/projects")), "The 5.24.0 locks migration does not run.");
    }

    static Stream<Arguments> versionBoundaries() {
        return Stream.of(Arguments.of("5.23.9", "test.run.parallel", "true", true),
                Arguments.of("5.24.0", "test.run.parallel", "true", false),
                Arguments.of("5.25.9", "security.saml.app-url", "https://studio.example.com", true),
                Arguments.of("5.26.0", "security.saml.app-url", "https://studio.example.com", false),
                Arguments.of("5.26.0", "repository.archive.factory", "repo-jdbc", true),
                Arguments.of("5.26.1", "repository.archive.factory", "repo-jdbc", false),
                Arguments.of("5.99.9", "repository.design.folder-structure.flat", "false", true),
                Arguments.of("6.0.0", "repository.design.folder-structure.flat", "false", false),
                Arguments.of("6.3.0", "repository.design.comment-template-old", "Old template", true),
                Arguments.of("6.3.1", "repository.design.comment-template-old", "Old template", false));
    }

    @ParameterizedTest(name = "{0}: {1} migrated = {3}")
    @MethodSource("versionBoundaries")
    void eachMigrationRunsOnlyForSettingsOlderThanItsVersion(String version,
            String property,
            String value,
            boolean migrated) throws IOException {
        writeSettings(".version=" + version + "\n" + property + "=" + value + "\n");

        assertEquals(version, migrate(), "The version the settings were written by is returned.");

        var saved = savedSettings();
        if (migrated) {
            assertFalse(saved.containsKey(property), "The migration of a newer version removes " + property + ".");
        } else {
            assertEquals(value, saved.get(property), "The migration of an older version keeps " + property + ".");
        }
    }

    @Test
    void samlModeGetsAGeneratedKeyAndCertificate() throws IOException, GeneralSecurityException {
        System.setProperty("user.mode", "saml");

        migrate();

        var saved = savedSettings();
        var key = saved.get("security.saml.local-key");
        var certificate = saved.get("security.saml.local-certificate");
        assertNotNull(key, "A private key is generated.");
        assertNotNull(certificate, "A certificate is generated.");
        var privateKey = (RSAPrivateCrtKey) KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key)));
        var x509 = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(certificate)));
        assertEquals("CN=webstudio", x509.getSubjectX500Principal().getName(), "The certificate is issued to Studio.");
        // Throws unless the certificate is signed with the key it holds, which makes it self-signed.
        x509.verify(x509.getPublicKey());
        assertEquals(privateKey.getModulus(),
                ((RSAPublicKey) x509.getPublicKey()).getModulus(),
                "The certificate holds the public key of the generated private key.");
    }

    @ParameterizedTest(name = "user.mode={0}, key set={1}, certificate set={2}: generated = {3}")
    @CsvSource({ "saml, false, false, true",
            "saml, true, false, true",
            "saml, false, true, true",
            "saml, true, true, false",
            "multi, false, false, false",
            "oauth2, false, false, false" })
    void onlySamlModeWithoutTheKeyOrTheCertificateGeneratesThem(String userMode,
            boolean keySet,
            boolean certificateSet,
            boolean generated) throws IOException {
        System.setProperty("user.mode", userMode);
        if (keySet) {
            System.setProperty("security.saml.local-key", randomValue());
        }
        if (certificateSet) {
            System.setProperty("security.saml.local-certificate", randomValue());
        }
        var pair = Pair.of(randomValue(), randomValue());

        try (var utils = mockStatic(KeyPairCertUtils.class)) {
            utils.when(KeyPairCertUtils::generateCertificate).thenReturn(pair);

            migrate();

            if (generated) {
                utils.verify(KeyPairCertUtils::generateCertificate);
            } else {
                utils.verifyNoInteractions();
            }
        }
        if (generated) {
            var saved = savedSettings();
            assertEquals(pair.getKey(), saved.get("security.saml.local-key"), "The generated key is saved.");
            assertEquals(pair.getValue(),
                    saved.get("security.saml.local-certificate"),
                    "The generated certificate is saved.");
        } else {
            assertFalse(Files.exists(settingsFile()), "Nothing is generated, so nothing is saved.");
        }
    }

    @Test
    void aFailedKeyGenerationSavesNothing() {
        System.setProperty("user.mode", "saml");

        try (var utils = mockStatic(KeyPairCertUtils.class)) {
            utils.when(KeyPairCertUtils::generateCertificate).thenReturn(null);

            migrate();
        }

        assertFalse(Files.exists(settingsFile()), "Without a generated key pair nothing is saved.");
    }

    @Test
    @StdIo
    void settingsThatCannotBeSavedAreLogged(StdErr err) throws IOException {
        // A file where the settings folder belongs keeps the settings file from being written.
        var blocker = Files.writeString(home.resolve("blocker"), "not a folder");
        System.setProperty("openl.home.shared", blocker.resolve("shared").toString());
        System.setProperty("user.mode", "saml");

        try (var utils = mockStatic(KeyPairCertUtils.class)) {
            utils.when(KeyPairCertUtils::generateCertificate).thenReturn(Pair.of(randomValue(), randomValue()));

            // Must not throw: settings that cannot be saved cannot break the start-up.
            assertEquals(OpenLVersion.getVersion(), migrate(), "The migration still returns the version.");
        }

        assertTrue(Files.isRegularFile(blocker), "The blocking file is left as it is.");
        assertEquals(1, linesWith(err, "Migration of properties failed."), "The failed save is logged once.");
    }

    @Test
    void settingsOf5_23AreMigratedTo5_24() throws IOException {
        writeSettings(LEGACY_SETTINGS + """
                project.history.unlimited=true
                project.history.home=/var/openl/history
                test.run.parallel=false
                repository.design.new-branch-pattern=WIP-{0}-{1}-{2}
                repository.design.comment-validation-pattern=PRJ-[0-9]+.*
                repository.design.invalid-comment-message=Start the comment with a ticket.
                """);

        migrate();

        var saved = savedSettings();
        assertEquals("", saved.get("project.history.count"), "An empty count keeps an unlimited history.");
        assertEquals("1", saved.get("test.run.thread.count"), "Sequential test runs use one thread.");
        assertFalse(saved.containsKey("project.history.unlimited"), "The unlimited history switch is removed.");
        assertFalse(saved.containsKey("project.history.home"), "The history folder is removed.");
        assertFalse(saved.containsKey("test.run.parallel"), "The parallel switch is removed.");
        assertEquals("WIP-{project-name}-{username}-{current-date}",
                saved.get("repository.design.new-branch.pattern"),
                "The positional placeholders of the branch pattern get their names.");
        assertFalse(saved.containsKey("repository.design.new-branch-pattern"), "The former pattern key is removed.");
        assertEquals("PRJ-[0-9]+.*",
                saved.get("repository.design.comment-template.comment-validation-pattern"),
                "The comment validation pattern moves to the comment template.");
        assertFalse(saved.containsKey("repository.design.comment-validation-pattern"),
                "The former validation pattern key is removed.");
        assertEquals("Start the comment with a ticket.",
                saved.get("repository.design.comment-template.invalid-comment-message"),
                "The invalid comment message moves to the comment template.");
        assertFalse(saved.containsKey("repository.design.invalid-comment-message"),
                "The former message key is removed.");
    }

    @Test
    void settingsOf5_23WithoutLegacyValuesGetNoReplacements() throws IOException {
        writeSettings(LEGACY_SETTINGS + "test.run.parallel=true\n");

        migrate();

        var saved = savedSettings();
        assertFalse(saved.containsKey("project.history.count"), "A limited history keeps the default count.");
        assertFalse(saved.containsKey("test.run.thread.count"), "Parallel test runs keep the default thread count.");
        assertFalse(saved.containsKey("test.run.parallel"), "The parallel switch is removed.");
        assertFalse(saved.containsKey("repository.design.new-branch.pattern"), "No branch pattern is added.");
        assertFalse(saved.containsKey("repository.design.comment-template.comment-validation-pattern"),
                "No validation pattern is added.");
        assertFalse(saved.containsKey("repository.design.comment-template.invalid-comment-message"),
                "No invalid comment message is added.");
    }

    @ParameterizedTest(name = "repository.design.factory={0}: local folder = {1}")
    @CsvSource({ ", true",
            "repo-git, true",
            "org.openl.rules.repository.git.GitRepository, true",
            "repo-jdbc, false" })
    void aGitDesignRepositoryOf5_23GetsALocalFolder(@Nullable String factory, boolean localFolder) throws IOException {
        writeSettings(LEGACY_SETTINGS + (factory == null ? "" : "repository.design.factory=" + factory + "\n"));

        migrate();

        assertEquals(localFolder ? "${openl.home}/design-repository" : null,
                savedSettings().get("repository.design.local-repository-path"),
                "Only a Git design repository, the former default, gets the former default local folder.");
    }

    @ParameterizedTest(name = "repository.production.factory={0}: local folder = {1}")
    @CsvSource({ "repo-git, true",
            "org.openl.rules.repository.git.GitRepositoryrepo-git, true",
            "repo-jdbc, false",
            ", false" })
    void aGitProductionRepositoryOf5_23GetsALocalFolder(@Nullable String factory, boolean localFolder)
            throws IOException {
        writeSettings(LEGACY_SETTINGS + (factory == null ? "" : "repository.production.factory=" + factory + "\n"));

        migrate();

        assertEquals(localFolder ? "${openl.home}/production-repository" : null,
                savedSettings().get("repository.production.local-repository-path"),
                "Only a Git production repository gets the former default local folder.");
    }

    @Test
    void configuredLocalFoldersOf5_23MoveToTheirUris() throws IOException {
        var designFolder = slashed(home.resolve("git-design"));
        var productionFolder = slashed(home.resolve("git-production"));
        writeSettings(LEGACY_SETTINGS + """
                repository.design.local-repository-path=%s
                repository.production.local-repository-path=%s
                repository.production.factory=repo-git
                """.formatted(designFolder, productionFolder));
        writeProjectList(home.resolve("git-design"), "project.1.name=Bank Rating\nproject.1.path=DESIGN/Bank Rating\n");

        migrate();

        var saved = savedSettings();
        assertEquals(designFolder, saved.get("repository.design.uri"), "The design folder becomes the design URI.");
        assertEquals(productionFolder,
                saved.get("repository.production.uri"),
                "The production folder becomes the production URI.");
        assertFalse(saved.containsKey("repository.design.local-repository-path"), "The design folder key is removed.");
        assertFalse(saved.containsKey("repository.production.local-repository-path"),
                "The production folder key is removed.");
        assertEquals(Map.of("Bank Rating", "DESIGN/Bank Rating"),
                projectIndexEntries(),
                "The project paths are read from the configured design folder.");
    }

    @Test
    @StdIo
    void settingsOf5_25DropTheRemovedSamlPropertiesAndReportH2Databases(StdErr err) throws IOException {
        var settings = new StringBuilder(".version=5.25.0\n");
        for (var property : REMOVED_SAML_PROPERTIES) {
            settings.append(property).append('=').append(randomValue()).append('\n');
        }
        // A line without a value is read as a property without a value.
        settings.append("""
                security.saml.entity-id=studio-sp
                repository.design.uri=jdbc:h2:./design-db
                repository.deploy-config.uri=jdbc:h2:./design-db
                repository.archive.url=jdbc:h2:mem:archive
                repository.production.uri=%s
                repository.unset.uri
                repository.design.name=Rules
                """.formatted(CHANGED_PRODUCTION_URI));
        writeSettings(settings.toString());

        migrate();

        var saved = savedSettings();
        for (var property : REMOVED_SAML_PROPERTIES) {
            assertFalse(saved.containsKey(property), "The unused SAML property " + property + " is removed.");
        }
        assertEquals("studio-sp", saved.get("security.saml.entity-id"), "A SAML property still in use is kept.");
        var warning = "You have h2 database with uri ";
        assertEquals(1,
                linesWith(err, warning + "'jdbc:h2:./design-db'"),
                "An H2 database of two repositories is reported once.");
        assertEquals(1, linesWith(err, warning + "'jdbc:h2:mem:archive'"), "An H2 database of a URL is reported.");
        assertEquals(2, linesWith(err, warning), "Other databases and properties without a value are not reported.");
        assertTrue(Arrays.stream(err.capturedLines())
                .filter(line -> line.contains(warning))
                .allMatch(line -> line.contains("WARN")), "The H2 databases are reported at WARN.");
    }

    @Test
    void settingsOf5_26MoveRepositoryFactoriesToReferences() throws IOException {
        writeSettings("""
                .version=5.26.0
                repository.archive.factory=repo-jdbc
                repository.deploy-config.factory=
                custom.factory=repo-git
                repository.archive.name=Archive
                """);

        migrate();

        var saved = savedSettings();
        assertEquals("repo-jdbc", saved.get("repository.archive.$ref"), "The factory becomes a reference.");
        assertFalse(saved.containsKey("repository.archive.factory"), "The migrated factory is removed.");
        assertEquals("", saved.get("repository.deploy-config.factory"), "A blank factory is kept.");
        assertFalse(saved.containsKey("repository.deploy-config.$ref"), "A blank factory gets no reference.");
        assertEquals("repo-git", saved.get("custom.factory"), "A factory outside the repositories is kept.");
        assertFalse(saved.containsKey("custom.$ref"), "A factory outside the repositories gets no reference.");
        assertEquals("Archive", saved.get("repository.archive.name"), "Other repository properties are kept.");
    }

    static Stream<Arguments> productionRepositories() {
        return Stream.of(Arguments.of("no production repository", "", Map.of()),
                Arguments.of("the unchanged default repository",
                        CONFIGS + "=production\n" + URI + "=" + DEFAULT_PRODUCTION_URI
                                + "\nrepository.production.factory=repo-jdbc\n",
                        Map.of(CONFIGS, "production", REF, "repo-jdbc", URI, DEFAULT_PRODUCTION_URI)),
                Arguments.of("the default URI alone",
                        URI + "=" + DEFAULT_PRODUCTION_URI + "\n",
                        Map.of(URI, DEFAULT_PRODUCTION_URI)),
                Arguments.of("a changed URI",
                        URI + "=" + CHANGED_PRODUCTION_URI + "\n",
                        Map.of(CONFIGS,
                                "production",
                                NAME,
                                "Deployment",
                                REF,
                                "repo-jdbc",
                                BASE_PATH,
                                DEFAULT_BASE_PATH,
                                URI,
                                CHANGED_PRODUCTION_URI)),
                Arguments.of("a changed factory of a listed and named repository",
                        CONFIGS + "=production\nrepository.production.factory=repo-git\n" + NAME + "=Releases\n",
                        Map.of(CONFIGS, "production", NAME, "Releases", REF, "repo-git", BASE_PATH, DEFAULT_BASE_PATH)),
                Arguments.of("a blank factory",
                        "repository.production.factory=\n",
                        Map.of(CONFIGS,
                                "production",
                                NAME,
                                "Deployment",
                                REF,
                                "repo-jdbc",
                                BASE_PATH,
                                DEFAULT_BASE_PATH)),
                Arguments.of("several repositories with the unchanged default",
                        CONFIGS + "=production,production1\n",
                        Map.of(CONFIGS,
                                "production,production1",
                                NAME,
                                "Deployment",
                                REF,
                                "repo-jdbc",
                                BASE_PATH,
                                DEFAULT_BASE_PATH,
                                URI,
                                DEFAULT_PRODUCTION_URI)),
                Arguments.of("several repositories with a changed default",
                        CONFIGS + "=production,production1\n" + URI + "=" + CHANGED_PRODUCTION_URI + "\n",
                        Map.of(CONFIGS,
                                "production,production1",
                                NAME,
                                "Deployment",
                                REF,
                                "repo-jdbc",
                                BASE_PATH,
                                DEFAULT_BASE_PATH,
                                URI,
                                CHANGED_PRODUCTION_URI)),
                Arguments.of("several repositories without the default",
                        CONFIGS + "=production1,production2\n",
                        Map.of(CONFIGS, "production1,production2")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("productionRepositories")
    void settingsOf5_26RestoreTheDefaultsOfAProductionRepositoryInUse(String description,
            String settings,
            Map<String, String> expected) throws IOException {
        writeSettings(".version=5.26.0\n" + settings);

        migrate();

        var saved = savedSettings();
        for (var property : List.of(CONFIGS, NAME, REF, BASE_PATH, URI)) {
            assertEquals(expected.get(property), saved.get(property), description + ": " + property);
        }
    }

    @Test
    void settingsOf5_27MoveLocalFoldersToUrisAndDropTheFlatFolderStructure() throws IOException {
        var productionFolder = slashed(home.resolve("production"));
        writeSettings("""
                .version=5.27.0
                repository.design.folder-structure.flat=false
                custom.folder-structure.flat=true
                repository.production.local-repository-path=%s
                repository.design.local-repository-path=/var/openl/design
                repository.design.uri=https://git.example.com/rules.git
                custom.local-repository-path=/var/openl/custom
                repository.design.name=Rules
                """.formatted(productionFolder));

        migrate();

        var saved = savedSettings();
        assertFalse(saved.containsKey("repository.design.folder-structure.flat"),
                "The flat structure flag is removed.");
        assertEquals("true", saved.get("custom.folder-structure.flat"), "A flag outside the repositories is kept.");
        assertEquals(productionFolder, saved.get(URI), "A local folder becomes the missing URI.");
        assertFalse(saved.containsKey("repository.production.local-repository-path"), "The folder key is removed.");
        assertEquals("https://git.example.com/rules.git",
                saved.get("repository.design.uri"),
                "A configured URI is kept.");
        assertFalse(saved.containsKey("repository.design.local-repository-path"),
                "The folder key of a repository with a URI is removed.");
        assertEquals("/var/openl/custom",
                saved.get("custom.local-repository-path"),
                "A folder outside the repositories is kept.");
        assertEquals("Rules", saved.get("repository.design.name"), "Other repository properties are kept.");
    }

    @Test
    void settingsOf6_3DropTheFormerCommentTemplates() throws IOException {
        var removed = List.of("repository.design.comment-template.user-message.default.archive",
                "repository.design.comment-template.user-message.default.delete",
                "repository.design.comment-template.user-message.default.restore",
                "repository.design.comment-template.user-message.default.erase",
                "repository.design.comment-template",
                "repository.design.comment-template-old");
        var settings = new StringBuilder(".version=6.3.0\n");
        for (var property : removed) {
            settings.append(property).append("=Former message of ").append(property).append('\n');
        }
        settings.append("""
                repository.design.comment-template.user-message.default.save=Saved {project-name}.
                custom.comment-template=Custom template
                """);
        writeSettings(settings.toString());

        migrate();

        var saved = savedSettings();
        for (var property : removed) {
            assertFalse(saved.containsKey(property), "The former comment template " + property + " is removed.");
        }
        assertEquals("Saved {project-name}.",
                saved.get("repository.design.comment-template.user-message.default.save"),
                "A current comment template is kept.");
        assertEquals("Custom template",
                saved.get("custom.comment-template"),
                "A template outside the repositories is kept.");
    }

    @Test
    void projectPathsOf5_23MoveToTheProjectIndex() throws IOException {
        writeSettings(LEGACY_SETTINGS);
        writeProjectList(home.resolve("design-repository"), PROJECT_LIST);

        migrate();

        assertEquals(Map.of("Bank Rating",
                "DESIGN/rules/Banking/Bank Rating",
                "Auto Policy",
                "DESIGN/rules/Insurance/Auto Policy"), projectIndexEntries(), "Every listed project is indexed.");
    }

    @Test
    void withoutAProjectListNoProjectIndexIsWritten() throws IOException {
        writeSettings(LEGACY_SETTINGS);
        writeLock(workspace().resolve(".locks/rules"), "Bank Rating", "user=jdoe");

        migrate();

        assertFalse(Files.exists(projectIndex()), "Nothing is indexed.");
        assertEquals("user=jdoe",
                Files.readString(workspace().resolve(".locks/projects/design/DESIGN/rules/Bank Rating/ready.lock")),
                "Without a project list a lock moves to the flat rules folder.");
    }

    @Test
    @StdIo
    void anUnreadableProjectListIsLoggedAndSkipped(StdErr err) throws IOException {
        writeSettings(LEGACY_SETTINGS);
        // A Unicode escape cut short by the end of the file cannot be read.
        writeProjectList(home.resolve("design-repository"), "project.1.name=Bank Rating\nproject.1.path=\\u00");

        migrate();

        assertEquals(1,
                linesWith(err, "Loading of openl-projects.properties has been failed."),
                "The unreadable project list is logged once.");
        assertFalse(Files.exists(projectIndex()), "Nothing is indexed.");
    }

    @Test
    @StdIo
    void aProjectIndexThatCannotBeWrittenIsLogged(StdErr err) throws IOException {
        writeSettings(LEGACY_SETTINGS);
        writeProjectList(home.resolve("design-repository"), PROJECT_LIST);
        // A file where the settings folder belongs keeps the index folder from being created.
        var blocker = Files.writeString(Files.createDirectories(home.resolve("repositories")).resolve("settings"), "");
        writeLock(workspace().resolve(".locks/rules"), "Bank Rating", "user=jdoe");

        migrate();

        assertEquals(1, linesWith(err, "Writing to file has been failed."), "The failed index is logged once.");
        assertTrue(Files.isRegularFile(blocker), "The blocking file is left as it is.");
        var lock = workspace().resolve(".locks/projects/design/DESIGN/rules/Banking/Bank Rating/ready.lock");
        assertEquals("user=jdoe", Files.readString(lock), "The migration goes on with the listed project paths.");
    }

    @Test
    void nonFlatProjectsOf5_23GetTheirRepositoryPath() throws IOException {
        writeSettings(LEGACY_SETTINGS);
        writeProjectList(home.resolve("design-repository"), PROJECT_LIST);
        var userDir = workspace().resolve("jdoe");
        writeLegacyVersion(userDir.resolve("Bank Rating"), "rev-7");
        writeLegacyVersion(userDir.resolve("Flat Project"), "rev-3");
        Files.createDirectories(userDir.resolve("Local Only"));

        migrate();

        var listed = metainfo(userDir, "Bank Rating");
        assertEquals("design", listed.repositoryId(), "The project is linked to the design repository.");
        assertEquals("DESIGN/rules/Banking/Bank Rating",
                listed.pathInRepository(),
                "A listed project is linked to its listed path.");
        assertEquals("rev-7", listed.version(), "The revision of the project is kept.");
        var unlisted = metainfo(userDir, "Flat Project");
        assertEquals("design", unlisted.repositoryId(), "The project is linked to the design repository.");
        assertEquals("DESIGN/rules/Flat Project",
                unlisted.pathInRepository(),
                "An unlisted project is linked to the flat rules folder.");
        assertNull(MetainfoRegistry.open(userDir).get("Local Only"),
                "A folder without legacy project settings gets no link.");
        assertFalse(Files.exists(workspace().resolve(".locks")), "A workspace without legacy locks gets no locks.");
    }

    @Test
    @StdIo
    void aMissingWorkspaceIsLogged(StdErr err) throws IOException {
        writeSettings(LEGACY_SETTINGS);
        Files.delete(workspace());

        migrate();

        assertEquals(1,
                linesWith(err, "Migration of locks failed."),
                "The walk of the missing workspace for non-flat projects is logged once.");
        assertFalse(Files.exists(workspace()), "No workspace is created.");
    }

    @Test
    void locksOf5_23MoveToTheProjectLocks() throws IOException {
        writeSettings(LEGACY_SETTINGS);
        writeProjectList(home.resolve("design-repository"), PROJECT_LIST);
        var legacyLocks = workspace().resolve(".locks/rules");
        writeLock(legacyLocks, "Bank Rating", "user=jdoe");
        writeLock(legacyLocks.resolve("branches/Auto Policy/feature/rates"), "Auto Policy", "user=asmith");
        writeLock(legacyLocks, "Flat Project", "user=bdoe");

        migrate();

        var locks = workspace().resolve(".locks/projects/design");
        assertEquals("user=jdoe",
                Files.readString(locks.resolve("DESIGN/rules/Banking/Bank Rating/ready.lock")),
                "The lock of a listed project moves to its listed path.");
        var branchLock = locks.resolve("DESIGN/rules/Insurance/Auto Policy/[branches]/feature/rates/ready.lock");
        assertEquals("user=asmith",
                Files.readString(branchLock),
                "The lock of a branch moves under the branch of the project.");
        assertEquals("user=bdoe",
                Files.readString(locks.resolve("DESIGN/rules/Flat Project/ready.lock")),
                "The lock of an unlisted project moves to the flat rules folder.");
        assertTrue(Files.exists(legacyLocks.resolve("Bank Rating")), "The legacy lock is copied, not moved.");
    }

    @Test
    @StdIo
    void anExistingProjectLockIsKept(StdErr err) throws IOException {
        writeSettings(LEGACY_SETTINGS);
        writeLock(workspace().resolve(".locks/rules"), "Bank Rating", "user=jdoe");
        var current = workspace().resolve(".locks/projects/design/DESIGN/rules/Bank Rating");
        writeLock(current, "ready.lock", "user=asmith");

        migrate();

        assertEquals("user=asmith",
                Files.readString(current.resolve("ready.lock")),
                "An existing lock is never overwritten.");
        assertEquals(1, linesWith(err, "Migration of locks failed."), "The failed lock copy is logged once.");
    }

    @Test
    void theSingleUserWorkspaceMovesToTheConfiguredUser() throws IOException {
        var username = "user" + RandomStringUtils.secure().nextNumeric(8);
        System.setProperty("user.mode", "single");
        System.setProperty("security.single.username", username);
        var project = Files.createDirectories(workspace().resolve("DEFAULT").resolve("SoloProj"));
        Files.writeString(project.resolve("solo-wip.txt"), "work in progress");

        migrate();

        assertFalse(Files.exists(workspace().resolve("DEFAULT")), "The legacy DEFAULT workspace is moved.");
        assertEquals("work in progress",
                Files.readString(workspace().resolve(username).resolve("SoloProj").resolve("solo-wip.txt")),
                "Uncommitted work is kept under the configured user name.");
    }

    @Test
    @StdIo
    void aBlankWorkspacePathIsNotTheWorkingDirectory(StdErr err) {
        System.setProperty("user.mode", "single");
        System.setProperty("user.workspace.home", "");

        assertEquals(OpenLVersion.getVersion(), migrate(), "The migration completes.");

        // Taken for the workspace root, the working directory would make each of its folders a user folder and
        // each of their subfolders a project, and every such project would be logged.
        assertEquals(0, linesWith(err, "repository link"), "No folder of the working directory is a project.");
        assertEquals(0, linesWith(err, "metainfo"), "No folder of the working directory is converted.");
    }

    /**
     * Loads the settings as the application does and runs the migration.
     *
     * @return the version the settings were written by
     */
    private static String migrate() {
        var servletContext = new MockServletContext();
        servletContext.setContextPath("/webstudio");
        var context = new GenericApplicationContext();
        new PropertySourcesLoader().initialize(context, servletContext);
        Props.setEnvironment(context.getEnvironment());
        return Migrator.migrate();
    }

    private Path workspace() {
        return home.resolve("user-workspace");
    }

    private Path settingsFile() {
        return home.resolve("webstudio.properties");
    }

    private void writeSettings(String settings) throws IOException {
        Files.writeString(settingsFile(), settings);
    }

    /**
     * Reads the saved settings; settings with nothing to save are deleted, which reads as no settings.
     */
    private Map<String, String> savedSettings() throws IOException {
        var saved = new HashMap<String, String>();
        if (Files.exists(settingsFile())) {
            PropertiesUtils.load(settingsFile(), saved::put);
        }
        return saved;
    }

    private Path projectIndex() {
        return home.resolve("repositories/settings/design/openl-projects.yaml");
    }

    /**
     * Reads the project index of the design repository as project names and their paths.
     */
    private Map<String, String> projectIndexEntries() throws IOException {
        var index = YamlMapperFactory.getYamlMapper().readValue(projectIndex().toFile(), ProjectIndex.class);
        var entries = new HashMap<String, String>();
        for (ProjectInfo project : index.getProjects()) {
            entries.put(project.getName(), project.getPath());
        }
        return entries;
    }

    private static void writeProjectList(Path designRepository, String projectList) throws IOException {
        Files.createDirectories(designRepository);
        Files.writeString(designRepository.resolve("openl-projects.properties"), projectList);
    }

    private static void writeLock(Path folder, String name, String content) throws IOException {
        Files.createDirectories(folder);
        Files.writeString(folder.resolve(name), content);
    }

    /**
     * Writes the legacy project settings of a non-flat project, which link it to no repository yet.
     */
    private static void writeLegacyVersion(Path project, String revision) throws IOException {
        var studioProps = Files.createDirectories(project.resolve(".studioProps"));
        Files.writeString(studioProps.resolve(".version"), "version=" + revision + "\n");
    }

    private static ProjectMetainfo metainfo(Path userDir, String projectName) {
        var metainfo = MetainfoRegistry.open(userDir).get(projectName);
        if (metainfo == null) {
            throw new AssertionError("The '" + projectName + "' project has no metainfo record.");
        }
        return metainfo;
    }

    private static long linesWith(StdErr err, String text) {
        return Arrays.stream(err.capturedLines()).filter(line -> line.contains(text)).count();
    }

    /**
     * A path as a settings value: a backslash starts an escape in a properties file.
     */
    private static String slashed(Path path) {
        return path.toString().replace('\\', '/');
    }

    private static String randomValue() {
        return RandomStringUtils.secure().nextAlphanumeric(32);
    }
}

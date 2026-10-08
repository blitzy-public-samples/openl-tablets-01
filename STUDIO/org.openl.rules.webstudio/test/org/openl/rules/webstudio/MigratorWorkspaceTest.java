package org.openl.rules.webstudio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;

import org.openl.rules.project.impl.local.MetainfoRegistry;

/**
 * Tests of the migration of legacy {@code .studioProps} workspaces to the metainfo registry.
 *
 * @author Yury Molchan
 */
class MigratorWorkspaceTest {

    @TempDir
    Path workspacesRoot;

    private Path userDir;

    @BeforeEach
    void init() throws IOException {
        userDir = workspacesRoot.resolve("jdoe");
        Files.createDirectories(userDir);
    }

    @Test
    void fullLegacyMetainfoIsConverted() throws IOException {
        var project = createProject("Example 1");
        var studioProps = project.resolve(".studioProps");
        Files.createDirectories(studioProps);
        Files.writeString(studioProps.resolve(".version"), """
                repository-id=design
                path-in-repository=DESIGN/rules/Example 1
                version=rev-42
                branch=main
                author=John Doe
                modified-at=2026-07-01
                modified-at-long=1751980000000
                size=12345
                comment=Copied from Example 1
                """);
        Files.createFile(studioProps.resolve(".modified"));
        var fileProperties = studioProps.resolve("file-properties").resolve("rules");
        Files.createDirectories(fileProperties);
        Files.writeString(fileProperties.resolve("Main.xlsx"), """
                unique-id=9f3c1a7e
                modified=true
                size=54321
                modified-at-long=1751979000000
                """);
        Files.createDirectories(project.resolve(".history").resolve("Main.xlsx"));

        Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);

        assertFalse(Files.exists(studioProps), "The legacy .studioProps folder must be deleted.");
        assertFalse(Files.exists(project.resolve(".history")), "The in-project edit history must be deleted.");
        var metainfo = MetainfoRegistry.open(userDir).get("Example 1");
        assertNotNull(metainfo);
        assertEquals("design", metainfo.repositoryId());
        assertEquals("DESIGN/rules/Example 1", metainfo.pathInRepository());
        assertEquals("main", metainfo.branch());
        assertEquals("rev-42", metainfo.version());
        assertEquals("John Doe", metainfo.author());
        assertEquals(1751980000000L, metainfo.modifiedAt());
        assertEquals(12345L, metainfo.size());
        assertEquals("Copied from Example 1", metainfo.comment());
        assertTrue(metainfo.hasRevision());
        var baseline = metainfo.files().get("/rules/Main.xlsx");
        assertNotNull(baseline);
        assertEquals("9f3c1a7e", baseline.uniqueId());
        assertEquals(54321L, baseline.size());
        assertEquals(1751979000000L, baseline.modifiedAt());
    }

    @Test
    void folderWithoutMetainfoIsDeletedAtFirstLoad() throws IOException {
        var project = createProject("Stray");

        Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);

        assertTrue(Files.exists(project), "Migration itself does not delete folders.");
        var registry = MetainfoRegistry.open(userDir);
        assertNull(registry.get("Stray"), "A folder without a repository link gets no record.");
        assertFalse(Files.exists(project), "The registry-first reconciliation deletes the unlinked folder.");
    }

    @Test
    void versionWithoutRepositoryLinkGetsNoRecord() throws IOException {
        var project = createProject("NoLink");
        var studioProps = project.resolve(".studioProps");
        Files.createDirectories(studioProps);
        Files.writeString(studioProps.resolve(".version"), """
                version=rev-1
                modified-at-long=1751980000000
                """);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);

        assertNull(MetainfoRegistry.open(userDir).get("NoLink"),
                "A record without the source repository cannot be restored.");
        assertFalse(Files.exists(project));
    }

    @Test
    void deprecatedDateFormatIsDropped() throws IOException {
        var studioProps = createProject("OldDate").resolve(".studioProps");
        Files.createDirectories(studioProps);
        Files.writeString(studioProps.resolve(".version"), """
                repository-id=design
                version=rev-1
                author=jdoe
                modified-at=2024-01-01
                """);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);

        var metainfo = MetainfoRegistry.open(userDir).get("OldDate");
        assertNotNull(metainfo);
        assertEquals("design", metainfo.repositoryId());
        assertEquals("rev-1", metainfo.version());
        assertNull(metainfo.modifiedAt(), "The deprecated date-only format is not supported anymore.");
        assertFalse(metainfo.hasRevision());
    }

    @Test
    void unparsableNumbersAreTolerated() throws IOException {
        var studioProps = createProject("Broken").resolve(".studioProps");
        var fileProperties = studioProps.resolve("file-properties");
        Files.createDirectories(fileProperties);
        Files.writeString(studioProps.resolve(".version"), """
                repository-id=design
                version=rev-1
                modified-at-long=1751980000000
                size=huge
                """);
        Files.writeString(fileProperties.resolve("Main.xlsx"), """
                unique-id=9f3c1a7e
                size=big
                modified-at-long=1751979000000
                """);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);

        var metainfo = MetainfoRegistry.open(userDir).get("Broken");
        assertNotNull(metainfo);
        assertTrue(metainfo.hasRevision());
        assertNull(metainfo.size());
        assertTrue(metainfo.files().isEmpty(),
                "A baseline without a numeric size is skipped, so the file is later detected as changed.");
    }

    @Test
    void serviceFoldersAreNotTouched() throws IOException {
        var locks = workspacesRoot.resolve(".locks").resolve("design").resolve("Example 1");
        Files.createDirectories(locks);
        Files.writeString(locks.resolve("ready.lock"), "user=jdoe");
        createProject("Plain");

        Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);

        assertTrue(Files.exists(locks.resolve("ready.lock")), "The shared .locks storage is not a user workspace.");
        assertFalse(Files.exists(workspacesRoot.resolve(".locks").resolve(".metainfo")));
    }

    @Test
    void migrationIsIdempotent() throws IOException {
        var studioProps = createProject("Twice").resolve(".studioProps");
        Files.createDirectories(studioProps);
        Files.writeString(studioProps.resolve(".version"), """
                repository-id=design
                version=rev-1
                modified-at-long=1751980000000
                """);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);
        Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);

        var metainfo = MetainfoRegistry.open(userDir).get("Twice");
        assertNotNull(metainfo);
        assertEquals("design", metainfo.repositoryId(),
                "A repeated migration must not degrade the record to a local project.");
    }

    @Test
    void linkedLegacyFolderWithUnsavedWorkSurvivesReconcile() throws IOException {
        var project = createProject("Linked");
        var studioProps = project.resolve(".studioProps");
        Files.createDirectories(studioProps);
        Files.writeString(studioProps.resolve(".version"), """
                repository-id=design
                path-in-repository=Linked
                version=rev-7
                branch=master
                """);
        var unsaved = project.resolve("unsaved.txt");
        Files.writeString(unsaved, "work in progress, never committed");

        // The conversion, then the registry-first reconciliation that open() performs on the first load.
        Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);
        MetainfoRegistry.open(userDir);

        assertTrue(Files.exists(project), "A converted legacy folder must survive the reconciliation.");
        assertTrue(Files.exists(unsaved), "Uncommitted work in a converted folder must be kept.");
        assertNotNull(MetainfoRegistry.open(userDir).get("Linked"),
                "The converted project keeps its registry record.");
    }

    // V1: a .version file that is not valid UTF-8 is unreadable, so its project gets no record and keeps its files.
    @Test
    @StdIo
    void unreadableVersionGetsNoRecord(StdErr err) throws IOException {
        var studioProps = createProject("Unreadable").resolve(".studioProps");
        Files.createDirectories(studioProps);
        var version = Files.write(studioProps.resolve(".version"), INVALID_UTF_8);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);

        assertFalse(MetainfoRegistry.exists(userDir, "Unreadable"), "An unreadable .version gives no record.");
        assertTrue(Files.isRegularFile(version), "The unreadable legacy metainfo is kept.");
        assertLogged(err, "The '" + version + "' file is unreadable.");
    }

    // V1: a file-properties entry that is unreadable or has no modification time gets no baseline; the others do.
    @Test
    @StdIo
    void unusableFilePropertiesEntriesAreSkipped(StdErr err) throws IOException {
        var studioProps = createProject("Partial").resolve(".studioProps");
        var fileProperties = studioProps.resolve("file-properties").resolve("rules");
        Files.createDirectories(fileProperties);
        Files.writeString(studioProps.resolve(".version"), """
                repository-id=design
                version=rev-1
                """);
        Files.writeString(fileProperties.resolve("Main.xlsx"), """
                unique-id=9f3c1a7e
                size=54321
                modified-at-long=1751979000000
                """);
        var unreadable = Files.write(fileProperties.resolve("Unreadable.xlsx"), INVALID_UTF_8);
        Files.writeString(fileProperties.resolve("Undated.xlsx"), """
                unique-id=1b2c3d4e
                size=10
                """);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);

        var metainfo = MetainfoRegistry.open(userDir).get("Partial");
        assertNotNull(metainfo);
        assertEquals(Set.of("/rules/Main.xlsx"), metainfo.files().keySet(),
                "Only the readable baseline with a size and a modification time is kept.");
        assertLogged(err, "The '" + unreadable + "' file properties are unreadable and are skipped.");
    }

    // V1: a record that cannot be stored, because .metainfo is a regular file, leaves the legacy metainfo in place.
    @Test
    @StdIo
    void projectWhoseRecordCannotBeStoredKeepsItsLegacyMetainfo(StdErr err) throws IOException {
        var project = createProject("Blocked");
        var studioProps = project.resolve(".studioProps");
        Files.createDirectories(studioProps);
        Files.writeString(studioProps.resolve(".version"), """
                repository-id=design
                version=rev-1
                """);
        Files.createDirectories(project.resolve(".history").resolve("Main.xlsx"));
        var metainfoFile = Files.writeString(userDir.resolve(MetainfoRegistry.METAINFO_FOLDER), "not a folder");

        Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);

        assertEquals("not a folder", Files.readString(metainfoFile), "The conflicting .metainfo file is untouched.");
        assertTrue(Files.isRegularFile(studioProps.resolve(".version")), "The legacy metainfo is kept.");
        assertTrue(Files.isDirectory(project.resolve(".history")), "The in-project edit history is kept.");
        assertLogged(err, "Migration of the 'Blocked' project metainfo failed.");
    }

    // V1: a missing workspace root means there is nothing to convert, and the root is not created.
    @Test
    void missingWorkspacesRootIsIgnored() {
        var missing = workspacesRoot.resolve("missing");

        Migrator.migrateUserWorkspacesToMetainfoRegistry(missing);

        assertFalse(Files.exists(missing, LinkOption.NOFOLLOW_LINKS), "A missing workspace root is not created.");
    }

    // V1: a user folder that cannot be listed is logged and left as it is.
    @Test
    @StdIo
    void userFolderThatCannotBeListedIsLeftAsItIs(StdErr err) throws IOException {
        var version = linkedLegacyProject("Unlisted");

        try (var ignored = Mockito.mockStatic(Files.class, failingListing(userDir))) {
            Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);
        }

        assertTrue(Files.isRegularFile(version), "The legacy metainfo of the unlisted user folder is kept.");
        assertFalse(MetainfoRegistry.exists(userDir, "Unlisted"), "The unlisted user folder gets no record.");
        assertLogged(err, "Migration of the user workspace '" + userDir + "' failed.");
    }

    // V1: a workspace root that cannot be listed is logged, and no user folder is converted.
    @Test
    @StdIo
    void workspacesRootThatCannotBeListedIsLeftAsItIs(StdErr err) throws IOException {
        var version = linkedLegacyProject("Unlisted");

        try (var ignored = Mockito.mockStatic(Files.class, failingListing(workspacesRoot))) {
            Migrator.migrateUserWorkspacesToMetainfoRegistry(workspacesRoot);
        }

        assertTrue(Files.isRegularFile(version), "The legacy metainfo below the unlisted root is kept.");
        assertFalse(MetainfoRegistry.exists(userDir, "Unlisted"),
                "No user folder below the unlisted root is converted.");
        assertLogged(err, "Migration of user workspaces failed.");
    }

    // V1: helpers of the conversion failure checks, private to this class.
    /** Bytes that are not valid UTF-8, so the strict UTF-8 reader of the legacy properties fails on them. */
    private static final byte[] INVALID_UTF_8 = {'k', '=', (byte) 0xFF, '\n'};

    /** Asserts that exactly one captured line holds the message. */
    private static void assertLogged(StdErr err, String message) {
        assertEquals(1, Arrays.stream(err.capturedLines()).filter(line -> line.contains(message)).count(),
                () -> "Exactly one line logs \"" + message + "\".");
    }

    /**
     * Calls every method of {@link Files} for real, except the listing of the given folder, which fails. A static
     * mock is confined to the test thread, so nothing else in the build sees it.
     */
    private static Answer<Object> failingListing(Path folder) {
        return invocation -> {
            if ("list".equals(invocation.getMethod().getName()) && folder.equals(invocation.getArgument(0))) {
                throw new IOException("The folder cannot be listed.");
            }
            return invocation.callRealMethod();
        };
    }

    /**
     * Creates a project of the user folder whose legacy {@code .version} links it to a repository.
     *
     * @return the {@code .version} file
     */
    private Path linkedLegacyProject(String name) throws IOException {
        var studioProps = createProject(name).resolve(".studioProps");
        Files.createDirectories(studioProps);
        return Files.writeString(studioProps.resolve(".version"), """
                repository-id=design
                version=rev-1
                """);
    }

    private Path createProject(String name) throws IOException {
        var project = userDir.resolve(name);
        Files.createDirectories(project.resolve("rules"));
        Files.writeString(project.resolve("rules").resolve("Main.xlsx"), "content");
        return project;
    }
}

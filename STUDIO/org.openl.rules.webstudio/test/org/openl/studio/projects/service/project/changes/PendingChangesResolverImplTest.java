package org.openl.studio.projects.service.project.changes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import org.openl.rules.project.abstraction.RulesProject;
import org.openl.rules.project.impl.local.LocalRepository;
import org.openl.rules.project.impl.local.MetainfoRegistry;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.studio.projects.model.project.status.ChangeType;
import org.openl.studio.projects.model.project.status.FileChange;
import org.openl.studio.projects.model.project.status.PendingChanges;
import org.openl.studio.projects.service.files.FileRoot;

/**
 * Local changes of an opened project against the design revision it is opened on.
 *
 * <p>V1: in a file-backed working copy or design repository, an entry whose real location leaves its project folder
 * through a link is not a project file. The Files tree leaves it out, opening the project does not copy it and saving
 * does not commit it, so Local changes do not report it either: neither as added nor, for a design link, as deleted.
 */
class PendingChangesResolverImplTest {

    private static final String PROJECT = "P";

    @TempDir
    Path userDir;

    @TempDir
    Path designRoot;

    @TempDir
    Path outside;

    private final PendingChangesResolverImpl resolver = new PendingChangesResolverImpl();
    private LocalRepository localRepository;
    private Path outsideFile;

    @BeforeEach
    void init() throws IOException {
        localRepository = new LocalRepository(userDir, MetainfoRegistry.open(userDir));
        outsideFile = Files.writeString(outside.resolve("secret.txt"), "outside-" + UUID.randomUUID());
    }

    @Test
    void anUnmodifiedProjectHasNoPendingChanges() {
        var project = mock(RulesProject.class);

        assertNull(resolver.resolve(project));
        verify(project, never()).getLocalRepository();
    }

    @Test
    void aProjectWithoutChangedFilesHasNoPendingChanges() {
        var project = project(localRepository, PROJECT);
        when(project.isLocalOnly()).thenReturn(true);

        assertNull(resolver.resolve(project));
    }

    @Test
    void anUnreadableWorkingCopyHasNoPendingChanges() throws IOException {
        var unreadable = mock(LocalRepository.class);
        when(unreadable.list(PROJECT + "/")).thenThrow(new IOException("unreadable"));
        var project = project(unreadable, PROJECT);

        assertNull(resolver.resolve(project));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void aLocalOnlyProjectListsItsFilesAsAddedWithoutLinksThatLeaveIt() throws IOException {
        writeLocal("rules/Main.xlsx");
        writeLocal("B.txt");
        Files.createSymbolicLink(local("inner.xlsx"), local("rules/Main.xlsx"));
        plantLeavingLinks(userDir.resolve(PROJECT));
        var project = project(localRepository, PROJECT);
        when(project.getRealPath()).thenReturn("rules/P");
        when(project.isLocalOnly()).thenReturn(true);

        var changes = resolver.resolve(project);

        assertChanges(changes,
                added("rules/P/B.txt"),
                added("rules/P/inner.xlsx"),
                added("rules/P/rules/Main.xlsx"));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void aFolderDesignOmitsWorkingCopyLinksThatLeaveTheProject() throws IOException {
        writeLocal("rules/Main.xlsx");
        writeLocal("new.txt");
        plantLeavingLinks(userDir.resolve(PROJECT));
        var design = repository(true, true);
        when(design.listFiles(PROJECT + "/", "v1")).thenReturn(List.of(unique(PROJECT + "/rules/Main.xlsx", "u1"),
                unique(PROJECT + "/gone.txt", "u2"),
                unique(PROJECT + "/leak.txt", "u3")));
        var project = project(localRepository, PROJECT);
        whenDesign(project, design, "v1");

        var changes = resolver.resolve(project);

        assertChanges(changes,
                added("P/new.txt"),
                modified("P/rules/Main.xlsx"),
                deleted("P/gone.txt"),
                deleted("P/leak.txt"));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void aFileDesignOmitsDesignLinksThatLeaveTheProject() throws IOException {
        writeLocal("rules/Main.xlsx");
        writeLocal("inner.xlsx");
        Files.createSymbolicLink(local("leak2.txt"), outsideFile);
        var designProject = designRoot.resolve("rules/P");
        write(designProject.resolve("rules/Main.xlsx"));
        write(designProject.resolve("gone.txt"));
        Files.createSymbolicLink(designProject.resolve("inner.xlsx"), designProject.resolve("rules/Main.xlsx"));
        plantLeavingLinks(designProject);
        var design = new FileSystemRepository();
        design.setRoot(designRoot);
        var project = project(localRepository, PROJECT);
        when(project.getRealPath()).thenReturn("rules/P");
        whenDesign(project, design, "v1");
        when(project.getDesignFolderName()).thenReturn("rules/P");

        var changes = resolver.resolve(project);

        assertChanges(changes,
                modified("rules/P/inner.xlsx"),
                modified("rules/P/rules/Main.xlsx"),
                deleted("rules/P/gone.txt"));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void aZipDesignOmitsWorkingCopyLinksThatLeaveTheProject() throws IOException {
        writeLocal("rules/Main.xlsx");
        writeLocal("new.txt");
        plantLeavingLinks(userDir.resolve(PROJECT));
        var entries = new LinkedHashMap<String, String>();
        entries.put("rules/", "");
        entries.put("rules/Main.xlsx", "main");
        entries.put("gone.txt", "gone");
        entries.put("../evil.txt", "evil");
        entries.put("/absolute.txt", "absolute");
        var design = repository(false, true);
        when(design.readHistory(PROJECT, "v1")).thenAnswer(invocation -> archive(entries));
        var project = project(localRepository, PROJECT);
        whenDesign(project, design, "v1");

        var changes = resolver.resolve(project);

        assertChanges(changes, added("P/new.txt"), modified("P/rules/Main.xlsx"), deleted("P/gone.txt"));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void aWorkingCopyFolderThatIsALinkKeepsNoEntry() throws IOException {
        // Opening the registry drops a project folder it holds no record of, so the link is planted afterwards
        var project = project(listing(List.of(data(PROJECT + "/rules/Main.xlsx", null))), PROJECT);
        when(project.isLocalOnly()).thenReturn(true);
        var elsewhere = outside.resolve("elsewhere");
        write(elsewhere.resolve("rules/Main.xlsx"));
        Files.createSymbolicLink(userDir.resolve(PROJECT), elsewhere);

        assertNull(resolver.resolve(project));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void oneListingKeepsTheUncachedVerdictsAcrossTheLinksItResolves() throws IOException {
        // Entries under a directory link are checked through the link's real location recorded by an earlier entry
        var names = List.of("rules/Main.xlsx",
                "rules/sub/Deep.xlsx",
                "alias/Main.xlsx",
                "alias/sub/Deep.xlsx",
                "inner.xlsx",
                "leak.txt",
                "sibling.txt",
                "dangling.txt",
                "away/a.txt",
                "away/b.txt",
                "other/x.txt",
                "nowhere/a.txt");
        // Opening the registry drops a project folder it holds no record of, so the tree is planted afterwards
        var project = project(listing(names.stream().map(name -> data(PROJECT + "/" + name, null)).toList()),
                PROJECT);
        when(project.isLocalOnly()).thenReturn(true);
        writeLocal("rules/Main.xlsx");
        writeLocal("rules/sub/Deep.xlsx");
        Files.createSymbolicLink(local("alias"), local("rules"));
        Files.createSymbolicLink(local("inner.xlsx"), local("rules/sub/Deep.xlsx"));
        plantLeavingLinks(userDir.resolve(PROJECT));
        var away = outside.resolve("away");
        write(away.resolve("a.txt"));
        write(away.resolve("b.txt"));
        Files.createSymbolicLink(local("away"), away);
        Files.createSymbolicLink(local("other"), userDir.resolve("Sibling"));
        Files.createSymbolicLink(local("nowhere"), outside.resolve("missing"));

        var changes = resolver.resolve(project);

        assertChanges(changes,
                added("P/alias/Main.xlsx"),
                added("P/alias/sub/Deep.xlsx"),
                added("P/inner.xlsx"),
                added("P/rules/Main.xlsx"),
                added("P/rules/sub/Deep.xlsx"));
        var kept = Set.of("rules/Main.xlsx", "rules/sub/Deep.xlsx", "alias/Main.xlsx", "alias/sub/Deep.xlsx",
                "inner.xlsx");
        var boundary = userDir.toRealPath().resolve(PROJECT);
        for (var name : names) {
            assertEquals(kept.contains(name),
                    FileRoot.resolvesInside(boundary, name),
                    "The uncached verdict on " + name);
        }
    }

    @Test
    void aProjectFolderOutsideItsRepositoryKeepsNoEntry() {
        var escaping = listing(List.of(data("../escape/a.txt", null)));
        var invalid = listing(List.of(data("bad\u0000name/a.txt", null)));
        var escapingProject = project(escaping, "../escape");
        when(escapingProject.isLocalOnly()).thenReturn(true);
        var invalidProject = project(invalid, "bad\u0000name");
        when(invalidProject.isLocalOnly()).thenReturn(true);

        assertNull(resolver.resolve(escapingProject));
        assertNull(resolver.resolve(invalidProject));
    }

    @Test
    void entriesOfAnotherFolderOrWithoutANameAreSkipped() {
        var entries = listing(List.of(data(PROJECT + "/a.txt", null), data("Other/b.txt", null), new FileData()));
        var project = project(entries, PROJECT);
        when(project.isLocalOnly()).thenReturn(true);

        assertChanges(resolver.resolve(project), added("P/a.txt"));
    }

    @Test
    void aFolderDesignReportsAddedModifiedAndDeletedFiles() throws IOException {
        var local = mock(LocalRepository.class);
        when(local.list(PROJECT + "/")).thenReturn(List.of(unique(PROJECT + "\\same.txt", "u-same"),
                unique(PROJECT + "/changed.txt", "u-new"),
                data(PROJECT + "/edited.txt", null),
                data(PROJECT + "/Added.txt", null),
                data("Other/x.txt", null),
                new FileData()));
        var design = repository(true, true);
        when(design.list("D/")).thenReturn(List.of(unique("D/same.txt", "u-same"),
                unique("D/changed.txt", "u-old"),
                unique("D/edited.txt", "u-edited"),
                unique("D/removed.txt", "u-removed"),
                unique("Other/y.txt", "u-other")));
        var project = project(local, PROJECT);
        whenDesign(project, design, null);
        when(project.getDesignFolderName()).thenReturn("D");
        when(project.getRealPath()).thenReturn("");

        var changes = resolver.resolve(project);

        assertChanges(changes,
                added("Added.txt"),
                modified("changed.txt"),
                modified("edited.txt"),
                deleted("removed.txt"));
    }

    @Test
    void anUnversionedFolderDesignIsListedAsItIsNow() throws IOException {
        var local = mock(LocalRepository.class);
        when(local.list(PROJECT + "/")).thenReturn(List.of(data(PROJECT + "/a.txt", null)));
        var design = repository(true, false);
        when(design.list(PROJECT + "/")).thenReturn(List.of(unique(PROJECT + "/b.txt", "u-b")));
        var project = project(local, PROJECT);
        whenDesign(project, design, "v1");

        assertChanges(resolver.resolve(project), added("P/a.txt"), deleted("P/b.txt"));
    }

    @Test
    void aZipDesignReportsAddedModifiedAndDeletedFiles() throws IOException {
        var local = mock(LocalRepository.class);
        when(local.list(PROJECT + "/")).thenReturn(List.of(unique(PROJECT + "/same.txt", "u-same"),
                data(PROJECT + "/edited.txt", null),
                data(PROJECT + "/added.txt", null),
                data("Other/x.txt", null)));
        var entries = Map.of("same.txt", "s", "edited.txt", "e", "removed.txt", "r");
        var design = repository(false, false);
        when(design.read(PROJECT)).thenAnswer(invocation -> archive(entries));
        var project = project(local, PROJECT);
        whenDesign(project, design, "v1");
        when(project.getRealPath()).thenReturn("");

        assertChanges(resolver.resolve(project), added("added.txt"), modified("edited.txt"), deleted("removed.txt"));
    }

    @Test
    void aZipDesignWithoutAnArchiveReportsEveryFileAsAdded() throws IOException {
        var local = mock(LocalRepository.class);
        when(local.list(PROJECT + "/")).thenReturn(List.of(unique(PROJECT + "/a.txt", "u-a")));
        var project = project(local, PROJECT);
        whenDesign(project, repository(false, true), null);

        assertChanges(resolver.resolve(project), added("P/a.txt"));
    }

    @Test
    void aZipDesignWithTooManyEntriesIsNotCompared() throws IOException {
        var local = mock(LocalRepository.class);
        when(local.list(PROJECT + "/")).thenReturn(List.of(unique(PROJECT + "/a.txt", "u-a")));
        var entries = new LinkedHashMap<String, String>();
        for (var i = 0; i <= 10_000; i++) {
            entries.put("f" + i + ".txt", "");
        }
        var bytes = zip(entries);
        var design = repository(false, true);
        when(design.readHistory(PROJECT, "v1"))
                .thenAnswer(invocation -> new FileItem(data(PROJECT, null), new ByteArrayInputStream(bytes)));
        var project = project(local, PROJECT);
        whenDesign(project, design, "v1");

        assertChanges(resolver.resolve(project), added("P/a.txt"));
    }

    // ---- helpers

    /** A modified project opened in the working copy folder, whose real path is that folder name. */
    private static RulesProject project(LocalRepository local, String localFolderName) {
        var project = mock(RulesProject.class);
        when(project.isModified()).thenReturn(true);
        when(project.getBusinessName()).thenReturn(PROJECT);
        when(project.getRealPath()).thenReturn(localFolderName);
        when(project.getLocalRepository()).thenReturn(local);
        when(project.getLocalFolderName()).thenReturn(localFolderName);
        return project;
    }

    private static void whenDesign(RulesProject project, Repository design, @Nullable String historyVersion) {
        when(project.getDesignRepository()).thenReturn(design);
        when(project.getDesignFolderName()).thenReturn(PROJECT);
        when(project.getHistoryVersion()).thenReturn(historyVersion);
    }

    /** A working copy over the user folder that lists the given entries, whatever is on disk. */
    private LocalRepository listing(List<FileData> entries) {
        return new LocalRepository(userDir, MetainfoRegistry.open(userDir)) {
            @Override
            public List<FileData> list(String path) {
                return entries;
            }
        };
    }

    private static Repository repository(boolean folders, boolean versions) {
        var repository = mock(Repository.class);
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setFolders(folders)
                .setVersions(versions)
                .build());
        return repository;
    }

    /** Links that lead out of the project folder: to an outside file, to another project's file and to nothing. */
    private void plantLeavingLinks(Path projectFolder) throws IOException {
        var sibling = projectFolder.resolveSibling("Sibling").resolve("x.txt");
        write(sibling);
        Files.createSymbolicLink(projectFolder.resolve("leak.txt"), outsideFile);
        Files.createSymbolicLink(projectFolder.resolve("sibling.txt"), sibling);
        Files.createSymbolicLink(projectFolder.resolve("dangling.txt"), outside.resolve("missing.txt"));
    }

    private Path local(String name) {
        return userDir.resolve(PROJECT).resolve(name);
    }

    private void writeLocal(String name) throws IOException {
        write(local(name));
    }

    private static void write(Path file) throws IOException {
        Files.createDirectories(file.getParent());
        Files.writeString(file, "content of " + file.getFileName());
    }

    private static FileData data(String name, @Nullable String uniqueId) {
        var data = new FileData();
        data.setName(name);
        if (uniqueId != null) {
            data.setUniqueId(uniqueId);
        }
        return data;
    }

    private static FileData unique(String name, String uniqueId) {
        return data(name, uniqueId);
    }

    private static FileItem archive(Map<String, String> entries) throws IOException {
        return new FileItem(data(PROJECT, null), new ByteArrayInputStream(zip(entries)));
    }

    private static byte[] zip(Map<String, String> entries) throws IOException {
        var out = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(out)) {
            for (var entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        }
        return out.toByteArray();
    }

    private static FileChange added(String path) {
        return new FileChange(path, ChangeType.ADDED);
    }

    private static FileChange modified(String path) {
        return new FileChange(path, ChangeType.MODIFIED);
    }

    private static FileChange deleted(String path) {
        return new FileChange(path, ChangeType.DELETED);
    }

    private static void assertChanges(@Nullable PendingChanges changes, FileChange... expected) {
        assertNotNull(changes);
        var files = new ArrayList<>(changes.files());
        assertEquals(List.of(expected), files);
        assertEquals(expected.length, changes.total());
    }
}

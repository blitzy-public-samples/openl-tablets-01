package org.openl.rules.project.abstraction;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.invocation.InvocationOnMock;

import org.openl.rules.common.CommonUser;
import org.openl.rules.common.ProjectException;
import org.openl.rules.common.ProjectVersion;
import org.openl.rules.repository.api.BranchRepository;
import org.openl.rules.repository.api.ChangesetType;
import org.openl.rules.repository.api.Features;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.workspace.WorkspaceUserImpl;
import org.openl.rules.workspace.dtr.FolderMapper;
import org.openl.rules.workspace.dtr.impl.FileMappingData;

class AProjectTest {

    @Test
    void requiresTheFileDataItIsReadFrom() {
        assertThrows(NullPointerException.class, () -> new AProject(null, (FileData) null));
    }

    // V1: below, the unchanged behaviour around the copy routine the link-containment fix changed in both classes

    private static final String CONTENT = "content of ";

    @TempDir
    Path folderRoot;

    @TempDir
    Path archiveRoot;

    private final CommonUser user = new WorkspaceUserImpl("jdoe", id -> new UserInfo("jdoe"));
    private FileSystemRepository folders;
    private FileSystemRepository archives;

    @BeforeEach
    void init() throws IOException {
        // Deleting the last project would also remove the emptied repository root
        Files.writeString(folderRoot.resolve("keep.txt"), "keep");
        folders = new FileSystemRepository();
        folders.setRoot(folderRoot);
        archives = new FileSystemRepository() {
            @Override
            public Features supports() {
                return new FeaturesBuilder(this).setVersions(false).setFolders(false).build();
            }
        };
        archives.setRoot(archiveRoot);
    }

    @Test
    void readsTheLatestStateOfAVersionedProject() throws IOException {
        var repository = repository(true, true, false);
        when(repository.check("P")).thenReturn(data("P", "v2"));
        var project = new AProject(repository, "P");

        assertFalse(project.isHistoric());
        assertTrue(project.isLastVersion());
        assertEquals("v2", project.getFileData().getVersion());
        assertNull(project.getFileData().getBranch(), "Only a branch repository has a branch.");
    }

    @Test
    void createsTheDataOfAVersionedProjectNotSavedYet() {
        var project = new AProject(repository(true, true, false), "P");

        assertEquals("P", project.getFileData().getName());
        assertNull(project.getFileData().getVersion());
        assertNull(project.getLastHistoryVersion(), "A project not saved yet has no versions.");
    }

    @Test
    void readsAnEarlierVersionOfAVersionedProject() throws IOException {
        var repository = repository(true, true, false);
        when(repository.check("P")).thenReturn(data("P", "v2"));
        when(repository.checkHistory("P", "v1")).thenReturn(data("P", "v1"));
        var project = new AProject(repository, "P", "v1");

        assertTrue(project.isHistoric());
        assertFalse(project.isLastVersion());
        assertEquals("v1", project.getFileData().getVersion());
        assertEquals("v2", project.getLastHistoryVersion());
    }

    @Test
    void readsTheLastVersionWhenTheRequestedVersionIsTheLastOne() throws IOException {
        var repository = repository(true, true, false);
        when(repository.check("P")).thenReturn(data("P", "v2"));

        assertTrue(new AProject(repository, "P", "v2").isLastVersion());
        verify(repository, never()).checkHistory(anyString(), anyString());
    }

    @Test
    void readsTheBranchOfABranchRepository() throws IOException {
        var repository = mock(BranchRepository.class);
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setFolders(true).build());
        when(repository.getBranch()).thenReturn("main");
        when(repository.check("P")).thenReturn(data("P", "v2"));

        assertEquals("main", new AProject(repository, "P").getFileData().getBranch());
    }

    @Test
    void resolvesTheVersionOfTheDataItIsCreatedWith() {
        var project = new AProject(repository(true, true, false), data("P", "v3"));

        assertEquals("v3", project.getHistoryVersion());
        assertEquals("v3", project.getHistoryVersion(), "The version is resolved once.");
    }

    @Test
    void failsWhenTheProjectDataCannotBeRead() throws IOException {
        var versioned = repository(true, true, false);
        when(versioned.check("P")).thenThrow(new IOException("unreadable"));
        var unversioned = repository(true, false, false);
        when(unversioned.check("P")).thenThrow(new IOException("unreadable"));

        assertThrows(IllegalStateException.class, () -> new AProject(versioned, "P").getFileData());
        assertThrows(IllegalStateException.class, () -> new AProject(unversioned, "P").getFileData());
        assertFalse(new AProject(versioned, "P").isDeleted(), "An unreadable project is not reported as deleted.");
    }

    @Test
    void listsTheVersionsOfAVersionedProject() throws IOException {
        var repository = repository(true, true, false);
        when(repository.listHistory("P")).thenReturn(List.of(data("P", "v1"), data("P", "v2")));
        var project = new AProject(repository, "P");

        assertEquals(2, project.getVersionsCount());
        assertEquals(List.of("v1", "v2"), project.getVersions().stream().map(ProjectVersion::getRevision).toList());
        assertEquals("v2", project.getLastHistoryVersion());
    }

    @Test
    void anEmptyHistoryHasNoLastVersion() throws IOException {
        var repository = repository(true, true, false);
        when(repository.listHistory("P")).thenReturn(List.of());
        var project = new AProject(repository, "P");

        assertEquals(0, project.getVersionsCount());
        assertNull(project.getLastHistoryVersion());
    }

    @Test
    void anUnreadableHistoryIsEmpty() throws IOException {
        var repository = repository(true, true, false);
        when(repository.listHistory("P")).thenThrow(new IOException("unreadable"));
        when(repository.check("P")).thenThrow(new IOException("unreadable"));
        var project = new AProject(repository, "P");

        assertEquals(List.of(), project.getHistoryFileDatas());
        assertNull(new AProject(repository, "P").getLastHistoryVersion());
    }

    @Test
    void aFileRepositoryHasNoHistory() {
        var project = new AProject(folders, "P");

        assertEquals(List.of(), project.getHistoryFileDatas());
        assertNull(project.getLastHistoryVersion());
    }

    @Test
    void deletesTheProjectFolder() throws Exception {
        write(folderRoot, "P/rules/Main.xlsx");
        var project = new AProject(folders, "P");

        project.delete();

        assertFalse(Files.exists(folderRoot.resolve("P")));
        assertNull(project.getHistoryVersion());
        assertNull(folders.check("P"), "The data is read again, and the project is gone.");
    }

    @Test
    void deletesTheProjectWithAComment() throws Exception {
        var repository = repository(true, true, false);
        when(repository.check("P")).thenReturn(data("P", "v2"));
        var project = new AProject(repository, "P");

        project.delete(user, "removed");

        var deleted = ArgumentCaptor.forClass(FileData.class);
        verify(repository).delete(deleted.capture());
        assertEquals("P", deleted.getValue().getName());
        assertEquals("v2", deleted.getValue().getVersion());
        assertEquals("jdoe", deleted.getValue().getAuthor().getName());
        assertEquals("removed", deleted.getValue().getComment());
        var gone = repository(true, true, false);
        when(gone.check("P")).thenReturn(deleted("P"));
        var error = assertThrows(ProjectException.class, () -> new AProject(gone, "P").delete(user, "again"));
        assertEquals("Project 'P' is already deleted.", error.getMessage());
    }

    @Test
    void failsWhenTheProjectCannotBeDeleted() throws IOException {
        var repository = repository(true, true, false);
        when(repository.check("P")).thenReturn(data("P", "v2"));
        when(repository.delete(any(FileData.class))).thenThrow(new IOException("read-only"));

        assertEquals("read-only", assertThrows(ProjectException.class, () -> new AProject(repository, "P").delete())
                .getMessage());
        assertEquals("read-only",
                assertThrows(ProjectException.class, () -> new AProject(repository, "P").delete(user, "removed"))
                        .getMessage());
    }

    @Test
    void describesItsShape() throws IOException {
        Files.write(archiveRoot.resolve("A"), zip(Map.of("a.txt", "a")));
        Files.write(archiveRoot.resolve("Empty"), new byte[0]);
        var folder = new AProject(folders, "P");
        var archive = new AProject(archives, "A");
        var empty = new AProject(archives, "Empty");

        assertTrue(folder.isFolder());
        assertFalse(archive.isFolder());
        assertTrue(archive.hasArtefacts());
        assertFalse(empty.hasArtefacts());
        assertFalse(folder.hasArtefacts());
        assertEquals("", folder.getInternalPath());
        assertSame(folder, folder.getProject());
        assertFalse(folder.isOpenedForEditing());
        archive.overrideFolderStructure(true);
        folder.overrideFolderStructure(false);
        assertTrue(archive.isFolder());
        assertFalse(folder.isFolder());
    }

    @Test
    void listsTheEntriesOfAnArchivedProject() throws Exception {
        var entries = new LinkedHashMap<String, String>();
        entries.put("rules/", null);
        entries.put("rules/Main.xlsx", "main");
        entries.put("rules.xml", "descriptor");
        Files.write(archiveRoot.resolve("A"), zip(entries));
        var project = new AProject(archives, "A");

        var artefacts = artefactContents(project);

        assertEquals(Map.of("rules/Main.xlsx", "main", "rules.xml", "descriptor"), artefacts);
    }

    @Test
    void listsTheEntriesOfAnEarlierVersionOfAnArchivedProject() throws Exception {
        var repository = repository(false, true, false);
        when(repository.check("A")).thenReturn(data("A", "v2"));
        when(repository.checkHistory("A", "v1")).thenReturn(data("A", "v1"));
        when(repository.readHistory("A", "v1"))
                .thenAnswer(invocation -> new FileItem(data("A", "v1"), zipStream(Map.of("a.txt", "old"))));

        var artefacts = new AProject(repository, "A", "v1").getArtefacts();

        assertEquals(List.of("A/a.txt"), artefacts.stream().map(a -> a.getFileData().getName()).toList());
    }

    @Test
    void anArchivedProjectWithoutContentHasNoEntries() throws IOException {
        var repository = repository(false, true, false);
        when(repository.check("A")).thenReturn(data("A", "v2"));

        assertTrue(new AProject(repository, "A").getArtefacts().isEmpty(), "The archive is absent.");
        assertTrue(new AProject(repository, "A", "v1").getArtefacts().isEmpty(), "The version is absent.");
    }

    @Test
    void failsWhenAnArchivedProjectCannotBeRead() throws IOException {
        var unreadable = repository(false, false, false);
        when(unreadable.read("A")).thenThrow(new IOException("unreadable"));
        var broken = repository(false, false, false);
        when(broken.read("A")).thenAnswer(invocation -> new FileItem(data("A", null), failingStream()));

        assertThrows(IllegalArgumentException.class, () -> new AProject(unreadable, "A").getArtefacts());
        assertThrows(IllegalArgumentException.class, () -> new AProject(broken, "A").getArtefacts());
    }

    @Test
    void updatesOnlyFromAnotherProject() throws ProjectException {
        var project = new AProject(folders, "P");
        var folder = project.addFolder("rules");

        assertThrows(IllegalArgumentException.class, () -> project.update(folder, user));
    }

    @Test
    void unpacksAnArchivedProjectIntoAFolder() throws Exception {
        Files.write(archiveRoot.resolve("A"), zip(Map.of("rules/Main.xlsx", "main", "rules.xml", "descriptor")));
        var target = new AProject(folders, "P");

        target.update(new AProject(archives, "A"), user);

        assertEquals("main", Files.readString(folderRoot.resolve("P/rules/Main.xlsx")));
        assertEquals("descriptor", Files.readString(folderRoot.resolve("P/rules.xml")));
        assertEquals("P", target.getFileData().getName());
    }

    @Test
    void unpacksAnEarlierVersionOfAnArchivedProject() throws Exception {
        var repository = repository(false, true, false);
        when(repository.check("A")).thenReturn(data("A", "v2"));
        when(repository.checkHistory("A", "v1")).thenReturn(data("A", "v1"));
        when(repository.readHistory("A", "v1"))
                .thenAnswer(invocation -> new FileItem(data("A", "v1"), zipStream(Map.of("a.txt", "old"))));

        new AProject(folders, "P").update(new AProject(repository, "A", "v1"), user);

        assertEquals("old", Files.readString(folderRoot.resolve("P/a.txt")));
    }

    @Test
    void unpackingAnAbsentArchiveKeepsTheFolder() throws Exception {
        var repository = repository(false, false, false);
        var target = new AProject(folders, "P");
        var before = target.getFileData();

        target.update(new AProject(repository, "A"), user);

        assertSame(before, target.getFileData());
        assertFalse(Files.exists(folderRoot.resolve("P")));
    }

    @Test
    void failsWhenTheArchiveToUnpackCannotBeRead() throws IOException {
        var repository = repository(false, false, false);
        when(repository.read("A")).thenThrow(new IOException("unreadable"));

        var error = assertThrows(ProjectException.class,
                () -> new AProject(folders, "P").update(new AProject(repository, "A"), user));
        assertEquals("unreadable", error.getMessage());
    }

    @Test
    void copiesAnArchiveAsIs() throws Exception {
        var archive = zip(Map.of("a.txt", "a"));
        var source = repository(false, false, false);
        when(source.read("S")).thenAnswer(invocation -> new FileItem(sized("S", archive.length),
                new ByteArrayInputStream(archive)));
        var target = new AProject(archives, "T");

        target.update(new AProject(source, "S"), user);

        assertArrayEquals(archive, Files.readAllBytes(archiveRoot.resolve("T")));
        assertEquals(archive.length, target.getFileData().getSize());
    }

    @Test
    void copiesAnEarlierVersionOfAnArchive() throws Exception {
        var archive = zip(Map.of("a.txt", "old"));
        var source = repository(false, true, false);
        when(source.check("S")).thenReturn(data("S", "v2"));
        when(source.checkHistory("S", "v1")).thenReturn(data("S", "v1"));
        when(source.readHistory("S", "v1")).thenAnswer(invocation -> new FileItem(sized("S", archive.length),
                new ByteArrayInputStream(archive)));

        new AProject(archives, "T").update(new AProject(source, "S", "v1"), user);

        assertEquals(Map.of("a.txt", "old"), unzip(archiveRoot.resolve("T")));
    }

    @Test
    void failsWhenTheArchiveToCopyCannotBeRead() throws IOException {
        var source = repository(false, false, false);
        when(source.read("S")).thenThrow(new IOException("unreadable"));

        var error = assertThrows(ProjectException.class,
                () -> new AProject(archives, "T").update(new AProject(source, "S"), user));
        assertEquals("unreadable", error.getMessage());
    }

    @Test
    void transformsAnArchiveThroughAnUnpackedCopy() throws Exception {
        Files.write(archiveRoot.resolve("S"), zip(Map.of("a.txt", "a", "rules/b.txt", "b")));
        var target = new AProject(archives, "T");
        target.setResourceTransformer(new UpperCaseTransformer());

        target.update(new AProject(archives, "S"), user);

        assertEquals(Map.of("a.txt", "A", "rules/b.txt", "B", "added.txt", "ADDED"), unzip(archiveRoot.resolve("T")));
    }

    @Test
    void archivesAFolderProjectWithItsTransformer() throws Exception {
        write(folderRoot, "P/a.txt");
        write(folderRoot, "P/rules/b.txt");
        var target = new AProject(archives, "T");
        target.setResourceTransformer(new UpperCaseTransformer());

        target.update(new AProject(folders, "P"), user);

        assertEquals(Map.of("a.txt", (CONTENT + "P/a.txt").toUpperCase(Locale.ROOT),
                        "rules/b.txt", (CONTENT + "P/rules/b.txt").toUpperCase(Locale.ROOT),
                        "added.txt", "ADDED"),
                unzip(archiveRoot.resolve("T")));
        assertEquals("jdoe", saveAuthorAfterArchiving(user));
    }

    @Test
    void archivesTheSubfoldersOfAFolderProject() throws Exception {
        write(folderRoot, "P/rules/b.txt");
        var source = new PrebuiltProject(folders, "P");
        var target = new AProject(archives, "T");

        target.update(source, user);

        assertEquals(Map.of("rules/b.txt", CONTENT + "P/rules/b.txt"), unzip(archiveRoot.resolve("T")));
    }

    @Test
    void failsWhenTheArchiveCannotBeSaved() throws IOException {
        write(folderRoot, "P/a.txt");
        var repository = repository(false, false, false);
        when(repository.save(any(FileData.class), any(InputStream.class))).thenThrow(new IOException("full"));

        var error = assertThrows(ProjectException.class,
                () -> new AProject(repository, "T").update(new AProject(folders, "P"), user));
        assertEquals("full", error.getMessage());
    }

    @Test
    void copiesAFolderProjectAsAFullChangeset() throws Exception {
        write(folderRoot, "S/a.txt");
        write(folderRoot, "S/rules/b.txt");
        write(folderRoot, "T/stale.txt");
        var target = new AProject(folders, "T");

        target.update(new AProject(folders, "S"), user);

        assertEquals(CONTENT + "S/a.txt", Files.readString(folderRoot.resolve("T/a.txt")));
        assertEquals(CONTENT + "S/rules/b.txt", Files.readString(folderRoot.resolve("T/rules/b.txt")));
        assertFalse(Files.exists(folderRoot.resolve("T/stale.txt")), "A full changeset removes absent files.");
    }

    @Test
    void copiesTheSubfoldersOfAFolderProjectWithItsTransformer() throws Exception {
        write(folderRoot, "S/rules/b.txt");
        var target = new AProject(folders, "T");
        target.setResourceTransformer(new UpperCaseTransformer());

        target.update(new PrebuiltProject(folders, "S"), user);

        assertEquals((CONTENT + "S/rules/b.txt").toUpperCase(Locale.ROOT), Files.readString(folderRoot.resolve("T/rules/b.txt")));
        assertEquals("ADDED", Files.readString(folderRoot.resolve("T/added.txt")));
    }

    @Test
    void copiesTheDifferenceFromTheLatestVersion() throws Exception {
        var source = repository(true, true, true);
        when(source.check("S")).thenReturn(data("S", "v7"));
        when(source.listFiles("S/", "v7")).thenReturn(List.of(data("S/a.txt", null),
                unique("S/same.txt", "u-same"),
                unique("S/changed.txt", "u-new"),
                unique("S/added.txt", "u-added")));
        when(source.readHistory(anyString(), eq("v7"))).thenAnswer(this::readAnswer);
        var target = repository(true, true, true);
        when(target.check("T")).thenReturn(data("T", "v1"));
        when(target.list("T/")).thenReturn(List.of(unique("T/same.txt", "u-same"),
                unique("T/changed.txt", "u-old"),
                unique("T/removed.txt", "u-removed")));
        var saved = captureSave(target);

        new AProject(target, "T").update(new AProject(source, "S"), user);

        assertEquals(Map.of("T/a.txt", CONTENT + "S/a.txt",
                "T/changed.txt", CONTENT + "S/changed.txt",
                "T/added.txt", CONTENT + "S/added.txt",
                "T/removed.txt", "<deleted>"), saved.changes);
        assertEquals(List.of(ChangesetType.DIFF), saved.types);
        assertEquals("v7", saved.data.getFirst().getVersion(), "The diff records the source version it is based on.");
        assertEquals("u-new", saved.uniqueIds.get("T/changed.txt"));
    }

    @Test
    void copiesTheDifferenceFromAnEarlierVersionWithATransformer() throws Exception {
        var source = repository(true, true, true);
        when(source.check("S")).thenReturn(data("S", "v7"));
        when(source.checkHistory("S", "v3")).thenReturn(data("S", "v3"));
        when(source.listFiles("S/", "v3")).thenReturn(List.of(unique("S/changed.txt", "u-new")));
        when(source.checkHistory("S/changed.txt", "v3")).thenReturn(data("S/changed.txt", "v3"));
        when(source.readHistory("S/changed.txt", "v3")).thenAnswer(this::readAnswer);
        var target = repository(true, true, true);
        when(target.check("T")).thenReturn(data("T", "v9"));
        when(target.listFiles("T/", "v9")).thenReturn(List.of(unique("T/changed.txt", "u-old")));
        var saved = captureSave(target);
        var project = new AProject(target, "T", "v9");
        project.setResourceTransformer(new UpperCaseTransformer());

        project.update(new AProject(source, "S", "v3"), user);

        assertEquals(Map.of("T/changed.txt", (CONTENT + "S/changed.txt").toUpperCase(Locale.ROOT), "T/added.txt", "ADDED"),
                saved.changes);
        assertEquals("v3", saved.data.getFirst().getVersion());
    }

    @Test
    void copiesTheDifferenceFromAnUnsavedProject() throws Exception {
        var source = repository(true, true, true);
        var target = repository(true, true, true);
        when(target.list("T/")).thenReturn(List.of(unique("T/removed.txt", "u-removed")));
        var saved = captureSave(target);

        new AProject(target, "T").update(new AProject(source, "S"), user);

        assertEquals(Map.of("T/removed.txt", "<deleted>"), saved.changes);
        assertNull(saved.data.getFirst().getVersion());
    }

    @Test
    void copiesTheDifferenceFromAnUnversionedRepository() throws Exception {
        var source = repository(true, false, true);
        when(source.list("S/")).thenReturn(List.of(unique("S/changed.txt", "u-new"), unique("S/plain.txt", "u-p")));
        when(source.check(anyString())).thenAnswer(invocation -> data(invocation.getArgument(0), null));
        when(source.read(anyString())).thenAnswer(this::readAnswer);
        var target = repository(true, true, true);
        var saved = captureSave(target);
        var project = new AProject(target, "T");
        project.setResourceTransformer(new UpperCaseTransformer());

        project.update(new AProject(source, "S"), user);

        assertEquals(Map.of("T/changed.txt", (CONTENT + "S/changed.txt").toUpperCase(Locale.ROOT),
                "T/plain.txt", (CONTENT + "S/plain.txt").toUpperCase(Locale.ROOT),
                "T/added.txt", "ADDED"), saved.changes);
        var plainTarget = repository(true, true, true);
        var plainSaved = captureSave(plainTarget);
        new AProject(plainTarget, "T").update(new AProject(source, "S"), user);
        assertEquals(Map.of("T/changed.txt", CONTENT + "S/changed.txt", "T/plain.txt", CONTENT + "S/plain.txt"),
                plainSaved.changes);
    }

    @Test
    void failsWhenTheCopyCannotBeSaved() throws Exception {
        write(folderRoot, "S/a.txt");
        var target = repository(true, false, false);
        when(target.save(any(FileData.class), ArgumentMatchers.<Iterable<FileItem>>any(), any(ChangesetType.class)))
                .thenThrow(new IOException("full"));

        var error = assertThrows(ProjectException.class,
                () -> new AProject(target, "T").update(new AProject(folders, "S"), user));
        assertEquals("full", error.getMessage());
    }

    @Test
    void aFolderThatIsNotAFolderIsNotUpdated() throws Exception {
        write(folderRoot, "S/a.txt");
        var target = new AProjectFolder(new HashMap<>(), new AProject(folders, "T"), folders, "T") {
            @Override
            public boolean isFolder() {
                return false;
            }
        };

        target.update(new AProject(folders, "S"), user);

        assertFalse(Files.exists(folderRoot.resolve("T")));
    }

    @Test
    void managesTheArtefactsOfAFolder() throws Exception {
        write(folderRoot, "P/a.txt");
        var project = new AProject(folders, "P");

        assertTrue(project.hasArtefact("a.txt"));
        assertTrue(project.hasArtefacts());
        assertEquals("a.txt", project.getArtefact("a.txt").getName());
        assertEquals("Cannot find project artefact 'b.txt'",
                assertThrows(ProjectException.class, () -> project.getArtefact("b.txt")).getMessage());

        var added = project.addResource("b.txt", stream("b"));
        assertEquals("P/b.txt", added.getFileData().getName());
        assertEquals("b", Files.readString(folderRoot.resolve("P/b.txt")));
        assertEquals("The file 'b.txt' exists in the folder.",
                assertThrows(ProjectException.class, () -> project.addResource("b.txt", stream("again")))
                        .getMessage());

        project.deleteArtefact("a.txt");
        assertFalse(project.hasArtefact("a.txt"));
        assertFalse(Files.exists(folderRoot.resolve("P/a.txt")));

        var subFolder = project.addFolder("rules");
        assertEquals("P/rules", subFolder.getFolderPath());
        assertTrue(subFolder.isFolder());
        assertEquals("rules", subFolder.getName());
        assertEquals("rules", subFolder.getInternalPath());
        assertEquals("P/rules", subFolder.getArtefactPath().getStringValue());
        assertSame(subFolder, project.getArtefact("rules"));
    }

    @Test
    void failsWhenAResourceCannotBeAdded() throws IOException {
        var repository = repository(true, false, false);
        when(repository.check("P/a.txt")).thenThrow(new IOException("unreadable"));

        var error = assertThrows(ProjectException.class,
                () -> new AProject(repository, "P").addResource("a.txt", stream("a")));
        assertEquals("Cannot add a resource", error.getMessage());
    }

    @Test
    void addsArtefactsToTheirSubfolders() throws ProjectException {
        var project = new AProject(folders, "P");
        var folder = new AProjectFolder(new HashMap<>(), project, folders, "/P/docs");
        project.addArtefact(folder);
        project.addArtefact(new AProjectResource(project, folders, data("P/rules/deep/Main.xlsx", null)));
        project.addArtefact(new AProjectResource(project, folders, data("P/rules/Other.xlsx", null)));
        project.addArtefact(new AProjectResource(project, folders, data("P/a.txt", null)));

        assertEquals("P/docs", folder.getFolderPath(), "A leading slash is dropped.");
        assertEquals(List.of("a.txt", "docs", "rules"), new TreeMap<>(project.getArtefactsInternal()).keySet()
                .stream()
                .toList());
        var rules = (AProjectFolder) project.getArtefact("rules");
        assertEquals(List.of("Other.xlsx", "deep"), new TreeMap<>(rules.getArtefactsInternal()).keySet()
                .stream()
                .toList());
        assertEquals("other/place", new AProjectFolder(new HashMap<>(), project, folders, "other/place").getInternalPath(),
                "A folder outside the project keeps its path.");
    }

    @Test
    void passesTheTransformerToTheLoadedArtefacts() {
        var project = new AProject(folders, "P");
        var folder = new AProjectFolder(new HashMap<>(), project, folders, "P/rules");
        var resource = new AProjectResource(project, folders, data("P/a.txt", null));
        project.addArtefact(folder);
        project.addArtefact(resource);
        project.getArtefactsInternal().put("other", mock(AProjectArtefact.class));
        var transformer = new UpperCaseTransformer();

        project.setResourceTransformer(transformer);

        assertSame(transformer, project.getResourceTransformer());
        assertSame(transformer, folder.getResourceTransformer());
    }

    @Test
    void deletesAFolderWithItsArtefacts() throws Exception {
        write(folderRoot, "P/a.txt");
        write(folderRoot, "P/rules/a.txt");
        write(folderRoot, "P/rules/b.txt");
        var folder = new AProject(folders, "P").addFolder("rules");

        folder.delete();

        assertFalse(Files.exists(folderRoot.resolve("P/rules/a.txt")));
        assertFalse(Files.exists(folderRoot.resolve("P/rules/b.txt")));
        assertFalse(folder.hasArtefacts());
        assertEquals(CONTENT + "P/a.txt", Files.readString(folderRoot.resolve("P/a.txt")));
    }

    @Test
    void listsAnEarlierVersionOfAFolder() throws IOException {
        var repository = repository(true, true, false);
        when(repository.check("P")).thenReturn(data("P", "v2"));
        when(repository.checkHistory("P", "v1")).thenReturn(data("P", "v1"));
        when(repository.listFiles("P/", "v1")).thenReturn(List.of(data("P/", "v1"),
                data("P/a.txt", "v1"),
                deleted("P/removed.txt")));
        var project = new AProject(repository, "P", "v1");
        var withoutData = new AProjectFolder(project, repository, "P/rules", "v1");

        assertEquals(List.of("P/a.txt"), project.getArtefacts().stream().map(a -> a.getFileData().getName()).toList());
        assertTrue(withoutData.getArtefacts().isEmpty(), "A folder without data has no listed version.");
    }

    @Test
    void doesNotListAnEarlierVersionOfAnArchive() {
        var repository = repository(false, true, false);
        var folder = new AProjectFolder(new AProject(repository, "A"), repository, "A/rules", "v1");

        assertThrows(UnsupportedOperationException.class, folder::getArtefacts);
    }

    @Test
    void anUnreadableFolderHasNoArtefacts() throws IOException {
        var repository = repository(true, false, false);
        when(repository.list("P/")).thenThrow(new IOException("unreadable"));

        assertTrue(new AProject(repository, "P").getArtefacts().isEmpty());
        assertEquals(List.of("keep.txt"),
                new AProject(folders, "").getArtefacts().stream().map(AProjectArtefact::getName).toList(),
                "An empty folder path lists the repository root.");
    }

    @Test
    void findsTheRealPathOfAMappedFolder() {
        var repository = mock(Repository.class, withSettings().extraInterfaces(FolderMapper.class));
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setFolders(true).setVersions(false)
                .setMappedFolders(true).build());
        when(((FolderMapper) repository).getRealPath("DESIGN/P")).thenReturn("mapped/P");
        var mapped = data("DESIGN/P", null);
        mapped.addAdditionalData(FileMappingData.forProject("DESIGN/P", "recorded", "P"));
        var otherMapping = data("DESIGN/P", null);
        otherMapping.addAdditionalData(new FileMappingData("DESIGN/Other", "other/P"));
        var project = new AProject(repository, "DESIGN/P");

        assertEquals("recorded/P", new AProject(repository, mapped).getRealPath());
        assertEquals("mapped/P", new AProject(repository, otherMapping).getRealPath());
        assertEquals("mapped/P", new AProject(repository, data("DESIGN/P", null)).getRealPath());
        assertEquals("mapped/P", new AProjectFolder(new HashMap<>(), project, repository, "DESIGN/P").getRealPath());
        assertEquals("plain/P", new AProject(folders, "plain/P").getRealPath());
    }

    // ---- helpers

    private static Repository repository(boolean folders, boolean versions, boolean uniqueFileId) {
        var repository = mock(Repository.class);
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setFolders(folders)
                .setVersions(versions)
                .setSupportsUniqueFileId(uniqueFileId)
                .build());
        when(repository.getId()).thenReturn("repository");
        return repository;
    }

    private static FileData data(String name, @Nullable String version) {
        var data = new FileData();
        data.setName(name);
        if (version != null) {
            data.setVersion(version);
        }
        return data;
    }

    private static FileData unique(String name, String uniqueId) {
        var data = data(name, null);
        data.setUniqueId(uniqueId);
        return data;
    }

    private static FileData deleted(String name) {
        var data = data(name, "v1");
        data.setDeleted(true);
        return data;
    }

    private static FileData sized(String name, long size) {
        var data = data(name, null);
        data.setSize(size);
        return data;
    }

    private FileItem readAnswer(InvocationOnMock invocation) {
        String name = invocation.getArgument(0);
        return new FileItem(data(name, null), stream(CONTENT + name));
    }

    private static ByteArrayInputStream stream(String content) {
        return new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
    }

    private static InputStream failingStream() {
        return new InputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("broken");
            }

            @Override
            public int read(byte[] buffer, int offset, int length) throws IOException {
                throw new IOException("broken");
            }
        };
    }

    private static void write(Path root, String name) throws IOException {
        var file = root.resolve(name);
        Files.createDirectories(file.getParent());
        Files.writeString(file, CONTENT + name);
    }

    private static byte[] zip(Map<String, String> entries) throws IOException {
        var out = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(out)) {
            for (var entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                if (entry.getValue() != null) {
                    zip.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                }
                zip.closeEntry();
            }
        }
        return out.toByteArray();
    }

    private static InputStream zipStream(Map<String, String> entries) throws IOException {
        return new ByteArrayInputStream(zip(entries));
    }

    private static Map<String, String> unzip(Path archive) throws IOException {
        var result = new HashMap<String, String>();
        try (var zip = new ZipInputStream(Files.newInputStream(archive))) {
            for (var entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                result.put(entry.getName(), new String(zip.readAllBytes(), StandardCharsets.UTF_8));
            }
        }
        return result;
    }

    private static Map<String, String> artefactContents(AProjectFolder folder) throws ProjectException, IOException {
        var result = new HashMap<String, String>();
        for (var artefact : folder.getArtefacts()) {
            try (var content = ((AProjectResource) artefact).getContent()) {
                result.put(artefact.getInternalPath(), new String(content.readAllBytes(), StandardCharsets.UTF_8));
            }
        }
        return result;
    }

    private String saveAuthorAfterArchiving(CommonUser author) throws Exception {
        var repository = repository(false, false, false);
        var data = ArgumentCaptor.forClass(FileData.class);
        when(repository.save(data.capture(), any(InputStream.class))).thenAnswer(invocation -> invocation
                .getArgument(0));
        new AProject(repository, "T").update(new AProject(folders, "P"), author);
        return data.getValue().getAuthor().getName();
    }

    private static SavedChanges captureSave(Repository repository) throws IOException {
        var saved = new SavedChanges();
        doAnswer(invocation -> {
            saved.data.add(invocation.getArgument(0));
            saved.types.add(invocation.getArgument(2));
            Iterable<FileItem> items = invocation.getArgument(1);
            for (var item : items) {
                var name = item.getData().getName();
                var stream = item.getStream();
                saved.changes.put(name,
                        stream == null ? "<deleted>" : new String(stream.readAllBytes(), StandardCharsets.UTF_8));
                if (item.getData().getUniqueId() != null) {
                    saved.uniqueIds.put(name, item.getData().getUniqueId());
                }
            }
            return invocation.getArgument(0);
        }).when(repository).save(any(FileData.class), ArgumentMatchers.<Iterable<FileItem>>any(), any(ChangesetType.class));
        return saved;
    }

    /** What a repository was asked to save as one changeset. */
    private static final class SavedChanges {
        private final Map<String, String> changes = new HashMap<>();
        private final Map<String, String> uniqueIds = new HashMap<>();
        private final List<FileData> data = new ArrayList<>();
        private final List<ChangesetType> types = new ArrayList<>();
    }

    /** Upper-cases every file and adds one file to each changeset. */
    private static final class UpperCaseTransformer implements ResourceTransformer {
        @Override
        public InputStream transform(AProjectResource resource) throws ProjectException {
            try (var content = resource.getContent()) {
                return stream(new String(content.readAllBytes(), StandardCharsets.UTF_8).toUpperCase(Locale.ROOT));
            } catch (IOException e) {
                throw new ProjectException("Cannot transform", e);
            }
        }

        @Override
        public List<FileItem> transformChangedFiles(String rootPath, List<FileItem> changes) {
            var result = new ArrayList<>(changes);
            result.add(new FileItem(rootPath == null ? "added.txt" : rootPath + "/added.txt", stream("ADDED")));
            return result;
        }
    }

    /** A folder project whose files are grouped into subfolder artefacts, as a project built in memory holds them. */
    private static final class PrebuiltProject extends AProject {
        private PrebuiltProject(Repository repository, String folderPath) {
            super(repository, folderPath);
        }

        @Override
        protected Map<String, AProjectArtefact> createInternalArtefacts() {
            var listed = super.createInternalArtefacts();
            var grouped = new HashMap<String, AProjectArtefact>();
            var root = new AProjectFolder(grouped, this, getRepository(), getFolderPath());
            for (var artefact : listed.values()) {
                root.addArtefact(artefact);
            }
            return grouped;
        }
    }
}

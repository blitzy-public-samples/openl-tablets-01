package org.openl.studio.projects.service.files;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.security.acls.domain.BasePermission;

import org.openl.rules.project.abstraction.AProject;
import org.openl.rules.project.abstraction.AProjectFolder;
import org.openl.rules.repository.api.ChangesetType;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.rest.acl.service.AclProjectsHelper;
import org.openl.studio.common.exception.ConflictException;
import org.openl.studio.common.exception.ForbiddenException;
import org.openl.studio.common.exception.NotFoundException;
import org.openl.studio.projects.model.files.FsNode;

/**
 * Verifies how the repository mount reads, authorizes, searches and writes, and how it answers failures.
 *
 * <p>A read of a named revision lists that revision and leaves out deleted entries. A revision that cannot
 * be listed is not found. A read of the latest revision passes a listing failure on unchanged. A not-found
 * answer from the backend is never remapped.
 *
 * <p>Permissions are checked on the repository root: reading needs {@code READ} and modifying needs
 * {@code WRITE}. A denial is forbidden. An ancestor search that cannot read files and a batch write that
 * cannot be saved are conflicts.
 */
class RepoFileRootTest {

    private final Repository repository = mock(Repository.class);
    private final AclProjectsHelper acl = mock(AclProjectsHelper.class);
    private final ProjectFileLookupService lookup = mock(ProjectFileLookupService.class);
    private final ProjectLockGuard lockGuard = mock(ProjectLockGuard.class);
    private final RepoFileRoot root = new RepoFileRoot(repository, acl, lookup, lockGuard);

    private static FileData file(String name) {
        var data = new FileData();
        data.setName(name);
        return data;
    }

    private static FileItem item(String name) {
        return new FileItem(file(name), new ByteArrayInputStream(new byte[0]));
    }

    // V1: readFolder(version) lists that revision through listFiles and drops the entries marked deleted.
    @Test
    void namedRevisionOmitsDeletedEntries() throws Exception {
        var live = file("a.txt");
        var nested = file("sub/b.txt");
        var gone = file("gone.txt");
        gone.setDeleted(true);
        when(repository.listFiles("", "v1")).thenReturn(List.of(live, gone, nested));

        var tree = root.readFolder("v1");

        assertEquals(2, tree.getArtefacts().size());
        assertSame(live, tree.getArtefact("a.txt").getFileData());
        assertFalse(tree.hasArtefact("gone.txt"));
        var sub = assertInstanceOf(AProjectFolder.class, tree.getArtefact("sub"));
        assertSame(nested, sub.getArtefact("b.txt").getFileData());
        verify(repository, never()).list(anyString());
    }

    // V1: readFolder(version) answers 404 file.version.not.found when listFiles fails with an IOException.
    @Test
    void unlistableRevisionIsNotFound() throws Exception {
        when(repository.listFiles("", "v1")).thenThrow(new IOException("Unknown revision"));

        var ex = assertThrows(NotFoundException.class, () -> root.readFolder("v1"));

        assertEquals("openl.error.404.file.version.not.found.message", ex.getErrorCode());
    }

    // V1: readFolder passes a NotFoundException of the backend on as it is, without remapping it.
    @Test
    void notFoundOfTheBackendIsNotRemapped() throws Exception {
        var notFound = new NotFoundException("file.not.found.message");
        when(repository.listFiles("", "v1")).thenThrow(notFound);

        assertSame(notFound, assertThrows(NotFoundException.class, () -> root.readFolder("v1")));
    }

    // V1: readFolder with a null or blank version lists the latest revision through list, never listFiles.
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = " ")
    void blankVersionReadsTheLatestRevision(String version) throws Exception {
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setFolders(true).build());
        when(repository.list("")).thenReturn(List.of(file("a.txt"), file("sub/b.txt")));

        var tree = root.readFolder(version);

        assertEquals(2, tree.getArtefacts().size());
        assertTrue(tree.hasArtefact("a.txt"));
        var sub = assertInstanceOf(AProjectFolder.class, tree.getArtefact("sub"));
        assertTrue(sub.hasArtefact("b.txt"));
        verify(repository, never()).listFiles(anyString(), anyString());
    }

    // V1: readFolder with a null or blank version rethrows a runtime failure of the listing, with no 404 mapping.
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = " ")
    void latestRevisionFailureIsPassedOn(String version) {
        var failure = new IllegalStateException("Repository is unavailable");
        when(repository.supports()).thenThrow(failure);

        assertSame(failure, assertThrows(IllegalStateException.class, () -> root.readFolder(version)));
    }

    // V1: requireReadable asks for READ on the repository root and allows the read when it is granted.
    @Test
    void readIsAllowedWithReadOnTheRepositoryRoot() {
        when(acl.hasPermission(any(AProject.class), eq(BasePermission.READ))).thenReturn(true);

        assertDoesNotThrow(root::requireReadable);

        var target = ArgumentCaptor.forClass(AProject.class);
        verify(acl).hasPermission(target.capture(), eq(BasePermission.READ));
        assertEquals("", target.getValue().getFolderPath());
        assertSame(repository, target.getValue().getRepository());
    }

    // V1: requireReadable answers 403 default.message when READ is denied, whatever else is granted.
    @Test
    void readWithoutReadIsForbidden() {
        when(acl.hasPermission(any(AProject.class), eq(BasePermission.WRITE))).thenReturn(true);

        var ex = assertThrows(ForbiddenException.class, root::requireReadable);

        assertEquals("openl.error.403.default.message", ex.getErrorCode());
    }

    // V1: requireModifiable asks for WRITE on the repository root and allows the change when it is granted.
    @Test
    void modificationIsAllowedWithWriteOnTheRepositoryRoot() {
        when(acl.hasPermission(any(AProject.class), eq(BasePermission.WRITE))).thenReturn(true);

        assertDoesNotThrow(root::requireModifiable);

        var target = ArgumentCaptor.forClass(AProject.class);
        verify(acl).hasPermission(target.capture(), eq(BasePermission.WRITE));
        assertEquals("", target.getValue().getFolderPath());
        assertSame(repository, target.getValue().getRepository());
    }

    // V1: requireModifiable answers 403 default.message when WRITE is denied, even with READ granted.
    @Test
    void modificationWithoutWriteIsForbidden() {
        when(acl.hasPermission(any(AProject.class), eq(BasePermission.READ))).thenReturn(true);

        var ex = assertThrows(ForbiddenException.class, root::requireModifiable);

        assertEquals("openl.error.403.default.message", ex.getErrorCode());
    }

    // V1: searchAncestors returns the content lookup of the repository path from the repository itself.
    @Test
    void ancestorSearchReturnsTheRepositoryLookup() throws Exception {
        List<FsNode> nodes = List.of(mock(FsNode.class));
        when(lookup.lookup(repository, "P1/rules/AGENTS.md", true)).thenReturn(nodes);

        assertSame(nodes, root.searchAncestors("P1/rules/AGENTS.md"));
    }

    // V1: searchAncestors answers 409 file.read.failed when the lookup fails with an IOException.
    @Test
    void unreadableAncestorSearchIsAConflict() throws Exception {
        when(lookup.lookup(repository, "P1/rules/AGENTS.md", true)).thenThrow(new IOException("Read failed"));

        var ex = assertThrows(ConflictException.class, () -> root.searchAncestors("P1/rules/AGENTS.md"));

        assertEquals("openl.error.409.file.read.failed.message", ex.getErrorCode());
    }

    // V1: writeBatch with a FULL changeset also guards the base path, whose absent files it deletes.
    @Test
    void fullChangesetGuardsTheBasePath() throws Exception {
        var items = List.of(item("data/a.txt"));

        root.writeBatch("data", items, ChangesetType.FULL, "Replace data");

        verify(lockGuard).requireUnlocked(List.of("data/a.txt", "data"));
        verify(repository).save(any(FileData.class), eq(items), eq(ChangesetType.FULL));
    }

    // V1: writeBatch with a DIFF changeset guards only the paths it writes.
    @Test
    void diffChangesetGuardsOnlyTheWrittenPaths() throws Exception {
        var items = List.of(item("data/a.txt"));

        root.writeBatch("data", items, ChangesetType.DIFF, "Upload");

        verify(lockGuard).requireUnlocked(List.of("data/a.txt"));
        verify(repository).save(any(FileData.class), eq(items), eq(ChangesetType.DIFF));
    }

    // V1: writeBatch answers 409 file.archive.upload.failed when the repository save fails with an IOException.
    @Test
    void failedSaveIsAConflict() throws Exception {
        var items = List.of(item("data/a.txt"));
        when(repository.save(any(FileData.class), eq(items), eq(ChangesetType.DIFF)))
                .thenThrow(new IOException("Disk is full"));

        var ex = assertThrows(ConflictException.class,
                () -> root.writeBatch("data", items, ChangesetType.DIFF, "Upload"));

        assertEquals("openl.error.409.file.archive.upload.failed.message", ex.getErrorCode());
    }
}

package org.openl.studio.projects.service.files;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.model.Permission;

import org.openl.rules.common.ProjectException;
import org.openl.rules.project.abstraction.AProject;
import org.openl.rules.project.abstraction.AProjectArtefact;
import org.openl.rules.project.abstraction.AProjectFolder;
import org.openl.rules.project.abstraction.AProjectResource;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.rest.acl.service.AclProjectsHelper;
import org.openl.security.acl.repository.RepositoryAclService;
import org.openl.security.acl.repository.RepositoryAclServiceProvider;
import org.openl.security.acl.repository.SecuredRepositoryFactory;
import org.openl.security.acl.repository.SimpleRepositoryAclService;
import org.openl.studio.projects.model.files.FileNode;
import org.openl.studio.projects.model.files.FsNode;

/**
 * Unit tests for {@link ProjectFileLookupServiceImpl} over a mocked repository: name matching up the
 * ancestor line, nearest-first ordering, content reads, and the text/size/count guards.
 */
class ProjectFileLookupServiceImplTest {

    private Repository repository;
    private ProjectFileLookupServiceImpl service;

    @BeforeEach
    void setUp() {
        repository = mock(Repository.class);
        lenient().when(repository.getId()).thenReturn("design");
        service = new ProjectFileLookupServiceImpl(mock(AclProjectsHelper.class), grantAllAclProvider());
    }

    private static RepositoryAclServiceProvider grantAllAclProvider() {
        var aclService = mock(RepositoryAclService.class);
        lenient().when(aclService.isGranted(anyString(), anyString(), anyBoolean(), any(Permission.class)))
                .thenReturn(true);
        var provider = mock(RepositoryAclServiceProvider.class);
        lenient().when(provider.getDesignRepoAclService()).thenReturn(aclService);
        return provider;
    }

    @Test
    void collectsAncestorsUpToRoot_nearestFirst_excludingDescendantsAndSiblings() throws IOException {
        listReturns(
                fileData("a/b/AGENTS.md"),
                fileData("a/AGENTS.md"),
                fileData("a/b/c/AGENTS.md"),   // descendant of the anchor — off the upward line
                fileData("AGENTS.md"),
                fileData("a/b/notes.md"),       // different name — ignored
                fileData("x/AGENTS.md"));        // sibling branch — off the upward line

        var files = service.lookup(repository, "a/b/AGENTS.md", false);

        // Walk up from a/b: the anchor (d0), its ancestor a/ (d1), the repository root (d2). The
        // descendant a/b/c/ and the sibling x/ are not visited.
        assertEquals(List.of(
                "a/b/AGENTS.md",
                "a/AGENTS.md",
                "AGENTS.md"), paths(files));
    }

    @Test
    void includeContent_readsEachReturnedFile() throws IOException {
        listReturns(fileData("a/AGENTS.md"), fileData("AGENTS.md"));
        when(repository.read("a/AGENTS.md")).thenReturn(fileItem("nearest"));
        when(repository.read("AGENTS.md")).thenReturn(fileItem("root"));

        var files = service.lookup(repository, "a/AGENTS.md", true);

        assertEquals(List.of("a/AGENTS.md", "AGENTS.md"), paths(files));
        assertEquals("nearest", content(files.getFirst()));
        assertEquals("root", content(files.get(1)));
    }

    @Test
    void unreadableFile_isSkipped_othersStillReturned() throws IOException {
        listReturns(fileData("a/AGENTS.md"), fileData("AGENTS.md"));
        when(repository.read("a/AGENTS.md")).thenThrow(new IOException("boom"));
        when(repository.read("AGENTS.md")).thenReturn(fileItem("root"));

        var files = service.lookup(repository, "a/AGENTS.md", true);

        // The nearest file fails to read; the lookup skips it and still returns the readable ancestor.
        assertEquals(List.of("AGENTS.md"), paths(files));
        assertEquals("root", content(files.getFirst()));
    }

    @Test
    void includeContentFalse_doesNotReadFiles() throws IOException {
        listReturns(fileData("a/AGENTS.md"), fileData("AGENTS.md"));

        var files = service.lookup(repository, "a/AGENTS.md", false);

        assertEquals(2, files.size());
        assertNull(content(files.getFirst()));
        verify(repository, never()).read("a/AGENTS.md");
        verify(repository, never()).read("AGENTS.md");
    }

    @Test
    void nonTextAnchor_returnsEmptyWithoutListing() throws IOException {
        var files = service.lookup(repository, "a/rules.xlsx", true);

        assertTrue(files.isEmpty());
        verify(repository, never()).list("");
    }

    @Test
    void missingName_returnsEmpty() throws IOException {
        listReturns(fileData("a/other.md"), fileData("README.md"));

        assertTrue(service.lookup(repository, "a/AGENTS.md", false).isEmpty());
    }

    @Test
    void deletedAndOversizeMatches_areSkipped() throws IOException {
        var deleted = fileData("a/AGENTS.md");
        deleted.setDeleted(true);
        var oversize = fileData("big/AGENTS.md");
        oversize.setSize(ProjectFileLookupServiceImpl.MAX_FILE_SIZE_BYTES + 1);
        listReturns(deleted, oversize, fileData("AGENTS.md"));

        var files = service.lookup(repository, "a/AGENTS.md", false);

        assertEquals(List.of("AGENTS.md"), paths(files));
    }

    @Test
    void includeContent_oversizeContentWithUndefinedSize_isSkipped() throws IOException {
        // The repository reports no size up front, but the content exceeds the cap: the bounded read
        // must reject it instead of surfacing a partial blob.
        listReturns(fileData("AGENTS.md"));
        var oversize = "a".repeat((int) ProjectFileLookupServiceImpl.MAX_FILE_SIZE_BYTES + 1);
        when(repository.read("AGENTS.md")).thenReturn(fileItem(oversize));

        assertTrue(service.lookup(repository, "AGENTS.md", true).isEmpty());
    }

    @Test
    void capsAtMaxFilesCount() throws IOException {
        // A pathological deep anchor with a same-named file at every level above it: the walk up must
        // stop collecting once the cap is reached.
        var data = new ArrayList<FileData>();
        var dir = new StringBuilder();
        for (var i = 0; i < ProjectFileLookupServiceImpl.MAX_FILES_COUNT + 5; i++) {
            data.add(fileData(dir + "AGENTS.md"));
            dir.append('d').append(i).append('/');
        }
        when(repository.list("")).thenReturn(data);

        var files = service.lookup(repository, dir + "AGENTS.md", false);

        assertEquals(ProjectFileLookupServiceImpl.MAX_FILES_COUNT, files.size());
    }

    // V1: B19 — an ancestor candidate reached through a link is omitted before its content is read.
    //
    // These tests run over a real FileSystemRepository in a temporary directory. They rely on existing
    // behaviour that is noted here and left unchanged: FileSystemRepository.resolveInRoot checks
    // containment lexically only, and FileSystemRepository.list walks with Files.walk filtered by
    // Files::isRegularFile, so a file link is listed and read() follows it, a directory link is silently
    // not descended, and a configured root that is itself a link lists nothing at all.

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void b19_fileLinkInAncestorPointingOutside_isOmittedAndNeverRead(@TempDir Path dir) throws IOException {
        var rootMarker = marker();
        var anchorMarker = marker();
        var outsideSentinel = marker();
        seedOutsideFileLink(dir, rootMarker, anchorMarker, outsideSentinel);
        var fileRepository = Mockito.spy(fileRepositoryAt(dir.resolve("repo")));

        var files = service.lookup(fileRepository, "a/b/AGENTS.md", true);

        assertOutsideFileLinkOmitted(files, rootMarker, anchorMarker, outsideSentinel);
        verify(fileRepository, never()).read("a/AGENTS.md");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void b19_fileLinkInAncestorPointingIntoAnotherProject_isOmitted(@TempDir Path dir) throws IOException {
        var anchorMarker = marker();
        var otherMarker = marker();
        var repo = dir.resolve("repo");
        write(repo.resolve("other/AGENTS.md"), otherMarker);
        write(repo.resolve("services/rating/AGENTS.md"), anchorMarker);
        // A relative link that stays inside the repository but leads into the sibling project "other".
        Files.createSymbolicLink(repo.resolve("services/AGENTS.md"), Path.of("..", "other", "AGENTS.md"));
        var fileRepository = Mockito.spy(fileRepositoryAt(repo));

        var files = service.lookup(fileRepository, "services/rating/AGENTS.md", true);

        // other/AGENTS.md is off the upward line, so it is never a candidate in its own right.
        assertEquals(List.of("services/rating/AGENTS.md"), paths(files),
                "the linked candidate services/AGENTS.md must be omitted");
        assertEquals(anchorMarker, content(files.getFirst()));
        assertNoContentContains(files, otherMarker,
                "no returned file may carry the content of the project file behind services/AGENTS.md");
        verify(fileRepository, never()).read("services/AGENTS.md");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void b19_securedWrapperIsUnwrapped_linkStillOmitted(@TempDir Path dir) throws IOException {
        var rootMarker = marker();
        var anchorMarker = marker();
        var outsideSentinel = marker();
        seedOutsideFileLink(dir, rootMarker, anchorMarker, outsideSentinel);
        var fileRepository = Mockito.spy(fileRepositoryAt(dir.resolve("repo")));
        // The REST routes receive the design repository behind this ACL wrapper, never the bare file repository.
        var secured = SecuredRepositoryFactory.wrapToSecureRepo(fileRepository, grantAllSimpleAcl());
        assertFalse(secured instanceof FileSystemRepository, "the lookup must receive a wrapped repository");

        var files = service.lookup(secured, "a/b/AGENTS.md", true);

        assertOutsideFileLinkOmitted(files, rootMarker, anchorMarker, outsideSentinel);
        verify(fileRepository, never()).read("a/AGENTS.md");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void b19_candidateBeneathDirectoryLink_neverAppears(@TempDir Path dir) throws IOException {
        var rootMarker = marker();
        var outsideSentinel = marker();
        var repo = dir.resolve("repo");
        write(repo.resolve("AGENTS.md"), rootMarker);
        write(dir.resolve("outside-dir/AGENTS.md"), outsideSentinel);
        Files.createSymbolicLink(repo.resolve("d"), dir.resolve("outside-dir"));
        var fileRepository = fileRepositoryAt(repo);

        // Neither d/sub nor the anchor itself exists; the walk up still reaches d/ and the root.
        var files = service.lookup(fileRepository, "d/sub/AGENTS.md", true);

        // Guard: the listing never descends the directory link, so nothing beneath it is a candidate.
        assertTrue(paths(files).stream().noneMatch(path -> path.startsWith("d/")),
                "no path beneath the directory link d/ may be returned");
        assertNoContentContains(files, outsideSentinel,
                "no returned file may carry the content of the folder behind d/");
        assertEquals(List.of("AGENTS.md"), paths(files));
        assertEquals(rootMarker, content(files.getFirst()));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void b19_regularAncestorStillReturned_whenRepositoryRootIsReachedThroughALink(@TempDir Path dir)
            throws IOException {
        var rootMarker = marker();
        var nearMarker = marker();
        write(dir.resolve("real/repo/AGENTS.md"), rootMarker);
        write(dir.resolve("real/repo/a/AGENTS.md"), nearMarker);
        // The configured root is reached through the link "via": links in the configured root's own path
        // are trusted and followed. The link sits on the root's parent, because FileSystemRepository.list
        // lists nothing when the configured root is itself a link (existing behaviour, noted above).
        Files.createSymbolicLink(dir.resolve("via"), dir.resolve("real"));
        var fileRepository = fileRepositoryAt(dir.resolve("via/repo"));

        var files = service.lookup(fileRepository, "a/AGENTS.md", true);

        assertEquals(List.of("a/AGENTS.md", "AGENTS.md"), paths(files));
        assertEquals(nearMarker, content(files.getFirst()));
        assertEquals(rootMarker, content(files.get(1)));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void b19_projectOverload_inProjectLinkAndAncestorLinkOmitted(@TempDir Path dir) throws IOException {
        var rootMarker = marker();
        var projectMarker = marker();
        var outsideSentinel = marker();
        var outsideSentinel2 = marker();
        var repo = dir.resolve("repo");
        write(repo.resolve("AGENTS.md"), rootMarker);
        write(repo.resolve("services/rating/AGENTS.md"), projectMarker);
        Files.createDirectories(repo.resolve("services/rating/config"));
        // An ancestor link above the project and an in-project link at the anchor, both to outside files.
        Files.createSymbolicLink(repo.resolve("services/AGENTS.md"),
                write(dir.resolve("outside/secret.md"), outsideSentinel));
        Files.createSymbolicLink(repo.resolve("services/rating/config/AGENTS.md"),
                write(dir.resolve("outside/secret2.md"), outsideSentinel2));
        var fileRepository = Mockito.spy(fileRepositoryAt(repo));
        // A local service whose project helper grants READ; the shared one denies every in-project artefact.
        var helper = mock(AclProjectsHelper.class);
        lenient().when(helper.hasPermission(any(AProjectArtefact.class), eq(BasePermission.READ))).thenReturn(true);
        var projectService = new ProjectFileLookupServiceImpl(helper, grantAllAclProvider());
        var project = new AProject(fileRepository, fileRepository.check("services/rating"));

        var files = projectService.lookup(project, fileRepository, "services/rating/config/AGENTS.md", true);

        assertEquals(List.of("services/rating/AGENTS.md", "AGENTS.md"), paths(files),
                "the linked candidates services/rating/config/AGENTS.md and services/AGENTS.md must be omitted");
        assertEquals(projectMarker, content(files.getFirst()));
        assertEquals(rootMarker, content(files.get(1)));
        assertNoContentContains(files, outsideSentinel,
                "no returned file may carry the content of the file behind services/AGENTS.md");
        assertNoContentContains(files, outsideSentinel2,
                "no returned file may carry the content of the file behind services/rating/config/AGENTS.md");
        verify(fileRepository, never()).read("services/AGENTS.md");
        verify(fileRepository, never()).read("services/rating/config/AGENTS.md");
    }

    @Test
    void b19_regularAncestorFileStillReturnedWithContent(@TempDir Path dir) throws IOException {
        // Positive control without links: the containment check never drops a legitimate ancestor file.
        var rootMarker = marker();
        var nearMarker = marker();
        write(dir.resolve("repo/AGENTS.md"), rootMarker);
        write(dir.resolve("repo/a/AGENTS.md"), nearMarker);
        var fileRepository = fileRepositoryAt(dir.resolve("repo"));

        var files = service.lookup(fileRepository, "a/AGENTS.md", true);

        assertEquals(List.of("a/AGENTS.md", "AGENTS.md"), paths(files));
        assertEquals(nearMarker, content(files.getFirst()));
        assertEquals(rootMarker, content(files.get(1)));
    }

    // V1: branch coverage of the lookup paths around the link check that the B19 tests do not reach, so
    // the changed lookup service keeps at least 90% line and branch coverage from this class and the Git test.

    @Test
    void blankOrNonTextAnchor_returnsEmptyWithoutListing_inBothOverloads() throws IOException {
        var project = mock(AProject.class);

        assertTrue(service.lookup(project, repository, "", true).isEmpty());
        assertTrue(service.lookup(project, repository, "a/rules.xlsx", true).isEmpty());
        assertTrue(service.lookup(repository, "", true).isEmpty());
        assertTrue(service.lookup(repository, "a/README", true).isEmpty());

        verify(project, never()).getArtefacts();
        verify(repository, never()).list("");
    }

    @Test
    void projectOverload_walksNestedFolders_andSkipsOversizeAndDeniedFiles() throws Exception {
        // A project at the root of a non-file backend: nested folders, a file without metadata, an
        // oversize file and a file the user may not read. A non-file backend keeps every candidate.
        var nearMarker = marker();
        var nearest = resource("a/b/AGENTS.md", null, nearMarker);
        var oversizeData = fileData("a/AGENTS.md");
        oversizeData.setSize(ProjectFileLookupServiceImpl.MAX_FILE_SIZE_BYTES + 1);
        var oversize = resource("a/AGENTS.md", oversizeData, marker());
        var denied = resource("AGENTS.md", fileData("AGENTS.md"), marker());
        List<AProjectArtefact> artefacts = List.of(folder(folder(nearest), oversize), denied);
        var project = mock(AProject.class);
        when(project.getRealPath()).thenReturn("");
        when(project.getArtefacts()).thenReturn(artefacts);
        var helper = mock(AclProjectsHelper.class);
        when(helper.hasPermission(nearest, BasePermission.READ)).thenReturn(true);
        var projectService = new ProjectFileLookupServiceImpl(helper, grantAllAclProvider());

        var files = projectService.lookup(project, null, "a/b/AGENTS.md", true);

        assertEquals(List.of("a/b/AGENTS.md"), paths(files));
        assertEquals(nearMarker, content(files.getFirst()));
        assertNull(((FileNode) files.getFirst()).getSize());
        assertNull(((FileNode) files.getFirst()).getLastModified());
        verify(helper).hasPermission(denied, BasePermission.READ);
        verify(oversize, never()).getContent();
        verify(denied, never()).getContent();
    }

    @Test
    void projectOverload_absentOrFailingContentIsSkipped_andFlatRepositoryIsNotListed() throws Exception {
        var absent = resource("AGENTS.md", fileData("p/AGENTS.md"), null);
        var failing = resource("sub/AGENTS.md", fileData("p/sub/AGENTS.md"), null);
        when(failing.getContent()).thenThrow(new ProjectException("unreadable"));
        List<AProjectArtefact> artefacts = List.of(absent, folder(failing));
        var project = mock(AProject.class);
        when(project.getRealPath()).thenReturn("p");
        when(project.getArtefacts()).thenReturn(artefacts);
        // A repository without folders exposes nothing outside the project, so it is never listed.
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setFolders(false).build());
        var helper = mock(AclProjectsHelper.class);
        when(helper.hasPermission(any(AProjectArtefact.class), eq(BasePermission.READ))).thenReturn(true);
        var projectService = new ProjectFileLookupServiceImpl(helper, grantAllAclProvider());

        var files = projectService.lookup(project, repository, "p/sub/AGENTS.md", true);

        assertTrue(files.isEmpty());
        verify(absent).getContent();
        verify(failing).getContent();
        verify(repository, never()).list("");
    }

    @Test
    void includeContent_missingItemOrStream_isSkipped() throws IOException {
        listReturns(fileData("a/AGENTS.md"), fileData("AGENTS.md"));
        when(repository.read("a/AGENTS.md")).thenReturn(null);
        when(repository.read("AGENTS.md")).thenReturn(new FileItem(fileData("AGENTS.md"), null));

        assertTrue(service.lookup(repository, "a/AGENTS.md", true).isEmpty());
    }

    // --- helpers ---

    private void listReturns(FileData... files) {
        try {
            lenient().when(repository.list("")).thenReturn(List.of(files));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<String> paths(List<FsNode> nodes) {
        return nodes.stream().map(FsNode::getPath).toList();
    }

    private static String content(FsNode node) {
        return ((FileNode) node).getContent();
    }

    private static FileData fileData(String name) {
        var data = new FileData();
        data.setName(name);
        return data;
    }

    private static FileItem fileItem(String content) {
        return new FileItem(fileData("ignored"), new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
    }

    // V1: B19 — the repository-root file, the anchor a/b/AGENTS.md and the ancestor file link a/AGENTS.md
    // to a file outside the repository.
    private static void seedOutsideFileLink(Path dir, String rootMarker, String anchorMarker, String outsideSentinel)
            throws IOException {
        var repo = dir.resolve("repo");
        write(repo.resolve("AGENTS.md"), rootMarker);
        write(repo.resolve("a/b/AGENTS.md"), anchorMarker);
        Files.createSymbolicLink(repo.resolve("a/AGENTS.md"), write(dir.resolve("outside/secret.md"), outsideSentinel));
    }

    // V1: B19 — the expected result over seedOutsideFileLink: the anchor and the root file, never the link.
    private static void assertOutsideFileLinkOmitted(List<FsNode> files, String rootMarker, String anchorMarker,
                                                     String outsideSentinel) {
        assertEquals(List.of("a/b/AGENTS.md", "AGENTS.md"), paths(files),
                "the linked candidate a/AGENTS.md must be omitted");
        assertEquals(anchorMarker, content(files.getFirst()));
        assertEquals(rootMarker, content(files.get(1)));
        assertNoContentContains(files, outsideSentinel,
                "no returned file may carry the content of the file behind a/AGENTS.md");
    }

    // V1: B19 — fails when any returned content holds the marker; the message names paths only.
    private static void assertNoContentContains(List<FsNode> files, String marker, String message) {
        assertTrue(files.stream()
                .map(ProjectFileLookupServiceImplTest::content)
                .noneMatch(content -> content != null && content.contains(marker)), message);
    }

    // V1: B19 — a file repository rooted at the given directory, as the repo-file design repository is.
    private static FileSystemRepository fileRepositoryAt(Path root) {
        var fileRepository = new FileSystemRepository();
        fileRepository.setRoot(root);
        fileRepository.setId("design");
        fileRepository.setName("Design");
        return fileRepository;
    }

    // V1: B19 — writes UTF-8 content, creating the parent folders, and returns the file.
    private static Path write(Path file, String content) throws IOException {
        Files.createDirectories(file.getParent());
        return Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    // V1: B19 — a non-secret file content marker, generated per run.
    private static String marker() {
        return RandomStringUtils.secure().nextAlphanumeric(24);
    }

    // V1: B19 — an ACL service granting every isGranted overload, so the secured wrapper hides nothing.
    private static SimpleRepositoryAclService grantAllSimpleAcl() {
        return mock(SimpleRepositoryAclService.class,
                invocation -> invocation.getMethod().getReturnType() == boolean.class
                        ? Boolean.TRUE
                        : Mockito.RETURNS_DEFAULTS.answer(invocation));
    }

    // V1: a mocked project file at a project-relative path; a null content yields an absent stream.
    private static AProjectResource resource(String internalPath, FileData data, String content)
            throws ProjectException {
        var resource = mock(AProjectResource.class);
        lenient().when(resource.getName()).thenReturn(FilePaths.name(internalPath));
        lenient().when(resource.getInternalPath()).thenReturn(internalPath);
        lenient().when(resource.getFileData()).thenReturn(data);
        lenient().when(resource.getContent()).thenReturn(content == null
                ? null
                : new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
        return resource;
    }

    // V1: a mocked project folder holding the given artefacts.
    private static AProjectFolder folder(AProjectArtefact... children) {
        var folder = mock(AProjectFolder.class);
        lenient().when(folder.isFolder()).thenReturn(true);
        lenient().when(folder.getArtefacts()).thenReturn(List.of(children));
        return folder;
    }
}

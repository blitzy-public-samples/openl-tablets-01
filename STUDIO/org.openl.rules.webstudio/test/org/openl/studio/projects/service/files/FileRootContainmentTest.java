package org.openl.studio.projects.service.files;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;

import org.openl.rules.lock.LockInfo;
import org.openl.rules.project.abstraction.AProject;
import org.openl.rules.project.abstraction.LockEngine;
import org.openl.rules.project.abstraction.RulesProject;
import org.openl.rules.project.impl.local.LocalRepository;
import org.openl.rules.project.impl.local.MetainfoRegistry;
import org.openl.rules.project.impl.local.ProjectMetainfo;
import org.openl.rules.repository.api.BranchRepository;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.api.RepositoryDelegate;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.rest.acl.service.AclProjectsHelper;
import org.openl.rules.workspace.WorkspaceUser;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.rules.workspace.dtr.FolderMapper;
import org.openl.rules.workspace.dtr.impl.MappedRepository;
import org.openl.security.acl.repository.SecureBranchRepository;
import org.openl.security.acl.repository.SecureMappedRepository;
import org.openl.security.acl.repository.SecureRepository;
import org.openl.security.acl.repository.SecuredRepositoryFactory;
import org.openl.security.acl.repository.SimpleRepositoryAclService;
import org.openl.studio.projects.validator.ProjectStateValidator;

/**
 * Covers V1-B, the new-file surface of the files API: the real-path containment of
 * {@link FileRoot#contains(String)} and of its static helpers {@link FileRoot#localRoot(Repository)},
 * {@link FileRoot#projectBoundary(AProject)}, {@link FileRoot#resolvesInside(Path, String)} and
 * {@link FileRoot#atOwnPath(Path, String)}.
 *
 * <p>The checks run on the four mounts the REST routes build, each reached through the secured wrapper
 * the route receives: an opened project served from the user's working copy, a closed project in a
 * flat file design repository behind {@code SecureRepository}, a closed project in a mapped file design
 * repository behind {@code SecureMappedRepository}, and a {@link RepoFileRoot} over a secured file
 * repository. Every layout uses real directories and links under a temporary folder. A project mount
 * accepts links that stay inside its project folder; the repository mount authorizes each repository
 * path separately, so it refuses every link at or above a path. Backends that are not file-backed
 * (Git, JDBC, S3, Azure Blob, mocks) accept every path without any filesystem or repository call.
 *
 * <p>The tests call API that exists only with the fix, so they are coverage of it, not evidence that
 * the finding reproduces. Only the cases that create links are disabled on Windows.
 *
 * <p>Existing behaviour these checks guard against, recorded here and left unchanged:
 * {@code FileSystemRepository.resolveInRoot} checks containment lexically, without resolving links, and
 * {@code FileSystemRepository.list} walks with {@code Files.walk} filtered by
 * {@code Files::isRegularFile}, so a link to a file is listed and then followed by {@code read()},
 * while a link to a directory is not descended into.
 */
class FileRootContainmentTest {

    /**
     * The four mounts the files API serves, as the REST routes build them.
     */
    enum MountKind {
        /** An opened project, served from the user's working copy. */
        OPENED,
        /** A closed project in a flat file design repository behind {@code SecureRepository}. */
        CLOSED_FLAT,
        /** A closed project in a mapped file design repository behind {@code SecureMappedRepository}. */
        CLOSED_MAPPED,
        /** A repository mount over a file repository behind {@code SecureRepository}. */
        REPO
    }

    /**
     * A mount with the physical folders of its project {@code P1} and of the sibling project {@code P2}.
     *
     * @param root    the mount under test
     * @param project the physical folder of {@code P1}
     * @param sibling the physical folder of {@code P2}
     * @param prefix  what turns a project-relative path into a mount-relative one
     */
    private record Mount(FileRoot root, Path project, Path sibling, String prefix) {

        boolean contains(String projectRelative) {
            return root.contains(prefix + projectRelative);
        }
    }

    private final String userName = RandomStringUtils.secure().nextAlphanumeric(24);
    private final List<Closeable> closeables = new ArrayList<>();

    @TempDir
    Path tmp;

    private Path outsideDir;
    private Path outsideFile;

    @BeforeEach
    void layOutOutside() throws IOException {
        outsideDir = tmp.resolve("outside/dir");
        write(outsideDir.resolve("rules.xml"), descriptor("P3"));
        outsideFile = tmp.resolve("outside/secret.txt");
        write(outsideFile, marker());
    }

    @AfterEach
    void closeRepositories() throws IOException {
        for (var closeable : closeables) {
            closeable.close();
        }
    }

    // ---------------------------------------------------------------------------------------------
    // contains(path) on the four mounts
    // ---------------------------------------------------------------------------------------------

    @ParameterizedTest
    @EnumSource(MountKind.class)
    void insidePathsAreContained(MountKind kind) throws IOException {
        var mount = mount(kind);

        assertTrue(mount.contains("rules.xml"), "A regular file of the project must be contained");
        assertTrue(mount.contains("sub/inside.txt"), "A regular nested file must be contained");
        assertTrue(mount.contains("sub"), "A regular folder of the project must be contained");
    }

    @ParameterizedTest
    @EnumSource(MountKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void intraProjectLinkIsContainedOnlyByProjectMounts(MountKind kind) throws IOException {
        var mount = mount(kind);
        Files.createSymbolicLink(mount.project().resolve("inner"), mount.project().resolve("sub"));

        // The repository mount authorizes each repository path, so even a link inside the project is refused.
        var expected = kind != MountKind.REPO;
        assertEquals(expected, mount.contains("inner/inside.txt"), "Link inside the project on " + kind);
        assertEquals(expected, mount.contains("inner"), "Link inside the project on " + kind);
    }

    @ParameterizedTest
    @EnumSource(MountKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void outsideDirectoryLinkIsNotContained(MountKind kind) throws IOException {
        var mount = mount(kind);
        Files.createSymbolicLink(mount.project().resolve("link"), outsideDir);

        assertFalse(mount.contains("link/x.txt"), "A new file through an outside directory link");
        assertFalse(mount.contains("link/rules.xml"), "An existing file through an outside directory link");
        assertFalse(mount.contains("link"), "The outside directory link itself");
    }

    @ParameterizedTest
    @EnumSource(MountKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void outsideFileLinkIsNotContained(MountKind kind) throws IOException {
        var mount = mount(kind);
        Files.createSymbolicLink(mount.project().resolve("leak.txt"), outsideFile);

        assertFalse(mount.contains("leak.txt"), "A link to a file outside the project");
    }

    @ParameterizedTest
    @EnumSource(MountKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void siblingProjectLinkIsNotContained(MountKind kind) throws IOException {
        var mount = mount(kind);
        Files.createSymbolicLink(mount.project().resolve("sib"), mount.sibling());

        assertFalse(mount.contains("sib/rules.xml"), "A file of the sibling project through a link");
        assertFalse(mount.contains("sib/x.txt"), "A new file in the sibling project through a link");
    }

    @ParameterizedTest
    @EnumSource(MountKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void danglingLinkIsNotContained(MountKind kind) throws IOException {
        var mount = mount(kind);
        Files.createSymbolicLink(mount.project().resolve("ghost"), tmp.resolve("outside/missing"));

        assertFalse(mount.contains("ghost"), "The dangling link itself");
        assertFalse(mount.contains("ghost/x.txt"), "A new file under the dangling link");
    }

    @ParameterizedTest
    @EnumSource(MountKind.class)
    void newPathIsContained(MountKind kind) throws IOException {
        var mount = mount(kind);

        assertTrue(mount.contains("newdir/sub/x.txt"), "A file in new sub-folders must be creatable");
        assertTrue(mount.contains("new.txt"), "A new file in the project folder must be creatable");
    }

    @ParameterizedTest
    @EnumSource(MountKind.class)
    void leadingAndTrailingSlashesAreIgnored(MountKind kind) throws IOException {
        var mount = mount(kind);

        assertTrue(mount.root().contains("/" + mount.prefix() + "rules.xml/"), "Slashes around a path");
        assertTrue(mount.root().contains("//" + mount.prefix() + "sub//"), "Repeated slashes around a path");
    }

    @Test
    void eachMountContainsItsRoot() throws IOException {
        assertTrue(openedMount().root().contains(""), "The opened project folder itself");
        assertTrue(closedFlatMount().root().contains(""), "The closed flat project folder itself");
        assertTrue(closedMappedMount().root().contains(""), "The closed mapped project folder itself");
        assertTrue(repositoryMount().root().contains(""), "The repository root itself");
    }

    @ParameterizedTest
    @EnumSource(MountKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void projectFolderThatIsItselfALinkIsNotContained(MountKind kind) throws IOException {
        var mount = mount(kind);
        // P3 is a link to a folder outside the anchor that holds a project descriptor.
        Files.createSymbolicLink(mount.project().resolveSibling("P3"), outsideDir);

        var root = switch (kind) {
            case OPENED -> {
                write(tmp.resolve("design-opened/P3/rules.xml"), descriptor("P3"));
                var workspace = tmp.resolve("ws");
                register(workspace, "P3");
                var project = openedProject(workspace, tmp.resolve("design-opened"), "P3");
                yield projectMount(project);
            }
            case CLOSED_FLAT -> projectMount(closedProject(secured(fileRepository(tmp.resolve("design-flat"))),
                    "P3"));
            // The mapped index does not descend into a linked folder, so the closed project is stubbed.
            case CLOSED_MAPPED -> projectMount(stubbedClosedProject(designRepositoryOf(mount), "catalog/P3"));
            case REPO -> mount.root();
        };
        var prefix = kind == MountKind.REPO ? "P3/" : "";

        assertFalse(root.contains(prefix + "rules.xml"), "A file of a project folder that is a link on " + kind);
        assertFalse(root.contains(prefix + "x.txt"), "A new file of a project folder that is a link on " + kind);
        assertFalse(root.contains(prefix), "A project folder that is a link on " + kind);
    }

    @Test
    void closedProjectInAMissingRulesLocationAcceptsNewFiles() throws IOException {
        var design = tmp.resolve("design-new");
        Files.createDirectories(design);
        var project = stubbedClosedProject(secured(fileRepository(design)), "rules/NewProject");
        var root = projectMount(project);

        assertTrue(root.contains("x.txt"), "A file of a project whose rules location does not exist yet");
        assertTrue(root.contains("sub/x.txt"), "A nested file of a project that does not exist yet");
        assertTrue(root.contains(""), "The folder of a project that does not exist yet");
    }

    @Test
    void repositoryMountOverAMissingRootAcceptsNewFiles() {
        var root = repoMount(secured(fileRepository(tmp.resolve("not-yet/design"))));

        assertTrue(root.contains("newproj/x.txt"), "A file in a repository whose root does not exist yet");
        assertTrue(root.contains(""), "The root of a repository that does not exist yet");
    }

    // ---------------------------------------------------------------------------------------------
    // Backends that are not file-backed
    // ---------------------------------------------------------------------------------------------

    @Test
    void repositoryMountOverNonFileBackendAcceptsEveryPathWithoutCallingIt() {
        var repository = mock(Repository.class);
        var root = repoMount(repository);

        for (var path : linkLikePaths()) {
            assertTrue(root.contains(path), "A non-file backend has no links to follow: " + path);
        }
        verifyNoInteractions(repository);
    }

    @Test
    void repositoryMountUnwrapsADelegateChainOnceAndOnlyUnwraps() {
        var delegate = mock(Repository.class, withSettings().extraInterfaces(RepositoryDelegate.class));
        var original = mock(Repository.class);
        when(((RepositoryDelegate) delegate).getOriginal()).thenReturn(original);
        var root = repoMount(delegate);

        assertTrue(root.contains("P1/rules.xml"), "A delegate chain ending in a non-file backend");
        assertTrue(root.contains("P1/link/x.txt"), "A delegate chain ending in a non-file backend");

        // The anchor is resolved lazily on the first call and cached for the lifetime of the mount.
        verify((RepositoryDelegate) delegate, times(1)).getOriginal();
        verifyNoMoreInteractions(delegate);
        verifyNoInteractions(original);
    }

    @Test
    void repositoryMountOverSecuredBranchRepositoryAcceptsEveryPath() {
        var branchRepository = mock(BranchRepository.class);
        var secured = secured(branchRepository);
        assertInstanceOf(SecureBranchRepository.class, secured, "Fixture: the secured branch wrapper");
        var root = repoMount(secured);

        for (var path : linkLikePaths()) {
            assertTrue(root.contains(path), "A secured branch repository is not file-backed: " + path);
        }
        verifyNoInteractions(branchRepository);
    }

    @Test
    void projectMountOverNonFileBackendAcceptsEveryPathWithoutReadingItsPath() {
        var opened = mock(RulesProject.class);
        when(opened.isOpened()).thenReturn(true);
        when(opened.getRepository()).thenReturn(mock(Repository.class));
        var closed = stubbedClosedProject(mock(Repository.class), "P1");
        var openedRoot = projectMount(opened);
        var closedRoot = projectMount(closed);

        for (var path : linkLikePaths()) {
            assertTrue(openedRoot.contains(path), "An opened project on a non-file backend: " + path);
            assertTrue(closedRoot.contains(path), "A closed project on a non-file backend: " + path);
        }
        // The project path is read only once the anchor is known to be file-backed.
        verify(opened, never()).getFolderPath();
        verify(closed, never()).getRealPath();
    }

    // ---------------------------------------------------------------------------------------------
    // Failures while resolving
    // ---------------------------------------------------------------------------------------------

    @Test
    void projectMountFailsClosedWhenTheProjectPathIsUnparsable() throws IOException {
        var design = layOutProjects(tmp.resolve("design-flat"));
        var project = stubbedClosedProject(secured(fileRepository(design)), "P1\u0000x");
        var root = projectMount(project);

        assertFalse(root.contains("rules.xml"), "An unparsable project path must reject every path");
        assertFalse(root.contains(""), "An unparsable project path must reject the project folder too");
        // The failure is remembered: the boundary is not resolved again.
        verify(project, times(1)).getRealPath();
    }

    @Test
    void projectMountFailsClosedWhenTheProjectPathIsRejected() throws IOException {
        var design = layOutProjects(tmp.resolve("design-flat"));
        var project = stubbedClosedProject(secured(fileRepository(design)), "P1");
        when(project.getRealPath()).thenThrow(new IllegalArgumentException(marker()));

        assertFalse(projectMount(project).contains("rules.xml"), "A rejected project path fails closed");
    }

    @Test
    void projectMountPropagatesAnUnexpectedFailureAndRetriesOnTheNextCall() throws IOException {
        var design = layOutProjects(tmp.resolve("design-flat"));
        var project = stubbedClosedProject(secured(fileRepository(design)), "P1");
        when(project.getRealPath()).thenThrow(new IllegalStateException(marker())).thenReturn("P1");
        var root = projectMount(project);

        // Only an unparsable path or a denied lookup fails closed; any other failure reaches the caller,
        // so it is never mistaken for a contained path.
        assertThrows(IllegalStateException.class, () -> root.contains("rules.xml"));
        assertTrue(root.contains("rules.xml"), "The boundary is resolved again after an unexpected failure");
        verify(project, times(2)).getRealPath();
    }

    @Test
    void repositoryMountPropagatesAnUnexpectedFailureAndRetriesOnTheNextCall() {
        var delegate = mock(Repository.class, withSettings().extraInterfaces(RepositoryDelegate.class));
        when(((RepositoryDelegate) delegate).getOriginal()).thenThrow(new IllegalStateException(marker()))
                .thenReturn(mock(Repository.class));
        var root = repoMount(delegate);

        // The anchor lookup has no checked failure to capture, so an unexpected one reaches the caller.
        assertThrows(IllegalStateException.class, () -> root.contains("P1/rules.xml"));
        assertTrue(root.contains("P1/rules.xml"), "The anchor is resolved again after an unexpected failure");
        verify((RepositoryDelegate) delegate, times(2)).getOriginal();
    }

    @Test
    void repositoryMountRejectsUnparsableAndEscapingPaths() throws IOException {
        var root = repositoryMount().root();

        assertFalse(root.contains("P1/a\u0000b.txt"), "A path holding a NUL byte");
        assertFalse(root.contains("../outside/secret.txt"), "A path leaving the repository root");
        assertFalse(root.contains("P1/../../outside/dir"), "A nested path leaving the repository root");
    }

    @Test
    void projectMountRejectsUnparsableAndEscapingPaths() throws IOException {
        var root = closedFlatMount().root();

        assertFalse(root.contains("a\u0000b.txt"), "A path holding a NUL byte");
        assertFalse(root.contains("../P2/rules.xml"), "A path leading into the sibling project");
        assertFalse(root.contains("sub/../../../outside"), "A nested path leaving the project folder");
    }

    @Test
    void defaultContainsAcceptsEveryPath() {
        var root = mock(FileRoot.class, CALLS_REAL_METHODS);

        assertTrue(root.contains("anything"), "A mount without its own check accepts every path");
        assertTrue(root.contains(""), "A mount without its own check accepts its root");
    }

    // ---------------------------------------------------------------------------------------------
    // FileRoot.resolvesInside
    // ---------------------------------------------------------------------------------------------

    @Test
    void resolvesInsideAcceptsTheBoundaryAndPathsToBeCreated() throws IOException {
        var boundary = boundary();

        assertTrue(FileRoot.resolvesInside(boundary, ""), "The boundary itself");
        assertTrue(FileRoot.resolvesInside(boundary, null), "The boundary itself, as a null input");
        assertTrue(FileRoot.resolvesInside(boundary, "sub"), "An existing folder");
        assertTrue(FileRoot.resolvesInside(boundary, "sub/file.txt"), "An existing file");
        assertTrue(FileRoot.resolvesInside(boundary, "new/sub/x.txt"), "A missing tail");
    }

    @Test
    void resolvesInsideAcceptsAMissingBoundary() throws IOException {
        var boundary = tmp.toRealPath().resolve("missing/deeper");

        assertTrue(FileRoot.resolvesInside(boundary, ""), "A boundary that does not exist yet");
        assertTrue(FileRoot.resolvesInside(boundary, "x.txt"), "A file under a boundary that does not exist yet");
    }

    @Test
    void resolvesInsideRejectsLexicalEscapesAndUnparsableInput() throws IOException {
        var boundary = boundary();

        assertFalse(FileRoot.resolvesInside(boundary, "../x"), "A parent segment leaving the boundary");
        assertFalse(FileRoot.resolvesInside(boundary, "sub/../../x"), "A nested parent segment leaving it");
        assertFalse(FileRoot.resolvesInside(boundary, outsideFile.toString()), "An absolute input");
        assertFalse(FileRoot.resolvesInside(boundary, "a\u0000b"), "An input holding a NUL byte");
    }

    @Test
    void resolvesInsideRejectsABoundaryWithoutAnyExistingAncestor() {
        var boundary = Path.of("missing-" + RandomStringUtils.secure().nextAlphanumeric(24));

        assertFalse(FileRoot.resolvesInside(boundary, ""), "Nothing of the boundary can be resolved");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void resolvesInsideFollowsLinksAndRejectsTheOnesThatLeave() throws IOException {
        var boundary = boundary();
        Files.createSymbolicLink(boundary.resolve("inner"), boundary.resolve("sub"));
        Files.createSymbolicLink(boundary.resolve("leak"), outsideFile);
        Files.createSymbolicLink(boundary.resolve("ghost"), tmp.resolve("outside/missing"));
        Files.createSymbolicLink(boundary.resolve("loop1"), boundary.resolve("loop2"));
        Files.createSymbolicLink(boundary.resolve("loop2"), boundary.resolve("loop1"));

        assertTrue(FileRoot.resolvesInside(boundary, "inner"), "A link inside the boundary");
        assertTrue(FileRoot.resolvesInside(boundary, "inner/file.txt"), "A file through a link inside");
        assertTrue(FileRoot.resolvesInside(boundary, "inner/new.txt"), "A new file through a link inside");
        assertFalse(FileRoot.resolvesInside(boundary, "leak"), "A link to a file outside");
        assertFalse(FileRoot.resolvesInside(boundary, "ghost"), "A dangling link");
        assertFalse(FileRoot.resolvesInside(boundary, "ghost/x"), "A new file under a dangling link");
        assertFalse(FileRoot.resolvesInside(boundary, "loop1/x"), "A link loop");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void resolvesInsideRejectsABoundaryThatIsItselfALink() throws IOException {
        var boundary = tmp.toRealPath().resolve("b2");
        Files.createSymbolicLink(boundary, outsideDir);

        assertFalse(FileRoot.resolvesInside(boundary, ""), "A boundary that is itself a link");
        assertFalse(FileRoot.resolvesInside(boundary, "rules.xml"), "A file under a boundary that is a link");
        assertFalse(FileRoot.resolvesInside(boundary.resolve("deeper"), ""), "A boundary under a link");
    }

    // ---------------------------------------------------------------------------------------------
    // FileRoot.atOwnPath
    // ---------------------------------------------------------------------------------------------

    @Test
    void atOwnPathAcceptsRegularAndNewEntries() throws IOException {
        var root = layOutProjects(tmp.resolve("own")).toRealPath();

        assertTrue(FileRoot.atOwnPath(root, ""), "The root itself");
        assertTrue(FileRoot.atOwnPath(root, "P1/rules.xml"), "A regular file");
        assertTrue(FileRoot.atOwnPath(root, "/P1/sub/"), "A regular folder, with slashes");
        assertTrue(FileRoot.atOwnPath(root, "P1/new/x.txt"), "A path to be created");
        assertFalse(FileRoot.atOwnPath(root, "../outside"), "A path leaving the root");
        assertFalse(FileRoot.atOwnPath(root, "P1/a\u0000b"), "A path holding a NUL byte");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void atOwnPathRejectsEveryLinkAtOrAboveThePath() throws IOException {
        var root = layOutProjects(tmp.resolve("own")).toRealPath();
        Files.createSymbolicLink(root.resolve("P1/inner"), root.resolve("P1/sub"));
        Files.createSymbolicLink(root.resolve("P1/ghost"), tmp.resolve("outside/missing"));

        assertFalse(FileRoot.atOwnPath(root, "P1/inner"), "A link that stays under the root");
        assertFalse(FileRoot.atOwnPath(root, "P1/inner/inside.txt"), "A file through a link under the root");
        assertFalse(FileRoot.atOwnPath(root, "P1/inner/new.txt"), "A new file through a link under the root");
        assertFalse(FileRoot.atOwnPath(root, "P1/ghost"), "A dangling link");
        assertTrue(FileRoot.atOwnPath(root, "P1/sub/inside.txt"), "The link target at its own place");
    }


    // ---------------------------------------------------------------------------------------------
    // FileRoot.localRoot
    // ---------------------------------------------------------------------------------------------

    @Test
    void localRootReturnsTheRealRootOfEveryFileBackedRepository() throws IOException {
        var root = layOutProjects(tmp.resolve("design-lr"));
        var expected = Optional.of(root.toRealPath());
        var plain = fileRepository(root);
        var secured = secured(fileRepository(root));
        var mapped = mapped(fileRepository(root));
        var securedMapped = secured(mapped(fileRepository(root)));
        var workspace = tmp.resolve("ws-lr");
        Files.createDirectories(workspace);
        var local = new LocalRepository(workspace, MetainfoRegistry.open(workspace));

        assertInstanceOf(SecureRepository.class, secured, "Fixture: the flat secured wrapper");
        assertInstanceOf(SecureMappedRepository.class, securedMapped, "Fixture: the mapped secured wrapper");
        assertEquals(expected, FileRoot.localRoot(plain), "A plain file repository");
        assertEquals(expected, FileRoot.localRoot(secured), "A file repository behind SecureRepository");
        assertEquals(expected, FileRoot.localRoot(mapped), "A file repository behind MappedRepository");
        assertEquals(expected, FileRoot.localRoot(securedMapped), "A file repository behind SecureMappedRepository");
        assertEquals(Optional.of(workspace.toRealPath()), FileRoot.localRoot(local), "The user's working copy");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void localRootFollowsLinksInTheConfiguredRoot() throws IOException {
        var realRoot = tmp.resolve("real-root");
        write(realRoot.resolve("P1/rules.xml"), descriptor("P1"));
        var rootLink = Files.createSymbolicLink(tmp.resolve("root-link"), realRoot);
        var repository = secured(fileRepository(rootLink));

        assertEquals(Optional.of(realRoot.toRealPath()), FileRoot.localRoot(repository),
                "Links in the configured root are trusted and followed");
        assertTrue(repoMount(repository).contains("P1/rules.xml"), "A regular path under a linked root");
    }

    @Test
    void localRootResolvesAMissingRootThroughItsDeepestExistingAncestor() throws IOException {
        var repository = fileRepository(tmp.resolve("not-yet/root"));

        assertEquals(Optional.of(tmp.toRealPath().resolve("not-yet/root")), FileRoot.localRoot(repository),
                "A root that does not exist yet");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void localRootKeepsTheLexicalLocationOfADanglingRootSoItsPathsFailClosed() throws IOException {
        var dangling = Files.createSymbolicLink(tmp.resolve("dangling-root"), tmp.resolve("outside/missing"));
        var repository = secured(fileRepository(dangling));

        assertEquals(Optional.of(dangling.toAbsolutePath().normalize()), FileRoot.localRoot(repository),
                "An unresolvable root keeps its lexical location");
        var root = repoMount(repository);
        assertFalse(root.contains("P1/x.txt"), "A path under a dangling root");
        assertFalse(root.contains(""), "A dangling root itself");
    }

    @Test
    void localRootIsEmptyForEveryOtherBackend() {
        var delegateChain = mock(Repository.class, withSettings().extraInterfaces(RepositoryDelegate.class));
        when(((RepositoryDelegate) delegateChain).getOriginal()).thenReturn(mock(Repository.class));
        var mapper = mock(Repository.class, withSettings().extraInterfaces(FolderMapper.class));
        when(((FolderMapper) mapper).getDelegate()).thenReturn(mock(Repository.class));

        assertEquals(Optional.empty(), FileRoot.localRoot(null), "No repository");
        assertEquals(Optional.empty(), FileRoot.localRoot(mock(Repository.class)), "A non-file backend");
        assertEquals(Optional.empty(), FileRoot.localRoot(new FileSystemRepository()),
                "A file repository without a root");
        assertEquals(Optional.empty(), FileRoot.localRoot(delegateChain),
                "A delegate chain ending in a non-file backend");
        assertEquals(Optional.empty(), FileRoot.localRoot(mapper), "A folder mapper over a non-file backend");
        assertEquals(Optional.empty(), FileRoot.localRoot(secured(mock(BranchRepository.class))),
                "A secured branch repository");
    }

    // ---------------------------------------------------------------------------------------------
    // FileRoot.projectBoundary
    // ---------------------------------------------------------------------------------------------

    @Test
    void projectBoundaryIsTheProjectFolderOnDisk() throws IOException {
        var opened = projectOf(openedMount());
        var closedFlat = projectOf(closedFlatMount());
        var closedMapped = projectOf(closedMappedMount());
        var flatDesign = tmp.resolve("design-flat");

        assertEquals(Optional.of(tmp.resolve("ws").toRealPath().resolve("P1")), FileRoot.projectBoundary(opened),
                "An opened project is served from its working-copy folder");
        assertEquals(Optional.of(flatDesign.toRealPath().resolve("P1")), FileRoot.projectBoundary(closedFlat),
                "A closed project in a flat file repository");
        assertEquals(Optional.of(tmp.resolve("design-mapped").toRealPath().resolve("catalog/P1")),
                FileRoot.projectBoundary(closedMapped), "A closed project in a mapped file repository");
        assertEquals(Optional.of(flatDesign.toRealPath().resolve("P1")),
                FileRoot.projectBoundary(new AProject(fileRepository(flatDesign), "P1")),
                "A plain project in a file repository");
    }

    @Test
    void projectBoundaryIsEmptyOutsideALocalDirectory() {
        var opened = mock(RulesProject.class);
        when(opened.isOpened()).thenReturn(true);
        when(opened.getRepository()).thenReturn(mock(Repository.class));

        assertEquals(Optional.empty(), FileRoot.projectBoundary(null), "No project");
        assertEquals(Optional.empty(), FileRoot.projectBoundary(opened), "An opened project on a non-file backend");
        assertEquals(Optional.empty(), FileRoot.projectBoundary(stubbedClosedProject(mock(Repository.class), "P1")),
                "A closed project on a non-file backend");
        assertEquals(Optional.empty(), FileRoot.projectBoundary(new AProject(mock(Repository.class), "P1")),
                "A plain project on a non-file backend");
    }

    // ---------------------------------------------------------------------------------------------
    // Mount fixtures
    // ---------------------------------------------------------------------------------------------

    private Mount mount(MountKind kind) throws IOException {
        return switch (kind) {
            case OPENED -> openedMount();
            case CLOSED_FLAT -> closedFlatMount();
            case CLOSED_MAPPED -> closedMappedMount();
            case REPO -> repositoryMount();
        };
    }

    /**
     * An opened project {@code P1}: the working copy {@code ws} holds {@code P1} and {@code P2}, and the
     * secured flat design repository {@code design-opened} holds their committed state.
     */
    private Mount openedMount() throws IOException {
        var workspace = layOutProjects(tmp.resolve("ws"));
        register(workspace, "P1", "P2");
        var project = openedProject(workspace, layOutProjects(tmp.resolve("design-opened")), "P1");
        return new Mount(projectMount(project), workspace.resolve("P1"), workspace.resolve("P2"), "");
    }

    /**
     * A closed project {@code P1} in the flat file design repository {@code design-flat}, behind
     * {@code SecureRepository}.
     */
    private Mount closedFlatMount() throws IOException {
        var design = layOutProjects(tmp.resolve("design-flat"));
        var secured = secured(fileRepository(design));
        assertInstanceOf(SecureRepository.class, secured, "Fixture: the flat secured wrapper");
        return new Mount(projectMount(closedProject(secured, "P1")), design.resolve("P1"), design.resolve("P2"), "");
    }

    /**
     * A closed project {@code P1} in the mapped file design repository {@code design-mapped}, whose
     * projects sit in {@code catalog}, behind {@code SecureMappedRepository}.
     */
    private Mount closedMappedMount() throws IOException {
        var design = tmp.resolve("design-mapped");
        layOutProjects(design.resolve("catalog"));
        var secured = secured(mapped(fileRepository(design)));
        assertInstanceOf(SecureMappedRepository.class, secured, "Fixture: the mapped secured wrapper");
        var project = closedProject(secured, mappedName(secured, "P1"));
        return new Mount(projectMount(project), design.resolve("catalog/P1"), design.resolve("catalog/P2"), "");
    }

    /**
     * A repository mount over the file repository {@code design-repo}, behind {@code SecureRepository};
     * its paths are repository-relative.
     */
    private Mount repositoryMount() throws IOException {
        var design = layOutProjects(tmp.resolve("design-repo"));
        var root = repoMount(secured(fileRepository(design)));
        return new Mount(root, design.resolve("P1"), design.resolve("P2"), "P1/");
    }

    /**
     * Records the projects as opened in the working copy. Loading the registry deletes every project
     * folder of the working copy that has no record, as a leftover of an interrupted operation.
     */
    private static void register(Path workspace, String... projectNames) throws IOException {
        for (var projectName : projectNames) {
            MetainfoRegistry.store(workspace, projectName,
                    new ProjectMetainfo("design", null, null, null, null, null, null, null, Map.of()));
        }
    }

    private RulesProject openedProject(Path workspace, Path design, String name) throws IOException {
        var local = new LocalRepository(workspace, MetainfoRegistry.open(workspace));
        var securedDesign = secured(fileRepository(design));
        var project = new RulesProject(user(), local, local.check(name), securedDesign, securedDesign.check(name),
                lockEngine());
        assertTrue(project.isOpened(), "Fixture: the project is served from the working copy");
        return project;
    }

    private RulesProject closedProject(Repository design, String name) throws IOException {
        var workspace = Files.createTempDirectory(tmp, "local");
        var local = new LocalRepository(workspace, MetainfoRegistry.open(workspace));
        var designData = design.check(name);
        assertNotNull(designData, "Fixture: the design repository holds " + name);
        var project = new RulesProject(user(), local, null, design, designData, lockEngine());
        project.setFileData(designData);
        assertFalse(project.isOpened(), "Fixture: the project is served from the design repository");
        return project;
    }

    private static RulesProject stubbedClosedProject(Repository design, String realPath) {
        var project = mock(RulesProject.class);
        when(project.isOpened()).thenReturn(false);
        when(project.getRepository()).thenReturn(design);
        when(project.getDesignRepository()).thenReturn(design);
        when(project.getRealPath()).thenReturn(realPath);
        return project;
    }

    private static RulesProject projectOf(Mount mount) {
        return ((ProjectFileRoot) mount.root()).getProject();
    }

    private static Repository designRepositoryOf(Mount mount) {
        return projectOf(mount).getDesignRepository();
    }

    private Repository mapped(Repository delegate) throws IOException {
        var mapped = MappedRepository.create(delegate, "DESIGN/");
        closeables.add((Closeable) mapped);
        return mapped;
    }

    private static String mappedName(Repository repository, String businessName) throws IOException {
        return repository.listFolders("DESIGN/")
                .stream()
                .map(FileData::getName)
                .filter(name -> name.startsWith("DESIGN/" + businessName + ":"))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Fixture: " + businessName + " is not mapped"));
    }

    private ProjectFileRoot projectMount(RulesProject project) {
        return new ProjectFileRoot(project, mock(AclProjectsHelper.class), mock(ProjectStateValidator.class),
                mock(ProjectFileLookupService.class), () -> new UserInfo(userName), mock(DesignTimeRepository.class));
    }

    private static RepoFileRoot repoMount(Repository repository) {
        return new RepoFileRoot(repository, mock(AclProjectsHelper.class), mock(ProjectFileLookupService.class),
                mock(ProjectLockGuard.class));
    }

    private static Repository secured(Repository repository) {
        return SecuredRepositoryFactory.wrapToSecureRepo(repository, grantAllRepoAcl());
    }

    /**
     * Grants every repository permission, so the secured wrappers behave as for a user who may do anything.
     */
    private static SimpleRepositoryAclService grantAllRepoAcl() {
        return mock(SimpleRepositoryAclService.class,
                invocation -> invocation.getMethod().getReturnType() == boolean.class
                        ? Boolean.TRUE
                        : Mockito.RETURNS_DEFAULTS.answer(invocation));
    }

    private static FileSystemRepository fileRepository(Path root) {
        var repository = new FileSystemRepository();
        repository.setRoot(root);
        repository.setId("design");
        repository.setName("Design");
        return repository;
    }

    private static LockEngine lockEngine() {
        var lockEngine = mock(LockEngine.class);
        when(lockEngine.tryLock(any(), any(), any(), any())).thenReturn(true);
        when(lockEngine.getLockInfo(any(), any(), any())).thenReturn(LockInfo.NO_LOCK);
        return lockEngine;
    }

    private WorkspaceUser user() {
        var user = mock(WorkspaceUser.class);
        when(user.getUserName()).thenReturn(userName);
        return user;
    }

    // ---------------------------------------------------------------------------------------------
    // Layout helpers
    // ---------------------------------------------------------------------------------------------

    /**
     * Lays out the project {@code P1} (a descriptor, {@code sub/inside.txt} and {@code src.txt}) and its
     * sibling {@code P2} under the parent folder.
     */
    private static Path layOutProjects(Path parent) throws IOException {
        write(parent.resolve("P1/rules.xml"), descriptor("P1"));
        write(parent.resolve("P1/sub/inside.txt"), marker());
        write(parent.resolve("P1/src.txt"), marker());
        write(parent.resolve("P2/rules.xml"), descriptor("P2"));
        return parent;
    }

    /**
     * An existing boundary folder {@code b}, at its real location, holding {@code sub/file.txt}.
     */
    private Path boundary() throws IOException {
        var boundary = tmp.toRealPath().resolve("b");
        write(boundary.resolve("sub/file.txt"), marker());
        return boundary;
    }

    /**
     * Mount-relative paths shaped like the link cases of the matrix, for backends without links.
     */
    private static List<String> linkLikePaths() {
        return List.of("", "P1", "P1/rules.xml", "P1/inner/inside.txt", "P1/link/x.txt", "P1/leak.txt",
                "P1/sib/rules.xml", "P1/ghost", "P1/ghost/x.txt", "P1/newdir/sub/x.txt", "/P1/rules.xml/");
    }

    private static String descriptor(String name) {
        return "<project><name>" + name + "</name></project>";
    }

    private static String marker() {
        return RandomStringUtils.secure().nextAlphanumeric(24);
    }

    private static void write(Path file, String content) throws IOException {
        var parent = file.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }
}

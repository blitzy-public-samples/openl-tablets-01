package org.openl.studio.projects.service.files;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiPredicate;
import java.util.function.Predicate;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.StdOut;
import org.mockito.Mockito;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import org.openl.rules.lock.LockInfo;
import org.openl.rules.project.abstraction.AProject;
import org.openl.rules.project.abstraction.LockEngine;
import org.openl.rules.project.abstraction.RulesProject;
import org.openl.rules.project.impl.local.LocalRepository;
import org.openl.rules.project.impl.local.MetainfoRegistry;
import org.openl.rules.project.impl.local.ProjectMetainfo;
import org.openl.rules.repository.PathCheckedRepository;
import org.openl.rules.repository.RepositoryInstatiator;
import org.openl.rules.repository.api.BranchRepository;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.api.RepositoryDelegate;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.rest.acl.service.AclProjectsHelper;
import org.openl.rules.webstudio.service.UserManagementService;
import org.openl.rules.workspace.WorkspaceUser;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.rules.workspace.dtr.FolderMapper;
import org.openl.rules.workspace.dtr.impl.MappedRepository;
import org.openl.rules.workspace.uw.UserWorkspace;
import org.openl.security.acl.repository.SecureBranchRepository;
import org.openl.security.acl.repository.SecureMappedRepository;
import org.openl.security.acl.repository.SecureRepository;
import org.openl.security.acl.repository.SecuredRepositoryFactory;
import org.openl.security.acl.repository.SimpleRepositoryAclService;
import org.openl.studio.projects.validator.ProjectStateValidator;
import org.openl.util.IOUtils;

/**
 * Covers V1-B, the new-file surface of the files API: the real-path containment of
 * {@link FileRoot#contains(String)} and of its static helpers {@link FileRoot#localRoot(Repository)},
 * {@link FileRoot#projectBoundary(AProject)}, {@link FileRoot#resolvesInside(Path, String)} and
 * {@link FileRoot#atOwnPath(Path, String)}, and of the overloads the mounts use to reuse the real locations
 * their earlier checks resolved, {@link FileRoot#resolvesInside(Path, String, Map)} and
 * {@link FileRoot#atOwnPath(Path, String, Map)}, which must give the same verdicts in every order of paths
 * and keep a file contained while a save replaces it.
 *
 * <p>The checks run on the four mounts the REST routes build, each reached through the secured wrapper
 * the route receives: an opened project served from the user's working copy, a closed project in a
 * flat file design repository behind {@code SecureRepository}, a closed project in a mapped file design
 * repository behind {@code SecureMappedRepository}, and a {@link RepoFileRoot} over a secured file
 * repository. Every layout uses real directories and links under a temporary folder. A project mount
 * accepts links that stay inside its project folder; the repository mount authorizes each repository
 * path separately, so it refuses every link at or above a path. Backends that are not file-backed
 * (Git, JDBC, S3, Azure Blob, mocks) accept every path without any filesystem access and without any
 * repository content access: their wrappers are only unwrapped, through {@code getOriginal()} and
 * {@code getDelegate()}, and the backend itself is never called.
 *
 * <p>The closed-project and repository mounts are also built over a {@code repo-file} repository
 * instantiated from its settings, as the application instantiates it, so behind
 * {@code PathCheckedRepository}.
 *
 * <p>A check that fails closed rejects or omits the path and writes nothing: the tests capture standard
 * output and standard error, where the unit-test logging binding writes, and assert that a rejected
 * input carrying a generated credential-shaped value leaves no output and no trace of that value.
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

    // V1: the application builds every repository from its settings, which puts it behind PathCheckedRepository
    /**
     * The mounts over a file design repository built from its settings, each reached through the secured
     * wrapper the REST routes receive.
     */
    enum ConfiguredKind {
        /** A closed project in the flat configured repository, behind {@code SecureBranchRepository}. */
        CLOSED_FLAT,
        /** A closed project in the mapped configured repository, behind {@code SecureMappedRepository}. */
        CLOSED_MAPPED,
        /** A repository mount over the flat configured repository, behind {@code SecureBranchRepository}. */
        REPO
    }

    // V1: the repository mount the REST routes really use, built by RepoFileRootFactory inside AuthoringRepository
    /**
     * The secured, configured file design repository a repository-mount route receives, which
     * {@link RepoFileRootFactory#of(Repository, String)} mounts inside {@code AuthoringRepository}.
     */
    enum FactoryKind {
        /**
         * A mapped repository behind {@code SecureMappedRepository}; the factory mounts its {@code getDelegate()},
         * the {@code PathCheckedRepository}.
         */
        MAPPED,
        /** A flat repository behind {@code SecureBranchRepository}, which the factory mounts as it is. */
        FLAT
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

    // V1: the captured output up to a point, so a check reads only what the containment calls after it write
    /**
     * The lengths of standard output and standard error captured by {@link StdIo} when the mark is taken.
     * Building the fixtures may write to them, for example when the mocking library initializes; only the
     * containment calls made after the mark are held to writing nothing.
     *
     * @param out       the captured standard output
     * @param err       the captured standard error, where the unit-test logging binding writes every level
     * @param outLength the length of the captured standard output when the mark is taken
     * @param errLength the length of the captured standard error when the mark is taken
     */
    private record Mark(StdOut out, StdErr err, int outLength, int errLength) {

        static Mark of(StdOut out, StdErr err) {
            return new Mark(out, err, out.capturedString().length(), err.capturedString().length());
        }

        /**
         * Asserts that nothing was written to standard output or standard error since the mark, and that no
         * output captured during the test holds any of the values. The messages never repeat the output, so a
         * failure does not copy a rejected value into the test report either.
         */
        void assertNothingWrittenAndNothingLeaked(String... values) {
            var capturedOut = out.capturedString();
            var capturedErr = err.capturedString();
            assertTrue(capturedOut.substring(outLength).isEmpty(),
                    "A containment check that fails closed writes nothing to standard output");
            assertTrue(capturedErr.substring(errLength).isEmpty(),
                    "A containment check that fails closed writes nothing to standard error");
            for (var value : values) {
                assertFalse(capturedOut.contains(value) || capturedErr.contains(value),
                        "No captured output may hold a rejected value");
            }
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
        var openedBackend = mock(Repository.class);
        var closedBackend = mock(Repository.class);
        var opened = mock(RulesProject.class);
        when(opened.isOpened()).thenReturn(true);
        when(opened.getRepository()).thenReturn(openedBackend);
        var closed = stubbedClosedProject(closedBackend, "P1");
        var openedRoot = projectMount(opened);
        var closedRoot = projectMount(closed);

        for (var path : linkLikePaths()) {
            assertTrue(openedRoot.contains(path), "An opened project on a non-file backend: " + path);
            assertTrue(closedRoot.contains(path), "A closed project on a non-file backend: " + path);
        }
        // The project path is read only once the anchor is known to be file-backed.
        verify(opened, never()).getFolderPath();
        verify(closed, never()).getRealPath();
        // A backend that is not file-backed is only unwrapped by type, never called.
        verifyNoInteractions(openedBackend, closedBackend);
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
    // V1: checks that reuse the real locations a mount resolved, and checks racing with a save
    // ---------------------------------------------------------------------------------------------

    // V1: reusing real locations changes the cost of a check, never its verdict, in whatever order paths come
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void reusingChecksGiveTheVerdictsOfTheFullWalkUnderEveryBoundaryInEveryOrder() throws IOException {
        var boundary = boundary();
        write(boundary.resolve("deep/a/b/c.txt"), marker());
        var sibling = tmp.toRealPath().resolve("b-sibling");
        write(sibling.resolve("rules.xml"), descriptor("P2"));
        Files.createSymbolicLink(boundary.resolve("inner"), boundary.resolve("sub"));
        Files.createSymbolicLink(boundary.resolve("deep/a/rel"), Path.of("b"));
        Files.createSymbolicLink(boundary.resolve("sub/up"), boundary);
        Files.createSymbolicLink(boundary.resolve("leak"), outsideFile);
        Files.createSymbolicLink(boundary.resolve("out"), outsideDir);
        Files.createSymbolicLink(boundary.resolve("sib"), sibling);
        Files.createSymbolicLink(boundary.resolve("ghost"), tmp.resolve("outside/missing"));
        Files.createSymbolicLink(boundary.resolve("loop1"), boundary.resolve("loop2"));
        Files.createSymbolicLink(boundary.resolve("loop2"), boundary.resolve("loop1"));
        var linkedBoundary = Files.createSymbolicLink(tmp.toRealPath().resolve("b2"), outsideDir);
        var inputs = List.of("", "sub", "sub/file.txt", "sub/file.txt/x", "sub/up", "sub/up/sub/file.txt", "inner",
                "inner/file.txt", "inner/new.txt", "deep", "deep/a", "deep/a/b", "deep/a/b/c.txt", "deep/a/rel",
                "deep/a/rel/c.txt", "leak", "leak/x", "out", "out/rules.xml", "out/new/x.txt", "sib", "sib/rules.xml",
                "sib/x.txt", "ghost", "ghost/x", "loop1", "loop1/x", "rules.xml", "new", "new/sub/x.txt", "../x",
                "sub/../../x", outsideFile.toString(), "a\u0000b");
        assertEquals(Set.of(true, false), Set.copyOf(inputs.stream().map(i -> FileRoot.resolvesInside(boundary, i))
                .toList()), "Fixture: the layout holds contained and uncontained paths");

        for (var checked : List.of(boundary, linkedBoundary, linkedBoundary.resolve("deeper"),
                tmp.toRealPath().resolve("missing/deeper"), Path.of("missing-" + marker()))) {
            assertEquals(FileRoot.resolvesInside(checked, null),
                    FileRoot.resolvesInside(checked, null, new HashMap<>()),
                    "resolvesInside under " + checked + ", a null input");
            assertSameVerdicts("resolvesInside under " + checked, inputs,
                    input -> FileRoot.resolvesInside(checked, input),
                    (input, realLocations) -> FileRoot.resolvesInside(checked, input, realLocations));
        }
    }

    // V1: the own-path check reusing real locations answers as the full own-path check, in whatever order paths come
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void reusingOwnPathChecksGiveTheVerdictsOfTheFullWalkUnderEveryRootInEveryOrder() throws IOException {
        var root = layOutProjects(tmp.resolve("own")).toRealPath();
        Files.createSymbolicLink(root.resolve("P1/inner"), root.resolve("P1/sub"));
        Files.createSymbolicLink(root.resolve("P1/ghost"), tmp.resolve("outside/missing"));
        Files.createSymbolicLink(root.resolve("P1/link"), outsideDir);
        Files.createSymbolicLink(root.resolve("P1/leak.txt"), outsideFile);
        Files.createSymbolicLink(root.resolve("P1/sib"), root.resolve("P2"));
        Files.createSymbolicLink(root.resolve("P1/loop1"), root.resolve("P1/loop2"));
        Files.createSymbolicLink(root.resolve("P1/loop2"), root.resolve("P1/loop1"));
        Files.createSymbolicLink(root.resolve("rootlink"), outsideDir);
        var linkedRoot = Files.createSymbolicLink(tmp.toRealPath().resolve("own-link"), root);
        var danglingRoot = Files.createSymbolicLink(tmp.toRealPath().resolve("own-ghost"),
                tmp.resolve("outside/missing"));
        var paths = List.of("", "/P1/", "P1", "P1/rules.xml", "P1/sub", "P1/sub/inside.txt", "P1/sub/inside.txt/x",
                "P1/inner", "P1/inner/inside.txt", "P1/inner/new.txt", "P1/ghost", "P1/ghost/x.txt", "P1/link",
                "P1/link/rules.xml", "P1/link/new/deep/x.txt", "P1/leak.txt", "P1/sib", "P1/sib/rules.xml",
                "P1/loop1/x", "rootlink", "rootlink/rules.xml", "P1/new/x.txt", "P2/rules.xml", "../outside",
                "P1/../../outside", "P1/a\u0000b");
        assertEquals(Set.of(true, false), Set.copyOf(paths.stream().map(p -> FileRoot.atOwnPath(root, p)).toList()),
                "Fixture: the layout holds paths at and away from their own place");

        for (var checked : List.of(root, linkedRoot, danglingRoot, tmp.toRealPath().resolve("not-yet/root"))) {
            assertSameVerdicts("atOwnPath under " + checked, paths,
                    path -> FileRoot.atOwnPath(checked, path),
                    (path, realLocations) -> FileRoot.atOwnPath(checked, path, realLocations));
        }
    }

    // V1: every mount answers as the full walk it reuses real locations for, on one mount and on a fresh one
    @ParameterizedTest
    @EnumSource(MountKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void mountsGiveTheVerdictsOfTheFullWalkInEveryOrder(MountKind kind) throws IOException {
        var mount = mount(kind);
        var project = mount.project();
        Files.createSymbolicLink(project.resolve("inner"), project.resolve("sub"));
        Files.createSymbolicLink(project.resolve("link"), outsideDir);
        Files.createSymbolicLink(project.resolve("leak.txt"), outsideFile);
        Files.createSymbolicLink(project.resolve("sib"), mount.sibling());
        Files.createSymbolicLink(project.resolve("ghost"), tmp.resolve("outside/missing"));
        Files.createSymbolicLink(project.resolve("loop1"), project.resolve("loop2"));
        Files.createSymbolicLink(project.resolve("loop2"), project.resolve("loop1"));
        var paths = List.of("", "rules.xml", "sub", "sub/inside.txt", "sub/inside.txt/x", "inner", "inner/inside.txt",
                "inner/new.txt", "link", "link/rules.xml", "link/x.txt", "leak.txt", "sib", "sib/rules.xml",
                "sib/x.txt", "ghost", "ghost/x.txt", "loop1/x", "newdir/sub/x.txt", "new.txt", "../P2/rules.xml",
                "a\u0000b.txt");
        Predicate<String> full;
        if (kind == MountKind.REPO) {
            var root = project.getParent().toRealPath();
            full = path -> FileRoot.atOwnPath(root, mount.prefix() + path);
        } else {
            var boundary = FileRoot.projectBoundary(projectOf(mount)).orElseThrow();
            full = path -> FileRoot.resolvesInside(boundary, FilePaths.trimSlashes(path));
        }
        var expected = paths.stream().map(full::test).toList();
        var fresh = kind == MountKind.REPO
                ? repoMount(secured(fileRepository(project.getParent())))
                : projectMount(projectOf(mount));

        for (var round = 1; round <= 2; round++) {
            for (var i = 0; i < paths.size(); i++) {
                assertEquals(expected.get(i), mount.contains(paths.get(i)),
                        "Parents first, round " + round + ", on " + kind + ": " + paths.get(i));
            }
        }
        for (var i = paths.size() - 1; i >= 0; i--) {
            assertEquals(expected.get(i), fresh.contains(mount.prefix() + paths.get(i)),
                    "Children first on " + kind + ": " + paths.get(i));
        }
    }

    // V1: one nested check records the boundary and the directories and links it walked, and nothing absent
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void aCheckRecordsTheRealLocationsOfTheDirectoriesAndLinksItWalked() throws IOException {
        var boundary = boundary();
        write(boundary.resolve("deep/a/b/c.txt"), marker());
        Files.createSymbolicLink(boundary.resolve("inner"), boundary.resolve("sub"));
        var realLocations = new HashMap<Path, Path>();
        var walked = Map.of(boundary, boundary, boundary.resolve("deep"), boundary.resolve("deep"),
                boundary.resolve("deep/a"), boundary.resolve("deep/a"), boundary.resolve("deep/a/b"),
                boundary.resolve("deep/a/b"));

        assertTrue(FileRoot.resolvesInside(boundary, "deep/a/b/c.txt", realLocations), "A nested regular file");
        assertEquals(walked, realLocations, "The boundary and the directories walked are recorded, a file is not");

        assertTrue(FileRoot.resolvesInside(boundary, "deep/a/b/d.txt", realLocations), "A sibling to be created");
        assertTrue(FileRoot.resolvesInside(boundary, "deep/a/new/x.txt", realLocations), "A path to be created");
        assertEquals(walked, realLocations, "A sibling reads only its own entry, and absent entries are not recorded");

        assertTrue(FileRoot.resolvesInside(boundary, "inner/file.txt", realLocations), "A file through a link inside");
        assertEquals(boundary.resolve("sub"), realLocations.get(boundary.resolve("inner")),
                "A link is recorded at its real location");
    }

    // V1: a check starts at its nearest recorded ancestor and resolves the start directory only once
    @Test
    void aCheckWalksOnlyBelowItsNearestRecordedAncestor() throws IOException {
        var boundary = boundary();
        var root = layOutProjects(tmp.resolve("own")).toRealPath();
        var outside = outsideDir.toRealPath();
        // Each record names an entry that does not exist at its lexical place, so only a walk that starts
        // from the record reaches the real location recorded for it; the full walk sees a path to be created.
        var projectRecords = new HashMap<Path, Path>(Map.of(boundary, boundary, boundary.resolve("virtual"), outside));
        var ownRecords = new HashMap<Path, Path>(Map.of(root, root, root.resolve("P9"), root.resolve("P1")));
        var startRecord = new HashMap<Path, Path>(Map.of(boundary, outside));

        assertTrue(FileRoot.resolvesInside(boundary, "virtual/rules.xml"), "Fixture: the full walk sees a new path");
        assertFalse(FileRoot.resolvesInside(boundary, "virtual/rules.xml", projectRecords),
                "The walk starts at the recorded ancestor of the input");
        assertTrue(FileRoot.atOwnPath(root, "P9/rules.xml"), "Fixture: the full own-path walk sees a new path");
        assertFalse(FileRoot.atOwnPath(root, "P9/rules.xml", ownRecords),
                "The own-path walk starts at the recorded ancestor of the path");
        assertFalse(FileRoot.resolvesInside(boundary, "", startRecord), "The recorded start directory is reused");
    }

    // V1: a version read checks the design repository folder; the real locations of the working copy go with it
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void aMountThatReadsAnotherTreeChecksThatTreesFolder() throws IOException {
        var workspace = layOutProjects(tmp.resolve("ws"));
        register(workspace, "P1", "P2");
        var design = layOutProjects(tmp.resolve("design-opened"));
        Files.createSymbolicLink(design.resolve("P1/inner"), outsideDir);
        var root = projectMount(openedProject(workspace, design, "P1"));

        assertTrue(root.contains("sub/inside.txt"), "A regular file of the working copy");
        assertTrue(root.contains("inner/rules.xml"), "A new path of the working copy");
        // A file repository keeps no history, so it serves its current state as every revision.
        assertNotNull(root.readFolder("v1"), "Fixture: the revision is found");
        assertTrue(root.contains("sub/inside.txt"), "A regular file of the revision");
        assertFalse(root.contains("inner/rules.xml"), "A link of the revision that leaves its folder");
        assertNotNull(root.readFolder(null), "Fixture: the current state is read again");
        assertTrue(root.contains("inner/rules.xml"), "The working copy is checked again after the revision");
    }

    // V1: a save deletes and recreates the file it replaces; no check racing with it may reject that file
    @Test
    void everyCheckAcceptsAFileWhileASaveKeepsReplacingIt() throws Exception {
        var mount = closedFlatMount();
        var design = mount.project().getParent();
        var root = design.toRealPath();
        var boundary = FileRoot.projectBoundary(projectOf(mount)).orElseThrow();
        var repositoryRoot = repoMount(secured(fileRepository(design)));
        var file = mount.project().resolve("sub/inside.txt");
        var content = marker().getBytes(StandardCharsets.UTF_8);
        var stop = new AtomicBoolean();
        var saves = new AtomicInteger();
        var saveFailure = new AtomicReference<Exception>();
        var writer = new Thread(() -> {
            try {
                while (!stop.get()) {
                    // FileSystemRepository.save writes a file this way: the existing one is deleted, then created.
                    Files.copy(new ByteArrayInputStream(content), file, StandardCopyOption.REPLACE_EXISTING);
                    saves.incrementAndGet();
                }
            } catch (IOException | RuntimeException e) {
                saveFailure.set(e);
            }
        });
        var rejected = new TreeMap<String, Integer>();

        writer.start();
        try {
            while (saves.get() == 0 && writer.isAlive()) {
                Thread.onSpinWait();
            }
            for (var i = 0; i < 3000; i++) {
                tally(rejected, "project mount", mount.root().contains("sub/inside.txt"));
                tally(rejected, "repository mount", repositoryRoot.contains("P1/sub/inside.txt"));
                tally(rejected, "resolvesInside", FileRoot.resolvesInside(boundary, "sub/inside.txt"));
                tally(rejected, "resolvesInside reusing nothing",
                        FileRoot.resolvesInside(boundary, "sub/inside.txt", new HashMap<>()));
                tally(rejected, "atOwnPath", FileRoot.atOwnPath(root, "P1/sub/inside.txt"));
                tally(rejected, "atOwnPath reusing nothing",
                        FileRoot.atOwnPath(root, "P1/sub/inside.txt", new HashMap<>()));
            }
        } finally {
            stop.set(true);
            writer.join();
        }

        assertNull(saveFailure.get(), "Fixture: the saves keep replacing the file");
        assertTrue(saves.get() > 1, "Fixture: the file is replaced while it is checked");
        assertEquals(Map.of(), rejected, "Rejections of a file a save keeps replacing, by check");
    }

    // V1: an entry that is not a link and vanishes between the probe and its resolution is resolved through its parent
    @Test
    void theFullWalkResolvesAnEntryThatVanishesWhileItIsResolvedThroughItsParent() throws IOException {
        var provider = mock(FileSystemProvider.class);
        var parent = pathOn(provider);
        var file = pathOn(provider);
        var name = mock(Path.class);
        when(provider.exists(parent, LinkOption.NOFOLLOW_LINKS)).thenReturn(true);
        when(provider.exists(file, LinkOption.NOFOLLOW_LINKS)).thenReturn(true);
        when(provider.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS))
                .thenThrow(new NoSuchFileException("replaced"));
        when(file.toRealPath()).thenThrow(new NoSuchFileException("replaced"));
        when(file.getParent()).thenReturn(parent);
        when(file.startsWith(file)).thenReturn(true);
        when(parent.toRealPath()).thenReturn(parent);
        when(parent.relativize(file)).thenReturn(name);
        when(parent.resolve(name)).thenReturn(file);

        assertTrue(FileRoot.resolvesInside(file, ""), "A file replaced while it is resolved stays contained");
        verify(parent).toRealPath();
    }

    // V1: a link that dangles when it is resolved is rejected at once, without walking past it
    @Test
    void theFullWalkRejectsALinkThatDanglesWhenItIsResolved() throws IOException {
        var provider = mock(FileSystemProvider.class);
        var parent = pathOn(provider);
        var link = pathOn(provider);
        var linkAttributes = attributes(true, false);
        when(provider.exists(parent, LinkOption.NOFOLLOW_LINKS)).thenReturn(true);
        when(provider.exists(link, LinkOption.NOFOLLOW_LINKS)).thenReturn(true);
        when(provider.readAttributes(link, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS))
                .thenReturn(linkAttributes);
        when(link.toRealPath()).thenThrow(new NoSuchFileException("dangling"));
        when(link.getParent()).thenReturn(parent);
        when(link.startsWith(link)).thenReturn(true);

        assertFalse(FileRoot.resolvesInside(link, ""), "A dangling link");
        verify(parent, never()).toRealPath();
    }

    // V1: a link removed while a reusing check resolves it is a path to be created, and is not recorded
    @Test
    void aReusingCheckTakesALinkRemovedWhileItIsResolvedAsAPathToBeCreated() throws IOException {
        var boundary = boundary();
        var provider = mock(FileSystemProvider.class);
        var real = pathOn(provider);
        var entry = pathOn(provider);
        var linkAttributes = attributes(true, false);
        when(real.resolve(Path.of("link"))).thenReturn(entry);
        when(provider.readAttributes(entry, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS))
                .thenReturn(linkAttributes)
                .thenThrow(new NoSuchFileException("removed"));
        when(entry.toRealPath()).thenThrow(new NoSuchFileException("removed"));
        when(entry.startsWith(boundary)).thenReturn(true);
        var realLocations = new HashMap<Path, Path>(Map.of(boundary, real));

        assertTrue(FileRoot.resolvesInside(boundary, "link", realLocations), "A link removed while it is resolved");
        assertEquals(Map.of(boundary, real), realLocations, "An entry that is gone is not recorded");
    }

    // V1: a link replaced by a directory while a reusing check resolves it is taken, and recorded, as that directory
    @Test
    void aReusingCheckTakesALinkReplacedWhileItIsResolvedAsWhatReplacedIt() throws IOException {
        var boundary = boundary();
        var provider = mock(FileSystemProvider.class);
        var real = pathOn(provider);
        var entry = pathOn(provider);
        var linkAttributes = attributes(true, false);
        var directoryAttributes = attributes(false, true);
        when(real.resolve(Path.of("link"))).thenReturn(entry);
        when(provider.readAttributes(entry, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS))
                .thenReturn(linkAttributes)
                .thenReturn(directoryAttributes);
        when(entry.toRealPath()).thenThrow(new NoSuchFileException("replaced"));
        when(entry.startsWith(boundary)).thenReturn(true);
        var realLocations = new HashMap<Path, Path>(Map.of(boundary, real));

        assertTrue(FileRoot.resolvesInside(boundary, "link", realLocations), "A link replaced while it is resolved");
        assertSame(entry, realLocations.get(boundary.resolve("link")), "The directory is recorded where it is");
    }

    // V1: the race tolerance never accepts a dangling link, on any check or mount
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void everyCheckStillRejectsADanglingLink() throws IOException {
        var boundary = boundary();
        var root = boundary.getParent();
        Files.createSymbolicLink(boundary.resolve("ghost"), tmp.resolve("outside/missing"));
        var realLocations = new HashMap<Path, Path>();
        var ownLocations = new HashMap<Path, Path>();
        var projectRoot = closedFlatMount();
        Files.createSymbolicLink(projectRoot.project().resolve("ghost"), tmp.resolve("outside/missing"));
        var repositoryRoot = repoMount(secured(fileRepository(projectRoot.project().getParent())));

        for (var input : List.of("ghost", "ghost/x.txt")) {
            assertFalse(FileRoot.resolvesInside(boundary, input), "The full walk: " + input);
            assertFalse(FileRoot.resolvesInside(boundary, input, realLocations), "The reusing walk: " + input);
            assertFalse(FileRoot.atOwnPath(root, "b/" + input), "The full own-path walk: " + input);
            assertFalse(FileRoot.atOwnPath(root, "b/" + input, ownLocations), "The reusing own-path walk: " + input);
            assertFalse(projectRoot.contains(input), "The project mount: " + input);
            assertFalse(repositoryRoot.contains("P1/" + input), "The repository mount: " + input);
        }
        assertFalse(realLocations.containsKey(boundary.resolve("ghost")), "A dangling link is never recorded");
        assertFalse(ownLocations.containsKey(boundary.resolve("ghost")), "A dangling link is never recorded");
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
    // V1: file repositories built from their settings, as the application builds them
    // ---------------------------------------------------------------------------------------------

    @Test
    void localRootReturnsTheRealRootOfAConfiguredFileRepository() throws IOException {
        var root = layOutProjects(tmp.resolve("design-configured"));
        var expected = Optional.of(root.toRealPath());
        var configured = configuredFileRepository(root);
        var flat = secured(configuredFileRepository(root));
        var securedMapped = secured(mapped(configuredFileRepository(root)));

        assertInstanceOf(PathCheckedRepository.class, configured, "Fixture: the settings build a path-checked wrapper");
        assertInstanceOf(SecureBranchRepository.class, flat, "Fixture: the flat secured wrapper");
        assertInstanceOf(SecureMappedRepository.class, securedMapped, "Fixture: the mapped secured wrapper");
        assertEquals(expected, FileRoot.localRoot(configured), "A configured file repository");
        assertEquals(expected, FileRoot.localRoot(flat), "A configured file repository behind its secured wrapper");
        assertEquals(expected, FileRoot.localRoot(securedMapped),
                "A configured file repository behind SecureMappedRepository");
    }

    // V1: the repository mount holds its repository inside AuthoringRepository, which localRoot looks behind
    @Test
    void localRootLooksBehindTheAuthoringWrapperOfTheRepositoryMount() throws IOException {
        var root = layOutProjects(tmp.resolve("design-authoring"));
        var expected = Optional.of(root.toRealPath());
        var author = new UserInfo(userName);
        var configured = assertInstanceOf(BranchRepository.class, configuredFileRepository(root),
                "Fixture: the path-checked wrapper is a branch repository");
        var mapped = new AuthoringRepository(configured, author);
        var flat = new AuthoringRepository((BranchRepository) secured(configuredFileRepository(root)), author);

        assertEquals(expected, FileRoot.localRoot(mapped),
                "A configured file repository inside AuthoringRepository, as a mapped repository is mounted");
        assertEquals(expected, FileRoot.localRoot(flat),
                "A secured configured file repository inside AuthoringRepository, as a flat repository is mounted");
    }

    // V1: behind AuthoringRepository, a backend that is not file-backed yields no root and is asked nothing
    @Test
    void localRootIsEmptyBehindTheAuthoringWrapperOfANonFileBackend() {
        var backend = mock(BranchRepository.class);
        var authoring = new AuthoringRepository(backend, new UserInfo(userName));

        assertEquals(Optional.empty(), FileRoot.localRoot(authoring),
                "A non-file branch repository inside AuthoringRepository");
        verifyNoInteractions(backend);
    }

    @ParameterizedTest
    @EnumSource(ConfiguredKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void configuredFileRepositoryMountsRejectLinksThatLeaveTheProject(ConfiguredKind kind) throws IOException {
        var mount = configuredMount(kind);
        Files.createSymbolicLink(mount.project().resolve("leak.txt"), outsideFile);
        Files.createSymbolicLink(mount.project().resolve("sib"), mount.sibling());
        Files.createSymbolicLink(mount.project().resolve("inner"), mount.project().resolve("sub"));

        assertTrue(mount.contains("rules.xml"), "A regular file of a configured repository on " + kind);
        assertTrue(mount.contains("sub/inside.txt"), "A regular nested file of a configured repository on " + kind);
        assertFalse(mount.contains("leak.txt"), "A link to a file outside the project on " + kind);
        assertFalse(mount.contains("sib/rules.xml"), "A file of the sibling project through a link on " + kind);
        assertFalse(mount.contains("sib/x.txt"), "A new file in the sibling project through a link on " + kind);
        // The repository mount authorizes each repository path, so even a link inside the project is refused.
        assertEquals(kind != ConfiguredKind.REPO, mount.contains("inner/inside.txt"),
                "A link inside the project on " + kind);
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void localRootFollowsAConfiguredRootThatClimbsOutOfALink() throws IOException {
        // base/link points to physical/child, so the file system reads base/link/../design at physical/design,
        // while the lexically normalized base/design does not exist.
        var physical = layOutProjects(tmp.resolve("physical/design"));
        var child = Files.createDirectories(tmp.resolve("physical/child"));
        var link = Files.createSymbolicLink(Files.createDirectories(tmp.resolve("base")).resolve("link"), child);
        Files.createSymbolicLink(physical.resolve("P1/leak.txt"), outsideFile);
        var repository = secured(configuredFileRepository(link.resolve("..").resolve("design")));

        assertFalse(Files.exists(tmp.resolve("base/design")), "Fixture: the lexical root does not exist");
        assertEquals(Optional.of(physical.toRealPath()), FileRoot.localRoot(repository),
                "The configured root is resolved where the repository reads");
        var project = projectMount(closedProject(repository, "P1"));
        assertTrue(project.contains("rules.xml"), "A regular file under a root that climbs out of a link");
        assertFalse(project.contains("leak.txt"), "A link outside the project under a root that climbs out of a link");
        var root = repoMount(repository);
        assertTrue(root.contains("P1/rules.xml"), "A regular path under a root that climbs out of a link");
        assertFalse(root.contains("P1/leak.txt"), "A link outside under a root that climbs out of a link");
    }

    // ---------------------------------------------------------------------------------------------
    // V1: the repository mount as RepoFileRootFactory builds it for the REST routes, inside AuthoringRepository
    // ---------------------------------------------------------------------------------------------

    // V1: the routes' own mount refuses every link at or above a repository path, as the directly built mount does
    @ParameterizedTest
    @EnumSource(FactoryKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void factoryRepositoryMountRejectsEveryLink(FactoryKind kind) throws IOException {
        var design = layOutProjects(tmp.resolve("design-factory"));
        var root = factoryMount(kind, design);
        Files.createSymbolicLink(design.resolve("P1/link"), outsideDir);
        Files.createSymbolicLink(design.resolve("P1/leak.txt"), outsideFile);
        Files.createSymbolicLink(design.resolve("P1/sib"), design.resolve("P2"));
        Files.createSymbolicLink(design.resolve("rootlink"), outsideDir);
        Files.createSymbolicLink(design.resolve("rootleak.txt"), outsideFile);
        Files.createSymbolicLink(design.resolve("P1/inner"), design.resolve("P1/sub"));
        Files.createSymbolicLink(design.resolve("P1/ghost"), tmp.resolve("outside/missing"));

        assertFalse(root.contains("P1/link"), "An outside directory link on " + kind);
        assertFalse(root.contains("P1/link/rules.xml"), "An existing file through an outside directory link on "
                + kind);
        assertFalse(root.contains("P1/link/new/deep/x.txt"), "A new deep path through an outside directory link on "
                + kind);
        assertFalse(root.contains("P1/leak.txt"), "A link to a regular file outside the repository on " + kind);
        assertFalse(root.contains("P1/sib"), "A link to the sibling project folder on " + kind);
        assertFalse(root.contains("P1/sib/rules.xml"), "A file of the sibling project through a link on " + kind);
        assertFalse(root.contains("P1/sib/x.txt"), "A new file in the sibling project through a link on " + kind);
        assertFalse(root.contains("rootlink"), "A directory link at the repository root on " + kind);
        assertFalse(root.contains("rootlink/rules.xml"), "A file through a link at the repository root on " + kind);
        assertFalse(root.contains("rootleak.txt"), "A file link at the repository root on " + kind);
        assertFalse(root.contains("P1/inner"), "A link inside the project on " + kind);
        assertFalse(root.contains("P1/inner/inside.txt"), "A file through a link inside the project on " + kind);
        assertFalse(root.contains("P1/ghost"), "A dangling link on " + kind);
        assertFalse(root.contains("P1/ghost/x.txt"), "A new file under a dangling link on " + kind);
        assertTrue(root.contains("P1/sub/inside.txt"), "The target of the link inside the project, at its own place");
    }

    // V1: the strict check still serves regular paths and creates new ones on the routes' own mount
    @ParameterizedTest
    @EnumSource(FactoryKind.class)
    void factoryRepositoryMountContainsRegularAndNewPaths(FactoryKind kind) throws IOException {
        var root = factoryMount(kind, layOutProjects(tmp.resolve("design-factory")));

        assertTrue(root.contains(""), "The repository root on " + kind);
        assertTrue(root.contains("P1/rules.xml"), "A regular file on " + kind);
        assertTrue(root.contains("P1/sub/inside.txt"), "A regular nested file on " + kind);
        assertTrue(root.contains("P1/newdir/sub/x.txt"), "A new file in a new sub-folder on " + kind);
    }

    // V1: a branch repository that is not file-backed stays lexical-only behind AuthoringRepository, as Git does
    @Test
    void factoryRepositoryMountOverNonFileBackendAcceptsEveryPathWithoutCallingIt() {
        var plain = mock(BranchRepository.class);
        when(plain.supports()).thenReturn(new FeaturesBuilder(plain).build());
        var behindSecured = mock(BranchRepository.class);
        when(behindSecured.supports()).thenReturn(new FeaturesBuilder(behindSecured).build());
        var plainRoot = factoryMount(plain);
        var securedRoot = factoryMount(secured(behindSecured));
        // Building the mount asks the backend for its features and its branch; containment asks it nothing.
        clearInvocations(plain, behindSecured);

        for (var path : linkLikePaths()) {
            assertTrue(plainRoot.contains(path), "A non-file branch repository has no links to follow: " + path);
            assertTrue(securedRoot.contains(path), "A secured non-file branch repository has no links: " + path);
        }
        verifyNoInteractions(plain, behindSecured);
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
    // V1: a containment step that fails closed writes nothing, so a rejected path never reaches the output
    // ---------------------------------------------------------------------------------------------

    // V1: an input that cannot be parsed is rejected without any output
    @Test
    @StdIo
    void resolvesInsideRejectsAnUnparsableInputWithoutOutput(StdOut out, StdErr err) throws IOException {
        var boundary = boundary();
        var credential = credentialLike();
        var input = "sub/" + credential + "\u0000.txt";
        assertThrows(InvalidPathException.class, () -> boundary.resolve(input), "Fixture: the input cannot be parsed");
        var mark = Mark.of(out, err);

        assertFalse(FileRoot.resolvesInside(boundary, input), "An input holding a NUL byte");

        mark.assertNothingWrittenAndNothingLeaked(input, credential);
    }

    // V1: a dangling link is rejected without any output
    @Test
    @StdIo
    @DisabledOnOs(OS.WINDOWS)
    void resolvesInsideRejectsADanglingLinkWithoutOutput(StdOut out, StdErr err) throws IOException {
        var boundary = boundary();
        var credential = credentialLike();
        var link = Files.createSymbolicLink(boundary.resolve(credential), tmp.resolve("outside/missing"));
        assertThrows(NoSuchFileException.class, () -> link.toRealPath(), "Fixture: the link cannot be resolved");
        var input = credential + "/x.txt";
        var mark = Mark.of(out, err);

        assertFalse(FileRoot.resolvesInside(boundary, credential), "A dangling link");
        assertFalse(FileRoot.resolvesInside(boundary, input), "A new file under a dangling link");

        mark.assertNothingWrittenAndNothingLeaked(link.toString(), input, credential);
    }

    // V1: a link loop is rejected without any output
    @Test
    @StdIo
    @DisabledOnOs(OS.WINDOWS)
    void resolvesInsideRejectsALinkLoopWithoutOutput(StdOut out, StdErr err) throws IOException {
        var boundary = boundary();
        var credential = credentialLike();
        var first = boundary.resolve(credential + "-1");
        var second = boundary.resolve(credential + "-2");
        Files.createSymbolicLink(first, second);
        Files.createSymbolicLink(second, first);
        assertThrows(FileSystemException.class, () -> first.toRealPath(), "Fixture: the loop cannot be resolved");
        var input = first.getFileName() + "/x.txt";
        var mark = Mark.of(out, err);

        assertFalse(FileRoot.resolvesInside(boundary, input), "A path through a link loop");

        mark.assertNothingWrittenAndNothingLeaked(first.toString(), input, credential);
    }

    // V1: a path that cannot be parsed fails the own-path check without any output
    @Test
    @StdIo
    void atOwnPathRejectsAnUnparsablePathWithoutOutput(StdOut out, StdErr err) throws IOException {
        var root = layOutProjects(tmp.resolve("own")).toRealPath();
        var credential = credentialLike();
        var relative = "P1/" + credential + "\u0000.txt";
        assertThrows(InvalidPathException.class, () -> root.resolve(relative), "Fixture: the path cannot be parsed");
        var mark = Mark.of(out, err);

        assertFalse(FileRoot.atOwnPath(root, relative), "A path holding a NUL byte");

        mark.assertNothingWrittenAndNothingLeaked(relative, credential);
    }

    // V1: a configured root that cannot be resolved keeps its lexical location without any output
    @Test
    @StdIo
    @DisabledOnOs(OS.WINDOWS)
    void localRootKeepsTheLexicalLocationOfADanglingRootWithoutOutput(StdOut out, StdErr err) throws IOException {
        var credential = credentialLike();
        var dangling = Files.createSymbolicLink(tmp.resolve(credential), tmp.resolve("outside/missing"));
        assertThrows(NoSuchFileException.class, () -> dangling.toRealPath(), "Fixture: the root cannot be resolved");
        var repository = secured(fileRepository(dangling));
        var root = repoMount(repository);
        var mark = Mark.of(out, err);

        assertEquals(Optional.of(dangling.toAbsolutePath().normalize()), FileRoot.localRoot(repository),
                "An unresolvable root keeps its lexical location");
        assertFalse(root.contains("P1/x.txt"), "A path under a dangling root");

        mark.assertNothingWrittenAndNothingLeaked(dangling.toString(), credential);
    }

    // V1: a project path that cannot be parsed makes the mount reject every path without any output
    @Test
    @StdIo
    void projectMountFailsClosedOnAnUnparsableProjectPathWithoutOutput(StdOut out, StdErr err) throws IOException {
        var design = layOutProjects(tmp.resolve("design-flat"));
        var credential = credentialLike();
        var realPath = "P1/" + credential + "\u0000";
        var project = stubbedClosedProject(secured(fileRepository(design)), realPath);
        var root = projectMount(project);
        var mark = Mark.of(out, err);

        assertFalse(root.contains("rules.xml"), "An unparsable project path must reject every path");
        assertFalse(root.contains(""), "An unparsable project path must reject the project folder too");

        mark.assertNothingWrittenAndNothingLeaked(realPath, credential);
        // The failure is remembered: the boundary is not resolved again.
        verify(project, times(1)).getRealPath();
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

    // V1: the mounts over a repository built from its settings, which the application wraps in PathCheckedRepository
    /**
     * A mount over a file design repository built from its settings: a closed project {@code P1} in the flat
     * {@code design-configured-flat} or in the mapped {@code design-configured-mapped}, whose projects sit in
     * {@code catalog}, or a repository mount over {@code design-configured-repo}.
     */
    private Mount configuredMount(ConfiguredKind kind) throws IOException {
        return switch (kind) {
            case CLOSED_FLAT -> {
                var design = layOutProjects(tmp.resolve("design-configured-flat"));
                var secured = secured(configuredFileRepository(design));
                var project = closedProject(secured, "P1");
                yield new Mount(projectMount(project), design.resolve("P1"), design.resolve("P2"), "");
            }
            case CLOSED_MAPPED -> {
                var design = tmp.resolve("design-configured-mapped");
                layOutProjects(design.resolve("catalog"));
                var secured = secured(mapped(configuredFileRepository(design)));
                assertInstanceOf(SecureMappedRepository.class, secured, "Fixture: the mapped secured wrapper");
                var project = closedProject(secured, mappedName(secured, "P1"));
                yield new Mount(projectMount(project), design.resolve("catalog/P1"), design.resolve("catalog/P2"), "");
            }
            case REPO -> {
                var design = layOutProjects(tmp.resolve("design-configured-repo"));
                var root = repoMount(secured(configuredFileRepository(design)));
                yield new Mount(root, design.resolve("P1"), design.resolve("P2"), "P1/");
            }
        };
    }

    // V1: the application instantiates its design repositories from their settings, path-checked
    /**
     * A {@code repo-file} design repository over the folder, built from its settings the way the application
     * builds it, and therefore behind {@link PathCheckedRepository}. It is closed after the test.
     */
    private Repository configuredFileRepository(Path root) {
        var settings = Map.of("repository.design.factory", "repo-file", "repository.design.uri", root.toString());
        var configured = RepositoryInstatiator.newRepository("repository.design", settings::get);
        closeables.add(() -> IOUtils.closeQuietly(configured));
        return configured;
    }

    // V1: the secured, configured file repository a repository-mount route receives, mounted by RepoFileRootFactory
    /**
     * A repository mount over a {@code repo-file} design repository built from its settings in the folder, behind
     * the secured wrapper a repository-mount route receives, and mounted by {@link RepoFileRootFactory}.
     */
    private RepoFileRoot factoryMount(FactoryKind kind, Path design) throws IOException {
        var secured = switch (kind) {
            case MAPPED -> {
                var mapper = assertInstanceOf(SecureMappedRepository.class,
                        secured(mapped(configuredFileRepository(design))), "Fixture: the mapped secured wrapper");
                assertInstanceOf(PathCheckedRepository.class, mapper.getDelegate(),
                        "Fixture: the factory mounts the path-checked repository behind the mapping");
                yield mapper;
            }
            case FLAT -> assertInstanceOf(SecureBranchRepository.class, secured(configuredFileRepository(design)),
                    "Fixture: the flat secured wrapper");
        };
        return factoryMount(secured);
    }

    // V1: RepoFileRootFactory stamps the authenticated user as the author, so one is authenticated while it runs
    /**
     * Mounts the repository on its default branch through {@link RepoFileRootFactory#of(Repository, String)}, as
     * the repository-mount routes do, so the mount holds the repository inside {@code AuthoringRepository}.
     */
    private RepoFileRoot factoryMount(Repository repository) {
        var user = user();
        var lockEngine = lockEngine();
        var userWorkspace = mock(UserWorkspace.class);
        when(userWorkspace.getUser()).thenReturn(user);
        when(userWorkspace.getDesignTimeRepository()).thenReturn(mock(DesignTimeRepository.class));
        when(userWorkspace.getProjectsLockEngine()).thenReturn(lockEngine);
        var factory = new RepoFileRootFactory(mock(AclProjectsHelper.class), mock(UserManagementService.class),
                mock(ProjectFileLookupService.class)) {
            @Override
            public UserWorkspace getUserWorkspace() {
                return userWorkspace;
            }
        };
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new TestingAuthenticationToken(userName, null));
        SecurityContextHolder.setContext(context);
        try {
            return assertInstanceOf(RepoFileRoot.class, factory.of(repository, null), "Fixture: a repository mount");
        } finally {
            SecurityContextHolder.clearContext();
        }
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
                        ? true
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

    // V1: the verdicts of a check that reuses real locations, held to the full check in every order
    /**
     * Asserts that the reusing check answers every input as the full check does: each input on a map of its
     * own, parents before children twice on one map, and children before parents on another map.
     */
    private static void assertSameVerdicts(String what, List<String> inputs, Predicate<String> full,
            BiPredicate<String, Map<Path, Path>> reusing) {
        var expected = inputs.stream().map(full::test).toList();
        for (var i = 0; i < inputs.size(); i++) {
            assertEquals(expected.get(i), reusing.test(inputs.get(i), new HashMap<>()),
                    what + ", alone: " + inputs.get(i));
        }
        var parentsFirst = new HashMap<Path, Path>();
        for (var round = 1; round <= 2; round++) {
            for (var i = 0; i < inputs.size(); i++) {
                assertEquals(expected.get(i), reusing.test(inputs.get(i), parentsFirst),
                        what + ", parents first, round " + round + ": " + inputs.get(i));
            }
        }
        var childrenFirst = new HashMap<Path, Path>();
        for (var i = inputs.size() - 1; i >= 0; i--) {
            assertEquals(expected.get(i), reusing.test(inputs.get(i), childrenFirst),
                    what + ", children first: " + inputs.get(i));
        }
    }

    // V1: counts the rejections of each check racing with a save
    private static void tally(Map<String, Integer> rejected, String check, boolean contained) {
        if (!contained) {
            rejected.merge(check, 1, Integer::sum);
        }
    }

    // V1: a path on a mocked file system provider, so a test decides what each probe of a walk finds
    private static Path pathOn(FileSystemProvider provider) {
        var fileSystem = mock(FileSystem.class);
        when(fileSystem.provider()).thenReturn(provider);
        var path = mock(Path.class);
        when(path.getFileSystem()).thenReturn(fileSystem);
        return path;
    }

    // V1: the attributes a probe without following a link reads for an entry
    private static BasicFileAttributes attributes(boolean link, boolean directory) {
        var attributes = mock(BasicFileAttributes.class);
        when(attributes.isSymbolicLink()).thenReturn(link);
        when(attributes.isDirectory()).thenReturn(directory);
        return attributes;
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

    // V1: a credential-shaped value generated per test, carried by the inputs the containment checks reject
    private static String credentialLike() {
        return "token_" + RandomStringUtils.secure().nextAlphanumeric(40);
    }

    private static void write(Path file, String content) throws IOException {
        var parent = file.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }
}

package org.openl.studio.projects.service.files;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import org.openl.rules.lock.LockInfo;
import org.openl.rules.project.abstraction.AProject;
import org.openl.rules.project.abstraction.AProjectArtefact;
import org.openl.rules.project.abstraction.LockEngine;
import org.openl.rules.project.abstraction.RulesProject;
import org.openl.rules.project.impl.local.LocalRepository;
import org.openl.rules.project.impl.local.MetainfoRegistry;
import org.openl.rules.project.impl.local.ProjectMetainfo;
import org.openl.rules.repository.PathCheckedRepository;
import org.openl.rules.repository.RepositoryInstatiator;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.rest.acl.service.AclProjectsHelper;
import org.openl.rules.webstudio.service.UserManagementService;
import org.openl.rules.workspace.WorkspaceUser;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.rules.workspace.dtr.impl.MappedRepository;
import org.openl.rules.workspace.uw.UserWorkspace;
import org.openl.security.acl.repository.RepositoryAclService;
import org.openl.security.acl.repository.RepositoryAclServiceProvider;
import org.openl.security.acl.repository.SecureMappedRepository;
import org.openl.security.acl.repository.SecureRepository;
import org.openl.security.acl.repository.SecuredRepositoryFactory;
import org.openl.security.acl.repository.SimpleRepositoryAclService;
import org.openl.studio.common.exception.BadRequestException;
import org.openl.studio.common.exception.ForbiddenException;
import org.openl.studio.common.exception.NotFoundException;
import org.openl.studio.common.exception.RestRuntimeException;
import org.openl.studio.common.validation.BeanValidationProvider;
import org.openl.studio.projects.model.files.FileNode;
import org.openl.studio.projects.model.files.FolderNode;
import org.openl.studio.projects.model.files.FsNode;
import org.openl.studio.projects.service.files.ProjectFilesService.UploadedFile;
import org.openl.studio.projects.validator.ProjectStateValidator;

class ProjectFilesServiceTest {

    private static UploadedFile file(String name, String content) {
        return new UploadedFile(name, content.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void filesHoldingEqualBytesAreEqual() {
        var one = file("Main.xlsx", "content");
        var other = file("Main.xlsx", "content");

        assertEquals(one, other);
        assertEquals(one.hashCode(), other.hashCode());
    }

    @Test
    void filesDifferingInNameOrBytesAreNotEqual() {
        var file = file("Main.xlsx", "content");

        assertNotEquals(file, file("Other.xlsx", "content"));
        assertNotEquals(file, file("Main.xlsx", "other"));
        assertNotEquals(file, new Object());
    }

    @Test
    void toStringReportsTheSizeInsteadOfTheBytes() {
        assertEquals("UploadedFile[name=Main.xlsx, content=7 bytes]", file("Main.xlsx", "content").toString());
        assertEquals("UploadedFile[name=Main.xlsx, content=0 bytes]", new UploadedFile("Main.xlsx", null).toString());
    }

    // V1: a folder copy or move checks every entry it would read or write before it reads or writes any.
    // ---------------------------------------------------------------------------------------------
    // Folder copy and move on an opened project, with real folders and links in its working copy
    // ---------------------------------------------------------------------------------------------

    private static final String INVALID_PATH = "openl.error.400.file.path.invalid.message";

    /**
     * The two operations that replicate a folder with all of its descendants, each with its own target.
     */
    enum Transfer {
        COPY("copied"),
        MOVE("moved");

        private final String target;

        Transfer(String target) {
            this.target = target;
        }

        void apply(OpenedProject fixture, String sourcePath, String destinationPath) {
            switch (this) {
                case COPY -> fixture.service().copyResource(fixture.root(), sourcePath, destinationPath);
                case MOVE -> fixture.service().moveResource(fixture.root(), sourcePath, destinationPath);
            }
        }
    }

    /**
     * The real files service over the opened project {@code P1}, served from the spied working copy.
     */
    private record OpenedProject(ProjectFilesServiceImpl service, ProjectFileRoot root, LocalRepository workingCopy) {
    }

    private final String userName = RandomStringUtils.secure().nextAlphanumeric(24);

    @TempDir
    Path tmp;

    @ParameterizedTest
    @EnumSource(Transfer.class)
    @DisabledOnOs(OS.WINDOWS)
    void folderHoldingALinkToAnOutsideFileIsRejectedBeforeAnythingIsReadOrWritten(Transfer transfer)
            throws IOException {
        var secret = marker();
        var outsideFile = write(tmp.resolve("outside/secret.txt"), secret);
        var own = marker();
        write(project().resolve("safe/ok.txt"), own);
        Files.createSymbolicLink(project().resolve("safe/leak.txt"), outsideFile);
        var fixture = open();

        var rejected = assertThrows(BadRequestException.class, () -> transfer.apply(fixture, "safe", transfer.target));

        assertEquals(INVALID_PATH, rejected.getErrorCode(),
                "A descendant linked outside the project rejects the whole " + transfer + " as an invalid path");
        assertFalse(Files.exists(project().resolve(transfer.target), LinkOption.NOFOLLOW_LINKS),
                "No partial " + transfer + " is left: the destination folder is never created");
        assertTrue(Files.isSymbolicLink(project().resolve("safe/leak.txt")),
                "The rejected " + transfer + " leaves the source link in place");
        assertEquals(own, Files.readString(project().resolve("safe/ok.txt")),
                "The rejected " + transfer + " leaves the regular source file in place");
        assertEquals(secret, Files.readString(outsideFile), "The outside file is not modified by the " + transfer);
        assertEquals(List.of(), regularFilesHolding(workspace(), secret),
                "No file of the working copy holds the outside content after the " + transfer);
        verify(fixture.workingCopy(), never().description("No source content is opened before the check rejects the "
                + transfer + ", so the outside file is never read")).read(anyString());
        verify(fixture.workingCopy(), never().description("Nothing is written by the rejected " + transfer))
                .save(any(FileData.class), any(InputStream.class));
    }

    @ParameterizedTest
    @EnumSource(Transfer.class)
    @DisabledOnOs(OS.WINDOWS)
    void folderHoldingALinkToAnOutsideFileDeepInItsTreeIsRejected(Transfer transfer) throws IOException {
        var secret = marker();
        var outsideFile = write(tmp.resolve("outside/secret.txt"), secret);
        write(project().resolve("safe/ok.txt"), marker());
        write(project().resolve("safe/deeper/ok.txt"), marker());
        Files.createSymbolicLink(project().resolve("safe/deeper/leak.txt"), outsideFile);
        var fixture = open();

        var rejected = assertThrows(BadRequestException.class, () -> transfer.apply(fixture, "safe", transfer.target));

        assertEquals(INVALID_PATH, rejected.getErrorCode(),
                "A link two levels down the folder rejects the whole " + transfer + " as an invalid path");
        assertFalse(Files.exists(project().resolve(transfer.target), LinkOption.NOFOLLOW_LINKS),
                "No partial " + transfer + " is left: the destination folder is never created");
        assertTrue(Files.isSymbolicLink(project().resolve("safe/deeper/leak.txt")),
                "The rejected " + transfer + " leaves the nested source link in place");
        assertEquals(List.of(), regularFilesHolding(workspace(), secret),
                "No file of the working copy holds the outside content after the " + transfer);
        verify(fixture.workingCopy(), never().description("Nothing is written by the rejected " + transfer))
                .save(any(FileData.class), any(InputStream.class));
    }

    @ParameterizedTest
    @EnumSource(Transfer.class)
    @DisabledOnOs(OS.WINDOWS)
    void folderIsRejectedOntoADestinationWhoseExistingChildLinksToAnOutsideFolder(Transfer transfer)
            throws IOException {
        var outsideDir = Files.createDirectories(tmp.resolve("outside/dir"));
        var created = marker();
        write(project().resolve("src/sub/new.txt"), created);
        var kept = marker();
        write(project().resolve("dest/keep.txt"), kept);
        Files.createSymbolicLink(project().resolve("dest/sub"), outsideDir);
        var fixture = open();

        var rejected = assertThrows(BadRequestException.class, () -> transfer.apply(fixture, "src", "dest"));

        assertEquals(INVALID_PATH, rejected.getErrorCode(), "A derived destination under a link leaving the project"
                + " rejects the " + transfer + " as an invalid path");
        try (var entries = Files.list(outsideDir)) {
            assertEquals(List.of(), entries.toList(),
                    "The " + transfer + " writes nothing into the outside folder through the destination link");
        }
        assertEquals(created, Files.readString(project().resolve("src/sub/new.txt")),
                "The rejected " + transfer + " leaves the source folder intact");
        assertEquals(kept, Files.readString(project().resolve("dest/keep.txt")),
                "The rejected " + transfer + " leaves the existing destination folder intact");
        verify(fixture.workingCopy(), never().description("Nothing is written by the rejected " + transfer))
                .save(any(FileData.class), any(InputStream.class));
    }

    @ParameterizedTest
    @EnumSource(Transfer.class)
    void ordinaryFolderIsCopiedOrMovedWithItsWholeTree(Transfer transfer) throws IOException {
        var top = marker();
        write(project().resolve("plain/a.txt"), top);
        var nested = marker();
        write(project().resolve("plain/deep/b.txt"), nested);
        var fixture = open();

        transfer.apply(fixture, "plain", transfer.target);

        var target = project().resolve(transfer.target);
        assertEquals(top, Files.readString(target.resolve("a.txt")),
                "The " + transfer + " of a folder without links writes its top-level file to the destination");
        assertEquals(nested, Files.readString(target.resolve("deep/b.txt")),
                "The " + transfer + " of a folder without links writes its nested file to the destination");
        assertEquals(transfer == Transfer.COPY, Files.exists(project().resolve("plain/a.txt")),
                "A copy keeps the source folder and a move removes it");
    }

    @ParameterizedTest
    @EnumSource(Transfer.class)
    @DisabledOnOs(OS.WINDOWS)
    void folderHoldingALinkThatStaysInsideTheProjectIsStillCopiedOrMoved(Transfer transfer) throws IOException {
        var shared = marker();
        var sharedFile = write(project().resolve("shared.txt"), shared);
        var own = marker();
        write(project().resolve("linked/own.txt"), own);
        Files.createSymbolicLink(project().resolve("linked/alias.txt"), sharedFile);
        var fixture = open();

        transfer.apply(fixture, "linked", transfer.target);

        var target = project().resolve(transfer.target);
        assertEquals(own, Files.readString(target.resolve("own.txt")),
                "The " + transfer + " writes the regular file of the folder to the destination");
        assertEquals(shared, Files.readString(target.resolve("alias.txt")),
                "A link that stays inside the project is accepted, and the " + transfer + " writes its content");
        assertEquals(shared, Files.readString(sharedFile),
                "The file inside the project that the link points to is left in place by the " + transfer);
        assertEquals(transfer == Transfer.COPY, Files.isSymbolicLink(project().resolve("linked/alias.txt")),
                "A copy keeps the source link and a move removes it");
    }

    @ParameterizedTest
    @EnumSource(Transfer.class)
    void folderToADestinationEndingInASlashKeepsItsPlacementInTheFolderAboveItsLastName(Transfer transfer)
            throws IOException {
        var top = marker();
        write(project().resolve("plain/a.txt"), top);
        var nested = marker();
        write(project().resolve("plain/deep/b.txt"), nested);
        var other = marker();
        write(project().resolve("other/c.txt"), other);
        var fixture = open();

        transfer.apply(fixture, "plain", "dest/");
        transfer.apply(fixture, "other", "nest/inner/");

        assertEquals(top, Files.readString(project().resolve("a.txt")),
                "The " + transfer + " to 'dest/' still places the top-level file in the project folder");
        assertEquals(nested, Files.readString(project().resolve("deep/b.txt")),
                "The " + transfer + " to 'dest/' still places the nested file under the project folder");
        assertFalse(Files.exists(project().resolve("dest"), LinkOption.NOFOLLOW_LINKS),
                "The " + transfer + " to 'dest/' still creates no folder of that name");
        assertEquals(other, Files.readString(project().resolve("nest/c.txt")),
                "The " + transfer + " to 'nest/inner/' still places the file in the folder above 'inner'");
        assertEquals(transfer == Transfer.COPY, Files.exists(project().resolve("plain/a.txt")),
                "A copy keeps the source folder and a move removes it");
    }

    @ParameterizedTest
    @EnumSource(Transfer.class)
    @DisabledOnOs(OS.WINDOWS)
    void folderToADestinationEndingInASlashIsCheckedWhereItsDescendantsLand(Transfer transfer) throws IOException {
        var outsideDir = Files.createDirectories(tmp.resolve("outside/dir"));
        var created = marker();
        write(project().resolve("src/sub/new.txt"), created);
        write(project().resolve("a/keep.txt"), marker());
        Files.createSymbolicLink(project().resolve("a/sub"), outsideDir);
        var fixture = open();

        var rejected = assertThrows(BadRequestException.class, () -> transfer.apply(fixture, "src", "a/b/"));

        assertEquals(INVALID_PATH, rejected.getErrorCode(), "The " + transfer + " to 'a/b/' fills 'a', whose child"
                + " 'sub' links outside the project, so it is rejected as an invalid path");
        try (var entries = Files.list(outsideDir)) {
            assertEquals(List.of(), entries.toList(),
                    "The " + transfer + " writes nothing into the outside folder through 'a/sub'");
        }
        assertEquals(created, Files.readString(project().resolve("src/sub/new.txt")),
                "The rejected " + transfer + " leaves the source folder intact");
        verify(fixture.workingCopy(), never().description("Nothing is written by the rejected " + transfer))
                .save(any(FileData.class), any(InputStream.class));
    }


    /**
     * Opens the project {@code P1} laid out under {@link #project()}: the working copy {@code ws} records
     * it as opened, and the secured flat design repository {@code design} holds its committed state.
     * The working copy is spied, so a test can prove which of its files were read or written.
     */
    private OpenedProject open() throws IOException {
        write(project().resolve("rules.xml"), descriptor());
        write(tmp.resolve("design/P1/rules.xml"), descriptor());
        // Loading the registry deletes every project folder of the working copy that has no record.
        MetainfoRegistry.store(workspace(), "P1",
                new ProjectMetainfo("design", null, null, null, null, null, null, null, Map.of()));
        var workingCopy = spy(new LocalRepository(workspace(), MetainfoRegistry.open(workspace())));
        var design = SecuredRepositoryFactory.wrapToSecureRepo(fileRepository(tmp.resolve("design")),
                grantAllRepoAcl());
        var project = new RulesProject(user(), workingCopy, workingCopy.check("P1"), design, design.check("P1"),
                lockEngine());
        assertTrue(project.isOpened(), "Fixture: the project is served from the working copy");

        var acl = grantAllProjectAcl();
        var stateValidator = mock(ProjectStateValidator.class);
        when(stateValidator.canModify(project)).thenReturn(true);
        var root = new ProjectFileRoot(project, acl, stateValidator, mock(ProjectFileLookupService.class),
                () -> new UserInfo(userName), mock(DesignTimeRepository.class));
        var service = new ProjectFilesServiceImpl(acl, mock(FileNodeMapper.class), mock(FileSearchSupport.class),
                mock(FileArchiveSupport.class), mock(ProjectDescriptorCleaner.class),
                new BeanValidationProvider(List.of()));
        clearInvocations(workingCopy);
        return new OpenedProject(service, root, workingCopy);
    }

    private Path workspace() {
        return tmp.resolve("ws");
    }

    private Path project() {
        return workspace().resolve("P1");
    }

    /**
     * Grants every project permission, so the service's ACL checks pass for any artefact.
     */
    private static AclProjectsHelper grantAllProjectAcl() {
        return mock(AclProjectsHelper.class,
                invocation -> invocation.getMethod().getReturnType() == boolean.class
                        ? Boolean.TRUE
                        : Mockito.RETURNS_DEFAULTS.answer(invocation));
    }

    /**
     * Grants every repository permission, so the secured wrapper behaves as for a user who may do anything.
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

    /**
     * The regular files under the folder, links excluded, whose bytes equal the content.
     */
    private static List<Path> regularFilesHolding(Path folder, String content) throws IOException {
        var expected = content.getBytes(StandardCharsets.UTF_8);
        try (var paths = Files.walk(folder)) {
            return paths.filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
                    .filter(path -> Arrays.equals(expected, readAllBytes(path)))
                    .toList();
        }
    }

    private static byte[] readAllBytes(Path file) {
        try {
            return Files.readAllBytes(file);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String descriptor() {
        return "<project><name>P1</name></project>";
    }

    private static String marker() {
        return RandomStringUtils.secure().nextAlphanumeric(24);
    }

    private static Path write(Path file, String content) throws IOException {
        var parent = file.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        return Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    // V1: surface B, the new-file surface of the files API: the destination matrix B1-B19 of the service.
    // ---------------------------------------------------------------------------------------------
    // The surface B matrix on the four mounts the REST routes build, each behind its secured wrapper
    // ---------------------------------------------------------------------------------------------

    // V1: the existing keys the matrix asserts besides the invalid path.
    private static final String NOT_FOUND = "openl.error.404.file.not.found.message";
    private static final String FORBIDDEN = "openl.error.403.default.message";
    private static final String BASE_PATH_NOT_FOLDER = "openl.error.400.file.base-path.not-folder.message";

    /**
     * The regular file of {@code P1} the matrix copies, moves, reads and denies, relative to {@code P1}.
     */
    private static final String SOURCE = "sub/inside.txt";

    // V1: the mounts of the matrix, each reached through the secured wrapper its REST route receives.
    /**
     * The four mounts the files service serves, as the REST routes build them.
     */
    enum MountKind {
        /** An opened project, served from the user's working copy. */
        OPENED,
        /** A closed project in a flat file design repository behind {@code SecureRepository}. */
        CLOSED_FLAT,
        /** A closed project in a mapped file design repository behind {@code SecureMappedRepository}. */
        CLOSED_MAPPED,
        /**
         * A repository mount that {@link RepoFileRootFactory#of(Repository, String)} builds, as the
         * {@code /rest/repos/{repo}/files} routes do, over a mapped {@code repo-file} repository built from its
         * settings and reached through {@code SecureMappedRepository}.
         */
        REPO
    }

    // V1: a matrix mount with the folders of its project P1, of the sibling project P2 and of the store holding them.
    /**
     * A mount of the matrix.
     *
     * @param root    the mount under test
     * @param project the physical folder of {@code P1}
     * @param sibling the physical folder of the sibling project {@code P2}
     * @param store   the physical root of the working copy or repository holding both projects
     * @param prefix  what turns a {@code P1}-relative path into a mount-relative one
     * @param acl     the project ACL that the mount and its service check
     */
    private record Mount(FileRoot root, Path project, Path sibling, Path store, String prefix, AclProjectsHelper acl) {

        String path(String projectRelative) {
            return prefix + projectRelative;
        }
    }

    // V1: what a payload may not change, recorded before it is sent.
    /**
     * The entries of the outside folder, of the sibling project and of the whole temporary tree.
     */
    private record Snapshot(Map<String, String> outside, Map<String, String> sibling, Map<String, String> tree) {
    }

    // V1: one payload of a matrix row, named by its operation and path.
    private record Payload(String description, Executable call) {
    }

    // V1: the operations a lexical payload is sent through, each taking it as the path it acts on.
    /**
     * The operations of the files service that take a path to create, write, read or delete.
     */
    enum PathOperation {
        CREATE,
        CREATE_FOLDER,
        COPY_TO,
        MOVE_TO,
        DELETE,
        READ,
        UPDATE,
        UPLOAD;

        void apply(ProjectFilesServiceImpl service, Mount mount, String payload) {
            var root = mount.root();
            switch (this) {
                case CREATE -> service.createResource(root, payload, stream(marker()), true);
                case CREATE_FOLDER -> service.createFolder(root, payload, true);
                case COPY_TO -> service.copyResource(root, mount.path(SOURCE), payload);
                case MOVE_TO -> service.moveResource(root, mount.path(SOURCE), payload);
                case DELETE -> service.deleteResource(root, payload);
                case READ -> service.getResource(root, payload, null);
                case UPDATE -> service.updateResource(root, payload, stream(marker()));
                case UPLOAD -> service.uploadFiles(root, "", List.of(file(payload, marker())), ConflictPolicy.FAIL);
            }
        }
    }

    // V1: the sentinel of the outside file; only a hash of it reaches a snapshot, never a message.
    private final String outsideSecret = marker();
    // V1: the repositories the matrix mounts open, closed after each test.
    private final List<Closeable> matrixCloseables = new ArrayList<>();

    // V1: the mapped repositories of the matrix are closed after the test.
    @AfterEach
    void closeMatrixRepositories() throws IOException {
        for (var closeable : matrixCloseables) {
            closeable.close();
        }
    }

    // V1: surface B payload B1 (parent segments)
    @ParameterizedTest
    @EnumSource(PathOperation.class)
    void b01ParentSegmentsAreRejected(PathOperation operation) throws IOException {
        assertLexicallyRejected("B1", operation, "rules/../../x.xlsx");
    }

    // V1: surface B payload B2 (current-folder segments)
    @ParameterizedTest
    @EnumSource(PathOperation.class)
    void b02CurrentFolderSegmentsAreRejected(PathOperation operation) throws IOException {
        assertLexicallyRejected("B2", operation, "./x.xlsx", "rules/./x.xlsx");
    }

    // V1: surface B payload B3 (absolute POSIX multipart name): stored inside P1 or rejected, never outside
    @Test
    void b03AbsoluteMultipartNameStaysInsideTheProject() throws IOException {
        var mount = openedMount();
        var content = marker();
        var before = snapshot(mount);

        try {
            service(mount.acl()).uploadFiles(mount.root(), "", List.of(file("/etc/passwd.txt", content)),
                    ConflictPolicy.FAIL);
            assertEquals(content, Files.readString(mount.project().resolve("etc/passwd.txt")),
                    "B3 multipart name /etc/passwd.txt is stored inside P1 as etc/passwd.txt");
        } catch (BadRequestException rejected) {
            assertEquals(INVALID_PATH, rejected.getErrorCode(), "B3 multipart name /etc/passwd.txt is rejected");
            assertEquals(before.tree(), snapshot(mount).tree(), "B3: the rejected upload writes nothing");
        }
        assertOutsideAndSiblingUnchanged("B3 multipart name /etc/passwd.txt", mount, before);
    }

    // V1: surface B payload B4 (absolute Windows paths)
    @ParameterizedTest
    @EnumSource(PathOperation.class)
    void b04AbsoluteWindowsPathsAreRejected(PathOperation operation) throws IOException {
        assertLexicallyRejected("B4", operation, "C:\\Windows\\win.ini", "C:x.xlsx");
    }

    // V1: surface B payload B5 (backslash separators), also after uploadFiles turns them into slashes
    @ParameterizedTest
    @EnumSource(PathOperation.class)
    void b05BackslashSeparatorsAreRejected(PathOperation operation) throws IOException {
        assertLexicallyRejected("B5", operation, "rules\\..\\..\\x.xlsx");
    }

    // V1: surface B payload B6 (double slash)
    @ParameterizedTest
    @EnumSource(PathOperation.class)
    void b06DoubleSlashIsRejected(PathOperation operation) throws IOException {
        assertLexicallyRejected("B6", operation, "a//b.xlsx");
    }

    // V1: surface B payload B7 (percent-encoded separator)
    @ParameterizedTest
    @EnumSource(PathOperation.class)
    void b07PercentEncodedSeparatorIsRejected(PathOperation operation) throws IOException {
        assertLexicallyRejected("B7", operation, "..%2Fx.xlsx");
    }

    // V1: surface B payload B8 (double-encoded traversal, as the decoded literal segment)
    @ParameterizedTest
    @EnumSource(PathOperation.class)
    void b08DoubleEncodedTraversalIsRejected(PathOperation operation) throws IOException {
        assertLexicallyRejected("B8", operation, "%2e%2e%2fx.xlsx");
    }

    // V1: surface B payload B9 (NUL byte). The path parser's unchecked InvalidPathException is kept, which the API
    // answers with 400 openl.error.400.default.message, so the existing rejection keeps its status and key.
    @ParameterizedTest
    @EnumSource(PathOperation.class)
    void b09NulByteKeepsItsExistingRejectionAndWritesNothing(PathOperation operation) throws IOException {
        var mount = openedMount();
        var service = service(mount.acl());
        var before = snapshot(mount);

        assertThrows(InvalidPathException.class, () -> operation.apply(service, mount, "x\u0000.xlsx"),
                "B9 x\\u0000.xlsx through " + operation + " keeps its existing rejection");

        assertNothingWritten("B9 x\\u0000.xlsx through " + operation, mount, before);
    }

    // V1: surface B payload B10 (control characters)
    @ParameterizedTest
    @EnumSource(PathOperation.class)
    void b10ControlCharactersAreRejected(PathOperation operation) throws IOException {
        assertLexicallyRejected("B10", operation, "x\u0007.xlsx", "x\n.xlsx");
    }

    // V1: surface B payload B11 (Windows reserved names): the exact upper-case name is rejected, as today
    @ParameterizedTest
    @EnumSource(PathOperation.class)
    void b11ReservedNameIsRejected(PathOperation operation) throws IOException {
        assertLexicallyRejected("B11", operation, "CON");
    }

    // V1: surface B payload B11 (Windows reserved names): recorded as-is, with no loosening and no tightening
    @Test
    void b11SuffixedAndLowerCaseReservedNamesAreStoredInsideTheProject() throws IOException {
        var mount = openedMount();
        var service = service(mount.acl());
        var before = snapshot(mount);
        var nul = marker();
        var aux = marker();

        service.createResource(mount.root(), "NUL.txt", stream(nul), true);
        service.uploadFiles(mount.root(), "", List.of(file("aux/x.txt", aux)), ConflictPolicy.FAIL);

        assertEquals(nul, Files.readString(mount.project().resolve("NUL.txt")), "B11 NUL.txt is stored inside P1");
        assertEquals(aux, Files.readString(mount.project().resolve("aux/x.txt")), "B11 aux/x.txt is stored inside P1");
        assertOutsideAndSiblingUnchanged("B11 NUL.txt and aux/x.txt", mount, before);
    }

    // V1: surface B payload B13 (zip-slip archive entry)
    @Test
    void b13ZipSlipEntryIsRejectedBeforeAnythingIsWritten() throws IOException {
        var mount = openedMount();
        var service = service(mount.acl());
        var archive = zip("../../evil.xlsx", marker());
        var before = snapshot(mount);

        assertPathRejected("B13 archive entry ../../evil.xlsx under slip",
                () -> service.uploadArchive(mount.root(), "slip", archive, true, ConflictPolicy.FAIL));

        assertNothingWritten("B13 archive entry ../../evil.xlsx under slip", mount, before);
    }

    // V1: surface B payload B14 (look-alike separators): a literal name directly inside P1, or rejected
    @ParameterizedTest
    @EnumSource(value = PathOperation.class, names = {"CREATE", "UPLOAD"})
    void b14LookAlikeSeparatorsStayLiteralNamesInsideTheProject(PathOperation operation) throws IOException {
        var mount = openedMount();
        var service = service(mount.acl());

        for (var payload : List.of("..\u2215x.txt", "\uFF0E\uFF0E\uFF0Fx.txt")) {
            var row = "B14 " + printable(payload) + " through " + operation;
            var before = snapshot(mount);
            try {
                operation.apply(service, mount, payload);
                var stored = mount.project().resolve(payload);
                assertEquals(mount.project(), stored.getParent(), row + " names a direct child of P1");
                assertTrue(Files.isRegularFile(stored, LinkOption.NOFOLLOW_LINKS),
                        row + " is stored as a regular file directly inside P1");
            } catch (BadRequestException rejected) {
                assertEquals(INVALID_PATH, rejected.getErrorCode(), row + " is rejected as an invalid path");
                assertEquals(before.tree(), snapshot(mount).tree(), row + ": the rejection writes nothing");
            }
            assertOutsideAndSiblingUnchanged(row, mount, before);
        }
    }

    // V1: surface B payload B15 (listing base path above the project): rejected with an existing key, or nothing
    // outside P1 is listed
    @ParameterizedTest
    @EnumSource(FileViewMode.class)
    void b15BasePathAboveTheProjectListsNothingOutsideIt(FileViewMode viewMode) throws IOException {
        var mount = openedMount();
        var service = service(mount.acl(), new FileNodeMapperImpl());
        var projectEntries = snapshotOf(mount.project()).keySet();

        for (var basePath : List.of("../..", "%2e%2e/%2e%2e")) {
            var row = "B15 base path " + basePath + " in the " + viewMode + " listing";
            var query = FileCriteriaQuery.builder().basePath(basePath).build();
            try {
                for (var listed : pathsOf(service.getResources(mount.root(), query, true, viewMode, null))) {
                    assertTrue(projectEntries.contains(listed), row + " lists only entries of P1: " + listed);
                }
            } catch (BadRequestException rejected) {
                assertTrue(List.of(BASE_PATH_NOT_FOLDER, INVALID_PATH).contains(rejected.getErrorCode()),
                        row + " is rejected with an existing key, not " + rejected.getErrorCode());
            }
        }
    }

    // V1: surface B payload B12 (directory link outside), on every mount (B18)
    @ParameterizedTest
    @EnumSource(MountKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void b12WritesThroughADirectoryLinkOutsideAreRejected(MountKind kind) throws IOException {
        var mount = mount(kind);
        var root = mount.root();
        var service = service(mount.acl(), new FileNodeMapperImpl());
        Files.createSymbolicLink(mount.project().resolve("link"), outsideDir());
        var source = mount.path(SOURCE);
        var underBase = zip("z.txt", marker());
        var atRoot = zip(mount.path("link/z.txt"), marker());

        var payloads = List.of(
                new Payload("uploadFiles link/x.txt", () -> service.uploadFiles(root, "",
                        List.of(file(mount.path("link/x.txt"), marker())), ConflictPolicy.FAIL)),
                new Payload("createResource link/y.txt",
                        () -> service.createResource(root, mount.path("link/y.txt"), stream(marker()), true)),
                new Payload("createFolder link/newdir",
                        () -> service.createFolder(root, mount.path("link/newdir"), true)),
                new Payload("copyResource to link/y.txt",
                        () -> service.copyResource(root, source, mount.path("link/y.txt"))),
                new Payload("moveResource to link/y.txt",
                        () -> service.moveResource(root, source, mount.path("link/y.txt"))),
                new Payload("uploadArchive under link", () -> service.uploadArchive(root, mount.path("link"), underBase,
                        true, ConflictPolicy.FAIL)),
                new Payload("uploadArchive entry link/z.txt",
                        () -> service.uploadArchive(root, "", atRoot, true, ConflictPolicy.FAIL)),
                new Payload("deleteResource link/keep.txt",
                        () -> service.deleteResource(root, mount.path("link/keep.txt"))));
        for (var payload : payloads) {
            var row = "B12 " + payload.description() + " on " + kind;
            var before = snapshot(mount);
            assertPathRejected(row, payload.call());
            assertNothingWritten(row, mount, before);
        }

        assertTrue(Files.isRegularFile(mount.project().resolve(SOURCE), LinkOption.NOFOLLOW_LINKS),
                "B12 on " + kind + ": the source of the rejected move is still in P1");
        assertTrue(Files.isSymbolicLink(mount.project().resolve("link")), "B12 on " + kind + ": the link is kept");
    }

    // V1: surface B payload B16 (file link outside), on every mount (B18)
    @ParameterizedTest
    @EnumSource(MountKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void b16AFileLinkOutsideIsNeitherListedNorSearchedNorRead(MountKind kind) throws IOException {
        var mount = mount(kind);
        var root = mount.root();
        var service = service(mount.acl(), new FileNodeMapperImpl());
        write(mount.project().resolve("docs/ok.txt"), marker());
        Files.createSymbolicLink(mount.project().resolve("docs/leak.txt"), outsideFile());
        var leak = mount.path("docs/leak.txt");
        var before = snapshot(mount);

        for (var viewMode : FileViewMode.values()) {
            var row = "B16 recursive " + viewMode + " listing on " + kind;
            var nodes = service.getResources(root, FileCriteriaQuery.builder().build(), true, viewMode, null);
            var listed = pathsOf(nodes);
            assertTrue(listed.contains(mount.path("docs/ok.txt")), row + " lists docs/ok.txt");
            assertFalse(listed.contains(leak), row + " omits docs/leak.txt");
            assertFalse(carries(nodes, outsideSecret), row + " returns nothing read through docs/leak.txt");
        }
        var found = service.search(root, FileSearchQuery.builder().content(outsideSecret).recursive(true).build());
        assertEquals(List.of(), pathsOf(found),
                "B16 content search on " + kind + " finds nothing behind docs/leak.txt");

        var export = new ByteArrayOutputStream();
        var payloads = List.of(
                new Payload("getResource docs/leak.txt", () -> service.getResource(root, leak, null)),
                new Payload("getNode docs/leak.txt", () -> service.getNode(root, leak, null)),
                new Payload("updateResource docs/leak.txt", () -> service.updateResource(root, leak, stream(marker()))),
                new Payload("copyResource from docs/leak.txt",
                        () -> service.copyResource(root, leak, mount.path("copied.txt"))),
                new Payload("moveResource from docs/leak.txt",
                        () -> service.moveResource(root, leak, mount.path("moved.txt"))),
                new Payload("writeFolderAsZip docs",
                        () -> service.writeFolderAsZip(root, mount.path("docs"), export, null)));
        for (var payload : payloads) {
            var row = "B16 " + payload.description() + " on " + kind;
            assertPathRejected(row, payload.call());
            assertNothingWritten(row, mount, before);
        }

        assertEquals(0, export.size(), "B16 on " + kind + ": the rejected export of docs streams nothing");
        assertTrue(Files.isSymbolicLink(mount.project().resolve("docs/leak.txt")),
                "B16 on " + kind + ": the link docs/leak.txt is kept");
    }

    // V1: surface B payload B17 (link into the sibling project), on every mount (B18)
    @ParameterizedTest
    @EnumSource(MountKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void b17ALinkIntoTheSiblingProjectNeitherReadsNorWritesIt(MountKind kind) throws IOException {
        var mount = mount(kind);
        var root = mount.root();
        var service = service(mount.acl(), new FileNodeMapperImpl());
        Files.createSymbolicLink(mount.project().resolve("link"), mount.sibling());
        var before = snapshot(mount);

        assertNotFoundOrRejected("B17 getResource link/rules.xml on " + kind,
                () -> service.getResource(root, mount.path("link/rules.xml"), null));
        assertPathRejected("B17 uploadFiles link/x.txt on " + kind, () -> service.uploadFiles(root, "",
                List.of(file(mount.path("link/x.txt"), marker())), ConflictPolicy.FAIL));

        assertNothingWritten("B17 link into P2 on " + kind, mount, before);
    }

    // V1: surface B payload B17 on the repository mount: it authorizes each repository path on its own, so a link at
    // the repository root and a link that stays inside the repository are refused as well
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void b17RepositoryMountRefusesLinksAtItsRootAndInsideIt() throws IOException {
        var mount = repoMount(mock(ProjectFileLookupService.class));
        var root = mount.root();
        var service = service(mount.acl(), new FileNodeMapperImpl());
        Files.createSymbolicLink(mount.store().resolve("rootlink"), outsideDir());
        Files.createSymbolicLink(mount.store().resolve("rootleak.txt"), outsideFile());
        Files.createSymbolicLink(mount.project().resolve("inner"), mount.project().resolve("sub"));
        Files.createSymbolicLink(mount.project().resolve("alias.txt"), mount.project().resolve(SOURCE));
        var before = snapshot(mount);

        assertPathRejected("B17 createResource rootlink/y.txt on REPO",
                () -> service.createResource(root, "rootlink/y.txt", stream(marker()), true));
        assertNotFoundOrRejected("B17 getResource rootlink/keep.txt on REPO",
                () -> service.getResource(root, "rootlink/keep.txt", null));
        assertPathRejected("B17 getResource rootleak.txt on REPO",
                () -> service.getResource(root, "rootleak.txt", null));
        assertPathRejected("B17 createResource P1/inner/new.txt on REPO",
                () -> service.createResource(root, "P1/inner/new.txt", stream(marker()), true));
        assertPathRejected("B17 getResource P1/alias.txt on REPO",
                () -> service.getResource(root, "P1/alias.txt", null));

        assertNothingWritten("B17 root and intra-repository links on REPO", mount, before);
    }

    // V1: surface B payload B17 on the project mounts: a link that stays inside the project keeps working
    @ParameterizedTest
    @EnumSource(value = MountKind.class, names = {"OPENED", "CLOSED_FLAT", "CLOSED_MAPPED"})
    @DisabledOnOs(OS.WINDOWS)
    void b17ProjectMountsKeepAcceptingLinksThatStayInsideTheProject(MountKind kind) throws Exception {
        var mount = mount(kind);
        var root = mount.root();
        var service = service(mount.acl(), new FileNodeMapperImpl());
        Files.createSymbolicLink(mount.project().resolve("inner"), mount.project().resolve("sub"));
        Files.createSymbolicLink(mount.project().resolve("alias.txt"), mount.project().resolve(SOURCE));
        var inside = Files.readString(mount.project().resolve(SOURCE));
        var created = marker();
        var before = snapshot(mount);

        try (var content = service.getResource(root, "alias.txt", null).getContent()) {
            assertEquals(inside, new String(content.readAllBytes(), StandardCharsets.UTF_8),
                    "B17 getResource alias.txt on " + kind + " reads the project file the link points to");
        }
        service.createResource(root, "inner/new.txt", stream(created), true);

        assertEquals(created, Files.readString(mount.project().resolve("sub/new.txt")),
                "B17 createResource inner/new.txt on " + kind + " writes into the project folder the link points to");
        assertOutsideAndSiblingUnchanged("B17 links inside P1 on " + kind, mount, before);
    }

    // V1: surface B payload B18 (ACL through the secured wrapper): a read without READ permission still gives 403
    @ParameterizedTest
    @EnumSource(MountKind.class)
    void b18ReadWithoutPermissionIsStillForbidden(MountKind kind) throws IOException {
        var mount = mount(kind);
        when(mount.acl().hasPermission(argThat((AProjectArtefact artefact) -> artefact != null
                && "inside.txt".equals(artefact.getName())), eq(BasePermission.READ))).thenReturn(false);
        var service = service(mount.acl(), new FileNodeMapperImpl());

        assertNotNull(service.getResource(mount.root(), mount.path("rules.xml"), null),
                "B18 on " + kind + ": a file the user may read is still served");
        var denied = assertThrows(ForbiddenException.class,
                () -> service.getResource(mount.root(), mount.path(SOURCE), null),
                "B18 on " + kind + ": reading sub/inside.txt without READ permission is forbidden");
        assertEquals(FORBIDDEN, denied.getErrorCode(), "B18 on " + kind + ": the read keeps its 403");
    }

    // V1: surface B payload B18 (ACL through the secured wrapper): a mount the user may not write keeps its 403, so
    // no ACL check is bypassed for a destination behind a link
    @ParameterizedTest
    @EnumSource(MountKind.class)
    @DisabledOnOs(OS.WINDOWS)
    void b18WriteWithoutPermissionIsStillForbiddenForALinkedDestination(MountKind kind) throws IOException {
        var mount = mount(kind);
        Files.createSymbolicLink(mount.project().resolve("link"), outsideDir());
        when(mount.acl().hasPermission(any(AProject.class), eq(BasePermission.WRITE))).thenReturn(false);
        var service = service(mount.acl(), new FileNodeMapperImpl());
        var before = snapshot(mount);

        var denied = assertThrows(ForbiddenException.class,
                () -> service.createResource(mount.root(), mount.path("link/y.txt"), stream(marker()), true),
                "B18 on " + kind + ": writing link/y.txt without WRITE permission on the mount is forbidden");

        assertEquals(FORBIDDEN, denied.getErrorCode(), "B18 on " + kind + ": the write keeps its 403");
        assertNothingWritten("B18 write without permission on " + kind, mount, before);
    }

    // V1: surface B payload B19 (ancestor search through a link): linked candidates are omitted unread, and regular
    // files above the anchor, the one above the project included, are still found with their content
    @ParameterizedTest
    @EnumSource(value = MountKind.class, names = {"CLOSED_FLAT", "REPO"})
    @DisabledOnOs(OS.WINDOWS)
    void b19AncestorSearchOmitsLinkedCandidatesAndStillFindsRegularOnes(MountKind kind) throws IOException {
        var lookup = new ProjectFileLookupServiceImpl(grantAllProjectAcl(), grantAllRepositoryAclProvider());
        var mount = mount(kind, lookup);
        var rootMarker = marker();
        var nearMarker = marker();
        var siblingMarker = marker();
        write(mount.store().resolve("AGENTS.md"), rootMarker);
        write(mount.project().resolve("AGENTS.md"), nearMarker);
        var siblingFile = write(mount.sibling().resolve("AGENTS.md"), siblingMarker);
        Files.createDirectories(mount.project().resolve("a/b"));
        Files.createSymbolicLink(mount.project().resolve("a/AGENTS.md"), outsideFile());
        Files.createSymbolicLink(mount.project().resolve("a/b/AGENTS.md"), siblingFile);
        var service = service(mount.acl(), new FileNodeMapperImpl());
        var query = FileSearchQuery.builder()
                .scope(FileSearchQuery.Scope.ANCESTORS)
                .pattern("AGENTS.md")
                .from(mount.path("a/b"))
                .build();

        var found = service.search(mount.root(), query);

        assertEquals(List.of("P1/AGENTS.md", "AGENTS.md"), pathsOf(found), "B19 on " + kind
                + ": the linked a/b/AGENTS.md and a/AGENTS.md are omitted, the regular ones are found nearest first");
        assertEquals(List.of(nearMarker, rootMarker), contentsOf(found),
                "B19 on " + kind + ": the regular files are returned with their content");
        assertFalse(carries(found, outsideSecret), "B19 on " + kind + ": nothing is read through a/AGENTS.md");
        assertFalse(carries(found, siblingMarker),
                "B19 on " + kind + ": nothing of P2 is read through a/b/AGENTS.md");
    }

    // V1: positive control on every mount: a new file in a new sub-folder is created, and a missing path stays 404
    @ParameterizedTest
    @EnumSource(MountKind.class)
    void newFileInANewSubFolderIsCreatedAndAMissingPathStaysNotFound(MountKind kind) throws IOException {
        var mount = mount(kind);
        var service = service(mount.acl(), new FileNodeMapperImpl());
        var content = marker();
        var before = snapshot(mount);

        service.createResource(mount.root(), mount.path("newdir/sub/x.txt"), stream(content), true);
        var missing = assertThrows(NotFoundException.class,
                () -> service.getResource(mount.root(), mount.path("missing.txt"), null),
                "A missing path on " + kind + " is not found");

        assertEquals(content, Files.readString(mount.project().resolve("newdir/sub/x.txt")),
                "newdir/sub/x.txt is created on " + kind + " with its folders");
        assertEquals(NOT_FOUND, missing.getErrorCode(), "A missing path on " + kind + " keeps its 404");
        assertOutsideAndSiblingUnchanged("newdir/sub/x.txt on " + kind, mount, before);
    }

    // ---------------------------------------------------------------------------------------------
    // V1: fixtures of the surface B matrix
    // ---------------------------------------------------------------------------------------------

    // V1: a mount whose ancestor search is not under test.
    private Mount mount(MountKind kind) throws IOException {
        return mount(kind, mock(ProjectFileLookupService.class));
    }

    // V1: the four mounts of the matrix, each laid out with P1, its sibling P2 and the outside folder.
    /**
     * Builds the mount of the kind over real folders under the temporary directory, with the project {@code P1}
     * ({@code rules.xml} and {@code sub/inside.txt}), its sibling {@code P2} ({@code rules.xml}) and the outside
     * folder ({@code outside/secret.txt} holding the sentinel, and {@code outside/dir/keep.txt}).
     *
     * <p>Existing behaviour these rows guard against, recorded here and left unchanged:
     * {@code FileSystemRepository.resolveInRoot} checks containment lexically, without resolving links, and
     * {@code FileSystemRepository.list} lists a link to a regular file, which {@code read()} then follows, but does
     * not descend into a link to a directory.
     */
    private Mount mount(MountKind kind, ProjectFileLookupService lookup) throws IOException {
        return switch (kind) {
            case OPENED -> openedMount(lookup);
            case CLOSED_FLAT -> closedFlatMount(lookup);
            case CLOSED_MAPPED -> closedMappedMount(lookup);
            case REPO -> repoMount(lookup);
        };
    }

    // V1: the opened mount the lexical rows run on.
    private Mount openedMount() throws IOException {
        return openedMount(mock(ProjectFileLookupService.class));
    }

    // V1: an opened project P1 in the working copy matrix-ws, which records P1 and P2 as opened.
    private Mount openedMount(ProjectFileLookupService lookup) throws IOException {
        layOutOutside();
        var workspace = layOutProjects(tmp.resolve("matrix-ws"));
        var design = layOutProjects(tmp.resolve("matrix-opened-design"));
        // Loading the registry deletes every project folder of the working copy that has no record.
        for (var name : List.of("P1", "P2")) {
            MetainfoRegistry.store(workspace, name,
                    new ProjectMetainfo("design", null, null, null, null, null, null, null, Map.of()));
        }
        var workingCopy = new LocalRepository(workspace, MetainfoRegistry.open(workspace));
        var securedDesign = SecuredRepositoryFactory.wrapToSecureRepo(fileRepository(design), grantAllRepoAcl());
        var project = new RulesProject(user(), workingCopy, workingCopy.check("P1"), securedDesign,
                securedDesign.check("P1"), lockEngine());
        assertTrue(project.isOpened(), "Fixture: the project is served from the working copy");
        return projectMount(project, workspace, workspace.resolve("P1"), lookup);
    }

    // V1: a closed project P1 in the flat file design repository matrix-design-flat, behind SecureRepository.
    private Mount closedFlatMount(ProjectFileLookupService lookup) throws IOException {
        layOutOutside();
        var design = layOutProjects(tmp.resolve("matrix-design-flat"));
        var secured = assertInstanceOf(SecureRepository.class,
                SecuredRepositoryFactory.wrapToSecureRepo(fileRepository(design), grantAllRepoAcl()),
                "Fixture: the flat secured wrapper");
        return projectMount(closedProject(secured, "P1"), design, design.resolve("P1"), lookup);
    }

    // V1: a closed project P1 in the mapped file design repository matrix-design-mapped, behind SecureMappedRepository.
    private Mount closedMappedMount(ProjectFileLookupService lookup) throws IOException {
        layOutOutside();
        var design = tmp.resolve("matrix-design-mapped");
        var store = layOutProjects(design.resolve("catalog"));
        var mapped = MappedRepository.create(fileRepository(design), "DESIGN/");
        matrixCloseables.add((Closeable) mapped);
        var secured = assertInstanceOf(SecureMappedRepository.class,
                SecuredRepositoryFactory.wrapToSecureRepo(mapped, grantAllRepoAcl()),
                "Fixture: the mapped secured wrapper");
        var project = closedProject(secured, mappedName(secured, "P1"));
        return projectMount(project, store, store.resolve("P1"), lookup);
    }

    // V1: the repository mount exactly as the /rest/repos/{repo}/files routes build it, through RepoFileRootFactory.
    private Mount repoMount(ProjectFileLookupService lookup) throws IOException {
        layOutOutside();
        var design = layOutProjects(tmp.resolve("matrix-design-repo"));
        var settings = Map.of("repository.design.factory", "repo-file", "repository.design.uri", design.toString());
        var configured = assertInstanceOf(PathCheckedRepository.class,
                RepositoryInstatiator.newRepository("repository.design", settings::get),
                "Fixture: the settings build a path-checked repo-file repository");
        // The mapped repository closes the configured one with it.
        var mapped = MappedRepository.create(configured, "DESIGN/");
        matrixCloseables.add((Closeable) mapped);
        var secured = assertInstanceOf(SecureMappedRepository.class,
                SecuredRepositoryFactory.wrapToSecureRepo(mapped, grantAllRepoAcl()),
                "Fixture: the mapped secured wrapper a repository-mount route receives");
        assertInstanceOf(PathCheckedRepository.class, secured.getDelegate(),
                "Fixture: the factory mounts the path-checked repository behind the mapping");
        var acl = grantAllProjectAcl();
        var root = factoryMount(secured, acl, lookup);
        return new Mount(root, design.resolve("P1"), design.resolve("P2"), design, "P1/", acl);
    }

    // V1: RepoFileRootFactory stamps the authenticated user as the author, so a generated user is authenticated.
    /**
     * Mounts the repository on its default branch through {@link RepoFileRootFactory#of(Repository, String)}, as the
     * repository-mount routes do, so the mount holds the repository inside {@code AuthoringRepository}.
     */
    private FileRoot factoryMount(Repository repository, AclProjectsHelper acl, ProjectFileLookupService lookup) {
        var user = user();
        var lockEngine = lockEngine();
        var userWorkspace = mock(UserWorkspace.class);
        when(userWorkspace.getUser()).thenReturn(user);
        when(userWorkspace.getDesignTimeRepository()).thenReturn(mock(DesignTimeRepository.class));
        when(userWorkspace.getProjectsLockEngine()).thenReturn(lockEngine);
        var factory = new RepoFileRootFactory(acl, mock(UserManagementService.class), lookup) {
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

    // V1: a project mount over a grant-all project ACL, which the mount and its service share.
    private Mount projectMount(RulesProject project, Path store, Path projectFolder, ProjectFileLookupService lookup) {
        var acl = grantAllProjectAcl();
        var stateValidator = mock(ProjectStateValidator.class);
        when(stateValidator.canModify(project)).thenReturn(true);
        var root = new ProjectFileRoot(project, acl, stateValidator, lookup, () -> new UserInfo(userName),
                mock(DesignTimeRepository.class));
        return new Mount(root, projectFolder, store.resolve("P2"), store, "", acl);
    }

    // V1: a project served from its design repository, as a closed project is.
    private RulesProject closedProject(Repository design, String name) throws IOException {
        var workspace = Files.createTempDirectory(tmp, "matrix-local");
        var local = new LocalRepository(workspace, MetainfoRegistry.open(workspace));
        var designData = design.check(name);
        assertNotNull(designData, "Fixture: the design repository holds " + name);
        var project = new RulesProject(user(), local, null, design, designData, lockEngine());
        project.setFileData(designData);
        assertFalse(project.isOpened(), "Fixture: the project is served from the design repository");
        return project;
    }

    // V1: the mapped name of a project in a mapped repository, under its base folder.
    private static String mappedName(Repository repository, String businessName) throws IOException {
        return repository.listFolders("DESIGN/")
                .stream()
                .map(FileData::getName)
                .filter(name -> name.startsWith("DESIGN/" + businessName + ":"))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Fixture: " + businessName + " is not mapped"));
    }

    // V1: the files service with mocked listing, search and descriptor collaborators.
    private static ProjectFilesServiceImpl service(AclProjectsHelper acl) {
        return new ProjectFilesServiceImpl(acl, mock(FileNodeMapper.class), mock(FileSearchSupport.class),
                new FileArchiveSupport(acl), mock(ProjectDescriptorCleaner.class),
                new BeanValidationProvider(List.of()));
    }

    // V1: the files service with a real node mapper and the real content search over it.
    private static ProjectFilesServiceImpl service(AclProjectsHelper acl, FileNodeMapper mapper) {
        return new ProjectFilesServiceImpl(acl, mapper, new FileSearchSupport(acl, mapper), new FileArchiveSupport(acl),
                mock(ProjectDescriptorCleaner.class), new BeanValidationProvider(List.of()));
    }

    // V1: the repository ACL of the ancestor search, granting every design repository path.
    private static RepositoryAclServiceProvider grantAllRepositoryAclProvider() {
        var aclService = mock(RepositoryAclService.class,
                invocation -> invocation.getMethod().getReturnType() == boolean.class
                        ? Boolean.TRUE
                        : Mockito.RETURNS_DEFAULTS.answer(invocation));
        var provider = mock(RepositoryAclServiceProvider.class);
        when(provider.getDesignRepoAclService()).thenReturn(aclService);
        return provider;
    }

    // V1: P1 with a descriptor and sub/inside.txt, and its sibling P2 with a descriptor, under the parent folder.
    private static Path layOutProjects(Path parent) throws IOException {
        write(parent.resolve("P1/rules.xml"), descriptor());
        write(parent.resolve("P1").resolve(SOURCE), marker());
        write(parent.resolve("P2/rules.xml"), "<project><name>P2</name></project>");
        return parent;
    }

    // V1: the outside folder: secret.txt holding the sentinel, and dir/keep.txt.
    private void layOutOutside() throws IOException {
        write(outsideFile(), outsideSecret);
        write(outsideDir().resolve("keep.txt"), marker());
    }

    // V1: the folder outside every mount that a directory link points to.
    private Path outsideDir() {
        return tmp.resolve("outside/dir");
    }

    // V1: the file outside every mount that a file link points to; it holds the sentinel.
    private Path outsideFile() {
        return tmp.resolve("outside/secret.txt");
    }

    // V1: the state of the folders a payload may not change.
    private Snapshot snapshot(Mount mount) throws IOException {
        return new Snapshot(snapshotOf(tmp.resolve("outside")), snapshotOf(mount.sibling()), snapshotOf(tmp));
    }

    // V1: every entry under the folder, links not followed: its kind, a link's target, a file's size and SHA-256.
    private static Map<String, String> snapshotOf(Path folder) throws IOException {
        var entries = new TreeMap<String, String>();
        try (var paths = Files.walk(folder)) {
            for (var path : paths.toList()) {
                String state;
                if (Files.isSymbolicLink(path)) {
                    state = "link " + Files.readSymbolicLink(path);
                } else if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                    state = "dir";
                } else {
                    state = "file " + Files.size(path) + " " + sha256(readAllBytes(path));
                }
                entries.put(folder.relativize(path).toString(), state);
            }
        }
        return entries;
    }

    // V1: the content fingerprint of a snapshot, so a snapshot never holds the content itself.
    private static String sha256(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // V1: a rejected payload writes nothing, outside the project, in the sibling project or anywhere else.
    private void assertNothingWritten(String row, Mount mount, Snapshot before) throws IOException {
        var after = snapshot(mount);
        assertEquals(before.outside(), after.outside(), row + ": the outside folder is unchanged");
        assertEquals(before.sibling(), after.sibling(), row + ": the sibling project P2 is unchanged");
        assertEquals(before.tree(), after.tree(), row + ": nothing is created, modified or deleted");
    }

    // V1: an accepted payload changes nothing outside the project and nothing in the sibling project.
    private void assertOutsideAndSiblingUnchanged(String row, Mount mount, Snapshot before) throws IOException {
        var after = snapshot(mount);
        assertEquals(before.outside(), after.outside(), row + ": the outside folder is unchanged");
        assertEquals(before.sibling(), after.sibling(), row + ": the sibling project P2 is unchanged");
    }

    // V1: the destination guard's rejection, 400 with the existing key, never a conflict.
    private static void assertPathRejected(String row, Executable call) {
        var rejected = assertThrows(BadRequestException.class, call, row + " is rejected");
        assertEquals(INVALID_PATH, rejected.getErrorCode(), row + " is rejected as an invalid path");
    }

    // V1: a path a link places outside: not found, or rejected as an invalid path, and nothing else.
    private static void assertNotFoundOrRejected(String row, Executable call) {
        var thrown = assertThrows(RestRuntimeException.class, call, row + " is not served");
        var notFound = thrown instanceof NotFoundException && NOT_FOUND.equals(thrown.getErrorCode());
        var rejected = thrown instanceof BadRequestException && INVALID_PATH.equals(thrown.getErrorCode());
        assertTrue(notFound || rejected, row + " is not found or rejected as an invalid path, not "
                + thrown.getClass().getSimpleName() + " " + thrown.getErrorCode());
    }

    // V1: a lexical payload is rejected by the operation and writes nothing.
    private void assertLexicallyRejected(String row, PathOperation operation, String... payloads) throws IOException {
        var mount = openedMount();
        var service = service(mount.acl());
        for (var payload : payloads) {
            var description = row + " " + printable(payload) + " through " + operation;
            var before = snapshot(mount);
            assertPathRejected(description, () -> operation.apply(service, mount, payload));
            assertNothingWritten(description, mount, before);
        }
    }

    // V1: the paths of the listed or found nodes, nested children included.
    private static List<String> pathsOf(List<FsNode> nodes) {
        var paths = new ArrayList<String>();
        var queue = new ArrayDeque<FsNode>(nodes);
        while (!queue.isEmpty()) {
            var node = queue.poll();
            paths.add(node.getPath());
            if (node instanceof FolderNode folder) {
                var children = folder.getChildren();
                if (children != null) {
                    queue.addAll(children);
                }
            }
        }
        return paths;
    }

    // V1: the content the found files carry.
    private static List<String> contentsOf(List<FsNode> nodes) {
        var contents = new ArrayList<String>();
        for (var node : nodes) {
            if (node instanceof FileNode fileNode) {
                contents.add(fileNode.getContent());
            }
        }
        return contents;
    }

    // V1: whether a returned node carries the marker; the marker itself is never reported.
    private static boolean carries(List<FsNode> nodes, String marker) {
        return contentsOf(nodes).stream().anyMatch(content -> content != null && content.contains(marker));
    }

    // V1: content to create or update a file with.
    private static InputStream stream(String content) {
        return new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
    }

    // V1: an archive holding one entry under the raw name, written as it is.
    private static InputStream zip(String entryName, String content) throws IOException {
        var bytes = new ByteArrayOutputStream();
        try (var archive = new ZipOutputStream(bytes)) {
            archive.putNextEntry(new ZipEntry(entryName));
            archive.write(content.getBytes(StandardCharsets.UTF_8));
            archive.closeEntry();
        }
        return new ByteArrayInputStream(bytes.toByteArray());
    }

    // V1: a payload with its control and non-ASCII characters escaped, for assertion messages.
    private static String printable(String payload) {
        var out = new StringBuilder();
        payload.chars()
                .forEach(c -> out.append(c < 0x20 || c > 0x7E ? "\\u%04X".formatted(c) : String.valueOf((char) c)));
        return out.toString();
    }
}

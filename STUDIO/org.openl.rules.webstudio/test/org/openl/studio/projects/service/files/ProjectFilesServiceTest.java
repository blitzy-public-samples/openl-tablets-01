package org.openl.studio.projects.service.files;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;

import org.openl.rules.lock.LockInfo;
import org.openl.rules.project.abstraction.LockEngine;
import org.openl.rules.project.abstraction.RulesProject;
import org.openl.rules.project.impl.local.LocalRepository;
import org.openl.rules.project.impl.local.MetainfoRegistry;
import org.openl.rules.project.impl.local.ProjectMetainfo;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.rest.acl.service.AclProjectsHelper;
import org.openl.rules.workspace.WorkspaceUser;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.security.acl.repository.SecuredRepositoryFactory;
import org.openl.security.acl.repository.SimpleRepositoryAclService;
import org.openl.studio.common.exception.BadRequestException;
import org.openl.studio.common.validation.BeanValidationProvider;
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
}

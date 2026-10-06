package org.openl.studio.repositories.service;

// V1-D: this test also covers the upload destination, archive entry and folder-link containment of surface D
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.FileMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import org.openl.rules.project.model.Module;
import org.openl.rules.project.model.ProjectDescriptor;
import org.openl.rules.repository.LocalWorkingTree;
import org.openl.rules.repository.PathCheckedRepository;
import org.openl.rules.repository.RepositoryInstatiator;
import org.openl.rules.repository.api.BranchRepository;
import org.openl.rules.repository.api.ChangesetType;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.repository.folder.FileChangesFromFolder;
import org.openl.rules.repository.git.GitRepository;
import org.openl.rules.repository.git.GitRepositoryFactory;
import org.openl.rules.security.SimpleUser;
import org.openl.rules.webstudio.service.UserManagementService;
import org.openl.rules.webstudio.web.repository.upload.zip.ZipCharsetDetector;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.rules.workspace.dtr.impl.FileMappingData;
import org.openl.rules.workspace.dtr.impl.MappedRepository;
import org.openl.rules.workspace.filter.PathFilter;
import org.openl.security.acl.repository.SecuredRepositoryFactory;
import org.openl.security.acl.repository.SimpleRepositoryAclService;
import org.openl.studio.common.exception.BadRequestException;
import org.openl.studio.repositories.model.CreateUpdateProjectModel;
import org.openl.util.IOUtils;
import org.openl.util.ZipUtils;

class ZipProjectSaveStrategyTest {

    private static final String BASE_RULES_LOCATION = "DESIGN/";
    // V1: the archive and the rejection the upload destination guard tests share
    private static final Path PROJECT_ARCHIVE = Path.of("test-resources/upload/zip/project.zip");
    // V1: the archive a Git project is first saved from, so the overwrite tests can place a link at 'rules'
    private static final Path EXCEL_ONLY_ARCHIVE = Path.of("test-resources/upload/zip/excel-only-project.zip");
    private static final String INVALID_PATH = "openl.error.400.file.path.invalid.message";

    private ZipProjectSaveStrategy saveStrategy;
    private DesignTimeRepository designTimeRepositoryMock;
    private UserManagementService userManagementService;
    private ArgumentCaptor<FileData> fileDataCaptor;
    // V1: the repositories a test opens over real folders, closed after it
    private final List<AutoCloseable> closeables = new ArrayList<>();

    @TempDir
    Path tmp;

    @BeforeEach
    void setUp() {
        this.fileDataCaptor = forClass(FileData.class);

        this.designTimeRepositoryMock = mock(DesignTimeRepository.class);
        this.userManagementService = mock(UserManagementService.class);
        when(designTimeRepositoryMock.getRulesLocation()).thenReturn(BASE_RULES_LOCATION);
        var user = new SimpleUser();
        user.setDisplayName("John Smith");
        user.setEmail("jsmith@email");
        when(userManagementService.getUser(anyString())).thenReturn(user);

        ZipCharsetDetector zipCharsetDetectorMock = mock(ZipCharsetDetector.class);
        when(zipCharsetDetectorMock.detectCharset(any())).thenReturn(StandardCharsets.UTF_8);

        PathFilter zipFilterMock = mock(PathFilter.class);
        when(zipFilterMock.accept(anyString())).thenReturn(Boolean.TRUE);

        saveStrategy = new ZipProjectSaveStrategy(designTimeRepositoryMock,
                zipFilterMock,
                zipCharsetDetectorMock,
                userManagementService);
    }

    // V1: releases the file repositories a test opened
    @AfterEach
    void closeRepositories() {
        closeables.forEach(IOUtils::closeQuietly);
    }

    @Test
    void testSaveMappedRepo() throws Exception {
        mockDesignRepository(MappedRepository.class, "design1", builder -> builder.setVersions(true));
        var model = new CreateUpdateProjectModel("design1",
                "jsmith",
                "Project 1",
                "foo/Project 1",
                "Bar",
                false);
        var repo = designTimeRepositoryMock.getRepository(model.getRepoName());
        var actualFileItems = captureFileItems(repo);

        Path expected = Path.of("test-resources/upload/zip/project.zip");
        saveStrategy.save(repo, model, expected);
        verify(repo, times(1)).save(fileDataCaptor.capture(), any(), eq(ChangesetType.FULL));
        assertSame(expected, BASE_RULES_LOCATION + "Project 1/", actualFileItems);

        var actualData = fileDataCaptor.getValue();
        assertEquals(BASE_RULES_LOCATION + "Project 1", actualData.getName());
        assertEquals("Bar", actualData.getComment());
        assertEquals("jsmith@email", actualData.getAuthor().getEmail());
        assertEquals("John Smith", actualData.getAuthor().getName());
        assertEquals(1, actualData.getAdditionalData().size());
        var actualAddData = (FileMappingData) actualData.getAdditionalData().values().iterator().next();
        assertEquals(BASE_RULES_LOCATION + "Project 1", actualAddData.getExternalPath());
        assertEquals("foo/Project 1", actualAddData.getInternalPath());
    }

    @Test
    void testSaveMappedRepo2() throws Exception {
        mockDesignRepository(MappedRepository.class, "design1", builder -> builder.setVersions(true));
        var model = new CreateUpdateProjectModel("design1",
                "jsmith",
                "Project 1",
                null,
                "Bar",
                false);
        var repo = designTimeRepositoryMock.getRepository(model.getRepoName());
        var actualFileItems = captureFileItems(repo);

        Path expected = Path.of("test-resources/upload/zip/project.zip");
        saveStrategy.save(repo, model, expected);
        verify(repo, times(1)).save(fileDataCaptor.capture(), any(), eq(ChangesetType.FULL));
        assertSame(expected, BASE_RULES_LOCATION + "Project 1/", actualFileItems);

        var actualData = fileDataCaptor.getValue();
        assertEquals(BASE_RULES_LOCATION + "Project 1", actualData.getName());
        assertEquals("Bar", actualData.getComment());
        assertEquals("jsmith@email", actualData.getAuthor().getEmail());
        assertEquals("John Smith", actualData.getAuthor().getName());
        assertEquals(1, actualData.getAdditionalData().size());
        var actualAddData = (FileMappingData) actualData.getAdditionalData().values().iterator().next();
        assertEquals(BASE_RULES_LOCATION + "Project 1", actualAddData.getExternalPath());
        assertEquals("Project 1", actualAddData.getInternalPath());
    }

    @Test
    void testSaveNotFolderRepo() throws Exception {
        mockDesignRepository(Repository.class, "design2", builder -> builder.setVersions(true));
        var model = new CreateUpdateProjectModel("design2",
                "jsmith",
                "Project 1",
                null,
                null,
                false);
        var repo = designTimeRepositoryMock.getRepository(model.getRepoName());
        var actualStream = captureStream(repo);

        Path expected = Path.of("test-resources/upload/zip/project.zip");
        saveStrategy.save(repo, model, expected);
        verify(repo, times(1)).save(fileDataCaptor.capture(), any());
        assertSame(expected, actualStream.get());

        var actualData = fileDataCaptor.getValue();
        assertEquals(BASE_RULES_LOCATION + "Project 1", actualData.getName());
        assertEquals("", actualData.getComment());
        assertEquals("jsmith@email", actualData.getAuthor().getEmail());
        assertEquals("John Smith", actualData.getAuthor().getName());
        assertEquals(0, actualData.getAdditionalData().size());
    }

    @Test
    void testSaveNotFolderRepoAddsDescriptorWithoutMovingFiles() throws Exception {
        mockDesignRepository(Repository.class, "design2", builder -> builder.setVersions(true));
        var model = new CreateUpdateProjectModel("design2",
                "jsmith",
                "Project 2",
                null,
                null,
                false);
        var repo = designTimeRepositoryMock.getRepository(model.getRepoName());
        var actualStream = captureStream(repo);

        var source = Path.of("test-resources/upload/zip/excel-only-project.zip");
        saveStrategy.save(repo, model, source);

        assertDescriptorAddedWithoutMovingFiles(source, actualStream.get());
    }

    @Test
    void testSaveNotFolderRepoKeepsLegacyExcelModules(@TempDir Path tempFolder) throws Exception {
        mockDesignRepository(Repository.class, "design2", builder -> builder.setVersions(true));
        var model = new CreateUpdateProjectModel("design2",
                "jsmith",
                "Project 2",
                null,
                null,
                false);
        var repo = designTimeRepositoryMock.getRepository(model.getRepoName());
        var actualStream = captureStream(repo);

        var source = tempFolder.resolve("legacy-project.zip");
        try (var zip = new ZipOutputStream(Files.newOutputStream(source))) {
            zip.putNextEntry(new ZipEntry("Main.xlsx"));
            zip.putNextEntry(new ZipEntry("Legacy.xls"));
            zip.putNextEntry(new ZipEntry("Macro.xlsm"));
        }
        saveStrategy.save(repo, model, source);

        var descriptor = descriptor(actualStream.get());
        var modulePaths = descriptor.getModules().stream().map(Module::getRulesRootPath).toList();
        assertEquals(3, modulePaths.size());
        assertEquals("*.xlsx", modulePaths.getFirst());
        assertTrue(modulePaths.contains("Legacy.xls"));
        assertTrue(modulePaths.contains("Macro.xlsm"));
    }

    // V1: the descriptor a save generates, and the guard checks, lists no AppleDouble companion of a workbook
    @Test
    void testSaveNotFolderRepoSkipsAppleDoubleCompanionsOfExcelModules(@TempDir Path tempFolder) throws Exception {
        mockDesignRepository(Repository.class, "design2", builder -> builder.setVersions(true));
        var model = new CreateUpdateProjectModel("design2", "jsmith", "Project 2", null, null, false);
        var repo = designTimeRepositoryMock.getRepository(model.getRepoName());
        var actualStream = captureStream(repo);

        // V1-D: the archive is built by the class's own archive helper, its entries in this order
        var entries = new LinkedHashMap<String, byte[]>();
        entries.put("Legacy.xls", new byte[0]);
        entries.put("._Legacy.xls", new byte[0]);
        var source = zip(tempFolder.resolve("apple-double-project.zip"), entries);
        saveStrategy.save(repo, model, source);

        var modulePaths = descriptor(actualStream.get()).getModules().stream().map(Module::getRulesRootPath).toList();
        assertEquals(List.of("*.xlsx", "Legacy.xls"), modulePaths);
    }

    @Test
    void testSaveMappedRepoCustomPath() throws Exception {
        mockDesignRepository(MappedRepository.class, "design1", builder -> builder.setVersions(true));
        var model = new CreateUpdateProjectModel("design1",
                "jsmith",
                "Project 1",
                "custom-name",
                "Bar",
                false);
        var repo = designTimeRepositoryMock.getRepository(model.getRepoName());
        var actualFileItems = captureFileItems(repo);

        Path expected = Path.of("test-resources/upload/zip/project.zip");
        saveStrategy.save(repo, model, expected);
        verify(repo, times(1)).save(fileDataCaptor.capture(), any(), eq(ChangesetType.FULL));
        final var expectedRootFolder = BASE_RULES_LOCATION + "Project 1/";
        assertSame(expected, expectedRootFolder, actualFileItems);

        var actualData = fileDataCaptor.getValue();
        assertEquals(BASE_RULES_LOCATION + "Project 1", actualData.getName());
        assertEquals("Bar", actualData.getComment());
        assertEquals("jsmith@email", actualData.getAuthor().getEmail());
        assertEquals("John Smith", actualData.getAuthor().getName());
        assertEquals(1, actualData.getAdditionalData().size());
        var actualAddData = (FileMappingData) actualData.getAdditionalData().values().iterator().next();
        assertEquals(BASE_RULES_LOCATION + "Project 1", actualAddData.getExternalPath());
        assertEquals("custom-name", actualAddData.getInternalPath());

        var descriptor = actualFileItems
                .get(expectedRootFolder + ProjectDescriptor.FILE_NAME);
        ((ByteArrayInputStream) descriptor.getStream()).reset();
        assertProjectDescriptor(expectedRootFolder, "Project 1", descriptor);
    }

    @Test
    void testSaveMappedRepoCustomPathExtraProjectDescriptor() throws Exception {
        mockDesignRepository(MappedRepository.class, "design1", builder -> builder.setVersions(true));
        var model = new CreateUpdateProjectModel("design1",
                "jsmith",
                "Project 2",
                "custom-name",
                "Bar",
                false);
        var repo = designTimeRepositoryMock.getRepository(model.getRepoName());
        var actualFileItems = captureFileItems(repo);

        Path expected = Path.of("test-resources/upload/zip/excel-only-project.zip");
        saveStrategy.save(repo, model, expected);
        verify(repo, times(1)).save(fileDataCaptor.capture(), any(), eq(ChangesetType.FULL));

        final var expectedRootFolder = BASE_RULES_LOCATION + "Project 2/";
        var descriptor = actualFileItems
                .remove(expectedRootFolder + ProjectDescriptor.FILE_NAME);
        var projectDescriptor = assertProjectDescriptor(expectedRootFolder, "Project 2", descriptor);
        assertRootXlsxModule(projectDescriptor);
        var workbook = actualFileItems.remove(expectedRootFolder + "Main.xlsx");
        assertNotNull(workbook);
        try (FileSystem fs = FileSystems.newFileSystem(ZipUtils.toJarURI(expected), Map.of());
             var expectedStream = Files.newInputStream(fs.getPath("/Main.xlsx"));
             var actualStream = workbook.getStream()) {
            assertTrue(org.apache.commons.io.IOUtils.contentEquals(expectedStream, actualStream));
        }
        assertTrue(actualFileItems.isEmpty());

        var actualData = fileDataCaptor.getValue();
        assertEquals(BASE_RULES_LOCATION + "Project 2", actualData.getName());
        assertEquals("Bar", actualData.getComment());
        assertEquals("jsmith@email", actualData.getAuthor().getEmail());
        assertEquals("John Smith", actualData.getAuthor().getName());
        assertEquals(1, actualData.getAdditionalData().size());
        var actualAddData = (FileMappingData) actualData.getAdditionalData().values().iterator().next();
        assertEquals(BASE_RULES_LOCATION + "Project 2", actualAddData.getExternalPath());
        assertEquals("custom-name", actualAddData.getInternalPath());
    }

    // ---------------------------------------------------------------------------------------------
    // V1: the upload destination guard over a file repository built from its settings, as the application builds it
    // Such a repository sits behind PathCheckedRepository and the secured wrapper.
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void saveIntoAConfiguredFileRepositoryRejectsAProjectFolderLinkedOutside() throws IOException {
        var root = tmp.resolve("design");
        var outside = Files.createDirectories(tmp.resolve("outside"));
        Files.createSymbolicLink(Files.createDirectories(root.resolve(BASE_RULES_LOCATION)).resolve("Linked"),
                outside);
        var repository = secured(configuredFileRepository(root));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Linked", null, null, false);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "Nothing is written through a project folder linked outside");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void saveIntoAMappedConfiguredFileRepositoryRejectsAProjectFolderLinkedOutside() throws IOException {
        var root = Files.createDirectories(tmp.resolve("design"));
        var outside = Files.createDirectories(tmp.resolve("outside"));
        Files.createSymbolicLink(root.resolve("linked"), outside);
        var repository = secured(mapped(configuredFileRepository(root)));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Linked", "linked", null, false);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "Nothing is written through a mapped project folder linked outside");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingAProjectOfAConfiguredFileRepositoryRejectsAnEntryThroughAnOutsideLink() throws IOException {
        var root = tmp.resolve("design");
        var project = Files.createDirectories(root.resolve(BASE_RULES_LOCATION + "Existing"));
        var outside = Files.createDirectories(tmp.resolve("outside"));
        // The archive holds rules/Project2-Main.xlsx, so the save would write it through this link.
        var link = Files.createSymbolicLink(project.resolve("rules"), outside);
        var repository = secured(configuredFileRepository(root));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "No entry is written through a link the existing project folder holds");
        assertTrue(Files.isSymbolicLink(link), "The existing project folder is left as it was");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void saveRejectsAProjectFolderLinkedOutsideUnderAConfiguredRootThatClimbsOutOfALink() throws IOException {
        // base/link points to physical/child, so the file system writes base/link/../design at physical/design,
        // while the lexically normalized base/design does not exist.
        var physical = Files.createDirectories(tmp.resolve("physical/design"));
        var child = Files.createDirectories(tmp.resolve("physical/child"));
        var link = Files.createSymbolicLink(Files.createDirectories(tmp.resolve("base")).resolve("link"), child);
        var outside = Files.createDirectories(tmp.resolve("outside"));
        Files.createSymbolicLink(Files.createDirectories(physical.resolve(BASE_RULES_LOCATION)).resolve("Linked"),
                outside);
        var repository = secured(configuredFileRepository(link.resolve("..").resolve("design")));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Linked", null, null, false);

        assertFalse(Files.exists(tmp.resolve("base/design")), "Fixture: the lexical root does not exist");
        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "Nothing is written through a project folder linked outside a root that climbs out");
    }

    @Test
    void anOrdinaryUploadIntoAConfiguredFileRepositorySucceeds() throws IOException {
        var root = tmp.resolve("design");
        var repository = secured(configuredFileRepository(root));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Fresh", null, null, false);

        assertNotNull(saveStrategy.save(repository, model, PROJECT_ARCHIVE), "The saved project folder is reported");

        var project = root.resolve(BASE_RULES_LOCATION + "Fresh");
        assertTrue(Files.isRegularFile(project.resolve(ProjectDescriptor.FILE_NAME)), "The descriptor is saved");
        assertTrue(Files.isRegularFile(project.resolve("rules/Project2-Main.xlsx")), "A nested entry is saved");
        // V1-D: the guard leaves the descriptor rewrite alone, so the archive's 'project2' becomes the upload's name
        try (var stream = Files.newInputStream(project.resolve(ProjectDescriptor.FILE_NAME))) {
            assertEquals("Fresh", ProjectDescriptor.read(stream).getName(), "The descriptor carries the project name");
        }
    }

    @Test
    void anOrdinaryUploadIntoAMappedConfiguredFileRepositorySucceeds() throws IOException {
        var root = Files.createDirectories(tmp.resolve("design"));
        var repository = secured(mapped(configuredFileRepository(root)));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Fresh", "catalog/Fresh", null, false);

        assertNotNull(saveStrategy.save(repository, model, PROJECT_ARCHIVE), "The saved project folder is reported");

        var project = root.resolve("catalog/Fresh");
        assertTrue(Files.isRegularFile(project.resolve(ProjectDescriptor.FILE_NAME)), "The descriptor is saved");
        assertTrue(Files.isRegularFile(project.resolve("rules/Project2-Main.xlsx")), "A nested entry is saved");
    }

    @Test
    void overwritingAnOrdinaryProjectOfAConfiguredFileRepositorySucceeds() throws IOException {
        var root = tmp.resolve("design");
        var project = root.resolve(BASE_RULES_LOCATION + "Existing");
        var stale = Files.createDirectories(project.resolve("rules")).resolve("Stale.xlsx");
        Files.write(stale, new byte[] { 1 });
        var repository = secured(configuredFileRepository(root));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        assertNotNull(saveStrategy.save(repository, model, PROJECT_ARCHIVE), "The saved project folder is reported");

        assertTrue(Files.isRegularFile(project.resolve("rules/Project2-Main.xlsx")), "The new entry is saved");
        assertFalse(Files.exists(stale), "A file the archive does not hold is removed by the full save");
    }

    // ---------------------------------------------------------------------------------------------
    // V1: the same guard over a Git repository built from its settings, which saves through its local working tree
    // A link in that tree leads a write wherever it points.
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingAProjectOfAConfiguredGitRepositoryRejectsAnEntryThroughAnUntrackedOutsideLink() throws IOException {
        var root = tmp.resolve("design");
        var outside = Files.createDirectories(tmp.resolve("outside"));
        var repository = secured(configuredGitRepository(root));
        saveNewProject(repository, "Existing", null);
        // The archive holds rules/Project2-Main.xlsx, so the save would write it through this link.
        var link = Files.createSymbolicLink(root.resolve(BASE_RULES_LOCATION + "Existing/rules"), outside);
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "No entry is written through an untracked link in the working tree");
        assertTrue(Files.isSymbolicLink(link), "The existing project folder is left as it was");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingAProjectOfAConfiguredGitRepositoryRejectsAnEntryThroughATrackedOutsideLink() throws Exception {
        var root = tmp.resolve("design");
        var outside = Files.createDirectories(tmp.resolve("outside"));
        var repository = secured(configuredGitRepository(root));
        saveNewProject(repository, "Existing", null);
        var linkPath = BASE_RULES_LOCATION + "Existing/rules";
        var link = Files.createSymbolicLink(root.resolve(linkPath), outside);
        try (var git = Git.open(root.toFile())) {
            git.add().addFilepattern(linkPath).call();
            git.commit()
                    .setMessage("Track a link to outside")
                    .setAuthor("Test", "test@example.org")
                    .setCommitter("Test", "test@example.org")
                    .setSign(false)
                    .call();
            assertEquals(FileMode.SYMLINK,
                    git.getRepository().readDirCache().getEntry(linkPath).getFileMode(),
                    "Fixture: the link is tracked as a link");
        }
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "No entry is written through a tracked link in the working tree");
        assertTrue(Files.isSymbolicLink(link), "The existing project folder is left as it was");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingAProjectOfAMappedConfiguredGitRepositoryRejectsAnEntryThroughAnOutsideLink() throws IOException {
        var root = tmp.resolve("design");
        var outside = Files.createDirectories(tmp.resolve("outside"));
        var repository = secured(mapped(configuredGitRepository(root)));
        saveNewProject(repository, "Existing", "linked/Existing");
        var link = Files.createSymbolicLink(root.resolve("linked/Existing/rules"), outside);
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", "linked/Existing", null, true);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "No entry is written through a link in a mapped project of the working tree");
        assertTrue(Files.isSymbolicLink(link), "The existing project folder is left as it was");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingAProjectOfAnUnwrappedGitRepositoryRejectsAnEntryThroughAnOutsideLink() throws IOException {
        var root = tmp.resolve("design");
        var outside = Files.createDirectories(tmp.resolve("outside"));
        // The factory itself returns the Git repository without the path-checked wrapper.
        var bare = new GitRepositoryFactory().create(Map.of("uri", root.toString())::get);
        closeables.add(bare);
        assertInstanceOf(GitRepository.class, bare, "Fixture: the Git repository is not wrapped");
        var repository = secured(bare);
        saveNewProject(repository, "Existing", null);
        var link = Files.createSymbolicLink(root.resolve(BASE_RULES_LOCATION + "Existing/rules"), outside);
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "No entry is written through a link in the working tree of an unwrapped repository");
        assertTrue(Files.isSymbolicLink(link), "The existing project folder is left as it was");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void saveIntoAConfiguredGitRepositoryRejectsAProjectFolderLinkedOutside() throws IOException {
        var root = tmp.resolve("design");
        var outside = Files.createDirectories(tmp.resolve("outside"));
        // The repository creates its working tree, so the link is placed in it afterwards.
        var repository = secured(configuredGitRepository(root));
        Files.createSymbolicLink(Files.createDirectories(root.resolve(BASE_RULES_LOCATION)).resolve("Linked"),
                outside);
        var model = new CreateUpdateProjectModel("design", "jsmith", "Linked", null, null, false);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "Nothing is written through a project folder of the working tree linked outside");
    }

    @Test
    void anOrdinaryUploadIntoAConfiguredGitRepositorySucceeds() throws IOException {
        var root = tmp.resolve("design");
        var repository = secured(configuredGitRepository(root));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Fresh", null, null, false);

        assertNotNull(saveStrategy.save(repository, model, PROJECT_ARCHIVE), "The saved project folder is reported");

        var project = root.resolve(BASE_RULES_LOCATION + "Fresh");
        assertTrue(Files.isRegularFile(project.resolve(ProjectDescriptor.FILE_NAME)), "The descriptor is saved");
        assertTrue(Files.isRegularFile(project.resolve("rules/Project2-Main.xlsx")), "A nested entry is saved");
        assertNotNull(repository.check(BASE_RULES_LOCATION + "Fresh/rules/Project2-Main.xlsx"),
                "The nested entry is committed");
    }

    @Test
    void overwritingAnOrdinaryProjectOfAConfiguredGitRepositorySucceeds() throws IOException {
        var root = tmp.resolve("design");
        var repository = secured(configuredGitRepository(root));
        saveNewProject(repository, "Existing", null);
        var project = root.resolve(BASE_RULES_LOCATION + "Existing");
        assertTrue(Files.isRegularFile(project.resolve("Main.xlsx")), "Fixture: the first save wrote the workbook");
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        assertNotNull(saveStrategy.save(repository, model, PROJECT_ARCHIVE), "The saved project folder is reported");

        assertTrue(Files.isRegularFile(project.resolve("rules/Project2-Main.xlsx")), "The new entry is saved");
        assertNotNull(repository.check(BASE_RULES_LOCATION + "Existing/rules/Project2-Main.xlsx"),
                "The new entry is committed");
        assertFalse(Files.exists(project.resolve("Main.xlsx")), "A file the archive does not hold is removed");
        assertNull(repository.check(BASE_RULES_LOCATION + "Existing/Main.xlsx"),
                "The removal of a file the archive does not hold is committed");
    }

    // V1-D: a full Git save's cleanup enters folder links, so a committed folder link out of the project is refused
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingAProjectOfAConfiguredGitRepositoryRejectsACommittedFolderLinkOutOfTheProject() throws Exception {
        var root = tmp.resolve("design");
        var outside = Files.createDirectories(tmp.resolve("outside"));
        Files.writeString(outside.resolve("canary.txt"), "kept");
        var repository = secured(configuredGitRepository(root));
        saveNewProject(repository, "Existing", null);
        // No archive entry reaches this link; only the cleanup of the full save would descend into it.
        var linkPath = BASE_RULES_LOCATION + "Existing/vendor";
        commitLink(root, linkPath, outside);
        var outsideBefore = snapshot(outside);
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        assertPathRejected(() -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(outsideBefore, snapshot(outside), "Nothing outside the project is touched");
        assertTrue(Files.isSymbolicLink(root.resolve(linkPath)), "The link is left as it was");
        assertNotNull(repository.check(BASE_RULES_LOCATION + "Existing/Main.xlsx"), "The project is left as it was");
    }

    // V1-D: a committed folder link to the rules location, an ancestor outside the project, is refused as well
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingAProjectOfAConfiguredGitRepositoryRejectsACommittedFolderLinkToAnAncestor() throws Exception {
        var root = tmp.resolve("design");
        var repository = secured(configuredGitRepository(root));
        saveNewProject(repository, "Existing", null);
        saveNewProject(repository, "Sibling", null);
        // The link leads back to the rules location, so the cleanup would walk the sibling and itself again.
        var linkPath = BASE_RULES_LOCATION + "Existing/loop";
        commitLink(root, linkPath, Path.of(".."));
        var rulesLocation = root.resolve(BASE_RULES_LOCATION);
        var rulesBefore = snapshot(rulesLocation);
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        assertPathRejected(() -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(rulesBefore, snapshot(rulesLocation), "Nothing in the rules location is removed or written");
        assertTrue(Files.isSymbolicLink(root.resolve(linkPath)), "The link is left as it was");
        assertNotNull(repository.check(BASE_RULES_LOCATION + "Existing/Main.xlsx"), "The project is left as it was");
        assertNotNull(repository.check(BASE_RULES_LOCATION + "Sibling/Main.xlsx"), "The sibling is left as it was");
    }

    // V1-D: a Git overwrite runs when its folder holds only a file link, a dangling link and a folder link inside it
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingAProjectOfAConfiguredGitRepositoryWhoseFolderHoldsOnlyLinksItsCleanupRemovesSucceeds()
            throws Exception {
        var root = tmp.resolve("design");
        var outside = Files.createDirectories(tmp.resolve("outside"));
        var canary = Files.writeString(outside.resolve("canary.txt"), "kept");
        var repository = secured(configuredGitRepository(root));
        var first = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, false);
        assertNotNull(saveStrategy.save(repository, first, PROJECT_ARCHIVE),
                "Fixture: the project holds a rules folder");
        var project = root.resolve(BASE_RULES_LOCATION + "Existing");
        commitLink(root, BASE_RULES_LOCATION + "Existing/notes.txt", canary);
        commitLink(root, BASE_RULES_LOCATION + "Existing/ghost", outside.resolve("missing"));
        commitLink(root, BASE_RULES_LOCATION + "Existing/alias", project.resolve("rules"));
        var outsideBefore = snapshot(outside);
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        assertNotNull(saveStrategy.save(repository, model, PROJECT_ARCHIVE), "The saved project folder is reported");

        assertEquals(outsideBefore, snapshot(outside), "Nothing outside the project is touched");
        assertNotNull(repository.check(BASE_RULES_LOCATION + "Existing/rules/Project2-Main.xlsx"),
                "The archive entry is committed");
        assertNull(repository.check(BASE_RULES_LOCATION + "Existing/notes.txt"),
                "The link to a file the archive does not hold is removed");
    }

    // ---------------------------------------------------------------------------------------------
    // V1: every entry is checked in the tree it is written through, that of the branch the Git save checks out
    // A Git repository checks out the branch it saves to only once it writes, and that branch may hold a link the
    // tree checked out before did not.
    // ---------------------------------------------------------------------------------------------

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingOnTheBaseBranchWhileAnotherIsCheckedOutRejectsAnEntryThroughALinkOfTheBaseBranch()
            throws Exception {
        var root = tmp.resolve("design");
        var outside = Files.createDirectories(tmp.resolve("outside"));
        var repository = (BranchRepository) secured(configuredGitRepository(root));
        saveNewProject(repository, "Existing", null);
        repository.createRepositoryBranch("B", null);
        var linkPath = BASE_RULES_LOCATION + "Existing/rules";
        commitLink(root, linkPath, outside);
        // An ordinary save on the branch leaves it checked out, and the branch holds no link.
        saveNewProject(repository.forBranch("B"), "Other", null);
        assertCheckedOut(root, "B");
        assertFalse(Files.isSymbolicLink(root.resolve(linkPath)), "Fixture: the checked-out tree holds no link");
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "No entry is written through a link of the branch the save checks out");
        assertNotNull(repository.check(BASE_RULES_LOCATION + "Existing/Main.xlsx"), "The project is left as it was");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingThroughABranchWhoseTreeHoldsALinkRejectsTheEntryWhileTheBaseBranchIsCheckedOut()
            throws Exception {
        var root = tmp.resolve("design");
        var outside = Files.createDirectories(tmp.resolve("outside"));
        var repository = (BranchRepository) secured(configuredGitRepository(root));
        var baseBranch = repository.getBranch();
        saveNewProject(repository, "Existing", null);
        repository.createRepositoryBranch("B", null);
        var onBranch = repository.forBranch("B");
        var linkPath = BASE_RULES_LOCATION + "Existing/rules";
        saveNewProject(onBranch, "Other", null);
        commitLink(root, linkPath, outside);
        // An ordinary save on the base branch leaves it checked out, with the project folder and without the link.
        saveNewProject(repository, "Another", null);
        assertCheckedOut(root, baseBranch);
        assertFalse(Files.isSymbolicLink(root.resolve(linkPath)), "Fixture: the checked-out tree holds no link");
        assertTrue(Files.isDirectory(root.resolve(BASE_RULES_LOCATION + "Existing")),
                "Fixture: the checked-out tree holds the project folder");
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(onBranch, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "No entry is written through a link of the branch the save checks out");
        assertNotNull(onBranch.check(BASE_RULES_LOCATION + "Existing/Main.xlsx"), "The project is left as it was");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingThroughABranchRejectsAnEntryThroughItsLinkWhenTheCheckedOutTreeLacksTheProjectFolder()
            throws Exception {
        var root = tmp.resolve("design");
        var outside = Files.createDirectories(tmp.resolve("outside"));
        var repository = (BranchRepository) secured(configuredGitRepository(root));
        var baseBranch = repository.getBranch();
        saveNewProject(repository, "Other", null);
        repository.createRepositoryBranch("B", null);
        var onBranch = repository.forBranch("B");
        var linkPath = BASE_RULES_LOCATION + "Existing/rules";
        saveNewProject(onBranch, "Existing", null);
        commitLink(root, linkPath, outside);
        // The base branch has no such project, so the folder is missing once that branch is checked out again.
        saveNewProject(repository, "Another", null);
        assertCheckedOut(root, baseBranch);
        assertFalse(Files.exists(root.resolve(BASE_RULES_LOCATION + "Existing"), LinkOption.NOFOLLOW_LINKS),
                "Fixture: the checked-out tree lacks the project folder");
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(onBranch, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "No entry is written through a link of a project folder only the target branch holds");
        assertNotNull(onBranch.check(BASE_RULES_LOCATION + "Existing/Main.xlsx"), "The project is left as it was");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingThroughABranchOfAMappedGitRepositoryRejectsAnEntryThroughALinkOfThatBranch() throws Exception {
        var root = tmp.resolve("design");
        var outside = Files.createDirectories(tmp.resolve("outside"));
        var repository = (BranchRepository) secured(mapped(configuredGitRepository(root)));
        var baseBranch = repository.getBranch();
        saveNewProject(repository, "Existing", "linked/Existing");
        repository.createRepositoryBranch("B", null);
        var onBranch = repository.forBranch("B");
        var linkPath = "linked/Existing/rules";
        saveNewProject(onBranch, "Other", "linked/Other");
        commitLink(root, linkPath, outside);
        saveNewProject(repository, "Another", "linked/Another");
        assertCheckedOut(root, baseBranch);
        assertFalse(Files.isSymbolicLink(root.resolve(linkPath)), "Fixture: the checked-out tree holds no link");
        assertTrue(Files.isDirectory(root.resolve("linked/Existing")),
                "Fixture: the checked-out tree holds the project folder");
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", "linked/Existing", null, true);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(onBranch, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "No entry is written through a link of a mapped project on the target branch");
        try (var git = Git.open(root.toFile())) {
            assertNotNull(git.getRepository().resolve("B:linked/Existing/Main.xlsx"), "The project is left as it was");
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void aRefusalAFileRepositoryLetsThroughIsTheRejection() throws IOException {
        var root = Files.createDirectories(tmp.resolve("design"));
        var outside = Files.createDirectories(tmp.resolve("outside"));
        var project = root.resolve(BASE_RULES_LOCATION + "Existing");
        // The link appears once the save has begun, after the checks made before it, as a checkout would place it.
        var fileRepository = new FileSystemRepository() {
            @Override
            public FileData save(FileData folderData,
                                 Iterable<FileItem> files,
                                 ChangesetType changesetType) throws IOException {
                Files.createSymbolicLink(Files.createDirectories(project).resolve("rules"), outside);
                return super.save(folderData, files, changesetType);
            }
        };
        fileRepository.setRoot(root);
        closeables.add(fileRepository);
        var repository = secured(fileRepository);
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(outside, "No entry is written through a link that appeared once the save began");
    }

    @Test
    void aChangeNamedOutsideTheProjectFolderIsRefused() throws IOException {
        var root = Files.createDirectories(tmp.resolve("design"));
        var repository = secured(configuredFileRepository(root));
        var stray = new FileItem(BASE_RULES_LOCATION + "Other/rules.xml", new ByteArrayInputStream(new byte[] { 1 }));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, false);

        var e = assertThrows(BadRequestException.class, () -> saveWithChange(repository, model, stray));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertFalse(Files.exists(root.resolve(BASE_RULES_LOCATION + "Other")), "Nothing is written to another folder");
    }

    @Test
    void aChangeClimbingOutOfTheProjectFolderIsRefused() throws IOException {
        var root = Files.createDirectories(tmp.resolve("design"));
        var repository = secured(configuredFileRepository(root));
        var climbing = new FileItem(BASE_RULES_LOCATION + "Existing/../Other/rules.xml",
                new ByteArrayInputStream(new byte[] { 1 }));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, false);

        var e = assertThrows(BadRequestException.class, () -> saveWithChange(repository, model, climbing));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertFalse(Files.exists(root.resolve(BASE_RULES_LOCATION + "Other")), "Nothing is written to another folder");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingAProjectOfAConfiguredFileRepositoryRejectsAGeneratedDescriptorThroughAnOutsideLink()
            throws IOException {
        var root = tmp.resolve("design");
        var project = Files.createDirectories(root.resolve(BASE_RULES_LOCATION + "Existing"));
        var outside = Files.writeString(Files.createDirectories(tmp.resolve("outside")).resolve("leak.xml"), "kept");
        // The archive holds no descriptor, so the save generates one and would write it through this link.
        Files.createSymbolicLink(project.resolve(ProjectDescriptor.FILE_NAME), outside);
        var repository = secured(configuredFileRepository(root));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        var e = assertThrows(BadRequestException.class,
                () -> saveStrategy.save(repository, model, EXCEL_ONLY_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEquals("kept", Files.readString(outside), "The generated descriptor is not written through the link");
    }

    @Test
    void overwritingAProjectOfAConfiguredFileRepositoryWithAnArchiveWithoutADescriptorSucceeds() throws IOException {
        var root = tmp.resolve("design");
        var project = root.resolve(BASE_RULES_LOCATION + "Existing");
        Files.write(Files.createDirectories(project).resolve(ProjectDescriptor.FILE_NAME), new byte[] { 1 });
        var repository = secured(configuredFileRepository(root));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        assertNotNull(saveStrategy.save(repository, model, EXCEL_ONLY_ARCHIVE), "The saved project folder is reported");

        assertTrue(Files.isRegularFile(project.resolve("Main.xlsx")), "The archive entry is saved");
        try (var stream = Files.newInputStream(project.resolve(ProjectDescriptor.FILE_NAME))) {
            var descriptor = ProjectDescriptor.read(stream);
            assertNotNull(descriptor, "The generated descriptor replaces the old one");
            assertEquals("Existing", descriptor.getName());
        }
    }

    @Test
    void saveRejectsAProjectNameTheNameCheckerRefuses() throws IOException {
        var root = Files.createDirectories(tmp.resolve("design"));
        var repository = secured(configuredFileRepository(root));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Bad:Name", null, null, false);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertEmpty(root, "Nothing is written for a refused project name");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingAProjectOfAConfiguredFileRepositoryRejectsAnEntryThroughADanglingLink() throws IOException {
        var root = tmp.resolve("design");
        var project = Files.createDirectories(root.resolve(BASE_RULES_LOCATION + "Existing"));
        var missing = tmp.resolve("outside/missing");
        Files.createSymbolicLink(project.resolve("rules"), missing);
        var repository = secured(configuredFileRepository(root));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, null, true);

        var e = assertThrows(BadRequestException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(INVALID_PATH, e.getErrorCode());
        assertFalse(Files.exists(missing.getParent()), "Nothing is created where the dangling link points");
    }

    @Test
    void aFailureOfTheRepositoryItselfPropagatesUnchanged() throws IOException {
        var root = Files.createDirectories(tmp.resolve("design"));
        var repository = mock(Repository.class, Mockito.withSettings().extraInterfaces(LocalWorkingTree.class));
        when(((LocalWorkingTree) repository).getLocalWorkingTree()).thenReturn(root);
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setFolders(true).build());
        var failure = new IOException("The repository cannot record the save", new IllegalStateException("Busy"));
        when(repository.save(any(FileData.class), any(), eq(ChangesetType.FULL))).thenAnswer(a -> {
            // Every change is inside the project folder and is taken, then the repository fails on its own.
            // V1-D: Mockito's typed argument accessor, so the changes need no unchecked cast
            Iterable<FileItem> changes = a.getArgument(1);
            for (FileItem change : changes) {
                IOUtils.closeQuietly(change.getStream());
            }
            throw failure;
        });
        var model = new CreateUpdateProjectModel("design", "jsmith", "Fresh", null, null, false);

        var e = assertThrows(IOException.class, () -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        Assertions.assertSame(failure, e, "The failure of the repository is reported as it is");
    }

    // ---------------------------------------------------------------------------------------------
    // V1-D: the remaining surface D link payloads, over the secured file repository the REST archive route receives
    // ---------------------------------------------------------------------------------------------

    // V1-D: the rules location itself is a link to outside, so the new project folder below it would leave the root
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void saveIntoAConfiguredFileRepositoryRejectsARulesLocationLinkedOutside() throws IOException {
        var root = Files.createDirectories(tmp.resolve("repo"));
        var outside = Files.createDirectories(tmp.resolve("outside"));
        Files.createSymbolicLink(root.resolve(BASE_RULES_LOCATION), outside);
        var repository = secured(configuredFileRepository(root));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Project 1", null, "c", false);

        assertPathRejected(() -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(Map.of(), snapshot(outside), "Nothing is written through a rules location linked outside");
    }

    // V1-D: an ancestor of a mapped project folder is a link to outside
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void saveIntoAMappedConfiguredFileRepositoryRejectsAnAncestorFolderLinkedOutside() throws IOException {
        var root = Files.createDirectories(tmp.resolve("repo"));
        var outside = Files.createDirectories(tmp.resolve("outside"));
        Files.createSymbolicLink(root.resolve("link"), outside);
        var repository = secured(mapped(configuredFileRepository(root)));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Project 1", "link/Project 1", "c", false);

        assertPathRejected(() -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertEquals(Map.of(), snapshot(outside), "Nothing is written below a mapped ancestor linked outside");
    }

    // V1-D: the new project folder is a dangling link, which can neither be resolved nor written through
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void saveIntoAConfiguredFileRepositoryRejectsADanglingProjectFolderLink() throws IOException {
        var root = Files.createDirectories(tmp.resolve("repo"));
        var missing = tmp.resolve("outside/ghost");
        var rulesLocation = Files.createDirectories(root.resolve(BASE_RULES_LOCATION));
        var ghost = Files.createSymbolicLink(rulesLocation.resolve("ghost"), missing);
        var repository = secured(configuredFileRepository(root));
        var model = new CreateUpdateProjectModel("design", "jsmith", "ghost", null, "c", false);

        assertPathRejected(() -> saveStrategy.save(repository, model, PROJECT_ARCHIVE));

        assertFalse(Files.exists(missing.getParent(), LinkOption.NOFOLLOW_LINKS),
                "Nothing is created where the dangling link points");
        assertTrue(Files.isSymbolicLink(ghost), "The dangling link is left as it was");
    }

    // V1-D: a Unix symlink entry to outside and an entry below it, saved into the flat secured file repository
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void saveIntoAConfiguredFileRepositoryStoresASymlinkEntryAsARegularFileAndNothingBelowIt() throws IOException {
        var root = Files.createDirectories(tmp.resolve("repo"));
        var repository = secured(configuredFileRepository(root));
        // A flat repository stores the project under its name and ignores the path.
        var model = new CreateUpdateProjectModel("design", "jsmith", "SecV1D12", "SecV1D12", "c", false);

        assertSymlinkEntrySavedAsARegularFile(repository, model, root, root.resolve(BASE_RULES_LOCATION + "SecV1D12"));
    }

    // V1-D: the same symlink-entry archive, saved into the mapped secured file repository at its internal path
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void saveIntoAMappedConfiguredFileRepositoryStoresASymlinkEntryAsARegularFileAndNothingBelowIt()
            throws IOException {
        var root = Files.createDirectories(tmp.resolve("repo"));
        var repository = secured(mapped(configuredFileRepository(root)));
        var model = new CreateUpdateProjectModel("design", "jsmith", "SecV1D12", "catalog/SecV1D12", "c", false);

        assertSymlinkEntrySavedAsARegularFile(repository, model, root, root.resolve("catalog/SecV1D12"));
    }

    // V1-D: overwrite through an existing link (0.6.2.4 D15), with raw archive entry names that reach the link
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void overwritingAProjectRejectsARawArchiveEntryThroughAnExistingLinkAndLeavesTheProjectAsItWas()
            throws IOException {
        var root = Files.createDirectories(tmp.resolve("repo"));
        var outside = Files.createDirectories(tmp.resolve("outside"));
        var project = Files.createDirectories(root.resolve(BASE_RULES_LOCATION + "Existing"));
        var descriptor = "<project><name>Existing</name></project>".getBytes(StandardCharsets.UTF_8);
        Files.write(project.resolve(ProjectDescriptor.FILE_NAME), descriptor);
        // V1-D: an ordinary file of the project and one outside it, so a change to their content is seen as well
        var existingWorkbook = new byte[16];
        ThreadLocalRandom.current().nextBytes(existingWorkbook);
        Files.write(project.resolve("Main.xlsx"), existingWorkbook);
        var sentinel = new byte[16];
        ThreadLocalRandom.current().nextBytes(sentinel);
        Files.write(outside.resolve("sentinel.bin"), sentinel);
        var link = Files.createSymbolicLink(project.resolve("link"), outside);
        var before = snapshot(project);
        var outsideBefore = snapshot(outside);
        var workbook = new byte[16];
        ThreadLocalRandom.current().nextBytes(workbook);
        var entries = new LinkedHashMap<String, byte[]>();
        entries.put(ProjectDescriptor.FILE_NAME, descriptor);
        entries.put("link/evil.xlsx", workbook);
        var archive = zip(tmp.resolve("overwrite-through-link.zip"), entries);
        var repository = secured(configuredFileRepository(root));
        var model = new CreateUpdateProjectModel("design", "jsmith", "Existing", null, "c", true);

        assertPathRejected(() -> saveStrategy.save(repository, model, archive));

        assertFalse(Files.exists(outside.resolve("evil.xlsx"), LinkOption.NOFOLLOW_LINKS),
                "No entry is written through the link the existing project folder holds");
        assertEquals(outsideBefore, snapshot(outside), "The folder the link points to is left as it was");
        assertEquals(before, snapshot(project), "The existing project folder is left as it was");
        assertTrue(Files.isSymbolicLink(link), "The link itself is left as it was");
        assertArrayEquals(descriptor, Files.readAllBytes(project.resolve(ProjectDescriptor.FILE_NAME)),
                "The existing descriptor is left as it was");
    }

    // V1-D: defense in depth, a climbing mapped path on a non-filesystem backend is refused lexically before saving
    @Test
    void saveIntoAMockedMappedRepositoryRejectsAClimbingPathBeforeSaving() throws Exception {
        mockDesignRepository(MappedRepository.class, "design1", builder -> builder.setVersions(true));
        var model = new CreateUpdateProjectModel("design1", "jsmith", "Project 1", "a/../../x", "c", false);
        var repo = designTimeRepositoryMock.getRepository(model.getRepoName());

        assertPathRejected(() -> saveStrategy.save(repo, model, PROJECT_ARCHIVE));

        verify(repo, never()).save(any(FileData.class), any(), eq(ChangesetType.FULL));
        verify(repo, never()).save(any(FileData.class), any(InputStream.class));
    }

    private ProjectDescriptor assertProjectDescriptor(String expectedRootFolder,
                                                      String expectedName,
                                                      FileItem descriptor) {
        assertNotNull(descriptor);
        assertEquals(expectedRootFolder + ProjectDescriptor.FILE_NAME,
                descriptor.getData().getName());
        var projectDescriptor = ProjectDescriptor.read(descriptor.getStream());
        assertNotNull(projectDescriptor);
        assertEquals(expectedName, projectDescriptor.getName());
        return projectDescriptor;
    }

    private static void assertDescriptorAddedWithoutMovingFiles(Path source, InputStream actual) throws IOException {
        var actualEntries = new HashMap<String, byte[]>();
        try (var actualZipStream = new ZipInputStream(actual)) {
            ZipEntry entry;
            while ((entry = actualZipStream.getNextEntry()) != null) {
                if (!entry.isDirectory()) {
                    actualEntries.put(entry.getName(), actualZipStream.readAllBytes());
                }
            }
        }
        var descriptor = ProjectDescriptor
                .read(new ByteArrayInputStream(actualEntries.remove(ProjectDescriptor.FILE_NAME)));
        assertNotNull(descriptor);
        assertEquals("Project 2", descriptor.getName());
        assertRootXlsxModule(descriptor);
        try (FileSystem fs = FileSystems.newFileSystem(ZipUtils.toJarURI(source), Map.of())) {
            assertFalse(Files.exists(fs.getPath("/" + ProjectDescriptor.FILE_NAME)));
            assertArrayEquals(Files.readAllBytes(fs.getPath("/Main.xlsx")),
                    actualEntries.remove("Main.xlsx"));
        }
        assertTrue(actualEntries.isEmpty());
    }

    private static ProjectDescriptor descriptor(InputStream projectArchive) throws IOException {
        try (var zipStream = new ZipInputStream(projectArchive)) {
            ZipEntry entry;
            while ((entry = zipStream.getNextEntry()) != null) {
                if (ProjectDescriptor.FILE_NAME.equals(entry.getName())) {
                    return ProjectDescriptor.read(zipStream);
                }
            }
        }
        throw new AssertionError("Project descriptor is missing");
    }

    private static void assertRootXlsxModule(ProjectDescriptor descriptor) {
        assertEquals(List.of("*.xlsx"), descriptor.getModules().stream().map(Module::getRulesRootPath).toList());
    }

    private static void assertSame(Path expectedArchive, InputStream actualStream) throws IOException {
        try (FileSystem fs = FileSystems.newFileSystem(ZipUtils.toJarURI(expectedArchive),
                Map.of("encoding", StandardCharsets.UTF_8.displayName()))) {
            var root = fs.getPath("/");
            try (var actualZipStream = new ZipInputStream(actualStream)) {
                ZipEntry ze;
                while ((ze = actualZipStream.getNextEntry()) != null) {
                    if (!ze.isDirectory()) {
                        var expected = root.resolve(ze.getName());
                        try (InputStream expectedStream = Files.newInputStream(expected)) {
                            if (!ze.getName().equals("rules.xml")) {
                                assertTrue(
                                        org.apache.commons.io.IOUtils.contentEquals(expectedStream, actualZipStream));
                            } else {
                                // rules xml must be modified
                                assertFalse(
                                        org.apache.commons.io.IOUtils.contentEquals(expectedStream, actualZipStream));
                            }
                        }
                    }
                }
            }
        }
    }

    private static void assertSame(Path expectedArchive,
                                   String expectedPrefix,
                                   Map<String, FileItem> actualFileItems) throws IOException {
        try (FileSystem fs = FileSystems.newFileSystem(ZipUtils.toJarURI(expectedArchive),
                Map.of("encoding", StandardCharsets.UTF_8.displayName()))) {
            var root = fs.getPath("/");
            actualFileItems.forEach((actualName, actualItem) -> {
                assertTrue(actualName.startsWith(expectedPrefix));
                var actualFileName = actualName.substring(expectedPrefix.length());
                var expected = root.resolve(actualFileName);
                assertTrue(Files.exists(expected));
                try (InputStream expectedStream = Files.newInputStream(expected);
                     var actualStream = actualItem.getStream()) {
                    if (!actualFileName.equals("rules.xml")) {
                        assertTrue(org.apache.commons.io.IOUtils.contentEquals(expectedStream, actualStream));
                    } else {
                        // rules xml must be modified
                        assertFalse(org.apache.commons.io.IOUtils.contentEquals(expectedStream, actualStream));
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }

    private Map<String, FileItem> captureFileItems(Repository repo) throws IOException {
        var actualFileItems = new HashMap<String, FileItem>();
        when(repo.save(any(FileData.class), any(), eq(ChangesetType.FULL))).thenAnswer(a -> {
            // noinspection unchecked
            for (FileItem fileItem : (Iterable<FileItem>) a.getArguments()[1]) {
                if (actualFileItems.containsKey(fileItem.getData().getName())) {
                    throw new RuntimeException("Unexpected entry!");
                }
                var os = new ByteArrayOutputStream();
                IOUtils.copyAndClose(fileItem.getStream(), os);
                actualFileItems.put(fileItem.getData().getName(),
                        new FileItem(fileItem.getData(), new ByteArrayInputStream(os.toByteArray())));
            }
            return null;
        });
        return actualFileItems;
    }

    private AtomicReference<InputStream> captureStream(Repository repo) throws IOException {
        var holder = new AtomicReference<InputStream>();
        when(repo.save(any(FileData.class), any())).thenAnswer(a -> {
            var os = new ByteArrayOutputStream();
            IOUtils.copyAndClose((InputStream) a.getArguments()[1], os);
            holder.set(new ByteArrayInputStream(os.toByteArray()));
            return null;
        });
        return holder;
    }

    private <T extends Repository> T mockDesignRepository(Class<T> tClass,
                                                          String repoName,
                                                          Consumer<FeaturesBuilder> featureConfig) throws IOException {
        T mockedRepo = mock(tClass);
        when(designTimeRepositoryMock.getRepository(repoName)).thenReturn(mockedRepo);

        when(mockedRepo.check(anyString())).thenReturn(null);

        var featuresBuilder = new FeaturesBuilder(mockedRepo);
        if (MappedRepository.class.isAssignableFrom(tClass)) {
            when(((MappedRepository) mockedRepo).getDelegate()).thenReturn(mockedRepo);
            featuresBuilder.setMappedFolders(true);
            featuresBuilder.setFolders(true);
        }
        featureConfig.accept(featuresBuilder);
        when(mockedRepo.supports()).thenReturn(featuresBuilder.build());

        return mockedRepo;
    }

    // V1: the application instantiates its design repositories from their settings, path-checked
    /**
     * A {@code repo-file} design repository over the folder, built from its settings the way the application
     * builds it, and therefore behind {@link PathCheckedRepository}. It is closed after the test.
     */
    private Repository configuredFileRepository(Path root) {
        var settings = Map.of("repository.design.factory", "repo-file", "repository.design.uri", root.toString());
        var configured = RepositoryInstatiator.newRepository("repository.design", settings::get);
        closeables.add(configured);
        assertInstanceOf(PathCheckedRepository.class, configured, "Fixture: the settings build a path-checked wrapper");
        return configured;
    }

    // V1: a Git design repository over a local folder, built from its settings as the application builds it
    /**
     * A {@code repo-git} design repository whose local Git repository and working tree are the folder, built from
     * its settings the way the application builds it, and therefore behind {@link PathCheckedRepository}. It is
     * closed after the test.
     */
    private Repository configuredGitRepository(Path root) {
        var settings = Map.of("repository.design.factory", "repo-git", "repository.design.uri", root.toString());
        var configured = RepositoryInstatiator.newRepository("repository.design", settings::get);
        closeables.add(configured);
        assertInstanceOf(PathCheckedRepository.class, configured, "Fixture: the settings build a path-checked wrapper");
        return configured;
    }

    // V1: a project the strategy saved first, holding Main.xlsx and its generated descriptor but no rules folder
    /**
     * Saves the archive that holds only {@code Main.xlsx} as a new project, so a later overwrite with
     * {@link #PROJECT_ARCHIVE} writes {@code rules/Project2-Main.xlsx} into a folder the project does not hold yet.
     */
    private void saveNewProject(Repository repository, String projectName, String path) throws IOException {
        var model = new CreateUpdateProjectModel("design", "jsmith", projectName, path, null, false);
        assertNotNull(saveStrategy.save(repository, model, EXCEL_ONLY_ARCHIVE), "Fixture: the project is saved");
    }

    // V1: the mapped layout of a design repository, whose projects sit where their file mapping places them
    private Repository mapped(Repository delegate) throws IOException {
        var mapped = MappedRepository.create(delegate, BASE_RULES_LOCATION);
        closeables.add(mapped);
        return mapped;
    }

    // V1: the secured wrapper the REST route receives, for a user granted every repository permission
    private static Repository secured(Repository repository) {
        var acl = mock(SimpleRepositoryAclService.class,
                invocation -> invocation.getMethod().getReturnType() == boolean.class
                        ? true
                        : Mockito.RETURNS_DEFAULTS.answer(invocation));
        return SecuredRepositoryFactory.wrapToSecureRepo(repository, acl);
    }

    // V1: a folder nothing was written to
    private static void assertEmpty(Path folder, String message) throws IOException {
        try (var entries = Files.list(folder)) {
            assertEquals(0, entries.count(), message);
        }
    }

    // V1: a link to outside committed on the checked-out branch of the working tree, as a push from elsewhere does
    private static void commitLink(Path workingTree, String linkPath, Path target) throws Exception {
        Files.createSymbolicLink(workingTree.resolve(linkPath), target);
        try (var git = Git.open(workingTree.toFile())) {
            git.add().addFilepattern(linkPath).call();
            git.commit()
                    .setMessage("Track a link to outside")
                    .setAuthor("Test", "test@example.org")
                    .setCommitter("Test", "test@example.org")
                    .setSign(false)
                    .call();
            assertEquals(FileMode.SYMLINK,
                    git.getRepository().readDirCache().getEntry(linkPath).getFileMode(),
                    "Fixture: the link is tracked as a link");
        }
    }

    // V1: an upload whose archive yields the one given change, for a change no real archive entry can name
    private FileData saveWithChange(Repository repository,
                                    CreateUpdateProjectModel model,
                                    FileItem change) throws IOException {
        try (var ignored = Mockito.mockConstruction(FileChangesFromFolder.class,
                (changes, context) -> when(changes.iterator()).thenReturn(List.of(change).iterator()))) {
            return saveStrategy.save(repository, model, PROJECT_ARCHIVE);
        }
    }

    // V1: the branch the working tree holds, which is the one the last save checked out
    private static void assertCheckedOut(Path workingTree, String branch) throws IOException {
        try (var git = Git.open(workingTree.toFile())) {
            assertEquals(branch, git.getRepository().getBranch(), "Fixture: the branch checked out");
        }
    }

    // V1-D: an archive holding the given entries under their raw names, in the given order
    private static Path zip(Path target, Map<String, byte[]> entries) throws IOException {
        try (var zos = new ZipArchiveOutputStream(Files.newOutputStream(target))) {
            for (var entry : entries.entrySet()) {
                zos.putArchiveEntry(new ZipArchiveEntry(entry.getKey()));
                zos.write(entry.getValue());
                zos.closeArchiveEntry();
            }
        }
        return target;
    }

    // V1-D: an archive holding the descriptor, a Unix symlink entry 'link' to the target, then 'link/passwd'
    private static Path symlinkEntryArchive(Path target,
                                            byte[] descriptor,
                                            Path linkTarget,
                                            byte[] belowLink) throws IOException {
        try (var zos = new ZipArchiveOutputStream(Files.newOutputStream(target))) {
            zos.putArchiveEntry(new ZipArchiveEntry(ProjectDescriptor.FILE_NAME));
            zos.write(descriptor);
            zos.closeArchiveEntry();
            // A symlink entry holds the path it points to as its content.
            var link = new ZipArchiveEntry("link");
            link.setUnixMode(0120777);
            zos.putArchiveEntry(link);
            zos.write(linkTarget.toString().getBytes(StandardCharsets.UTF_8));
            zos.closeArchiveEntry();
            zos.putArchiveEntry(new ZipArchiveEntry("link/passwd"));
            zos.write(belowLink);
            zos.closeArchiveEntry();
        }
        return target;
    }

    // V1-D: saves a symlink-entry archive whose link names an outside folder; no link and no outside effect follow
    /**
     * Saves an archive holding a Unix symlink entry {@code link} to a folder outside the repository root and an
     * entry {@code link/passwd} below it, then checks that no link is created, that nothing beside the repository
     * root changes, that the repository holds nothing outside the project folder and that the outside folder's
     * content never reaches it. The symlink entry is stored as a regular file holding the link target as text, and
     * the entry below it is not stored.
     */
    private void assertSymlinkEntrySavedAsARegularFile(Repository repository,
                                                       CreateUpdateProjectModel model,
                                                       Path root,
                                                       Path project) throws IOException {
        var canary = Files.createDirectories(tmp.resolve("outside"));
        var secret = new byte[32];
        ThreadLocalRandom.current().nextBytes(secret);
        Files.write(canary.resolve("passwd"), secret);
        var belowLink = new byte[16];
        ThreadLocalRandom.current().nextBytes(belowLink);
        var descriptor = "<project><name>SecV1D12</name></project>".getBytes(StandardCharsets.UTF_8);
        var archive = symlinkEntryArchive(tmp.resolve("d12-symlink.zip"), descriptor, canary, belowLink);
        var canaryBefore = snapshot(canary);
        var besideBefore = besideRoot(root);

        assertNotNull(saveStrategy.save(repository, model, archive), "The saved project folder is reported");

        List<Path> saved;
        try (var paths = Files.walk(root)) {
            saved = paths.toList();
        }
        assertEquals(List.of(), saved.stream().filter(Files::isSymbolicLink).toList(),
                "No symbolic link is created under the repository root");
        assertEquals(canaryBefore, snapshot(canary), "The folder the symlink entry names is left as it was");
        assertEquals(besideBefore, besideRoot(root), "Nothing is written beside the repository root");
        assertEquals(List.of(), saved.stream().filter(p -> !p.startsWith(project) && !project.startsWith(p)).toList(),
                "The repository holds no entry outside the project folder");
        assertTrue(Files.isRegularFile(project.resolve(ProjectDescriptor.FILE_NAME), LinkOption.NOFOLLOW_LINKS),
                "The descriptor is saved in the project folder");
        var link = project.resolve("link");
        assertTrue(Files.isRegularFile(link, LinkOption.NOFOLLOW_LINKS),
                "The symlink entry is stored as a regular file");
        assertArrayEquals(canary.toString().getBytes(StandardCharsets.UTF_8), Files.readAllBytes(link),
                "The stored file holds the link target as text");
        assertFalse(Files.exists(project.resolve("link/passwd"), LinkOption.NOFOLLOW_LINKS),
                "The entry below the symlink entry is not stored");
        // ISO-8859-1 maps each byte to one char, so a byte sequence is found as a substring.
        var secretText = new String(secret, StandardCharsets.ISO_8859_1);
        for (var file : saved) {
            if (Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                assertFalse(new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1).contains(secretText),
                        "The content of the folder the link names never reaches " + root.relativize(file));
            }
        }
    }

    // V1-D: the snapshot of the test folder without the repository root, so a write beside the root is seen
    private Map<String, String> besideRoot(Path root) throws IOException {
        var beside = new TreeMap<>(snapshot(tmp));
        beside.keySet().removeIf(name -> tmp.resolve(name).startsWith(root));
        return beside;
    }

    // V1-D: each entry below a folder, links never followed: its kind, a link's target, a file's size and SHA-256
    private static Map<String, String> snapshot(Path dir) throws IOException {
        if (!Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
            return Map.of();
        }
        var entries = new TreeMap<String, String>();
        try (var paths = Files.walk(dir)) {
            for (var path : paths.filter(p -> !p.equals(dir)).toList()) {
                String state;
                if (Files.isSymbolicLink(path)) {
                    state = "link " + Files.readSymbolicLink(path);
                } else if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                    state = "dir";
                } else {
                    state = "file " + Files.size(path) + " " + sha256(Files.readAllBytes(path));
                }
                entries.put(dir.relativize(path).toString(), state);
            }
        }
        return entries;
    }

    // V1-D: the content fingerprint of a snapshot entry, so a snapshot never holds the content itself
    private static String sha256(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // V1-D: the rejection the upload destination guard raises, 400 with the existing invalid-path key
    private static void assertPathRejected(Executable call) {
        var e = assertThrows(BadRequestException.class, call);
        assertEquals(INVALID_PATH, e.getErrorCode());
    }
}

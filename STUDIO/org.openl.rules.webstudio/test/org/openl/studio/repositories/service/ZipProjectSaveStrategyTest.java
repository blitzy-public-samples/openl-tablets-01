package org.openl.studio.repositories.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import org.openl.rules.project.model.Module;
import org.openl.rules.project.model.ProjectDescriptor;
import org.openl.rules.repository.PathCheckedRepository;
import org.openl.rules.repository.RepositoryInstatiator;
import org.openl.rules.repository.api.ChangesetType;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
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
    // V1: the upload destination guard over a file repository built from its settings, as the
    // application builds it, and so behind PathCheckedRepository and the secured wrapper
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
                        ? Boolean.TRUE
                        : Mockito.RETURNS_DEFAULTS.answer(invocation));
        return SecuredRepositoryFactory.wrapToSecureRepo(repository, acl);
    }

    // V1: a folder nothing was written to
    private static void assertEmpty(Path folder, String message) throws IOException {
        try (var entries = Files.list(folder)) {
            assertEquals(0, entries.count(), message);
        }
    }
}

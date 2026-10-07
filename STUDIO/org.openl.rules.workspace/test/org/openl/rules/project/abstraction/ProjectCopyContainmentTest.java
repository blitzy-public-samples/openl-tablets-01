package org.openl.rules.project.abstraction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipInputStream;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.AdditionalAnswers;

import org.openl.rules.common.ProjectException;
import org.openl.rules.project.impl.local.DummyLockEngine;
import org.openl.rules.project.impl.local.LocalRepository;
import org.openl.rules.project.impl.local.MetainfoRegistry;
import org.openl.rules.repository.RepositoryInstatiator;
import org.openl.rules.repository.api.Features;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.api.RepositoryDelegate;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.workspace.WorkspaceUser;
import org.openl.rules.workspace.WorkspaceUserImpl;
import org.openl.rules.workspace.dtr.impl.MappedRepository;
import org.openl.util.FileUtils;
import org.openl.util.IOUtils;

/**
 * V1: opening and saving a project copy only the files whose real location stays inside the source project folder.
 *
 * <p>A file-backed source, a {@code repo-file} design repository or the user's working copy, lists a link to a
 * regular file and reads through it. A link to a file outside the repository, to a file of another project or to
 * nothing is therefore neither read nor copied, while a link that stays inside the project is copied with its
 * content. A project folder that is itself reached through a link is refused before anything is read or written.
 * A file that a concurrent save is replacing is still copied. Other backends are not read through filesystem links
 * and copy every file, with no filesystem call.
 */
@DisabledOnOs(OS.WINDOWS)
class ProjectCopyContainmentTest {

    private static final String PROJECT = "Example 1";
    private static final String MAIN = "rules/Main.xlsx";
    private static final String INNER = "rules/Inner.xlsx";
    private static final String OUTSIDE_LINK = "leak.txt";
    private static final String SIBLING_LINK = "sibling.properties";
    private static final String DANGLING_LINK = "dangling.txt";
    private static final String WORKSPACE_LINK = "leak2.txt";

    /** How the design repository is reached, as the application reaches a {@code repo-file} design repository. */
    enum DesignKind {
        /** A bare file repository. */
        PLAIN,
        /** A {@code repo-file} repository built from its settings, behind the path-checking wrapper. */
        CONFIGURED,
        /** The configured repository behind a delegating wrapper, as the secured wrapper holds it. */
        DELEGATED,
        /** The configured repository behind the folder mapping of a mapped design repository. */
        MAPPED
    }

    @TempDir
    Path designRoot;

    @TempDir
    Path userDir;

    @TempDir
    Path outside;

    @TempDir
    Path archiveRoot;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final WorkspaceUser user = new WorkspaceUserImpl("jdoe", id -> new UserInfo("jdoe"));
    private MetainfoRegistry registry;
    private LocalRepository localRepository;
    private String secret;
    private Path outsideFile;
    private String siblingContent;
    private @Nullable Path siblingFile;

    @BeforeEach
    void init() throws IOException {
        registry = MetainfoRegistry.open(userDir);
        localRepository = new LocalRepository(userDir, registry);
        localRepository.setId("design");
        localRepository.initialize();
        secret = "outside-" + UUID.randomUUID();
        outsideFile = Files.writeString(outside.resolve("secret.txt"), secret);
        siblingContent = "sibling-" + UUID.randomUUID();
    }

    @AfterEach
    void closeRepositories() {
        closeables.forEach(IOUtils::closeQuietly);
    }

    @ParameterizedTest
    @EnumSource(DesignKind.class)
    void openFromFileDesignCopiesOnlyFilesInsideTheProject(DesignKind kind) throws Exception {
        var folder = kind == DesignKind.MAPPED ? "catalog/" + PROJECT : PROJECT;
        var designProject = writeDesignProject(folder);
        var design = design(kind);
        var project = rulesProject(design, designName(kind, design));

        project.open();

        var workingCopy = userDir.resolve(PROJECT);
        assertEquals("design content", Files.readString(workingCopy.resolve(MAIN)));
        assertFalse(Files.isSymbolicLink(workingCopy.resolve(INNER)), "A link inside the project is copied as a file.");
        assertEquals("design content", Files.readString(workingCopy.resolve(INNER)),
                "A link that stays inside the project is copied with its content.");
        assertAbsent(workingCopy.resolve(OUTSIDE_LINK));
        assertAbsent(workingCopy.resolve(SIBLING_LINK));
        assertAbsent(workingCopy.resolve(DANGLING_LINK));
        assertNoFileHolds(workingCopy, secret);
        assertNoFileHolds(workingCopy, siblingContent);
        assertOutsideFilesUnchanged();
        assertTrue(Files.isSymbolicLink(designProject.resolve(OUTSIDE_LINK)), "Opening does not touch the design.");
    }

    @Test
    void saveIntoFileDesignLeavesOutAWorkspaceLinkAndRemovesTheDesignLinks() throws Exception {
        var designProject = writeDesignProject(PROJECT);
        var design = design(DesignKind.CONFIGURED);
        var project = rulesProject(design, PROJECT);
        project.open();
        var workingCopy = userDir.resolve(PROJECT);
        Files.createSymbolicLink(workingCopy.resolve(WORKSPACE_LINK), outsideFile);
        saveLocally(MAIN, "edited content");

        project.save(user);

        assertEquals("edited content", Files.readString(designProject.resolve(MAIN)));
        assertAbsent(designProject.resolve(WORKSPACE_LINK));
        assertNoFileHolds(designRoot, secret);
        // The design links the open left out are removed from the project folder, never their targets
        assertAbsent(designProject.resolve(OUTSIDE_LINK));
        assertAbsent(designProject.resolve(SIBLING_LINK));
        assertOutsideFilesUnchanged();
        assertTrue(Files.isSymbolicLink(workingCopy.resolve(WORKSPACE_LINK)), "Saving does not touch the link.");
    }

    @Test
    void saveDiffLeavesOutAWorkspaceLinkWithoutReadingIt() throws Exception {
        var designProject = designRoot.resolve(PROJECT);
        Files.createDirectories(designProject.resolve("rules"));
        Files.writeString(designProject.resolve(MAIN), "design content");
        var design = new VersionedFileRepository(true);
        design.setRoot(designRoot);
        design.setId("design");
        var watched = spy(localRepository);
        var project = new RulesProject(user,
                watched,
                watched.check(PROJECT),
                design,
                design.check(PROJECT),
                new DummyLockEngine());
        project.open();
        var workingCopy = userDir.resolve(PROJECT);
        Files.createSymbolicLink(workingCopy.resolve(WORKSPACE_LINK), outsideFile);
        Files.writeString(workingCopy.resolve("rules/Added.xlsx"), "added content");

        project.save(user);

        assertEquals("added content", Files.readString(designProject.resolve("rules/Added.xlsx")));
        assertEquals("design content", Files.readString(designProject.resolve(MAIN)));
        assertAbsent(designProject.resolve(WORKSPACE_LINK));
        assertNoFileHolds(designRoot, secret);
        verify(watched, never()).read(PROJECT + "/" + WORKSPACE_LINK);
        verify(watched, never()).readHistory(eq(PROJECT + "/" + WORKSPACE_LINK), any());
        assertOutsideFilesUnchanged();
    }

    @Test
    void saveIntoAnArchiveLeavesOutAWorkspaceLink() throws Exception {
        var workingCopy = userDir.resolve(PROJECT);
        Files.createDirectories(workingCopy.resolve("rules"));
        Files.writeString(workingCopy.resolve(MAIN), "local content");
        Files.createSymbolicLink(workingCopy.resolve(WORKSPACE_LINK), outsideFile);
        Files.createSymbolicLink(workingCopy.resolve(INNER), workingCopy.resolve(MAIN));
        var archives = new FileSystemRepository() {
            @Override
            public Features supports() {
                return new FeaturesBuilder(this).setVersions(false).setFolders(false).build();
            }
        };
        archives.setRoot(archiveRoot);
        var target = new AProject(archives, PROJECT);

        target.update(new AProject(localRepository, PROJECT), user);

        var entries = new ArrayList<String>();
        var contents = new ArrayList<String>();
        try (var zip = new ZipInputStream(Files.newInputStream(archiveRoot.resolve(PROJECT)))) {
            for (var entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                entries.add(entry.getName());
                contents.add(new String(zip.readAllBytes(), StandardCharsets.UTF_8));
            }
        }
        assertEquals(List.of(INNER, MAIN), entries.stream().sorted().toList());
        assertEquals(List.of("local content", "local content"), contents);
        assertOutsideFilesUnchanged();
    }

    @Test
    void openRefusesADesignProjectFolderThatIsALink() throws Exception {
        var elsewhere = outside.resolve("elsewhere");
        Files.createDirectories(elsewhere.resolve("rules"));
        Files.writeString(elsewhere.resolve(MAIN), "elsewhere content");
        Files.createSymbolicLink(designRoot.resolve(PROJECT), elsewhere);
        var design = design(DesignKind.PLAIN);
        var project = rulesProject(design, PROJECT);

        var error = assertThrows(ProjectException.class, project::open);

        assertEquals("The folder of the project '" + PROJECT + "' is reached through a link or cannot be resolved.",
                error.getMessage());
        assertFalse(Files.exists(userDir.resolve(PROJECT), LinkOption.NOFOLLOW_LINKS), "Nothing may be copied.");
        assertNull(registry.get(PROJECT), "No metainfo record may be written.");
        assertEquals("elsewhere content", Files.readString(elsewhere.resolve(MAIN)));
    }

    @Test
    void saveRefusesAWorkingCopyFolderThatIsALink() throws Exception {
        var designProject = designRoot.resolve(PROJECT);
        Files.createDirectories(designProject.resolve("rules"));
        Files.writeString(designProject.resolve(MAIN), "design content");
        var project = rulesProject(design(DesignKind.CONFIGURED), PROJECT);
        project.open();
        var elsewhere = outside.resolve("elsewhere");
        Files.createDirectories(elsewhere.resolve("rules"));
        Files.writeString(elsewhere.resolve(MAIN), "elsewhere content");
        FileUtils.delete(userDir.resolve(PROJECT));
        Files.createSymbolicLink(userDir.resolve(PROJECT), elsewhere);

        assertThrows(ProjectException.class, () -> project.save(user));

        assertEquals("design content", Files.readString(designProject.resolve(MAIN)));
        assertNoFileHolds(designRoot, "elsewhere content");
    }

    @Test
    void sourceNotBackedByFilesIsCopiedUnfilteredWithoutAFilesystemCall() throws Exception {
        var repository = mock(Repository.class);
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setFolders(true).setVersions(false)
                .build());
        when(repository.list(PROJECT + "/")).thenReturn(List.of(fileData(PROJECT + "/" + OUTSIDE_LINK),
                fileData(PROJECT + "/" + MAIN)));
        when(repository.read(anyString())).thenAnswer(invocation -> {
            String name = invocation.getArgument(0);
            return new FileItem(fileData(name), stream("content of " + name));
        });
        var source = spy(new AProject(repository, PROJECT));

        var contained = AProjectFolder.containedFiles(source);

        assertTrue(contained.test(PROJECT + "/../../" + OUTSIDE_LINK), "Other backends are checked lexically only.");
        var target = new AProject(localRepository, PROJECT);
        target.update(source, user);
        verify(source, never()).getRealPath();
        assertEquals("content of " + PROJECT + "/" + OUTSIDE_LINK,
                Files.readString(userDir.resolve(PROJECT).resolve(OUTSIDE_LINK)));
        assertEquals("content of " + PROJECT + "/" + MAIN, Files.readString(userDir.resolve(PROJECT).resolve(MAIN)));
    }

    @Test
    void containedFilesChecksEveryNameAgainstTheProjectFolder() throws Exception {
        writeDesignProject(PROJECT);
        var design = design(DesignKind.PLAIN);

        var contained = AProjectFolder.containedFiles(new AProject(design, PROJECT));

        assertTrue(contained.test(PROJECT + "/" + MAIN));
        assertTrue(contained.test(PROJECT + "/" + INNER), "A link inside the project is contained.");
        assertTrue(contained.test(PROJECT + "/rules/New.xlsx"), "A file still to be created is contained.");
        assertFalse(contained.test(PROJECT + "/" + OUTSIDE_LINK));
        assertFalse(contained.test(PROJECT + "/" + SIBLING_LINK));
        assertFalse(contained.test(PROJECT + "/" + DANGLING_LINK));
        assertFalse(contained.test("Sibling/rules.properties"), "A file of another folder is not contained.");
        assertFalse(contained.test(PROJECT + "/../Sibling/rules.properties"), "A parent segment may not leave it.");
        assertFalse(contained.test(PROJECT + "/bad\u0000name"), "A name that is not a valid path is refused.");
    }

    @Test
    void containedFilesTakesTheFolderAsTheRepositoryListsIt() throws Exception {
        writeDesignProject(PROJECT);
        var design = design(DesignKind.PLAIN);

        var withTrailingSlash = AProjectFolder.containedFiles(new AProject(design, PROJECT + "/"));
        var repositoryRoot = AProjectFolder.containedFiles(new AProject(design, ""));

        assertTrue(withTrailingSlash.test(PROJECT + "/" + MAIN));
        assertFalse(withTrailingSlash.test(PROJECT + "/" + OUTSIDE_LINK));
        assertTrue(repositoryRoot.test(PROJECT + "/" + MAIN), "The repository root is the boundary of an empty path.");
        assertTrue(repositoryRoot.test(PROJECT + "/" + SIBLING_LINK), "Another project is inside the repository.");
        assertFalse(repositoryRoot.test(PROJECT + "/" + OUTSIDE_LINK));
    }

    @Test
    void containedFilesRefusesAProjectFolderOutsideItsRepository() throws IOException {
        var design = design(DesignKind.PLAIN);

        var escaping = assertThrows(ProjectException.class,
                () -> AProjectFolder.containedFiles(new AProject(design, "../" + PROJECT)));
        var invalid = assertThrows(ProjectException.class,
                () -> AProjectFolder.containedFiles(new AProject(design, "bad\u0000name")));

        assertEquals("The folder of the project '../" + PROJECT + "' is reached through a link or cannot be resolved.",
                escaping.getMessage());
        assertEquals("The folder of the project 'bad\u0000name' is not a valid path.", invalid.getMessage());
    }

    @Test
    void containedFilesRefusesARepositoryRootThatCannotBeResolved() throws IOException {
        var dangling = Files.createSymbolicLink(outside.resolve("dangling-root"), outside.resolve("missing"));
        var design = new FileSystemRepository();
        design.setRoot(dangling.resolve("repository"));

        assertThrows(ProjectException.class, () -> AProjectFolder.containedFiles(new AProject(design, PROJECT)));
    }

    // V1: a save deletes and recreates the file it replaces; no copy racing with it may leave that file out
    @Test
    void containedFilesAcceptsAFileWhileASaveKeepsReplacingIt() throws Exception {
        var designProject = writeDesignProject(PROJECT);
        var contained = AProjectFolder.containedFiles(new AProject(design(DesignKind.CONFIGURED), PROJECT));
        var file = designProject.resolve(MAIN);
        var content = "replaced content".getBytes(StandardCharsets.UTF_8);
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
        var rejected = 0;

        writer.start();
        try {
            while (saves.get() == 0 && writer.isAlive()) {
                Thread.onSpinWait();
            }
            for (var i = 0; i < 3000; i++) {
                if (!contained.test(PROJECT + "/" + MAIN)) {
                    rejected++;
                }
            }
        } finally {
            stop.set(true);
            writer.join();
        }

        assertNull(saveFailure.get(), "Fixture: the saves keep replacing the file");
        assertTrue(saves.get() > 1, "Fixture: the file is replaced while it is checked");
        assertEquals(0, rejected, "Rejections of a file a save keeps replacing");
        assertFalse(contained.test(PROJECT + "/" + DANGLING_LINK), "The dangling link is still left out");
    }

    // V1: an entry that is not a link and vanishes between the probe and its resolution is resolved through its parent
    @Test
    void containedFilesResolvesAFileThatVanishesWhileItIsResolvedThroughItsParent() throws Exception {
        var provider = mock(FileSystemProvider.class);
        var boundary = existingDirectoryOn(provider);
        var folder = existingDirectoryOn(provider);
        var file = pathOn(provider);
        var name = mock(Path.class);
        when(boundary.resolve("rules/Main.xlsx")).thenReturn(file);
        when(file.normalize()).thenReturn(file);
        when(file.startsWith(boundary)).thenReturn(true);
        when(provider.exists(file, LinkOption.NOFOLLOW_LINKS)).thenReturn(true);
        when(provider.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS))
                .thenThrow(new NoSuchFileException("replaced"));
        when(file.toRealPath()).thenThrow(new NoSuchFileException("replaced"));
        when(file.getParent()).thenReturn(folder);
        when(folder.relativize(file)).thenReturn(name);
        when(folder.resolve(name)).thenReturn(file);

        var contained = AProjectFolder.containedFiles(new AProject(designOn(provider, boundary), PROJECT));

        assertTrue(contained.test(PROJECT + "/" + MAIN), "A file replaced while it is resolved stays contained");
        verify(folder).toRealPath();
    }

    // V1: a link that dangles when it is resolved is rejected at once, without walking past it
    @Test
    void containedFilesRejectsALinkThatDanglesWhenItIsResolved() throws Exception {
        var provider = mock(FileSystemProvider.class);
        var boundary = existingDirectoryOn(provider);
        var folder = existingDirectoryOn(provider);
        var link = pathOn(provider);
        var linkAttributes = mock(BasicFileAttributes.class);
        when(linkAttributes.isSymbolicLink()).thenReturn(true);
        when(boundary.resolve(DANGLING_LINK)).thenReturn(link);
        when(link.normalize()).thenReturn(link);
        when(link.startsWith(boundary)).thenReturn(true);
        when(provider.exists(link, LinkOption.NOFOLLOW_LINKS)).thenReturn(true);
        when(provider.readAttributes(link, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS))
                .thenReturn(linkAttributes);
        when(link.toRealPath()).thenThrow(new NoSuchFileException("dangling"));
        when(link.getParent()).thenReturn(folder);

        var contained = AProjectFolder.containedFiles(new AProject(designOn(provider, boundary), PROJECT));

        assertFalse(contained.test(PROJECT + "/" + DANGLING_LINK), "A dangling link");
        verify(folder, never()).toRealPath();
    }

    // V1: walking past a vanished entry never accepts a dangling link, below the project folder or as the folder
    @Test
    void containedFilesStillRejectsADanglingLink() throws Exception {
        writeDesignProject(PROJECT);
        var design = design(DesignKind.CONFIGURED);
        Files.createSymbolicLink(designRoot.resolve("Ghost"), outside.resolve("missing"));

        var contained = AProjectFolder.containedFiles(new AProject(design, PROJECT));
        var error = assertThrows(ProjectException.class,
                () -> AProjectFolder.containedFiles(new AProject(design, "Ghost")));

        assertFalse(contained.test(PROJECT + "/" + DANGLING_LINK), "A dangling link");
        assertFalse(contained.test(PROJECT + "/" + DANGLING_LINK + "/x.txt"), "A path below a dangling link");
        assertTrue(contained.test(PROJECT + "/" + MAIN), "A regular file beside it");
        assertEquals("The folder of the project 'Ghost' is reached through a link or cannot be resolved.",
                error.getMessage());
    }

    // V1: walking past a vanished entry never accepts a link loop, which fails to resolve without vanishing
    @Test
    void containedFilesStillRejectsALinkLoop() throws Exception {
        var designProject = writeDesignProject(PROJECT);
        Files.createSymbolicLink(designProject.resolve("loop"), designProject.resolve("loop"));

        var contained = AProjectFolder.containedFiles(new AProject(design(DesignKind.CONFIGURED), PROJECT));

        assertFalse(contained.test(PROJECT + "/loop"), "A link loop");
        assertFalse(contained.test(PROJECT + "/loop/x.txt"), "A path below a link loop");
        assertTrue(contained.test(PROJECT + "/" + MAIN), "A regular file beside it");
    }

    /**
     * Writes a project folder with a regular file, a link inside the project, and links that lead to a file outside
     * the repository, to a file of a sibling project and to nothing.
     */
    private Path writeDesignProject(String folder) throws IOException {
        var project = designRoot.resolve(folder);
        Files.createDirectories(project.resolve("rules"));
        Files.writeString(project.resolve("rules.xml"), "<project><name>" + PROJECT + "</name></project>");
        Files.writeString(project.resolve(MAIN), "design content");
        Files.createSymbolicLink(project.resolve(INNER), project.resolve(MAIN));
        Files.createSymbolicLink(project.resolve(OUTSIDE_LINK), outsideFile);
        var sibling = project.resolveSibling("Sibling");
        Files.createDirectories(sibling);
        Files.writeString(sibling.resolve("rules.xml"), "<project><name>Sibling</name></project>");
        siblingFile = Files.writeString(sibling.resolve("rules.properties"), siblingContent);
        Files.createSymbolicLink(project.resolve(SIBLING_LINK), siblingFile);
        Files.createSymbolicLink(project.resolve(DANGLING_LINK), outside.resolve("missing.txt"));
        return project;
    }

    private Repository design(DesignKind kind) throws IOException {
        if (kind == DesignKind.PLAIN) {
            var plain = new VersionedFileRepository(false);
            plain.setRoot(designRoot);
            plain.setId("design");
            return plain;
        }
        var settings = Map.of("repository.design.factory", "repo-file",
                "repository.design.uri", designRoot.toString());
        var configured = RepositoryInstatiator.newRepository("repository.design", settings::get);
        closeables.add(configured);
        return switch (kind) {
            case DELEGATED -> {
                var wrapper = mock(Repository.class, withSettings().extraInterfaces(RepositoryDelegate.class)
                        .defaultAnswer(AdditionalAnswers.delegatesTo(configured)));
                doReturn(configured).when((RepositoryDelegate) wrapper).getOriginal();
                yield wrapper;
            }
            case MAPPED -> {
                var mapped = MappedRepository.create(configured, "DESIGN/");
                closeables.add(mapped);
                yield mapped;
            }
            default -> configured;
        };
    }

    private static String designName(DesignKind kind, Repository design) throws IOException {
        if (kind != DesignKind.MAPPED) {
            return PROJECT;
        }
        return design.listFolders("DESIGN/")
                .stream()
                .map(FileData::getName)
                .filter(name -> name.startsWith("DESIGN/" + PROJECT + ":"))
                .findFirst()
                .orElseThrow();
    }

    /** A project that is not opened yet: the working copy holds no data for it. */
    private RulesProject rulesProject(Repository design, String designName) throws IOException {
        return new RulesProject(user,
                localRepository,
                localRepository.check(PROJECT),
                design,
                design.check(designName),
                new DummyLockEngine());
    }

    private void saveLocally(String file, String content) throws IOException {
        var change = new FileData();
        change.setName(PROJECT + "/" + file);
        localRepository.save(change, stream(content));
    }

    private void assertOutsideFilesUnchanged() throws IOException {
        assertEquals(secret, Files.readString(outsideFile), "The outside file may be neither read nor modified.");
        if (siblingFile != null) {
            assertEquals(siblingContent, Files.readString(siblingFile), "The sibling project must stay unchanged.");
        }
    }

    private static void assertAbsent(Path path) {
        assertFalse(Files.exists(path, LinkOption.NOFOLLOW_LINKS), "Must be left out: " + path);
    }

    private static void assertNoFileHolds(Path folder, String content) throws IOException {
        try (var files = Files.walk(folder)) {
            for (var file : files.filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)).toList()) {
                assertFalse(Files.readString(file).contains(content), "The content must not reach " + file);
            }
        }
    }

    private static FileData fileData(String name) {
        var data = new FileData();
        data.setName(name);
        return data;
    }

    private static ByteArrayInputStream stream(String content) {
        return new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
    }

    // V1: a path on a mocked file system provider, so a test decides what each probe of a walk finds
    private static Path pathOn(FileSystemProvider provider) {
        var fileSystem = mock(FileSystem.class);
        when(fileSystem.provider()).thenReturn(provider);
        var path = mock(Path.class);
        when(path.getFileSystem()).thenReturn(fileSystem);
        return path;
    }

    // V1: a directory on a mocked provider that exists, sits at its own real location and holds itself
    private static Path existingDirectoryOn(FileSystemProvider provider) throws IOException {
        var directory = pathOn(provider);
        var itself = mock(Path.class);
        when(provider.exists(directory, LinkOption.NOFOLLOW_LINKS)).thenReturn(true);
        when(directory.toAbsolutePath()).thenReturn(directory);
        when(directory.toRealPath()).thenReturn(directory);
        when(directory.normalize()).thenReturn(directory);
        when(directory.resolve("")).thenReturn(directory);
        when(directory.startsWith(directory)).thenReturn(true);
        when(directory.relativize(directory)).thenReturn(itself);
        when(directory.resolve(itself)).thenReturn(directory);
        return directory;
    }

    // V1: a file repository on a mocked provider whose project folder is the given boundary
    private static FileSystemRepository designOn(FileSystemProvider provider, Path boundary) throws IOException {
        var root = existingDirectoryOn(provider);
        when(root.resolve(PROJECT)).thenReturn(boundary);
        when(boundary.startsWith(root)).thenReturn(true);
        var design = new FileSystemRepository();
        design.setRoot(root);
        return design;
    }

    /**
     * A file repository with a stub revision, which opening a project requires, optionally with per-file ids, so
     * that copies between it and a working copy are computed as differences.
     */
    private static final class VersionedFileRepository extends FileSystemRepository {
        private final boolean uniqueFileId;

        private VersionedFileRepository(boolean uniqueFileId) {
            this.uniqueFileId = uniqueFileId;
        }

        @Override
        protected String getVersion(Path file) {
            return "rev-1";
        }

        @Override
        protected String getVersion(String path) {
            return "rev-1";
        }

        @Override
        public Features supports() {
            return new FeaturesBuilder(this).setVersions(false).setFolders(true).setSupportsUniqueFileId(uniqueFileId)
                    .build();
        }
    }
}

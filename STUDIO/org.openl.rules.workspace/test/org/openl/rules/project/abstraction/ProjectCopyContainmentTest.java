package org.openl.rules.project.abstraction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyIterable;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
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
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

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
import org.openl.rules.repository.LocalWorkingTree;
import org.openl.rules.repository.PathCheckedRepository;
import org.openl.rules.repository.RepositoryInstatiator;
import org.openl.rules.repository.api.ChangesetType;
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
import org.openl.rules.workspace.dtr.FolderMapper;
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
 *
 * <p>V1: the copy writes only where no link in the destination project folder leads it out of that folder, in a
 * {@code repo-file} design repository and in the working tree a Git-like repository checks out to write. A write or
 * an unpacked archive entry through a link to outside or into another project is refused before anything is written
 * through it, while links that stay inside the project are written through. Other backends get the changes as they
 * are, with no filesystem call.
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
    // V1: folder links of a destination project folder, to a folder outside the repository and to a sibling project
    private static final String OUTSIDE_FOLDER_LINK = "linkout";
    private static final String SIBLING_FOLDER_LINK = "sib";
    private static final String FOLDER_REFUSAL =
            "The folder of the project '" + PROJECT + "' is reached through a link or cannot be resolved.";

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

    // V1: a save never writes through a folder link of the design project folder, to outside or into a sibling (B12)
    @ParameterizedTest
    @EnumSource(DesignKind.class)
    void saveRefusesAWriteThroughAFolderLinkOfTheDesignProjectFolder(DesignKind kind) throws Exception {
        var folder = kind == DesignKind.MAPPED ? "catalog/" + PROJECT : PROJECT;
        var designProject = writeLinkedDesignProject(folder);
        var design = design(kind);
        var project = rulesProject(design, designName(kind, design));
        project.open();
        assertAbsent(userDir.resolve(PROJECT).resolve(OUTSIDE_FOLDER_LINK));
        assertAbsent(userDir.resolve(PROJECT).resolve(SIBLING_FOLDER_LINK));
        saveLocally(OUTSIDE_FOLDER_LINK + "/b12.txt", "escape");
        saveLocally(SIBLING_FOLDER_LINK + "/b12.txt", "sibling");
        saveLocally(MAIN, "edited content");

        var error = assertThrows(ProjectException.class, () -> project.save(user));

        assertRefusedByTheDestination(error);
        assertEquals(List.of("secret.txt"), entries(outside), "Nothing is written outside the repository.");
        assertEquals(List.of("rules.properties", "rules.xml"), entries(designProject.resolveSibling("Sibling")),
                "Nothing is written into the sibling project.");
        assertOutsideFilesUnchanged();
        assertEquals("design content", Files.readString(designProject.resolve(MAIN)), "Nothing of the save is written");
        assertTrue(Files.isSymbolicLink(designProject.resolve(OUTSIDE_FOLDER_LINK)), "The design is left as it was.");
        assertTrue(Files.isSymbolicLink(designProject.resolve(SIBLING_FOLDER_LINK)), "The design is left as it was.");
    }

    // V1: a save that writes through none of the design project folder's links still writes, inside the folder only
    @ParameterizedTest
    @EnumSource(DesignKind.class)
    void saveWritesIntoADesignProjectFolderWhoseLinksItDoesNotWriteThrough(DesignKind kind) throws Exception {
        var folder = kind == DesignKind.MAPPED ? "catalog/" + PROJECT : PROJECT;
        var designProject = writeLinkedDesignProject(folder);
        var design = design(kind);
        var project = rulesProject(design, designName(kind, design));
        project.open();
        saveLocally(MAIN, "edited content");
        saveLocally("rules/New.xlsx", "new content");

        project.save(user);

        assertEquals("edited content", Files.readString(designProject.resolve(MAIN)));
        assertEquals("new content", Files.readString(designProject.resolve("rules/New.xlsx")));
        assertEquals(List.of("secret.txt"), entries(outside), "Nothing is written outside the repository.");
        assertEquals(List.of("rules.properties", "rules.xml"), entries(designProject.resolveSibling("Sibling")),
                "Nothing is written into the sibling project.");
        assertOutsideFilesUnchanged();
    }

    // V1: a design project folder that becomes a link after the project was opened is refused on save
    @Test
    void saveRefusesADesignProjectFolderThatBecameALink() throws Exception {
        var designProject = designRoot.resolve(PROJECT);
        Files.createDirectories(designProject.resolve("rules"));
        Files.writeString(designProject.resolve(MAIN), "design content");
        var project = rulesProject(design(DesignKind.CONFIGURED), PROJECT);
        project.open();
        saveLocally(MAIN, "edited content");
        var elsewhere = Files.createDirectories(outside.resolve("elsewhere"));
        FileUtils.delete(designProject);
        Files.createSymbolicLink(designProject, elsewhere);

        var error = assertThrows(ProjectException.class, () -> project.save(user));

        assertRefusedByTheDestination(error);
        assertEquals(FOLDER_REFUSAL, error.getMessage());
        assertEquals(List.of(), entries(elsewhere), "Nothing is written through the link.");
    }

    // V1: a file repository's changeset at hand is checked change by change and handed on as the same instance
    @Test
    void containedWritesChecksEveryChangeAgainstTheDestinationProjectFolder() throws Exception {
        writeDesignProject(PROJECT);
        writeLinkedDesignProject(PROJECT);
        var target = new AProject(design(DesignKind.PLAIN), PROJECT);
        var inside = List.of(new FileItem(PROJECT + "/" + MAIN, stream("main")),
                new FileItem(PROJECT + "/" + INNER, stream("inner")),
                new FileItem(PROJECT + "/rules/New.xlsx", stream("new")));

        assertSame(inside, target.containedWrites(inside, ChangesetType.FULL), "The same changeset is handed on.");
        for (var name : List.of(PROJECT + "/" + OUTSIDE_FOLDER_LINK + "/x.txt",
                PROJECT + "/" + SIBLING_FOLDER_LINK + "/x.txt",
                PROJECT + "/" + OUTSIDE_LINK,
                PROJECT + "/" + DANGLING_LINK + "/x.txt",
                "Sibling/x.txt",
                PROJECT + "/../Sibling/x.txt",
                PROJECT + "/bad\u0000name")) {
            var changes = List.of(new FileItem(PROJECT + "/" + MAIN, stream("main")), new FileItem(name, stream("x")));
            var error = assertThrows(UncontainedWriteException.class,
                    () -> target.containedWrites(changes, ChangesetType.FULL), name);
            assertFalse(error.getMessage().contains(designRoot.toString()), "No location on disk is named: " + name);
        }
        assertEquals("The file '" + OUTSIDE_FOLDER_LINK + "/x.txt' would be written outside the folder of the project '"
                        + PROJECT + "', through a link or its path.",
                assertThrows(UncontainedWriteException.class, () -> target.containedWrites(
                        List.of(new FileItem(PROJECT + "/" + OUTSIDE_FOLDER_LINK + "/x.txt", stream("x"))),
                        ChangesetType.DIFF)).getMessage());
    }

    // V1: the destination folder is taken as the repository names it, with a trailing slash or as the repository root
    @Test
    void containedWritesTakesTheDestinationFolderAsTheRepositoryNamesIt() throws Exception {
        writeLinkedDesignProject(PROJECT);
        var design = design(DesignKind.PLAIN);
        var main = List.of(new FileItem(PROJECT + "/" + MAIN, stream("main")));
        var throughLink = List.of(new FileItem(PROJECT + "/" + OUTSIDE_FOLDER_LINK + "/x.txt", stream("x")));
        var intoSibling = List.of(new FileItem(PROJECT + "/" + SIBLING_FOLDER_LINK + "/x.txt", stream("x")));

        for (var folder : List.of(PROJECT + "/", "")) {
            var target = new AProject(design, folder);
            assertSame(main, target.containedWrites(main, ChangesetType.FULL), folder);
            assertThrows(UncontainedWriteException.class, () -> target.containedWrites(throughLink, ChangesetType.FULL),
                    folder);
        }
        assertThrows(UncontainedWriteException.class,
                () -> new AProject(design, PROJECT + "/").containedWrites(intoSibling, ChangesetType.FULL));
        assertSame(intoSibling, new AProject(design, "").containedWrites(intoSibling, ChangesetType.FULL),
                "Another project is inside the repository root.");
    }

    // V1: a removal deletes the entry itself, never what a link there leads to, so only its folder must stay inside
    @Test
    void containedWritesChecksTheFolderARemovalDeletesFrom() throws Exception {
        var designProject = writeLinkedDesignProject(PROJECT);
        Files.createSymbolicLink(designProject.resolve(OUTSIDE_LINK), outsideFile);
        var design = design(DesignKind.CONFIGURED);
        var target = new AProject(design, PROJECT);
        var throughLink = List.of(removal(PROJECT + "/" + OUTSIDE_FOLDER_LINK + "/secret.txt"));
        var linkItself = List.of(removal(PROJECT + "/" + OUTSIDE_LINK));

        assertThrows(UncontainedWriteException.class, () -> target.containedWrites(throughLink, ChangesetType.DIFF));
        assertSame(linkItself, target.containedWrites(linkItself, ChangesetType.DIFF));
        design.save(fileData(PROJECT), linkItself, ChangesetType.DIFF);

        assertAbsent(designProject.resolve(OUTSIDE_LINK));
        assertOutsideFilesUnchanged();
    }

    // V1: the destination folder must lie at its own place inside the repository, and be a valid path
    @Test
    void containedWritesRefusesADestinationFolderOutsideItsRepository() throws IOException {
        var design = design(DesignKind.PLAIN);

        var escaping = assertThrows(UncontainedWriteException.class,
                () -> new AProject(design, "../" + PROJECT).containedWrites(List.of(), ChangesetType.FULL));
        var invalid = assertThrows(UncontainedWriteException.class,
                () -> new AProject(design, "bad\u0000name").containedWrites(List.of(), ChangesetType.FULL));

        assertEquals("The folder of the project '../" + PROJECT + "' is reached through a link or cannot be resolved.",
                escaping.getMessage());
        assertEquals("The folder of the project 'bad\u0000name' is reached through a link or cannot be resolved.",
                invalid.getMessage());
    }

    // V1: a backend without a local folder is handed the very changeset, and the destination is never resolved
    @Test
    void containedWritesHandsTheChangesOfABackendWithoutALocalFolderOnAsTheyAre() throws Exception {
        var repository = mock(Repository.class);
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setFolders(true).setVersions(false)
                .build());
        var target = spy(new AProject(repository, PROJECT));
        var changes = List.of(new FileItem(PROJECT + "/../../escape.txt", stream("x")));
        writeWorkingCopy();

        assertSame(changes, target.containedWrites(changes, ChangesetType.FULL), "Other backends are not checked.");
        target.update(new AProject(localRepository, PROJECT), user);

        verify(repository).save(any(FileData.class),
                argThat(files -> files instanceof List<?> list && list.size() == 2),
                eq(ChangesetType.FULL));
        verify(target, never()).getRealPath();
    }

    // V1: an archive unpacked into a design project folder never writes an entry through a folder link of it
    @ParameterizedTest
    @EnumSource(DesignKind.class)
    void unpackRefusesAnArchiveEntryThroughAFolderLinkOfTheDesignProjectFolder(DesignKind kind) throws Exception {
        var folder = kind == DesignKind.MAPPED ? "catalog/" + PROJECT : PROJECT;
        var designProject = writeLinkedDesignProject(folder);
        var design = design(kind);
        Files.write(archiveRoot.resolve(PROJECT), zip(OUTSIDE_FOLDER_LINK + "/evil.txt", "rules.xml"));
        var target = new AProject(design, designName(kind, design));

        var error = assertThrows(ProjectException.class, () -> target.update(new AProject(archives(), PROJECT), user));

        assertRefusedByTheDestination(error);
        assertEquals(List.of("secret.txt"), entries(outside), "Nothing is written outside the repository.");
        assertOutsideFilesUnchanged();
        assertTrue(Files.isSymbolicLink(designProject.resolve(OUTSIDE_FOLDER_LINK)), "The link is left as it was.");
    }

    // V1: an archive whose entries stay inside the design project folder is unpacked into it
    @Test
    void unpackWritesAnArchiveIntoADesignProjectFolderWhoseLinksItDoesNotWriteThrough() throws Exception {
        var designProject = writeLinkedDesignProject(PROJECT);
        Files.write(archiveRoot.resolve(PROJECT), zip("rules.xml", MAIN));
        var target = new AProject(design(DesignKind.CONFIGURED), PROJECT);

        target.update(new AProject(archives(), PROJECT), user);

        assertEquals("archived " + MAIN, Files.readString(designProject.resolve(MAIN)));
        assertEquals(List.of("secret.txt"), entries(outside), "Nothing is written outside the repository.");
        assertOutsideFilesUnchanged();
    }

    // V1: a working tree is checked in the tree its save checks out, so a folder link that checkout brings is found
    // and the full save, whose cleanup would enter it, is refused before anything is written (Git, B12)
    @Test
    void saveIntoAWorkingTreeRefusesAFullSaveWhoseCheckoutBringsAFolderLinkOutOfTheProject() throws Exception {
        writeWorkingCopy();
        var folder = designRoot.resolve(PROJECT);
        var repository = workingTree(false, () -> link(folder.resolve("vendor"), outside));

        var error = assertThrows(ProjectException.class,
                () -> new AProject(repository, PROJECT).update(new AProject(localRepository, PROJECT), user));

        assertRefusedByTheDestination(error);
        assertEquals(List.of("vendor"), entries(folder), "Nothing of the save is written.");
        assertEquals(List.of("secret.txt"), entries(outside), "Nothing is written outside the repository.");
    }

    // V1: a write through a folder link the checkout brings is refused, and no change of the save is written at all
    @Test
    void saveIntoAWorkingTreeRefusesAWriteThroughAFolderLinkItsCheckoutBrings() throws Exception {
        writeWorkingCopy("glink/g-escape.txt");
        var folder = designRoot.resolve(PROJECT);
        var repository = workingTree(true, () -> link(folder.resolve("glink"), outside));

        var error = assertThrows(ProjectException.class,
                () -> new AProject(repository, PROJECT).update(new AProject(localRepository, PROJECT), user));

        assertRefusedByTheDestination(error);
        assertEquals(List.of("glink"), entries(folder), "Nothing of the save is written.");
        assertEquals(List.of("secret.txt"), entries(outside), "Nothing is written outside the repository.");
    }

    // V1: a project folder the checkout turns into a link is refused, and nothing is written through it
    @Test
    void saveIntoAWorkingTreeRefusesAProjectFolderItsCheckoutTurnsIntoALink() throws Exception {
        writeWorkingCopy();
        var elsewhere = Files.createDirectories(outside.resolve("elsewhere"));
        var repository = workingTree(true, () -> link(designRoot.resolve(PROJECT), elsewhere));

        var error = assertThrows(ProjectException.class,
                () -> new AProject(repository, PROJECT).update(new AProject(localRepository, PROJECT), user));

        assertRefusedByTheDestination(error);
        assertEquals(FOLDER_REFUSAL, error.getMessage());
        assertEquals(List.of(), entries(elsewhere), "Nothing is written through the link.");
    }

    // V1: links that stay inside the project, and file links or dangling links a full save only removes, are accepted
    @Test
    void saveIntoAWorkingTreeWritesThroughLinksThatStayInsideTheProject() throws Exception {
        writeWorkingCopy("alias/x.txt");
        var folder = designRoot.resolve(PROJECT);
        var repository = workingTree(false, () -> {
            Files.createDirectories(folder.resolve("rules"));
            link(folder.resolve("alias"), folder.resolve("rules"));
            link(folder.resolve("notes.txt"), outsideFile);
            link(folder.resolve("ghost"), outside.resolve("missing"));
        });

        new AProject(repository, PROJECT).update(new AProject(localRepository, PROJECT), user);

        assertEquals("local alias/x.txt", Files.readString(folder.resolve("rules/x.txt")));
        assertEquals("local content", Files.readString(folder.resolve(MAIN)));
        assertEquals(List.of("secret.txt"), entries(outside), "Nothing is written outside the repository.");
        assertOutsideFilesUnchanged();
    }

    // V1: a first save into a working tree that holds no folder for the project yet writes it
    @Test
    void saveIntoAWorkingTreeWritesANewProjectFolder() throws Exception {
        writeWorkingCopy();
        var repository = workingTree(false, () -> {
        });

        new AProject(repository, PROJECT).update(new AProject(localRepository, PROJECT), user);

        assertEquals("local content", Files.readString(designRoot.resolve(PROJECT).resolve(MAIN)));
    }

    // V1: changes that arrive one by one are checked as the working tree takes them, the refused one released
    @Test
    void containedWritesChecksTheChangesAWorkingTreeTakesOneByOne() throws Exception {
        link(designRoot.resolve(PROJECT).resolve("glink"), outside);
        var target = new AProject(workingTree(false, () -> {
        }), PROJECT);
        var released = new AtomicBoolean();
        var refused = new FileItem(PROJECT + "/glink/x.txt", new ByteArrayInputStream(new byte[0]) {
            @Override
            public void close() {
                released.set(true);
            }
        });
        var listed = List.of(new FileItem(PROJECT + "/a.txt", stream("a")), refused);
        Iterable<FileItem> oneByOne = () -> listed.iterator();

        var checked = target.containedWrites(oneByOne, ChangesetType.DIFF);
        var iterator = checked.iterator();

        assertFalse(checked instanceof Collection, "The secured wrapper hands the changes on as they are.");
        assertTrue(iterator.hasNext());
        assertEquals(PROJECT + "/a.txt", iterator.next().getData().getName());
        assertTrue(iterator.hasNext());
        assertThrows(UncontainedWriteException.class, iterator::next);
        assertTrue(released.get(), "The refused change is released.");
        assertFalse(iterator.hasNext());
    }

    // V1: the working tree is found behind the wrappers the application puts around a Git repository
    @ParameterizedTest
    @EnumSource(TreeWrapper.class)
    void containedWritesFindsTheWorkingTreeBehindItsWrappers(TreeWrapper wrapper) throws Exception {
        var bare = workingTree(false, () -> {
        });
        var features = bare.supports();
        var folderPath = wrapper == TreeWrapper.MAPPED ? "DESIGN/" + PROJECT : PROJECT;
        var repository = switch (wrapper) {
            case BARE -> bare;
            case DELEGATED -> {
                var delegating = mock(Repository.class, withSettings().extraInterfaces(RepositoryDelegate.class));
                when(((RepositoryDelegate) delegating).getOriginal()).thenReturn(bare);
                when(delegating.supports()).thenReturn(features);
                yield delegating;
            }
            case PATH_CHECKED -> {
                var pathChecked = mock(PathCheckedRepository.class);
                when(pathChecked.getLocalWorkingTree()).thenReturn(designRoot);
                when(pathChecked.supports()).thenReturn(features);
                yield pathChecked;
            }
            case MAPPED -> {
                var mapped = mock(Repository.class, withSettings().extraInterfaces(FolderMapper.class));
                when(((FolderMapper) mapped).getDelegate()).thenReturn(bare);
                when(((FolderMapper) mapped).getRealPath(folderPath)).thenReturn("projects/" + PROJECT);
                when(mapped.supports()).thenReturn(new FeaturesBuilder(mapped).setFolders(true).setVersions(false)
                        .setMappedFolders(true).build());
                yield mapped;
            }
        };
        var folder = designRoot.resolve(wrapper == TreeWrapper.MAPPED ? "projects/" + PROJECT : PROJECT);
        link(folder.resolve("glink"), outside);
        var inside = List.of(new FileItem(folderPath + "/a.txt", stream("a")));
        var throughLink = List.of(new FileItem(folderPath + "/glink/x.txt", stream("x")));

        var target = new AProject(repository, folderPath);

        assertEquals(List.of(folderPath + "/a.txt"), names(target.containedWrites(inside, ChangesetType.DIFF)));
        var checked = target.containedWrites(throughLink, ChangesetType.DIFF);
        assertThrows(UncontainedWriteException.class, checked::iterator);
    }

    // V1: a working tree whose repository is not initialized yet keeps no local folder to check
    @Test
    void containedWritesHandsTheChangesOfAWorkingTreeNotInitializedYetOnAsTheyAre() throws Exception {
        var repository = workingTree(false, () -> {
        });
        when(((LocalWorkingTree) repository).getLocalWorkingTree()).thenReturn(null);
        var changes = List.of(new FileItem(PROJECT + "/a.txt", stream("a")));

        assertSame(changes, new AProject(repository, PROJECT).containedWrites(changes, ChangesetType.FULL));
    }

    // V1: a working-tree project folder a full save cannot walk is refused, since its links cannot be told apart
    @Test
    void containedWritesRefusesAWorkingTreeProjectFolderThatCannotBeWalked() throws Exception {
        var provider = mock(FileSystemProvider.class);
        var tree = existingDirectoryOn(provider);
        var boundary = existingDirectoryOn(provider);
        when(tree.resolve(PROJECT)).thenReturn(boundary);
        when(boundary.startsWith(tree)).thenReturn(true);
        var directory = mock(BasicFileAttributes.class);
        when(directory.isDirectory()).thenReturn(true);
        when(provider.readAttributesIfExists(boundary, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS))
                .thenReturn(directory);
        when(provider.readAttributes(boundary, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS))
                .thenReturn(directory);
        when(provider.newDirectoryStream(eq(boundary), any())).thenThrow(new IOException("unreadable"));
        var repository = workingTree(false, () -> {
        });
        when(((LocalWorkingTree) repository).getLocalWorkingTree()).thenReturn(tree);

        var checked = new AProject(repository, PROJECT).containedWrites(List.of(), ChangesetType.FULL);

        assertEquals(FOLDER_REFUSAL, assertThrows(UncontainedWriteException.class, checked::iterator).getMessage());
    }

    /** V1: the wrappers a working-tree repository may be reached through. */
    enum TreeWrapper {
        /** The repository itself. */
        BARE,
        /** Behind a delegating wrapper, as the secured wrapper holds it. */
        DELEGATED,
        /** Behind the path-checking wrapper of a configured repository. */
        PATH_CHECKED,
        /** Behind the folder mapping of a mapped design repository, which keeps the project in projects/. */
        MAPPED
    }

    /** V1: what a working-tree repository finds in its tree once it has checked out the branch it saves to. */
    @FunctionalInterface
    private interface Checkout {
        void run() throws IOException;
    }

    /**
     * V1: a repository that saves through its working tree, {@code designRoot}, as Git does: each save first checks
     * out the branch it writes, then takes the changes once and writes each with a {@link FileOutputStream}, following
     * every link on its way, the last one included.
     */
    private Repository workingTree(boolean uniqueFileIds, Checkout checkout) throws IOException {
        var repository = mock(Repository.class, withSettings().extraInterfaces(LocalWorkingTree.class));
        when(((LocalWorkingTree) repository).getLocalWorkingTree()).thenReturn(designRoot);
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setFolders(true).setVersions(false)
                .setSupportsUniqueFileId(uniqueFileIds).build());
        when(repository.save(any(FileData.class), anyIterable(), any(ChangesetType.class))).thenAnswer(invocation -> {
            checkout.run();
            Iterable<FileItem> changes = invocation.getArgument(1);
            for (var change : changes) {
                var file = designRoot.resolve(change.getData().getName()).toFile();
                var stream = change.getStream();
                if (stream == null) {
                    Files.deleteIfExists(file.toPath());
                    continue;
                }
                var parent = file.getParentFile();
                assertTrue(parent.isDirectory() || parent.mkdirs(), "The folder of a change is created as Git does.");
                try (var output = new FileOutputStream(file)) {
                    stream.transferTo(output);
                }
            }
            return invocation.getArgument(0);
        });
        return repository;
    }

    /**
     * V1: the project folder holds a descriptor, a workbook and two folder links: one to the folder outside the
     * repository, one to the sibling project.
     */
    private Path writeLinkedDesignProject(String folder) throws IOException {
        var project = designRoot.resolve(folder);
        Files.createDirectories(project.resolve("rules"));
        Files.writeString(project.resolve("rules.xml"), "<project><name>" + PROJECT + "</name></project>");
        Files.writeString(project.resolve(MAIN), "design content");
        var sibling = Files.createDirectories(project.resolveSibling("Sibling"));
        Files.writeString(sibling.resolve("rules.xml"), "<project><name>Sibling</name></project>");
        siblingFile = Files.writeString(sibling.resolve("rules.properties"), siblingContent);
        Files.createSymbolicLink(project.resolve(OUTSIDE_FOLDER_LINK), outside);
        Files.createSymbolicLink(project.resolve(SIBLING_FOLDER_LINK), sibling);
        return project;
    }

    /** V1: the working copy of the project, opened from no design: a descriptor, a workbook and the given files. */
    private void writeWorkingCopy(String... files) throws IOException {
        var workingCopy = userDir.resolve(PROJECT);
        Files.createDirectories(workingCopy.resolve("rules"));
        Files.writeString(workingCopy.resolve("rules.xml"), "<project><name>" + PROJECT + "</name></project>");
        Files.writeString(workingCopy.resolve(MAIN), "local content");
        for (var file : files) {
            Files.createDirectories(workingCopy.resolve(file).getParent());
            Files.writeString(workingCopy.resolve(file), "local " + file);
        }
    }

    /** V1: a repository that keeps each project as an archive, in {@code archiveRoot}. */
    private FileSystemRepository archives() {
        var archives = new FileSystemRepository() {
            @Override
            public Features supports() {
                return new FeaturesBuilder(this).setVersions(false).setFolders(false).build();
            }
        };
        archives.setRoot(archiveRoot);
        return archives;
    }

    /** V1: an archive holding the given entries, in order, each with the content {@code archived <entry>}. */
    private static byte[] zip(String... entries) throws IOException {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            for (var entry : entries) {
                zip.putNextEntry(new ZipEntry(entry));
                zip.write(("archived " + entry).getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        }
        return bytes.toByteArray();
    }

    /** V1: a change that removes the named file, so it carries no content. */
    private static FileItem removal(String name) {
        var removal = mock(FileItem.class);
        when(removal.getData()).thenReturn(fileData(name));
        return removal;
    }

    /** V1: a link at the given place, its folder created first. */
    private static void link(Path link, Path target) throws IOException {
        Files.createDirectories(link.getParent());
        Files.createSymbolicLink(link, target);
    }

    /** V1: the copy failed because the destination check refused a write, and names no location on disk. */
    private void assertRefusedByTheDestination(ProjectException error) {
        @Nullable Throwable cause = error;
        while (cause != null && !(cause instanceof UncontainedWriteException)) {
            cause = cause.getCause();
        }
        var refusal = assertInstanceOf(UncontainedWriteException.class, cause, "The destination check refused it.");
        assertEquals(refusal.getMessage(), error.getMessage(), "The project error tells what was refused.");
        for (var root : List.of(designRoot, userDir, outside)) {
            assertFalse(refusal.getMessage().contains(root.toString()), "No location on disk is named.");
        }
    }

    /** V1: the entries below a folder, links not followed, as sorted relative paths. */
    private static List<String> entries(Path folder) throws IOException {
        try (var paths = Files.walk(folder)) {
            return paths.filter(path -> !path.equals(folder))
                    .map(path -> folder.relativize(path).toString())
                    .sorted()
                    .toList();
        }
    }

    /** V1: the names of the changes a check hands on, taken one by one. */
    private static List<String> names(Iterable<FileItem> changes) {
        var names = new ArrayList<String>();
        changes.forEach(change -> names.add(change.getData().getName()));
        return names;
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

package org.openl.rules.project.abstraction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalAnswers.delegatesTo;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import org.openl.rules.project.impl.local.DummyLockEngine;
import org.openl.rules.project.impl.local.LocalRepository;
import org.openl.rules.project.impl.local.MetainfoRegistry;
import org.openl.rules.repository.RepositoryInstatiator;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.api.RepositoryDelegate;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.workspace.WorkspaceUserImpl;
import org.openl.rules.workspace.dtr.FolderMapper;
import org.openl.rules.workspace.dtr.impl.MappedRepository;

/**
 * Opening a project from a file design repository copies into the working copy only the files that lie inside the
 * project folder on disk.
 *
 * <p>A file repository lists a link to a regular file as a file and follows it when the file is read. The tests plant
 * links to files outside the repository, to a sibling project, from a sub-folder, a dangling link and a link to an
 * outside directory, and check that the working copy holds exactly the regular files of the project and the links
 * that stay inside it, that no outside or sibling content reaches the working copy, and that the escaping files are
 * never read. The design repository is built from its settings as the application builds it, so it is wrapped in the
 * path-checked repository, and is reached through stand-ins of the secured wrappers the application hands out. A
 * backend that is not file-backed keeps every listed file.
 */
class RulesProjectOpenContainmentTest {

    private static final String OUTSIDE_CANARY = "outside-file-canary";
    private static final String OUTSIDE_AGENTS_CANARY = "outside-agents-canary";
    private static final String SIBLING_CANARY = "sibling-project-canary";
    private static final String LINKED_FOLDER_CANARY = "linked-folder-canary";
    private static final String INSIDE_CONTENT = "inside content";

    @TempDir
    Path base;

    @TempDir
    Path userDir;

    private LocalRepository localRepository;
    private Path outside;

    @BeforeEach
    void init() throws IOException {
        localRepository = new LocalRepository(userDir, MetainfoRegistry.open(userDir));
        localRepository.setId("design");
        localRepository.initialize();

        outside = Files.createDirectories(base.resolve("outside"));
        Files.writeString(outside.resolve("secret.txt"), OUTSIDE_CANARY);
        Files.writeString(outside.resolve("AGENTS.md"), OUTSIDE_AGENTS_CANARY);
        Files.writeString(Files.createDirectories(outside.resolve("dir")).resolve("inner.txt"), OUTSIDE_CANARY);
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void flatProjectBehindSecuredWrapperGetsNoLinkedOutsideOrSiblingFile() throws Exception {
        var root = base.resolve("repo");
        plantFlatProjects(root);

        try (var configured = fileRepository(root)) {
            var secured = securedStandIn(configured);

            openProject(secured, "P1", null);

            var copy = userDir.resolve("P1");
            assertEquals(Set.of("rules.xml", "inside.txt", "inlink.txt"), regularFiles(copy));
            assertEquals(INSIDE_CONTENT, Files.readString(copy.resolve("inlink.txt")),
                    "A link that stays inside the project must be copied as its content.");
            assertFalse(Files.isSymbolicLink(copy.resolve("inlink.txt")));
            assertNoCanaryIn(userDir);
            verify(secured, never()).read("P1/leak.txt");
            verify(secured, never()).read("P1/sib.txt");
            verify(secured, never()).read("P1/sub/AGENTS.md");
            verify(secured).read("P1/inlink.txt");
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void listedNamesThatLeaveTheProjectOrCannotBeResolvedAreDropped() throws Exception {
        var root = base.resolve("repo");
        plantFlatProjects(root);

        try (var configured = fileRepository(root)) {
            var secured = securedStandIn(configured);
            doAnswer(invocation -> {
                var listed = new ArrayList<>(configured.list(invocation.getArgument(0)));
                listed.add(fileData("P1/../P2/secretB.txt"));
                listed.add(fileData("P1/bad\u0000.txt"));
                listed.add(fileData("P1/ghost.txt"));
                return listed;
            }).when(secured).list("P1/");

            openProject(secured, "P1", null);

            assertEquals(Set.of("rules.xml", "inside.txt", "inlink.txt"), regularFiles(userDir.resolve("P1")));
            assertNoCanaryIn(userDir);
            verify(secured, never()).read("P1/../P2/secretB.txt");
            verify(secured, never()).read("P1/bad\u0000.txt");
            verify(secured, never()).read("P1/ghost.txt");
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void mappedProjectBehindSecuredMappedWrapperGetsNoLinkedOutsideOrSiblingFile() throws Exception {
        var root = base.resolve("repo");
        var project = Files.createDirectories(root.resolve("custom/area/PM"));
        Files.writeString(project.resolve("rules.xml"), "<project><name>PM</name></project>");
        Files.writeString(project.resolve("inside.txt"), INSIDE_CONTENT);
        Files.createSymbolicLink(project.resolve("leak.txt"), outside.resolve("secret.txt"));
        Files.createSymbolicLink(project.resolve("sib.txt"), Path.of("../PB/secretB.txt"));
        var sibling = Files.createDirectories(root.resolve("custom/area/PB"));
        Files.writeString(sibling.resolve("rules.xml"), "<project><name>PB</name></project>");
        Files.writeString(sibling.resolve("secretB.txt"), SIBLING_CANARY);

        try (var configured = fileRepository(root)) {
            var mapped = MappedRepository.create(configured, "DESIGN/");
            try {
                var secured = securedMappedStandIn(mapped);
                var designName = mapped.listFolders("DESIGN/")
                        .stream()
                        .map(FileData::getName)
                        .filter(name -> name.startsWith("DESIGN/PM:"))
                        .findFirst()
                        .orElseThrow();

                openProject(secured, designName, null);

                assertEquals(Set.of("rules.xml", "inside.txt"), regularFiles(userDir.resolve("PM")));
                assertNoCanaryIn(userDir);
                verify(secured, never()).read(designName + "/leak.txt");
                verify(secured, never()).read(designName + "/sib.txt");
            } finally {
                ((Closeable) mapped).close();
            }
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void projectFolderThatIsALinkGetsNothingCopied() throws Exception {
        var root = Files.createDirectories(base.resolve("repo"));
        var target = Files.createDirectories(outside.resolve("project"));
        Files.writeString(target.resolve("rules.xml"), LINKED_FOLDER_CANARY);
        Files.writeString(target.resolve("data.txt"), LINKED_FOLDER_CANARY);
        Files.createSymbolicLink(root.resolve("P1"), target);

        try (var configured = fileRepository(root)) {
            openProject(configured, "P1", null);

            assertEquals(Set.of(), regularFiles(userDir.resolve("P1")));
            assertNoCanaryIn(userDir);
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void projectUnderALinkedFolderGetsNothingCopied() throws Exception {
        var root = Files.createDirectories(base.resolve("repo"));
        var area = Files.createDirectories(outside.resolve("area"));
        var target = Files.createDirectories(area.resolve("P1"));
        Files.writeString(target.resolve("rules.xml"), LINKED_FOLDER_CANARY);
        Files.writeString(target.resolve("data.txt"), LINKED_FOLDER_CANARY);
        Files.createSymbolicLink(root.resolve("area"), area);

        try (var configured = fileRepository(root)) {
            var secured = securedStandIn(configured);

            openProject(secured, "area/P1", null);

            assertEquals(Set.of(), regularFiles(userDir.resolve("P1")));
            assertNoCanaryIn(userDir);
            verify(secured, never()).read(anyString());
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void repositoryRootReachedThroughALinkIsTrusted() throws Exception {
        var realRoot = base.resolve("real-repo");
        var project = Files.createDirectories(realRoot.resolve("P1"));
        Files.writeString(project.resolve("rules.xml"), "<project><name>P1</name></project>");
        Files.writeString(Files.createDirectories(project.resolve("sub")).resolve("inside.txt"), INSIDE_CONTENT);
        var root = Files.createSymbolicLink(base.resolve("repo"), realRoot);

        try (var configured = fileRepository(root)) {
            openProject(configured, "P1", null);

            var copy = userDir.resolve("P1");
            assertEquals(Set.of("rules.xml", "sub/inside.txt"), regularFiles(copy));
            assertEquals(INSIDE_CONTENT, Files.readString(copy.resolve("sub/inside.txt")));
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void unresolvableRepositoryRootCopiesNothing() throws Exception {
        var root = Files.createSymbolicLink(base.resolve("repo"), base.resolve("missing"));
        try (var designRepository = new FileSystemRepository()) {
            designRepository.setRoot(root);
            designRepository.setId("design");
            designRepository.initialize();

            openProject(designRepository, "P1", "rev-1");

            assertEquals(Set.of(), regularFiles(userDir.resolve("P1")));
        }
    }

    @Test
    void repositoryRootThatDoesNotExistYetCopiesNothing() throws Exception {
        // No folder of the path exists below the file system root, and opening only reads the design repository.
        var root = base.getRoot().resolve("openl-absent-" + UUID.randomUUID()).resolve("repo");
        try (var configured = fileRepository(root)) {
            openProject(configured, "P1", "rev-1");

            assertEquals(Set.of(), regularFiles(userDir.resolve("P1")));
        }
    }

    @Test
    void backendThatIsNotFileBackedKeepsEveryListedFile() throws Exception {
        var backend = mock(Repository.class);
        when(backend.getId()).thenReturn("design");
        when(backend.supports()).thenReturn(new FeaturesBuilder(backend).setVersions(false).setFolders(true).build());
        var folder = fileData("P1");
        folder.setVersion("rev-1");
        when(backend.check("P1")).thenReturn(folder);
        when(backend.list("P1/")).thenReturn(List.of(fileData("P1/rules.xml"), fileData("P1/leak.txt")));
        when(backend.read("P1/rules.xml")).thenAnswer(invocation -> fileItem("P1/rules.xml", "rules"));
        when(backend.read("P1/leak.txt")).thenAnswer(invocation -> fileItem("P1/leak.txt", "listed by the backend"));

        openProject(backend, "P1", null);

        var copy = userDir.resolve("P1");
        assertEquals(Set.of("rules.xml", "leak.txt"), regularFiles(copy));
        assertEquals("listed by the backend", Files.readString(copy.resolve("leak.txt")));
    }

    @Test
    void archivedProjectKeepsItsEntriesWithoutLookingForALocalRoot() throws Exception {
        var archive = mock(Repository.class, withSettings().extraInterfaces(RepositoryDelegate.class));
        when(archive.supports()).thenReturn(new FeaturesBuilder(archive).setVersions(false).build());
        when(archive.read("P1")).thenAnswer(invocation -> new FileItem(fileData("P1"),
                new ByteArrayInputStream(zip("rules.xml", "sub/data.txt"))));
        // Opening unpacks an archived project before any listing, so the listing is reached directly here.
        var type = Class.forName(RulesProject.class.getName() + "$ContainedDesignProject");
        var constructor = type.getDeclaredConstructor(Repository.class, String.class, String.class);
        constructor.setAccessible(true);
        var designProject = (AProject) constructor.newInstance(archive, "P1", null);

        var names = designProject.getArtefacts().stream().map(AProjectArtefact::getName).collect(Collectors.toSet());

        assertEquals(Set.of("rules.xml", "data.txt"), names);
        verify((RepositoryDelegate) archive, never()).getOriginal();
    }

    /**
     * Two projects in a flat file repository: {@code P1} with regular files, a link inside the project, a link to an
     * outside file, a link to a file of {@code P2}, a link to an outside file from a sub-folder, a dangling link and a
     * link to an outside directory; {@code P2} holds the sibling file.
     */
    private void plantFlatProjects(Path root) throws IOException {
        var project = Files.createDirectories(root.resolve("P1"));
        Files.writeString(project.resolve("rules.xml"), "<project><name>P1</name></project>");
        Files.writeString(project.resolve("inside.txt"), INSIDE_CONTENT);
        Files.createSymbolicLink(project.resolve("inlink.txt"), Path.of("inside.txt"));
        Files.createSymbolicLink(project.resolve("leak.txt"), outside.resolve("secret.txt"));
        Files.createSymbolicLink(project.resolve("sib.txt"), Path.of("../P2/secretB.txt"));
        Files.createSymbolicLink(Files.createDirectories(project.resolve("sub")).resolve("AGENTS.md"),
                outside.resolve("AGENTS.md"));
        Files.createSymbolicLink(project.resolve("ghost.txt"), base.resolve("missing.txt"));
        Files.createSymbolicLink(project.resolve("linkdir"), outside.resolve("dir"));
        var sibling = Files.createDirectories(root.resolve("P2"));
        Files.writeString(sibling.resolve("rules.xml"), "<project><name>P2</name></project>");
        Files.writeString(sibling.resolve("secretB.txt"), SIBLING_CANARY);
    }

    /** The {@code repo-file} design repository, built from its settings as the application builds it. */
    private static Repository fileRepository(Path root) {
        var settings = Map.of("repository.design.factory", "repo-file", "repository.design.uri", root.toString());
        return RepositoryInstatiator.newRepository("repository.design", settings::get);
    }

    /** A stand-in of the secured wrapper of a flat repository: it delegates every call to the configured one. */
    private static Repository securedStandIn(Repository configured) {
        var secured = mock(Repository.class,
                withSettings().extraInterfaces(RepositoryDelegate.class).defaultAnswer(delegatesTo(configured)));
        doReturn(configured).when((RepositoryDelegate) secured).getOriginal();
        return secured;
    }

    /** A stand-in of the secured wrapper of a mapped repository: it delegates every call to the mapped one. */
    private static Repository securedMappedStandIn(Repository mapped) {
        var secured = mock(Repository.class,
                withSettings().extraInterfaces(RepositoryDelegate.class, FolderMapper.class)
                        .defaultAnswer(delegatesTo(mapped)));
        doReturn(mapped).when((RepositoryDelegate) secured).getOriginal();
        return secured;
    }

    @SuppressWarnings("NullAway") // an unopened project has no working copy; a null version opens the latest revision
    private void openProject(Repository designRepository, String designName, @Nullable String version)
            throws Exception {
        var designData = designRepository.check(designName);
        if (designData == null) {
            designData = fileData(designName);
        }
        var project = new RulesProject(new WorkspaceUserImpl("jdoe", id -> new UserInfo("jdoe")),
                localRepository,
                null,
                designRepository,
                designData,
                new DummyLockEngine());
        project.openVersion(version);
        assertTrue(project.isOpened());
    }

    /** The regular files under the folder, as slash-separated paths relative to it. */
    private static Set<String> regularFiles(Path folder) throws IOException {
        if (!Files.isDirectory(folder)) {
            return Set.of();
        }
        try (var walk = Files.walk(folder)) {
            return walk.filter(Files::isRegularFile)
                    .map(file -> folder.relativize(file).toString().replace('\\', '/'))
                    .collect(Collectors.toSet());
        }
    }

    /** No file anywhere under the folder, the workspace records included, holds outside or sibling content. */
    private static void assertNoCanaryIn(Path folder) throws IOException {
        var canaries = List.of(OUTSIDE_CANARY, OUTSIDE_AGENTS_CANARY, SIBLING_CANARY, LINKED_FOLDER_CANARY);
        try (var walk = Files.walk(folder)) {
            for (var file : walk.filter(Files::isRegularFile).toList()) {
                var content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
                for (var canary : canaries) {
                    assertFalse(content.contains(canary), () -> "Outside content copied to " + folder.relativize(file));
                }
            }
        }
    }

    private static FileData fileData(String name) {
        var data = new FileData();
        data.setName(name);
        return data;
    }

    private static FileItem fileItem(String name, String content) {
        return new FileItem(fileData(name), new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
    }

    private static byte[] zip(String... entries) throws IOException {
        var out = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(out)) {
            for (var entry : entries) {
                zip.putNextEntry(new ZipEntry(entry));
                zip.write(entry.getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        }
        return out.toByteArray();
    }
}

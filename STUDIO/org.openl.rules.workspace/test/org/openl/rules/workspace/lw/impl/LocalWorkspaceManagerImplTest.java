package org.openl.rules.workspace.lw.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.env.PropertyResolver;

import org.openl.rules.project.impl.local.DummyLockEngine;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.workspace.WorkspaceUserImpl;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.rules.workspace.lw.LocalWorkspace;
import org.openl.util.FileUtils;

class LocalWorkspaceManagerImplTest {
    @TempDir
    public File tempFolder;
    private LocalWorkspaceManagerImpl manager;

    @BeforeEach
    void init() throws Exception {
        manager = new LocalWorkspaceManagerImpl();
        manager.setWorkspaceHome(tempFolder.getAbsolutePath());
        manager.init();
    }

    @Test
    void removeWorkspaceOnSessionTimeout() {
        var user = new WorkspaceUserImpl("user.1",
                username -> new UserInfo("user.1", "user.1@email", "User 1"));
        var workspace1 = manager.getWorkspace(user.getUserId());
        var repoId = "design";

        // Must return cached version
        var workspace2 = manager.getWorkspace(user.getUserId());
        assertSame(workspace1, workspace2);

        // Session timeout
        workspace1.release();

        // Must create new instance
        workspace2 = manager.getWorkspace(user.getUserId());
        assertNotSame(workspace1, workspace2);
        assertNotSame(workspace1.getRepository(repoId), workspace2.getRepository(repoId));
    }

    @Test
    void dontCreateEmptyFolder() {
        var workspace1 = manager.getWorkspace(
                new WorkspaceUserImpl("user.1", username -> new UserInfo("user.1", "user.1@email", "User 1"))
                        .getUserId());
        assertFalse(workspace1.getLocation().exists());
    }

    @Test
    void rejectsUserIdEscapingTheWorkspaceRoot() {
        assertThrows(IllegalArgumentException.class, () -> manager.refreshMetainfoRegistry("../other"));
        assertThrows(IllegalArgumentException.class, () -> manager.refreshMetainfoRegistry("a/b"));
        assertThrows(IllegalArgumentException.class, () -> manager.refreshMetainfoRegistry(" "));
        assertThrows(IllegalArgumentException.class, () -> manager.refreshMetainfoRegistry(".hidden"));
        assertThrows(IllegalArgumentException.class, () -> manager.getWorkspace("../other"));
        assertFalse(new File(tempFolder.getParentFile(), "other").exists(),
                "Nothing must be created outside the workspace root.");
    }

    @Test
    void refreshMetainfoRegistryReconcilesTheUserWorkspace() throws IOException {
        var userDir = tempFolder.toPath().resolve("user.1");
        Files.createDirectories(userDir.resolve("stray"));

        // The registry is not loaded yet, so the load performs the reconciliation.
        manager.refreshMetainfoRegistry("user.1");
        assertFalse(Files.exists(userDir.resolve("stray")), "A folder without a record is garbage.");

        // The registry is live now and is shared with the workspace, so the refresh reconciles it.
        var workspace = manager.getWorkspace("user.1");
        Files.createDirectories(userDir.resolve("stray"));
        manager.refreshMetainfoRegistry("user.1");
        assertFalse(Files.exists(userDir.resolve("stray")));
        assertSame(workspace.getMetainfoRegistry(), manager.getWorkspace("user.1").getMetainfoRegistry());
    }

    // V1: surface A path-containment matrix (AAP 0.6.2.1)
    private static final String INVALID_ID = "The user id is not a valid workspace folder name.";

    /**
     * The two public operations that turn a user id into a workspace folder.
     *
     * <p>Both resolve the folder, and both reconcile it on the first load, which deletes every folder without a
     * metainfo record. So an id that escapes the root must be rejected by each of them. The constant name tells the
     * test report which operation escaped. Each constant carries its own body rather than a function field, because
     * Error Prone's ImmutableEnumChecker flags an enum that holds a mutable-typed field.
     */
    enum Operation {
        GET_WORKSPACE {
            @Override
            void apply(LocalWorkspaceManagerImpl m, String id) {
                m.getWorkspace(id);
            }
        },
        REFRESH {
            @Override
            void apply(LocalWorkspaceManagerImpl m, String id) {
                m.refreshMetainfoRegistry(id);
            }
        };

        abstract void apply(LocalWorkspaceManagerImpl m, String id);
    }

    /**
     * Ids that leave the root lexically: dot segments, absolute paths, separators and their encoded forms
     * (A1-A8, A14, A15). The labels render every payload in ASCII.
     */
    static Stream<Arguments> lexicallyEscapingIds() {
        return crossOperations(Named.of("A1 ..", ".."),
                Named.of("A2 .", "."),
                Named.of("A3 /etc", "/etc"),
                Named.of("A4 C:\\Windows", "C:\\Windows"),
                Named.of("A5 ..\\outside", "..\\outside"),
                Named.of("A6 a//b", "a//b"),
                Named.of("A7 ..%2Foutside", "..%2Foutside"),
                Named.of("A8 ..%252Foutside", "..%252Foutside"),
                Named.of("A14 a/../../outside", "a/../../outside"),
                Named.of("A15 ..\\u2215outside", "..\u2215outside"),
                Named.of("A15 ..\\uFF0Foutside", "..\uFF0Foutside"));
    }

    /**
     * Ids that stay a single name right under the root and that only the web module's name check rejects (A4, A10,
     * A11, A15). With the default accept-all check they name an ordinary folder under the root.
     */
    static Stream<Arguments> namesOnlyTheNameCheckerRejects() {
        return crossOperations(Named.of("A4 C:x", "C:x"),
                Named.of("A10 user\\u0007x", "user\u0007x"),
                Named.of("A10 user\\nx", "user\nx"),
                Named.of("A11 CON", "CON"),
                Named.of("A11 NUL", "NUL"),
                Named.of("A11 COM1", "COM1"),
                Named.of("A15 \\u2024\\u2024", "\u2024\u2024"),
                Named.of("A15 \\uFF0E\\uFF0E", "\uFF0E\uFF0E"));
    }

    /**
     * Pairs every payload with every operation.
     */
    @SafeVarargs
    private static Stream<Arguments> crossOperations(Named<String>... payloads) {
        return Stream.of(payloads)
                .flatMap(payload -> Stream.of(Operation.values()).map(op -> Arguments.of(payload, op)));
    }

    @ParameterizedTest
    @MethodSource("lexicallyEscapingIds")
    void rejectsLexicallyEscapingIds(String payload, Operation op, @TempDir Path outside) {
        var rootBefore = snapshot(tempFolder.toPath());
        var outsideBefore = snapshot(outside);
        var candidatesBefore = outsideCandidates();

        assertRejected(() -> op.apply(manager, payload));

        assertEquals(rootBefore, snapshot(tempFolder.toPath()), "Nothing may change under the workspace root.");
        assertEquals(outsideBefore, snapshot(outside), "Nothing may change outside the workspace root.");
        assertEquals(candidatesBefore, outsideCandidates(), "Nothing may be created beside the workspace root.");
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void rejectsUserIdWithNulByte(Operation op, @TempDir Path outside) {
        // A9: the JDK path parser refuses the NUL byte, so no folder can be derived from the id
        var rootBefore = snapshot(tempFolder.toPath());
        var outsideBefore = snapshot(outside);
        var candidatesBefore = outsideCandidates();

        assertThrows(IllegalArgumentException.class, () -> op.apply(manager, "user\u0000x"));

        assertEquals(rootBefore, snapshot(tempFolder.toPath()), "No entry may be created under the workspace root.");
        assertEquals(outsideBefore, snapshot(outside));
        assertEquals(candidatesBefore, outsideCandidates());
    }

    @ParameterizedTest
    @MethodSource("namesOnlyTheNameCheckerRejects")
    void keepsNamesOnlyTheNameCheckerRejectsRightUnderTheRoot(String payload,
                                                             Operation op,
                                                             @TempDir Path outside) throws IOException {
        var rootBefore = snapshot(tempFolder.toPath());
        var outsideBefore = snapshot(outside);
        var candidatesBefore = outsideCandidates();

        try {
            if (op == Operation.GET_WORKSPACE) {
                assertDirectChildOfRoot(manager.getWorkspace(payload), payload);
            } else {
                op.apply(manager, payload);
            }
        } catch (IllegalArgumentException platformRejection) {
            // A path parser that refuses ':' or control characters, as on Windows, rejects the id. That keeps it
            // inside the root too, and the checks below still apply.
        }

        // Neither operation creates the user folder, so the root stays exactly as it was
        assertEquals(rootBefore, snapshot(tempFolder.toPath()));
        assertEquals(outsideBefore, snapshot(outside));
        assertEquals(candidatesBefore, outsideCandidates());
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    @DisabledOnOs(OS.WINDOWS)
    void rejectsUserFolderLinkedOutsideTheRoot(Operation op, @TempDir Path outside) throws IOException {
        // A12: the folder of user 'victim' is a link to a folder outside the root
        Files.createDirectories(outside.resolve("stray"));
        Files.writeString(outside.resolve("keep.txt"), "content-" + UUID.randomUUID());
        Files.createSymbolicLink(tempFolder.toPath().resolve("victim"), outside);
        var rootBefore = snapshot(tempFolder.toPath());
        var outsideBefore = snapshot(outside);
        var candidatesBefore = outsideCandidates();

        assertRejected(() -> op.apply(manager, "victim"));

        assertEquals(outsideBefore, snapshot(outside), "Nothing outside the root may be deleted through the link.");
        assertTrue(Files.isDirectory(outside.resolve("stray")));
        assertEquals(rootBefore, snapshot(tempFolder.toPath()));
        assertEquals(candidatesBefore, outsideCandidates());
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    @DisabledOnOs(OS.WINDOWS)
    void rejectsUserFolderThatIsADanglingLink(Operation op, @TempDir Path outside) throws IOException {
        // A13: the folder of user 'ghost' is a link to a path outside the root that does not exist
        var missing = outside.resolve("missing");
        Files.createSymbolicLink(tempFolder.toPath().resolve("ghost"), missing);
        var rootBefore = snapshot(tempFolder.toPath());
        var outsideBefore = snapshot(outside);
        var candidatesBefore = outsideCandidates();

        assertRejected(() -> op.apply(manager, "ghost"));

        assertFalse(Files.exists(missing, LinkOption.NOFOLLOW_LINKS), "The link target must not be created.");
        assertEquals(outsideBefore, snapshot(outside));
        assertEquals(rootBefore, snapshot(tempFolder.toPath()));
        assertEquals(candidatesBefore, outsideCandidates());
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    @DisabledOnOs(OS.WINDOWS)
    void rejectsUserFolderLinkedToAnotherUsersFolder(Operation op, @TempDir Path outside) throws IOException {
        // A16: the folder of user 'alice' is a link to the folder of user 'bob'. 'bob' itself is never reconciled
        // here, because that would legitimately delete his stray folder.
        var root = tempFolder.toPath();
        Files.createDirectories(root.resolve("bob").resolve("stray"));
        Files.createSymbolicLink(root.resolve("alice"), root.resolve("bob"));
        var rootBefore = snapshot(root);
        var outsideBefore = snapshot(outside);
        var candidatesBefore = outsideCandidates();

        assertRejected(() -> op.apply(manager, "alice"));

        assertEquals(rootBefore, snapshot(root), "Nothing of another user's folder may be deleted through a link.");
        assertTrue(Files.isDirectory(root.resolve("bob").resolve("stray")));
        assertEquals(outsideBefore, snapshot(outside));
        assertEquals(candidatesBefore, outsideCandidates());
    }

    @Test
    void givesANewUserAWorkspaceRightUnderTheRoot() throws IOException {
        var userId = "user-" + UUID.randomUUID();
        var candidatesBefore = outsideCandidates();

        var workspace = manager.getWorkspace(userId);

        assertDirectChildOfRoot(workspace, userId);
        assertFalse(workspace.getLocation().exists(), "The first access must not create the folder.");
        assertEquals(candidatesBefore, outsideCandidates());
    }

    @Test
    void reconcilesTheRealFolderOfAnExistingUser() throws IOException {
        var userId = "user-" + UUID.randomUUID();
        var userDir = tempFolder.toPath().resolve(userId);
        Files.createDirectories(userDir.resolve("stray"));

        manager.refreshMetainfoRegistry(userId);

        assertFalse(Files.exists(userDir.resolve("stray")), "A real user folder is still reconciled.");
        assertTrue(Files.isDirectory(userDir));
        assertDirectChildOfRoot(manager.getWorkspace(userId), userId);
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void trustsLinksInTheConfiguredWorkspaceHome(@TempDir Path realHome, @TempDir Path linkParent) throws IOException {
        var link = Files.createSymbolicLink(linkParent.resolve("home-link"), realHome);
        var linked = new LocalWorkspaceManagerImpl();
        linked.setWorkspaceHome(link.toString());
        linked.init();
        var userId = "user-" + UUID.randomUUID();

        var workspace = linked.getWorkspace(userId);
        assertEquals(userId, workspace.getLocation().getName());
        assertEquals(realHome.toRealPath(), workspace.getLocation().getParentFile().toPath().toRealPath());

        // The folder under the linked home is the user's own folder, so the reconciliation still reaches it
        var stray = realHome.resolve(userId).resolve("stray");
        Files.createDirectories(stray);
        linked.refreshMetainfoRegistry(userId);
        assertFalse(Files.exists(stray));
    }

    @Test
    void acceptsUsersOfAWorkspaceHomeThatDoesNotExistYet(@TempDir Path base) {
        var missing = base.resolve("missing");
        var fresh = new LocalWorkspaceManagerImpl();
        fresh.setWorkspaceHome(missing.resolve("sub").toString());
        var first = "user-" + UUID.randomUUID();
        var second = "user-" + UUID.randomUUID();

        var workspace = fresh.getWorkspace(first);
        fresh.refreshMetainfoRegistry(second);

        assertEquals(fresh.getWorkspaceHome().resolve(first), workspace.getLocation().toPath());
        assertFalse(Files.exists(missing, LinkOption.NOFOLLOW_LINKS), "Resolving a user must not create the home.");
    }

    @Test
    void initUsesTheTemporaryFolderWhenTheHomeIsNotSet() throws IOException {
        var expected = Path.of(FileUtils.getTempDirectoryPath(), "rules-workspaces").toAbsolutePath().normalize();
        var existedBefore = Files.exists(expected);
        var defaults = new LocalWorkspaceManagerImpl();
        try {
            defaults.init();

            assertEquals(expected, defaults.getWorkspaceHome());
            assertTrue(Files.isDirectory(expected));
        } finally {
            if (!existedBefore) {
                deleteIfEmpty(expected);
            }
        }
    }

    @Test
    void initFailsWhenTheHomeCannotBeCreated(@TempDir Path dir) throws IOException {
        var file = Files.writeString(dir.resolve("file.txt"), "content-" + UUID.randomUUID());
        var home = file.resolve("sub").toString();
        var blocked = new LocalWorkspaceManagerImpl();
        blocked.setWorkspaceHome(home);

        var e = assertThrows(FileNotFoundException.class, blocked::init);

        assertEquals("Cannot create workspace location '" + home + "'", e.getMessage());
    }

    @Test
    void returnsANewDummyLockEngineWhenLocksAreDisabled() {
        manager.setEnableLocks(false);

        var first = manager.getLockEngine("rules");

        assertInstanceOf(DummyLockEngine.class, first);
        assertNotSame(first, manager.getLockEngine("rules"));
    }

    @Test
    void cachesOneLockEnginePerProjectType() {
        var rules = manager.getLockEngine("rules");

        assertFalse(rules instanceof DummyLockEngine);
        assertSame(rules, manager.getLockEngine("rules"));
        assertNotSame(rules, manager.getLockEngine("deployment"));
    }

    @Test
    void readsTheWorkspaceHomeFromTheProperties(@TempDir Path dir) {
        var resolver = mock(PropertyResolver.class);
        when(resolver.getProperty("user.workspace.home")).thenReturn(dir.toString());

        // A mock rather than null: the parameter is not @Nullable, and NullAway flags a null argument
        var configured = new LocalWorkspaceManagerImpl(resolver, mock(DesignTimeRepository.class));

        assertEquals(dir.toAbsolutePath().normalize(), configured.getWorkspaceHome());
    }

    // V1: fix-only cases for setFolderNameCheck (AAP 0.3.2.2)
    private static final Set<String> RESERVED_NAMES = Set.of("CON", "NUL", "COM1");

    /**
     * The ids of the matrix that the injected check rejects (A4, A10, A11).
     */
    static Stream<Arguments> namesTheInjectedCheckRejects() {
        return crossOperations(Named.of("A4 C:x", "C:x"),
                Named.of("A10 user\\u0007x", "user\u0007x"),
                Named.of("A10 user\\nx", "user\nx"),
                Named.of("A11 CON", "CON"),
                Named.of("A11 NUL", "NUL"),
                Named.of("A11 COM1", "COM1"));
    }

    /**
     * A stand-in for the web module's name check: it rejects reserved device names, ':' and control characters,
     * and records every id it is asked about.
     */
    private static Predicate<String> recordingCheck(List<String> seen) {
        return name -> {
            seen.add(name);
            return !RESERVED_NAMES.contains(name)
                    && name.indexOf(':') < 0
                    && name.codePoints().noneMatch(c -> c < 0x20);
        };
    }

    @ParameterizedTest
    @MethodSource("namesTheInjectedCheckRejects")
    void rejectsIdsTheInjectedCheckRejects(String payload, Operation op, @TempDir Path outside) {
        manager.setFolderNameCheck(recordingCheck(new CopyOnWriteArrayList<>()));
        var rootBefore = snapshot(tempFolder.toPath());
        var outsideBefore = snapshot(outside);
        var candidatesBefore = outsideCandidates();

        assertRejected(() -> op.apply(manager, payload));

        assertEquals(rootBefore, snapshot(tempFolder.toPath()));
        assertEquals(outsideBefore, snapshot(outside));
        assertEquals(candidatesBefore, outsideCandidates());
    }

    @ParameterizedTest
    @MethodSource("namesTheInjectedCheckRejects")
    @DisabledOnOs(OS.WINDOWS)
    void asksTheInjectedCheckAboutTheExactId(String payload, Operation op) {
        // The path parser of Windows can refuse these ids before the check is asked, so this runs elsewhere only
        var seen = new CopyOnWriteArrayList<String>();
        manager.setFolderNameCheck(recordingCheck(seen));

        assertRejected(() -> op.apply(manager, payload));

        assertTrue(seen.contains(payload), "The injected check must receive the id unchanged.");
    }

    @Test
    void givesAWorkspaceToAnIdTheInjectedCheckAccepts() throws IOException {
        var seen = new CopyOnWriteArrayList<String>();
        manager.setFolderNameCheck(recordingCheck(seen));
        var userId = "user-" + UUID.randomUUID();

        assertDirectChildOfRoot(manager.getWorkspace(userId), userId);
        assertTrue(seen.contains(userId));
    }

    @Test
    void nullRestoresTheAcceptAllCheck() throws IOException {
        manager.setFolderNameCheck(name -> false);
        var rejected = "user-" + UUID.randomUUID();
        assertRejected(() -> manager.getWorkspace(rejected));

        manager.setFolderNameCheck(null);

        var userId = "user-" + UUID.randomUUID();
        assertDirectChildOfRoot(manager.getWorkspace(userId), userId);
        assertDirectChildOfRoot(manager.getWorkspace(rejected), rejected);
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void nullRestoresTheAcceptAllCheckForReservedNames() throws IOException {
        manager.setFolderNameCheck(recordingCheck(new CopyOnWriteArrayList<>()));
        assertRejected(() -> manager.getWorkspace("CON"));

        manager.setFolderNameCheck(null);

        assertDirectChildOfRoot(manager.getWorkspace("CON"), "CON");
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void rejectsTheIdWhenTheInjectedCheckFails(Operation op) {
        manager.setFolderNameCheck(name -> {
            throw new IllegalArgumentException("check-" + UUID.randomUUID());
        });

        assertRejected(() -> op.apply(manager, "user-" + UUID.randomUUID()));
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void rejectsUserIdWithNulByteWithTheExistingMessage(Operation op, @TempDir Path outside) {
        // A9: the parser failure is reported as the existing rejection, not as the JDK message
        var rootBefore = snapshot(tempFolder.toPath());
        var outsideBefore = snapshot(outside);
        var candidatesBefore = outsideCandidates();

        assertRejected(() -> op.apply(manager, "user\u0000x"));

        assertEquals(rootBefore, snapshot(tempFolder.toPath()));
        assertEquals(outsideBefore, snapshot(outside));
        assertEquals(candidatesBefore, outsideCandidates());
    }

    @Test
    void runsTheInjectedCheckOnlyAfterTheLexicalChecks() {
        var seen = new CopyOnWriteArrayList<String>();
        manager.setFolderNameCheck(recordingCheck(seen));

        for (var op : Operation.values()) {
            assertRejected(() -> op.apply(manager, ".."));
            assertRejected(() -> op.apply(manager, "a/b"));
        }

        assertTrue(seen.isEmpty(), "The lexical checks must reject the id before the injected check is asked.");
    }

    /**
     * Captures every entry under the folder without following links: a file with its content, a link with its
     * target, and a folder as such. Two equal captures prove that nothing was created, changed or deleted.
     */
    private static Map<String, String> snapshot(Path dir) {
        var entries = new TreeMap<String, String>();
        try (var paths = Files.walk(dir)) {
            paths.forEach(p -> entries.put(dir.relativize(p).toString().replace(File.separatorChar, '/'), describe(p)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return entries;
    }

    private static String describe(Path p) {
        try {
            if (Files.isSymbolicLink(p)) {
                return "link:" + Files.readSymbolicLink(p);
            }
            if (Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
                return "file:" + Files.readString(p);
            }
            return "dir";
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Tells whether the names an escaping id would reach exist beside the root. The parent is the shared temporary
     * folder, which other tests use at the same time, so only these names are checked, never the whole folder.
     */
    private Map<String, Boolean> outsideCandidates() {
        var candidates = new TreeMap<String, Boolean>();
        for (var name : List.of("outside", "other")) {
            candidates.put(name, Files.exists(tempFolder.toPath().resolveSibling(name), LinkOption.NOFOLLOW_LINKS));
        }
        return candidates;
    }

    private static void assertRejected(Executable call) {
        var e = assertThrows(IllegalArgumentException.class, call);
        assertEquals(INVALID_ID, e.getMessage());
    }

    /**
     * Asserts that the workspace folder is named by the id and sits right under the root. Real paths are compared,
     * because the temporary folder may itself be reached through a link, such as /var on macOS.
     */
    private void assertDirectChildOfRoot(LocalWorkspace workspace, String userId) throws IOException {
        assertEquals(userId, workspace.getLocation().getName());
        assertEquals(tempFolder.toPath().toRealPath(), workspace.getLocation().getParentFile().toPath().toRealPath());
    }

    /**
     * Deletes the folder unless something else in the shared temporary folder has put content into it.
     */
    private static void deleteIfEmpty(Path dir) throws IOException {
        try {
            Files.deleteIfExists(dir);
        } catch (DirectoryNotEmptyException inUse) {
            // Another user of the shared temporary folder keeps its workspaces there, so the folder stays
        }
    }
}

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
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
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
import org.junitpioneer.jupiter.RestoreSystemProperties;
import org.springframework.core.env.PropertyResolver;

import org.openl.rules.project.impl.local.DummyLockEngine;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.workspace.WorkspaceUserImpl;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.rules.workspace.lw.LocalWorkspace;

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

    // V1: path-containment matrix of the workspace folder that a user id names
    private static final String INVALID_ID = "The user id is not a valid workspace folder name.";

    /**
     * A test-private folder that holds the workspace home two levels down, at {@code sandbox/a/home}. An id that
     * escapes the home lexically, such as {@code ..} or {@code a/../../outside}, still lands inside this folder, so
     * a snapshot of it catches a regression, and the reconciliation can never reach the shared temporary folder.
     */
    @TempDir
    Path sandbox;
    private Path root;
    private LocalWorkspaceManagerImpl sandboxed;

    @BeforeEach
    void initSandboxed() throws Exception {
        root = sandbox.resolve("a").resolve("home");
        sandboxed = new LocalWorkspaceManagerImpl();
        sandboxed.setWorkspaceHome(root.toString());
        sandboxed.init();
    }

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
     * Ids that leave the root lexically: dot segments, a drive path, separators and their encoded forms (A1, A2,
     * A4-A8, A14, A15). The labels render every payload in ASCII. The absolute path A3 names a folder of the sandbox,
     * so it has its own test.
     */
    static Stream<Arguments> lexicallyEscapingIds() {
        return crossOperations(Named.of("A1 ..", ".."),
                Named.of("A2 .", "."),
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
     * Ids that stay a single name right under the root (A4, A10, A11, A15). The web module's name check rejects the
     * A4, A10 and A11 ids, but accepts the A15 look-alikes as ordinary names. With the default accept-all check each
     * of them names an ordinary folder under the root.
     */
    static Stream<Arguments> singleNamesUnderTheRoot() {
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
    void rejectsLexicallyEscapingIds(String payload, Operation op) {
        var before = snapshot(sandbox);

        assertRejected(() -> op.apply(sandboxed, payload));

        assertEquals(before, snapshot(sandbox), "Nothing may change under or beside the workspace root.");
    }

    @ParameterizedTest(name = "[{index}] A3 absolute path, {0}")
    @EnumSource(Operation.class)
    void rejectsAnAbsolutePathId(Operation op) throws IOException {
        // A3: a folder of the sandbox with content stands in for a system folder such as /etc
        var etc = sandbox.resolve("etc");
        Files.createDirectories(etc.resolve("stray"));
        Files.writeString(etc.resolve("hosts"), "content-" + UUID.randomUUID());
        var before = snapshot(sandbox);

        assertRejected(() -> op.apply(sandboxed, etc.toAbsolutePath().toString()));

        assertEquals(before, snapshot(sandbox), "Nothing may change in the folder the absolute path names.");
        assertTrue(Files.isDirectory(etc.resolve("stray")));
    }

    @ParameterizedTest
    @MethodSource("singleNamesUnderTheRoot")
    void keepsSingleNamesRightUnderTheRoot(String payload, Operation op) throws IOException {
        var before = snapshot(sandbox);

        try {
            if (op == Operation.GET_WORKSPACE) {
                assertDirectChildOfRoot(sandboxed.getWorkspace(payload), payload);
            } else {
                op.apply(sandboxed, payload);
            }
        } catch (IllegalArgumentException platformRejection) {
            // The Windows path parser refuses ':' and control characters, which keeps the id inside the root too, so
            // the checks below still apply. Elsewhere the default check must accept every one of these ids.
            if (!OS.WINDOWS.isCurrentOs()) {
                throw platformRejection;
            }
        }

        // Neither operation creates the user folder, so the sandbox stays exactly as it was
        assertEquals(before, snapshot(sandbox));
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    @DisabledOnOs(OS.WINDOWS)
    void rejectsUserFolderLinkedOutsideTheRoot(Operation op) throws IOException {
        // A12: the folder of user 'victim' is a link to a folder outside the root
        var outside = sandbox.resolve("outside");
        Files.createDirectories(outside.resolve("stray"));
        Files.writeString(outside.resolve("keep.txt"), "content-" + UUID.randomUUID());
        Files.createSymbolicLink(root.resolve("victim"), outside);
        var before = snapshot(sandbox);

        assertRejected(() -> op.apply(sandboxed, "victim"));

        assertEquals(before, snapshot(sandbox), "Nothing outside the root may be deleted through the link.");
        assertTrue(Files.isDirectory(outside.resolve("stray")));
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    @DisabledOnOs(OS.WINDOWS)
    void rejectsUserFolderThatIsADanglingLink(Operation op) throws IOException {
        // A13: the folder of user 'ghost' is a link to a path outside the root that does not exist
        var missing = Files.createDirectories(sandbox.resolve("outside")).resolve("missing");
        Files.createSymbolicLink(root.resolve("ghost"), missing);
        var before = snapshot(sandbox);

        assertRejected(() -> op.apply(sandboxed, "ghost"));

        assertFalse(Files.exists(missing, LinkOption.NOFOLLOW_LINKS), "The link target must not be created.");
        assertEquals(before, snapshot(sandbox));
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    @DisabledOnOs(OS.WINDOWS)
    void rejectsUserFolderLinkedToAnotherUsersFolder(Operation op) throws IOException {
        // A16: the folder of user 'alice' is a link to the folder of user 'bob'. 'bob' itself is never reconciled
        // here, because that would legitimately delete his stray folder.
        Files.createDirectories(root.resolve("bob").resolve("stray"));
        Files.createSymbolicLink(root.resolve("alice"), root.resolve("bob"));
        var before = snapshot(sandbox);

        assertRejected(() -> op.apply(sandboxed, "alice"));

        assertEquals(before, snapshot(sandbox), "Nothing of another user's folder may be deleted through a link.");
        assertTrue(Files.isDirectory(root.resolve("bob").resolve("stray")));
    }

    @Test
    void givesANewUserAWorkspaceRightUnderTheRoot() throws IOException {
        var userId = "user-" + UUID.randomUUID();
        var before = snapshot(sandbox);

        var workspace = sandboxed.getWorkspace(userId);

        assertDirectChildOfRoot(workspace, userId);
        assertFalse(workspace.getLocation().exists(), "The first access must not create the folder.");
        assertEquals(before, snapshot(sandbox));
    }

    @Test
    void reconcilesTheRealFolderOfAnExistingUser() throws IOException {
        var userId = "user-" + UUID.randomUUID();
        var userDir = root.resolve(userId);
        Files.createDirectories(userDir.resolve("stray"));

        sandboxed.refreshMetainfoRegistry(userId);

        assertFalse(Files.exists(userDir.resolve("stray")), "A real user folder is still reconciled.");
        assertTrue(Files.isDirectory(userDir));
        assertDirectChildOfRoot(sandboxed.getWorkspace(userId), userId);
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void trustsLinksInTheConfiguredWorkspaceHome() throws IOException {
        // Both the real home and the link sit two levels inside the sandbox
        var realHome = Files.createDirectories(sandbox.resolve("real").resolve("home"));
        var linkParent = Files.createDirectories(sandbox.resolve("links"));
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
    @RestoreSystemProperties
    void initUsesTheTemporaryFolderWhenTheHomeIsNotSet(@TempDir Path tmp) throws IOException {
        // The default home lives in java.io.tmpdir, so that property points into a private folder for this test
        System.setProperty("java.io.tmpdir", tmp.toString());
        var expected = tmp.resolve("rules-workspaces").toAbsolutePath().normalize();
        var defaults = new LocalWorkspaceManagerImpl();

        defaults.init();

        assertEquals(expected, defaults.getWorkspaceHome());
        assertTrue(Files.isDirectory(expected));
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

    // V1: cases for the user-id check injected through setFolderNameCheck
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
    void rejectsIdsTheInjectedCheckRejects(String payload, Operation op) {
        sandboxed.setFolderNameCheck(recordingCheck(new CopyOnWriteArrayList<>()));
        var before = snapshot(sandbox);

        assertRejected(() -> op.apply(sandboxed, payload));

        assertEquals(before, snapshot(sandbox));
    }

    @ParameterizedTest
    @MethodSource("namesTheInjectedCheckRejects")
    @DisabledOnOs(OS.WINDOWS)
    void asksTheInjectedCheckAboutTheExactId(String payload, Operation op) {
        // The path parser of Windows can refuse these ids before the check is asked, so this runs elsewhere only
        var seen = new CopyOnWriteArrayList<String>();
        sandboxed.setFolderNameCheck(recordingCheck(seen));

        assertRejected(() -> op.apply(sandboxed, payload));

        assertTrue(seen.contains(payload), "The injected check must receive the id unchanged.");
    }

    @Test
    void givesAWorkspaceToAnIdTheInjectedCheckAccepts() throws IOException {
        var seen = new CopyOnWriteArrayList<String>();
        sandboxed.setFolderNameCheck(recordingCheck(seen));
        var userId = "user-" + UUID.randomUUID();

        assertDirectChildOfRoot(sandboxed.getWorkspace(userId), userId);
        assertTrue(seen.contains(userId));
    }

    @Test
    void nullRestoresTheAcceptAllCheck() throws IOException {
        sandboxed.setFolderNameCheck(name -> false);
        var rejected = "user-" + UUID.randomUUID();
        assertRejected(() -> sandboxed.getWorkspace(rejected));

        sandboxed.setFolderNameCheck(null);

        var userId = "user-" + UUID.randomUUID();
        assertDirectChildOfRoot(sandboxed.getWorkspace(userId), userId);
        assertDirectChildOfRoot(sandboxed.getWorkspace(rejected), rejected);
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void nullRestoresTheAcceptAllCheckForReservedNames() throws IOException {
        sandboxed.setFolderNameCheck(recordingCheck(new CopyOnWriteArrayList<>()));
        assertRejected(() -> sandboxed.getWorkspace("CON"));

        sandboxed.setFolderNameCheck(null);

        assertDirectChildOfRoot(sandboxed.getWorkspace("CON"), "CON");
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void rejectsTheIdWhenTheInjectedCheckFails(Operation op) {
        sandboxed.setFolderNameCheck(name -> {
            throw new IllegalArgumentException("check-" + UUID.randomUUID());
        });

        assertRejected(() -> op.apply(sandboxed, "user-" + UUID.randomUUID()));
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void rejectsUserIdWithNulByteWithTheExistingMessage(Operation op) {
        // A9: the JDK path parser refuses the NUL byte. Its failure is the cause of the existing rejection, whose
        // message is not the JDK one.
        var before = snapshot(sandbox);

        var e = assertRejected(() -> op.apply(sandboxed, "user\u0000x"));

        assertInstanceOf(InvalidPathException.class, e.getCause(), "The parser failure must be kept as the cause.");
        assertEquals(before, snapshot(sandbox), "No entry may be created under or beside the workspace root.");
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void rejectsTheIdWhenTheInjectedCheckIsDenied(Operation op) {
        sandboxed.setFolderNameCheck(name -> {
            throw new SecurityException("denied-" + UUID.randomUUID());
        });
        var before = snapshot(sandbox);

        assertRejected(() -> op.apply(sandboxed, "user-" + UUID.randomUUID()));

        assertEquals(before, snapshot(sandbox));
    }

    @Test
    void runsTheInjectedCheckOnlyAfterTheLexicalChecks() {
        var seen = new CopyOnWriteArrayList<String>();
        sandboxed.setFolderNameCheck(recordingCheck(seen));

        for (var op : Operation.values()) {
            assertRejected(() -> op.apply(sandboxed, ".."));
            assertRejected(() -> op.apply(sandboxed, "a/b"));
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

    private static IllegalArgumentException assertRejected(Executable call) {
        var e = assertThrows(IllegalArgumentException.class, call);
        assertEquals(INVALID_ID, e.getMessage());
        return e;
    }

    /**
     * Asserts that the workspace folder is named by the id and sits right under the sandboxed root. Real paths are
     * compared, because the temporary folder may itself be reached through a link, such as /var on macOS.
     */
    private void assertDirectChildOfRoot(LocalWorkspace workspace, String userId) throws IOException {
        assertEquals(userId, workspace.getLocation().getName());
        assertEquals(root.toRealPath(), workspace.getLocation().getParentFile().toPath().toRealPath());
    }
}

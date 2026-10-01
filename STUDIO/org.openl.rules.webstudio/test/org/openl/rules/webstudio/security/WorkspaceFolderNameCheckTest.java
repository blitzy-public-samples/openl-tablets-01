package org.openl.rules.webstudio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;

import org.apache.commons.lang3.RandomStringUtils;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import org.openl.rules.workspace.lw.LocalWorkspace;
import org.openl.rules.workspace.lw.impl.LocalWorkspaceManagerImpl;

/**
 * Tests of {@link WorkspaceFolderNameCheck} for V1, surface A (workspace directory).
 *
 * <p>The check is tested twice: on its own, through {@link WorkspaceFolderNameCheck#test(String)}, and installed in
 * a {@link LocalWorkspaceManagerImpl} through {@code setFolderNameCheck}, as {@code repository-beans.xml} wires it at
 * runtime. The second part runs the surface A path-traversal matrix through {@code getWorkspace} and
 * {@code refreshMetainfoRegistry}. It proves the {@code NameChecker} rows A7 to A11 on the runtime path: the
 * workspace module's own checks accept the A10 and A11 ids, so only the installed check can reject them.
 *
 * <p>Every row asserts the exact rejection message of {@code LocalWorkspaceManagerImpl}, and that the call changes
 * nothing on disk. The parameterized display names hold the row id only, because the payloads carry NUL and control
 * characters that would corrupt the test reports.
 */
class WorkspaceFolderNameCheckTest {

    /** The message of every user id that {@code LocalWorkspaceManagerImpl} rejects. */
    private static final String REJECTED = "The user id is not a valid workspace folder name.";

    /** The name of the workspace home inside the temporary folder. */
    private static final String HOME_NAME = "ws";

    @TempDir
    Path root;

    private Path home;
    private LocalWorkspaceManagerImpl manager;

    @BeforeEach
    void setUp() throws IOException {
        home = root.resolve(HOME_NAME);
        manager = new LocalWorkspaceManagerImpl();
        manager.setWorkspaceHome(home.toString());
        manager.setFolderNameCheck(new WorkspaceFolderNameCheck());
        manager.init();
    }

    // The check on its own.

    /**
     * Ids the check rejects on every operating system, labelled with their row id. Each row passes through a
     * different branch of the check: {@code null} and the empty id are refused before {@code NameChecker} runs, A9
     * makes the path API throw {@code InvalidPathException}, and the other rows make {@code NameChecker} throw
     * {@code IOException}. On Windows the path API already refuses the control characters of A10.
     *
     * <p>{@code /etc} (A3), {@code C:\Windows} and {@code C:x} (A4) are left out on purpose. {@code NameChecker} checks
     * the name elements of the parsed path, so it accepts {@code /etc} on Unix, and {@code C:\Windows} and
     * {@code C:x} on Windows. {@code LocalWorkspaceManagerImpl} rejects those ids with its own earlier checks, which
     * {@link #managerRejectsLexicalPayloads(String, String)} covers. This is the existing behavior of
     * {@code NameChecker}, which this work does not change.
     */
    static Stream<Arguments> rejectedIds() {
        return Stream.of(Arguments.of("null-input", null),
                Arguments.of("empty-input", ""),
                Arguments.of("A1", ".."),
                Arguments.of("A2", "."),
                Arguments.of("A5", "..\\outside"),
                Arguments.of("A6", "a//b"),
                Arguments.of("A7", "..%2Foutside"),
                Arguments.of("A8", "..%252Foutside"),
                Arguments.of("A9", "user\u0000x"),
                Arguments.of("A10-bell", "user\u0007x"),
                Arguments.of("A10-newline", "user\nx"),
                Arguments.of("A11-CON", "CON"),
                Arguments.of("A11-NUL", "NUL"),
                Arguments.of("A11-COM1", "COM1"),
                Arguments.of("A14", "a/../../outside"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("rejectedIds")
    void rejectsIdsThatCannotNameAWorkspaceFolder(String row, @Nullable String payload) {
        var check = new WorkspaceFolderNameCheck();

        // A failure of NameChecker or of the path API must become false, never an exception
        assertFalse(check.test(payload), () -> row + ": the id must not name a workspace folder.");
    }

    @Test
    void acceptsAnOrdinaryUserId() {
        assertTrue(new WorkspaceFolderNameCheck().test("jdoe.1"), "An ordinary user id names a workspace folder.");
    }

    // The check installed in LocalWorkspaceManagerImpl: the surface A matrix.

    /**
     * The lexical rows of the surface A matrix, labelled with their row id, with the payloads of
     * {@code MigratorSingleUserWorkspaceTest}.
     */
    static Stream<Arguments> lexicalPayloads() {
        return Stream.of(Arguments.of("A1", ".."),
                Arguments.of("A2", "."),
                Arguments.of("A3", "/etc"),
                Arguments.of("A4-drive-path", "C:\\Windows"),
                Arguments.of("A4-drive-relative", "C:x"),
                Arguments.of("A5", "..\\outside"),
                Arguments.of("A6", "a//b"),
                Arguments.of("A7", "..%2Foutside"),
                Arguments.of("A8", "..%252Foutside"),
                Arguments.of("A9", "user\u0000x"),
                Arguments.of("A10-bell", "user\u0007x"),
                Arguments.of("A10-newline", "user\nx"),
                Arguments.of("A11-CON", "CON"),
                Arguments.of("A11-NUL", "NUL"),
                Arguments.of("A11-COM1", "COM1"),
                Arguments.of("A14", "a/../../outside"));
    }

    /**
     * The exact message matters: for A9 it proves that the path API's {@code InvalidPathException} is mapped, not
     * leaked, and for A10 and A11 it proves that the installed check rejects the id, because the workspace module's
     * own checks accept it.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("lexicalPayloads")
    void managerRejectsLexicalPayloads(String row, String payload) throws IOException {
        var before = snapshot(root);

        if ("A4-drive-relative".equals(row) && OS.WINDOWS.isCurrentOs()) {
            // On Windows "C:x" is drive-relative: NameChecker checks its name elements, where only "x" remains, and on
            // the drive of the home it resolves to the direct child "x". It stays contained, so either outcome is
            // secure.
            assertRejectedOrDirectChild(row, payload);
        } else {
            assertRejectedByManager(row, () -> manager.getWorkspace(payload));
        }

        assertEquals(before, snapshot(root), () -> row + ": nothing may change in or beside the workspace home.");
    }

    /** Row A15: division slash, fullwidth solidus, one dot leader and fullwidth full stop. */
    static Stream<Arguments> lookAlikePayloads() {
        return Stream.of(Arguments.of("A15-division-slash", "..\u2215outside"),
                Arguments.of("A15-fullwidth-solidus", "..\uFF0Foutside"),
                Arguments.of("A15-one-dot-leader", "\u2024\u2024"),
                Arguments.of("A15-fullwidth-full-stop", "\uFF0E\uFF0E"));
    }

    /**
     * Look-alike separators are ordinary characters and never act as separators. The id is either rejected or names a
     * direct child of the home; neither outcome is hard-coded.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("lookAlikePayloads")
    void managerKeepsLookAlikeSeparatorsInsideTheHome(String row, String payload) throws IOException {
        var before = outsideHome(snapshot(root));

        assertRejectedOrDirectChild(row, payload);

        assertEquals(before,
                outsideHome(snapshot(root)),
                () -> row + ": nothing may change beside the workspace home.");
    }

    // Row A12: the user's folder is a link to a directory outside the home. The reconciliation of the registry would
    // delete the unrecorded folder 'stray' behind it.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void managerRejectsAUserFolderLinkedOutsideTheHome() throws IOException {
        var outsideTarget = root.resolve("outside-target");
        var stray = Files.createDirectories(outsideTarget.resolve("stray"));
        Files.writeString(stray.resolve("marker.txt"), marker());
        var victim = Files.createSymbolicLink(home.resolve("victim"), outsideTarget);
        var before = snapshot(outsideTarget);

        assertRejectedByManager("A12 getWorkspace", () -> manager.getWorkspace("victim"));
        assertRejectedByManager("A12 refreshMetainfoRegistry", () -> manager.refreshMetainfoRegistry("victim"));

        assertEquals(before, snapshot(outsideTarget), "A12: nothing outside the home may change through the link.");
        assertEquals(outsideTarget, Files.readSymbolicLink(victim), "A12: the link still points to the same target.");
    }

    // Row A13: the user's folder is a dangling link to a missing path outside the home.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void managerRejectsAUserFolderThatIsADanglingLink() throws IOException {
        var ghostTarget = root.resolve("ghost-target");
        var ghost = Files.createSymbolicLink(home.resolve("ghost"), ghostTarget);

        assertRejectedByManager("A13 getWorkspace", () -> manager.getWorkspace("ghost"));
        assertRejectedByManager("A13 refreshMetainfoRegistry", () -> manager.refreshMetainfoRegistry("ghost"));

        assertFalse(Files.exists(ghostTarget, LinkOption.NOFOLLOW_LINKS), "A13: the link target must not be created.");
        assertTrue(Files.isSymbolicLink(ghost), "A13: the link is still a link.");
    }

    // Row A16: the folder of user 'alice' is a link to the folder of user 'bob' inside the home.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void managerRejectsAUserFolderLinkedToAnotherUsersFolder() throws IOException {
        var bob = home.resolve("bob");
        var project = Files.createDirectories(bob.resolve("Proj"));
        Files.writeString(project.resolve("marker.txt"), marker());
        Files.createDirectories(bob.resolve("stray"));
        var alice = Files.createSymbolicLink(home.resolve("alice"), bob);
        var before = snapshot(bob);

        assertRejectedByManager("A16 getWorkspace", () -> manager.getWorkspace("alice"));
        assertRejectedByManager("A16 refreshMetainfoRegistry", () -> manager.refreshMetainfoRegistry("alice"));

        assertEquals(before, snapshot(bob), "A16: nothing of another user's workspace may change through the link.");
        assertEquals(bob, Files.readSymbolicLink(alice), "A16: the link still points to the same target.");
    }

    // The installed check must not break the first access of a new user, whose folder does not exist yet.
    @Test
    void managerGivesANewUserAWorkspaceRightUnderTheHome() {
        var workspace = manager.getWorkspace("jdoe.1");
        try {
            assertEquals(manager.getWorkspaceHome().resolve("jdoe.1"),
                    workspace.getLocation().toPath(),
                    "A new user's workspace is the folder named by the user id right under the home.");
        } finally {
            workspace.release();
        }
    }

    // Helpers of the surface A matrix, private to this class.

    /** Asserts that the call fails with the rejection of {@code LocalWorkspaceManagerImpl}. */
    private static void assertRejectedByManager(String row, Executable call) {
        var e = assertThrows(IllegalArgumentException.class, call, () -> row + ": the id must be rejected.");
        assertEquals(REJECTED, e.getMessage(), () -> row + ": the rejection keeps the existing message.");
    }

    /**
     * Asserts that the id is either rejected with the message of {@code LocalWorkspaceManagerImpl} or names a direct
     * child of the home. A returned workspace is released.
     */
    private void assertRejectedOrDirectChild(String row, String payload) {
        LocalWorkspace workspace;
        try {
            workspace = manager.getWorkspace(payload);
        } catch (IllegalArgumentException e) {
            assertEquals(REJECTED, e.getMessage(), () -> row + ": the rejection keeps the existing message.");
            return;
        }
        try {
            assertEquals(manager.getWorkspaceHome(),
                    workspace.getLocation().toPath().toAbsolutePath().normalize().getParent(),
                    () -> row + ": an accepted id names a direct child of the workspace home.");
        } finally {
            workspace.release();
        }
    }

    /**
     * Captures the tree under the folder without following links: each entry, keyed by its path relative to the
     * folder, maps to its link target, its file content or {@code dir}.
     *
     * @return a sorted map, empty when the folder does not exist
     */
    private static Map<String, String> snapshot(Path dir) throws IOException {
        var entries = new TreeMap<String, String>();
        if (!Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
            return entries;
        }
        try (var paths = Files.walk(dir)) {
            for (var p : paths.toList()) {
                String value;
                if (Files.isSymbolicLink(p)) {
                    value = "link:" + Files.readSymbolicLink(p);
                } else if (Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
                    value = "file:" + Files.readString(p);
                } else {
                    value = "dir";
                }
                entries.put(dir.relativize(p).toString(), value);
            }
        }
        return entries;
    }

    /** Drops the workspace home and everything under it from a snapshot of the temporary folder. */
    private Map<String, String> outsideHome(Map<String, String> rootSnapshot) {
        var homePrefix = HOME_NAME + root.getFileSystem().getSeparator();
        var outside = new TreeMap<String, String>();
        rootSnapshot.forEach((key, value) -> {
            if (!key.equals(HOME_NAME) && !key.startsWith(homePrefix)) {
                outside.put(key, value);
            }
        });
        return outside;
    }

    /** Random content for a planted file, so its surviving copy is unambiguous; never a literal. */
    private static String marker() {
        return RandomStringUtils.secure().nextAlphanumeric(16);
    }
}

package org.openl.rules.webstudio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.abort;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.TreeMap;
import java.util.stream.Stream;

import org.apache.commons.lang3.RandomStringUtils;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;

/**
 * Tests of the single-user workspace move from the former {@code DEFAULT} name to the resolved user name.
 * EPBDS-16213 changed the single-user default from {@code DEFAULT} to the OS account.
 * It also runs the V1 surface A (workspace directory) path-traversal matrix against the move.
 *
 * <p>The V1 rows also check the skip WARN. Unit tests log through slf4j-simple, which writes to {@link System#err}
 * and resolves that stream on every write, so {@link StdIo} captures the line. The assertions match message
 * substrings only and never the logger name, which is a detail of the logging binding.
 */
class MigratorSingleUserWorkspaceTest {

    @TempDir
    Path root;

    @Test
    void movesLegacyWorkspaceToResolvedName() throws IOException {
        var project = Files.createDirectories(root.resolve("DEFAULT").resolve("SoloProj"));
        Files.writeString(project.resolve("solo-wip.txt"), "work in progress");

        Migrator.migrateSingleUserWorkspace("single", root.toString(), "openl");

        assertFalse(Files.exists(root.resolve("DEFAULT")), "The legacy DEFAULT workspace is moved.");
        assertTrue(Files.exists(root.resolve("openl").resolve("SoloProj").resolve("solo-wip.txt")),
                "Uncommitted work is preserved under the resolved user name.");
    }

    @Test
    void keepsWorkspaceWhenNameStaysDefault() throws IOException {
        var project = Files.createDirectories(root.resolve("DEFAULT").resolve("SoloProj"));

        Migrator.migrateSingleUserWorkspace("single", root.toString(), "DEFAULT");

        assertTrue(Files.exists(project), "An install still using DEFAULT keeps its workspace in place.");
    }

    @Test
    void skipsWhenTargetWorkspaceExists() throws IOException {
        Files.createDirectories(root.resolve("DEFAULT").resolve("Legacy"));
        var fresh = Files.createDirectories(root.resolve("openl").resolve("Fresh"));

        Migrator.migrateSingleUserWorkspace("single", root.toString(), "openl");

        assertTrue(Files.exists(root.resolve("DEFAULT").resolve("Legacy")),
                "An existing target workspace is never overwritten.");
        assertTrue(Files.exists(fresh), "The existing target workspace is left intact.");
    }

    @Test
    void skipsWhenNoLegacyWorkspace() {
        Migrator.migrateSingleUserWorkspace("single", root.toString(), "openl");

        assertFalse(Files.exists(root.resolve("openl")), "Nothing is created without a legacy workspace.");
    }

    @Test
    void skipsWhenNotSingleMode() throws IOException {
        var project = Files.createDirectories(root.resolve("DEFAULT").resolve("SoloProj"));

        Migrator.migrateSingleUserWorkspace("multi", root.toString(), "openl");

        assertTrue(Files.exists(project), "In multi-user mode a DEFAULT folder is a real user and is not touched.");
    }

    @Test
    void toleratesBlankOrMissingConfiguration() throws IOException {
        Files.createDirectories(root.resolve("DEFAULT").resolve("SoloProj"));

        Migrator.migrateSingleUserWorkspace("single", null, "openl");
        Migrator.migrateSingleUserWorkspace("single", root.toString(), null);
        // A blank path must not fall through to Path.of(""), which resolves to the process working directory.
        Migrator.migrateSingleUserWorkspace("single", "", "openl");
        Migrator.migrateSingleUserWorkspace("single", "   ", "openl");
        Migrator.migrateSingleUserWorkspace("single", root.toString(), " ");

        assertTrue(Files.exists(root.resolve("DEFAULT")), "Blank or absent configuration is a no-op, not a failure.");
    }

    // V1: a nested name no longer reaches the move, so the failing move takes a single folder name of 256 ASCII
    // characters. It passes every name check and exceeds the 255-byte file name limit of ext4, APFS and NTFS.
    @Test
    @StdIo
    void logsInsteadOfThrowingWhenMoveFails(StdErr err) throws IOException {
        Files.createDirectories(root.resolve("DEFAULT").resolve("SoloProj"));
        var username = "u".repeat(256);

        // Must not throw: a failed migration cannot break startup.
        Migrator.migrateSingleUserWorkspace("single", root.toString(), username);

        assertTrue(Files.exists(root.resolve("DEFAULT")), "A failed move leaves the legacy workspace intact.");
        // V1: the ERROR proves that the name passed the checks and that the move itself failed.
        var message = "Failed to move the single-user workspace from 'DEFAULT' to '" + username + "'.";
        var lines = Arrays.stream(err.capturedLines()).filter(line -> line.contains(message)).toList();
        assertEquals(1, lines.size(), "Exactly one line logs the failed move.");
        assertTrue(lines.get(0).contains("ERROR"), "The failed move is logged at ERROR.");
    }

    @Test
    void skipsWhenUserNameTraversesOutOfRoot() throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        Files.createDirectories(ws.resolve("DEFAULT").resolve("SoloProj"));

        Migrator.migrateSingleUserWorkspace("single", ws.toString(), "../outside");

        assertTrue(Files.exists(ws.resolve("DEFAULT")), "A traversing user name must not move the workspace out of root.");
        assertFalse(Files.exists(root.resolve("outside")), "Nothing is created outside the workspace root.");
    }

    @Test
    void skipsWhenUserNameIsAbsolute(@TempDir Path other) throws IOException {
        Files.createDirectories(root.resolve("DEFAULT").resolve("SoloProj"));
        var absolute = other.resolve("hijack");

        Migrator.migrateSingleUserWorkspace("single", root.toString(), absolute.toString());

        assertTrue(Files.exists(root.resolve("DEFAULT")), "An absolute user name must not move the workspace out of root.");
        assertFalse(Files.exists(absolute), "Nothing is created at the absolute location.");
    }

    // V1: surface A lexical matrix, rows A1-A11 and A14 (this hunk also brings the V1 imports). The display name is
    // the row id only: the payloads carry NUL and control characters that would corrupt the test reports.
    // V1: each row also gets its logged name and the captured log.
    @ParameterizedTest(name = "{0}")
    @MethodSource("lexicalPayloads")
    @StdIo
    void skipsInvalidUserName(String row, String userId, String loggedName, StdErr err) throws IOException {
        var ws = legacyLayout();
        var before = capture(ws, List.of(), List.of());

        var thrown = invoke(ws, userId);

        assertContained(ws, before, thrown);
        assertFalse(Files.exists(root.resolve("outside"), LinkOption.NOFOLLOW_LINKS),
                "V1 containment: nothing is created beside the workspace root.");
        if ("A4b".equals(row) && OS.WINDOWS.isCurrentOs()) {
            // V1: on Windows "C:x" is drive-relative. NameChecker checks its name elements, where only "x" remains,
            // and on the root's drive it resolves to the direct child "x": contained, so either outcome is secure.
            assertNull(thrown, () -> "V1 rejection: the migration threw " + describe(thrown));
            assertTrue(isLegacyWorkspaceKept(ws) || isMovedToDirectChild(ws, "x"),
                    "V1 rejection: a drive-relative name keeps the workspace or moves it to a direct child of the root.");
        } else {
            assertRejected(ws, thrown);
            // V1: the skip names the invalid name once, at WARN, with every control character replaced.
            assertSkipLogged(err, invalidNameMessage(loggedName));
            assertLogPrintable(err);
        }
    }

    // V1: surface A row A15, look-alike separators are ordinary characters and never act as separators.
    @ParameterizedTest(name = "{0}")
    @MethodSource("lookAlikePayloads")
    void keepsLookAlikeSeparatorsInsideRoot(String row, String userId) throws IOException {
        var ws = legacyLayout();
        var before = capture(ws, List.of(), List.of());

        var thrown = invoke(ws, userId);

        assertContained(ws, before, thrown);
        assertFalse(Files.exists(root.resolve("outside"), LinkOption.NOFOLLOW_LINKS),
                "V1 containment: nothing is created beside the workspace root.");
        assertNull(thrown, () -> "V1 rejection: the migration threw " + describe(thrown));
        // Both validators accept these names, so the move may land on the literal direct child: still contained.
        assertTrue(isLegacyWorkspaceKept(ws) || isMovedToDirectChild(ws, userId),
                "V1 rejection: a look-alike separator keeps the workspace or moves it to a direct child of the root.");
    }

    // V1: surface A, the name must be a single folder name, as the user workspace directory requires. A nested name
    // would move the legacy workspace into another user's folder and a leading dot would hide it as a service folder,
    // so each is skipped with the invalid-name WARN and nothing of the sibling workspace is written (row A16).
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"bob/x", "x/", "bob/x/y", ".hidden"})
    @StdIo
    void skipsUserNameThatIsNotSingleFolderName(String userId, StdErr err) throws IOException {
        var ws = legacyLayout();
        var bob = Files.createDirectories(ws.resolve("bob"));
        var marker = RandomStringUtils.secure().nextAlphanumeric(16);
        Files.writeString(bob.resolve("marker.txt"), marker);
        var before = capture(ws, List.of(bob), List.of());

        var thrown = invoke(ws, userId);

        assertContained(ws, before, thrown);
        assertEquals(Map.of("marker.txt", "file:" + marker), snapshot(bob),
                "V1 containment: the sibling workspace holds only its marker.");
        assertRejected(ws, thrown);
        assertSkipLogged(err, invalidNameMessage(userId));
    }

    // V1: surface A row A12, the user's folder is a link to a directory outside the workspace root. The id is skipped
    // with the escape WARN. The nested id is not a single folder name, so it is skipped with the invalid-name WARN
    // before the link is followed.
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"victim", "victim/x"})
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void skipsWhenUserFolderLinksOutsideRoot(String userId, StdErr err) throws IOException {
        var ws = legacyLayout();
        var outsideTarget = Files.createDirectories(root.resolve("outside-target"));
        var marker = RandomStringUtils.secure().nextAlphanumeric(16);
        Files.writeString(outsideTarget.resolve("marker.txt"), marker);
        var victim = Files.createSymbolicLink(ws.resolve("victim"), outsideTarget);
        var before = capture(ws, List.of(outsideTarget), List.of(victim));

        var thrown = invoke(ws, userId);

        assertContained(ws, before, thrown);
        assertEquals(Map.of("marker.txt", "file:" + marker), snapshot(outsideTarget),
                "V1 containment: the outside directory holds only its marker.");
        assertRejected(ws, thrown);
        // V1: the expected WARN depends on whether the id is nested.
        assertSkipLogged(err, linkSkipMessage(userId));
    }

    // V1: surface A row A13, the user's folder is a dangling link to a missing path outside the workspace root. The id
    // is skipped with the escape WARN. The nested id is not a single folder name, so it is skipped with the
    // invalid-name WARN before the link is followed.
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"ghost", "ghost/x"})
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void skipsWhenUserFolderIsDanglingLink(String userId, StdErr err) throws IOException {
        var ws = legacyLayout();
        var ghostTarget = root.resolve("ghost-target");
        var ghost = Files.createSymbolicLink(ws.resolve("ghost"), ghostTarget);
        var before = capture(ws, List.of(), List.of(ghost));

        var thrown = invoke(ws, userId);

        assertContained(ws, before, thrown);
        assertFalse(Files.exists(ghostTarget, LinkOption.NOFOLLOW_LINKS),
                "V1 containment: the target of the dangling link is never created.");
        assertRejected(ws, thrown);
        // V1: the expected WARN depends on whether the id is nested.
        assertSkipLogged(err, linkSkipMessage(userId));
    }

    // V1: surface A row A16, the user's folder is a link to another user's folder inside the workspace root. The id is
    // skipped with the escape WARN. The nested id is not a single folder name, so it is skipped with the
    // invalid-name WARN before the link is followed.
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"alice", "alice/x"})
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void skipsWhenUserFolderLinksToSibling(String userId, StdErr err) throws IOException {
        var ws = legacyLayout();
        var bob = Files.createDirectories(ws.resolve("bob"));
        var marker = RandomStringUtils.secure().nextAlphanumeric(16);
        Files.writeString(bob.resolve("marker.txt"), marker);
        var alice = Files.createSymbolicLink(ws.resolve("alice"), bob);
        var before = capture(ws, List.of(bob), List.of(alice));

        var thrown = invoke(ws, userId);

        assertContained(ws, before, thrown);
        assertEquals(Map.of("marker.txt", "file:" + marker), snapshot(bob),
                "V1 containment: the sibling workspace holds only its marker.");
        assertRejected(ws, thrown);
        // V1: the expected WARN depends on whether the id is nested.
        assertSkipLogged(err, linkSkipMessage(userId));
    }

    // V1: the user's folder is a link to itself. The loop cannot be resolved, so the id is skipped with the WARN of a
    // folder that cannot be resolved, not with the escape WARN. The nested id is not a single folder name, so it is
    // skipped with the invalid-name WARN before the loop is followed.
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"loop", "loop/x"})
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void skipsWhenUserFolderIsLinkLoop(String userId, StdErr err) throws IOException {
        var ws = legacyLayout();
        var loop = Files.createSymbolicLink(ws.resolve("loop"), ws.resolve("loop"));
        var before = capture(ws, List.of(), List.of(loop));

        var thrown = invoke(ws, userId);

        assertContained(ws, before, thrown);
        assertRejected(ws, thrown);
        // V1: the nested id fails the single folder name check, so the loop is never resolved.
        if (isNested(userId)) {
            assertSkipLogged(err, invalidNameMessage(userId));
            assertFalse(err.capturedString().contains(UNRESOLVABLE_TEXT),
                    "V1 rejection: a nested id is not reported as a folder that cannot be resolved.");
        } else {
            assertUnresolvableLogged(err, userId);
        }
        assertFalse(err.capturedString().contains(OUTSIDE_ROOT_TEXT),
                "V1 rejection: a folder that cannot be resolved is not reported as resolving outside the root.");
    }

    // V1: a link loop whose name holds a C1 control or a Unicode line or paragraph separator. The failure behind the
    // WARN quotes the raw path, and the WARN shows both the name and that failure with the character replaced.
    @ParameterizedTest(name = "{0}")
    @MethodSource("lineBreakingPayloads")
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void replacesLineBreakersInUnresolvableWarning(String row, String userId, String loggedName, StdErr err)
            throws IOException {
        var ws = legacyLayout();
        var loopPath = linkPath(ws, userId);
        var loop = Files.createSymbolicLink(loopPath, loopPath);
        var before = capture(ws, List.of(), List.of(loop));

        var thrown = invoke(ws, userId);

        assertContained(ws, before, thrown);
        assertRejected(ws, thrown);
        assertUnresolvableLogged(err, loggedName);
        assertLogPrintable(err);
    }

    // V1: a name that passes both validators may still hold a C1 control or a Unicode line or paragraph separator.
    // Its link to an outside directory is rejected, and the escape WARN shows the name with that character replaced.
    @ParameterizedTest(name = "{0}")
    @MethodSource("lineBreakingPayloads")
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void replacesLineBreakersInEscapeWarning(String row, String userId, String loggedName, StdErr err)
            throws IOException {
        var ws = legacyLayout();
        var outsideTarget = Files.createDirectories(root.resolve("outside-target"));
        var marker = RandomStringUtils.secure().nextAlphanumeric(16);
        Files.writeString(outsideTarget.resolve("marker.txt"), marker);
        var link = Files.createSymbolicLink(linkPath(ws, userId), outsideTarget);
        var before = capture(ws, List.of(outsideTarget), List.of(link));

        var thrown = invoke(ws, userId);

        assertContained(ws, before, thrown);
        assertEquals(Map.of("marker.txt", "file:" + marker), snapshot(outsideTarget),
                "V1 containment: the outside directory holds only its marker.");
        assertRejected(ws, thrown);
        assertSkipLogged(err, outsideRootMessage(loggedName));
        assertLogPrintable(err);
    }

    // V1: a missing workspace root means there is nothing to migrate; it returns silently and creates nothing.
    @Test
    void skipsWhenWorkspaceRootIsMissing() {
        var missing = root.resolve("missing-ws");

        var thrown = invoke(missing, "openl");

        assertNull(thrown, () -> "V1 rejection: the migration threw " + describe(thrown));
        assertFalse(Files.exists(missing, LinkOption.NOFOLLOW_LINKS),
                "V1 containment: a missing workspace root is not created.");
    }

    // V1: payloads of the lexical matrix, labelled with their row id and followed by the name as the skip logs it.
    static Stream<Arguments> lexicalPayloads() {
        return Stream.of(Arguments.of("A1", "..", ".."),
                Arguments.of("A2", ".", "."),
                Arguments.of("A3", "/etc", "/etc"),
                Arguments.of("A4a", "C:\\Windows", "C:\\Windows"),
                Arguments.of("A4b", "C:x", "C:x"),
                Arguments.of("A5", "..\\outside", "..\\outside"),
                Arguments.of("A6", "a//b", "a//b"),
                Arguments.of("A7", "..%2Foutside", "..%2Foutside"),
                Arguments.of("A8", "..%252Foutside", "..%252Foutside"),
                Arguments.of("A9", "user\u0000x", "user_x"),
                Arguments.of("A10a", "user\u0007x", "user_x"),
                Arguments.of("A10b", "user\nx", "user_x"),
                Arguments.of("A11a", "CON", "CON"),
                Arguments.of("A11b", "NUL", "NUL"),
                Arguments.of("A11c", "COM1", "COM1"),
                Arguments.of("A14", "a/../../outside", "a/../../outside"));
    }

    // V1: names that both validators accept although they hold a line separator, a paragraph separator or a C1
    // control (next line), labelled with their row id and followed by the name as the skip logs it.
    static Stream<Arguments> lineBreakingPayloads() {
        return Stream.of(Arguments.of("A12-LS", "v\u2028x", "v_x"),
                Arguments.of("A12-PS", "v\u2029x", "v_x"),
                Arguments.of("A12-NEL", "v\u0085x", "v_x"));
    }

    // V1: payloads of row A15: division slash, fullwidth solidus, one dot leader and fullwidth full stop.
    static Stream<Arguments> lookAlikePayloads() {
        return Stream.of(Arguments.of("A15a", "..\u2215outside"),
                Arguments.of("A15b", "..\uFF0Foutside"),
                Arguments.of("A15c", "\u2024\u2024"),
                Arguments.of("A15d", "\uFF0E\uFF0E"));
    }

    // V1: helpers of the surface A matrix, private to this class.
    private static final Path ETC = Path.of("/etc");

    /** Uncommitted work planted by {@link #legacyLayout()}; random, so its surviving copy is unambiguous. */
    private final String legacyWork = RandomStringUtils.secure().nextAlphanumeric(16);

    /** The state that the tier-1 containment assertion compares after the call. */
    private record Before(Map<String, String> outside,
            Map<Path, Map<String, String>> siblings,
            Map<Path, Path> links,
            boolean etcIsDirectory) {
    }

    /**
     * Builds {@code ws/DEFAULT/SoloProj/solo-wip.txt}, the layout of {@link #skipsWhenUserNameTraversesOutOfRoot()}.
     *
     * @return the workspace root {@code ws}
     */
    private Path legacyLayout() throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var project = Files.createDirectories(ws.resolve("DEFAULT").resolve("SoloProj"));
        Files.writeString(project.resolve("solo-wip.txt"), legacyWork);
        return ws;
    }

    private Before capture(Path ws, List<Path> siblings, List<Path> links) throws IOException {
        var siblingSnapshots = new LinkedHashMap<Path, Map<String, String>>();
        for (var sibling : siblings) {
            siblingSnapshots.put(sibling, snapshot(sibling));
        }
        var linkTargets = new LinkedHashMap<Path, Path>();
        for (var link : links) {
            linkTargets.put(link, Files.readSymbolicLink(link));
        }
        return new Before(outside(root, ws), siblingSnapshots, linkTargets, Files.isDirectory(ETC));
    }

    /**
     * Runs the move and captures whatever it throws, so that tier 1 judges the containment before tier 2 judges the
     * rejection.
     */
    private static @Nullable Throwable invoke(Path ws, String userId) {
        try {
            Migrator.migrateSingleUserWorkspace("single", ws.toString(), userId);
            return null;
        } catch (Throwable e) {
            return e;
        }
    }

    /**
     * Tier 1: nothing outside the user's own folder changes and the legacy work survives exactly once, in
     * {@code DEFAULT} or in a single direct child of the workspace root. An {@link IllegalArgumentException} (which
     * includes {@link java.nio.file.InvalidPathException}) is recorded, not treated as an escape.
     */
    private void assertContained(Path ws, Before before, @Nullable Throwable thrown) throws IOException {
        assertTrue(thrown == null || thrown instanceof IllegalArgumentException,
                () -> "V1 containment: the migration failed with " + describe(thrown));
        assertEquals(before.outside(), outside(root, ws), "V1 containment: nothing outside the workspace root changes.");
        for (var sibling : before.siblings().entrySet()) {
            assertEquals(sibling.getValue(), snapshot(sibling.getKey()),
                    () -> "V1 containment: the folder " + sibling.getKey().getFileName() + " is unchanged.");
        }
        for (var link : before.links().entrySet()) {
            assertTrue(Files.isSymbolicLink(link.getKey()),
                    () -> "V1 containment: " + link.getKey().getFileName() + " is still a link.");
            assertEquals(link.getValue(), Files.readSymbolicLink(link.getKey()),
                    () -> "V1 containment: " + link.getKey().getFileName() + " still points to the same target.");
        }
        var copies = snapshot(ws).entrySet()
                .stream()
                .filter(entry -> entry.getValue().equals("file:" + legacyWork))
                .map(entry -> entry.getKey().split("/"))
                .toList();
        assertEquals(1, copies.size(), "V1 containment: the legacy work survives exactly once in the workspace root.");
        var copy = copies.get(0);
        assertTrue(copy.length == 3 && "SoloProj".equals(copy[1]) && "solo-wip.txt".equals(copy[2]),
                "V1 containment: the legacy work stays in DEFAULT or in a single direct child of the workspace root.");
        assertEquals(before.etcIsDirectory(), Files.isDirectory(ETC), "V1 containment: /etc keeps its type.");
        assertFalse(Files.exists(ETC.resolve("SoloProj"), LinkOption.NOFOLLOW_LINKS),
                "V1 containment: nothing is moved into /etc.");
    }

    /** Tier 2: the name is rejected, so nothing is thrown and the legacy workspace stays in place. */
    private static void assertRejected(Path ws, @Nullable Throwable thrown) {
        assertNull(thrown, () -> "V1 rejection: the migration threw " + describe(thrown));
        assertTrue(isLegacyWorkspaceKept(ws), "V1 rejection: the legacy DEFAULT workspace is kept in place.");
    }

    private static boolean isLegacyWorkspaceKept(Path ws) {
        return Files.isRegularFile(ws.resolve("DEFAULT").resolve("SoloProj").resolve("solo-wip.txt"),
                LinkOption.NOFOLLOW_LINKS);
    }

    /** Called only once the legacy workspace is gone, when the name has already resolved as a folder name. */
    private static boolean isMovedToDirectChild(Path ws, String name) {
        var moved = ws.resolve(name);
        return ws.equals(moved.getParent()) && Files.isDirectory(moved.resolve("SoloProj"), LinkOption.NOFOLLOW_LINKS);
    }

    /** Names only the exception class: its message may echo a payload with NUL or control characters. */
    private static String describe(@Nullable Throwable thrown) {
        return thrown == null ? "nothing" : thrown.getClass().getName();
    }

    // V1: helpers of the skip WARN checks.
    /** The part of the escape WARN that names the reason, whatever user name it carries. */
    private static final String OUTSIDE_ROOT_TEXT = "resolves outside the workspace root";

    /** The WARN of a name whose folder leads outside its own place under the workspace root. */
    private static String outsideRootMessage(String loggedName) {
        return "The single-user name '" + loggedName + "' " + OUTSIDE_ROOT_TEXT + "; the move is skipped.";
    }

    /** The WARN of a name that cannot name a workspace folder. */
    private static String invalidNameMessage(String loggedName) {
        return "The single-user name '" + loggedName + "' is not a valid workspace folder name; the move is skipped.";
    }

    // V1: helpers of the link rows, whose nested ids fail the single folder name check before any link is followed.
    /** The reason part of the WARN of a folder that cannot be resolved, whatever user name it carries. */
    private static final String UNRESOLVABLE_TEXT = "cannot be resolved";

    /** Whether the id has more than one segment, so that it is not a single workspace folder name. */
    private static boolean isNested(String userId) {
        return userId.contains("/");
    }

    /** The WARN of a link row: the invalid-name WARN for a nested id, the escape WARN otherwise. */
    private static String linkSkipMessage(String userId) {
        return isNested(userId) ? invalidNameMessage(userId) : outsideRootMessage(userId);
    }

    /**
     * Asserts that exactly one captured line logs at WARN that the folder of the name cannot be resolved, for example
     * because of a link loop, and that the line names the file-system failure behind it. The failure text quotes only
     * the expected start of the message, which holds no control character.
     */
    private static void assertUnresolvableLogged(StdErr err, String loggedName) {
        var start = "The workspace folder of the single-user name '" + loggedName + "' cannot be resolved (";
        var lines = Arrays.stream(err.capturedLines()).filter(line -> line.contains(start)).toList();
        assertEquals(1, lines.size(), () -> "V1 rejection: exactly one line logs \"" + start + "...\".");
        var line = lines.get(0);
        assertTrue(line.contains("WARN"), () -> "V1 rejection: \"" + start + "...\" is logged at WARN.");
        assertTrue(line.contains("FileSystemException"),
                () -> "V1 rejection: \"" + start + "...\" names the file-system failure.");
        assertTrue(line.endsWith("); the move is skipped."),
                () -> "V1 rejection: \"" + start + "...\" ends with the skip on the same line.");
    }

    /**
     * Asserts that exactly one captured line holds the message and that it is logged at WARN. The failure text
     * quotes only the expected message, which holds no control character.
     */
    private static void assertSkipLogged(StdErr err, String message) {
        var lines = Arrays.stream(err.capturedLines()).filter(line -> line.contains(message)).toList();
        assertEquals(1, lines.size(), () -> "V1 rejection: exactly one line logs \"" + message + "\".");
        assertTrue(lines.get(0).contains("WARN"), () -> "V1 rejection: \"" + message + "\" is logged at WARN.");
    }

    /** Asserts that the captured log holds no character that could break a line or forge one. */
    private static void assertLogPrintable(StdErr err) {
        assertTrue(err.capturedString().chars().allMatch(MigratorSingleUserWorkspaceTest::isLogSafe),
                "V1 rejection: the log holds no control character and no line or paragraph separator.");
    }

    /** The line ending and the tab of a stack trace are safe; other ISO controls and U+2028, U+2029 are not. */
    private static boolean isLogSafe(int c) {
        if (c == '\n' || c == '\r' || c == '\t') {
            return true;
        }
        return !Character.isISOControl(c) && c != '\u2028' && c != '\u2029';
    }

    /** The link of a payload, or an aborted test where the platform cannot encode the payload in a file name. */
    private static Path linkPath(Path ws, String name) {
        try {
            return ws.resolve(name);
        } catch (InvalidPathException e) {
            return abort("V1: the platform cannot encode the payload of this row in a file name.");
        }
    }

    /**
     * A no-follow view of a tree, keyed by the {@code /}-joined path relative to {@code base}: {@code dir} for a
     * directory, {@code file:<content>} for a regular file and {@code link:<target>} for a link, which is never
     * descended into.
     *
     * @return the entries below {@code base}, or an empty map when {@code base} does not exist
     */
    private static Map<String, String> snapshot(Path base) throws IOException {
        var entries = new TreeMap<String, String>();
        if (!Files.exists(base, LinkOption.NOFOLLOW_LINKS)) {
            return entries;
        }
        Files.walkFileTree(base, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                if (Files.isSymbolicLink(dir)) {
                    entries.put(key(base, dir), "link:" + Files.readSymbolicLink(dir));
                    return FileVisitResult.SKIP_SUBTREE;
                }
                if (!dir.equals(base)) {
                    entries.put(key(base, dir), "dir");
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (attrs.isSymbolicLink()) {
                    entries.put(key(base, file), "link:" + Files.readSymbolicLink(file));
                } else if (attrs.isRegularFile()) {
                    entries.put(key(base, file), "file:" + Files.readString(file));
                } else {
                    entries.put(key(base, file), "other");
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return entries;
    }

    private static String key(Path base, Path path) {
        var joiner = new StringJoiner("/");
        for (var name : base.relativize(path)) {
            joiner.add(name.toString());
        }
        return joiner.toString();
    }

    /** The outside world: every entry below {@code root} except the subtree of the workspace root {@code ws}. */
    private static Map<String, String> outside(Path root, Path ws) throws IOException {
        var prefix = key(root, ws);
        var entries = snapshot(root);
        entries.keySet().removeIf(name -> name.equals(prefix) || name.startsWith(prefix + "/"));
        return entries;
    }
}

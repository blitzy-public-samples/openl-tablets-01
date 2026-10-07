package org.openl.rules.webstudio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.abort;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
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

import org.openl.rules.project.impl.local.MetainfoRegistry;

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

    // V1: a valid single folder name of 256 ASCII characters passes every name check, yet the move itself fails.
    // The name exceeds the 255-byte file name limit of ext4, APFS and NTFS.
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

    // V1: surface A lexical matrix, rows A1-A11 and A14.
    // The display name is only the row id: the payloads' NUL and control characters would corrupt the test reports.
    // V1: each row also gets its logged name and the captured log.
    // Every row is skipped on every OS, the drive-relative A4b included, because the raw name is checked before path
    // parsing can drop a drive prefix.
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
        assertRejected(ws, thrown);
        // V1: the skip names the invalid name once, at WARN, with every control character replaced.
        assertSkipLogged(err, invalidNameMessage(loggedName));
        assertLogPrintable(err);
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

    // V1: surface A, the name must be a single folder name, as the user workspace directory requires.
    // A nested name would move the legacy workspace into another user's folder and a leading dot would hide it as a
    // service folder, so each is skipped with the invalid-name WARN and nothing of the sibling workspace is written
    // (row A16).
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

    // V1: surface A row A12, the user's folder is a link to a directory outside the workspace root.
    // The id is skipped with the escape WARN. The nested id is not a single folder name, so it is skipped with the
    // invalid-name WARN before the link is followed.
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

    // V1: surface A row A13, the user's folder is a dangling link to a missing path outside the workspace root.
    // The id is skipped with the escape WARN. The nested id is not a single folder name, so it is skipped with the
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

    // V1: surface A row A16, the user's folder is a link to another user's folder inside the workspace root.
    // The id is skipped with the escape WARN. The nested id is not a single folder name, so it is skipped with the
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

    // V1: the user's folder is a link to itself, a loop that cannot be resolved.
    // The id is skipped with the WARN of a folder that cannot be resolved, not with the escape WARN. The nested id is
    // not a single folder name, so it is skipped with the invalid-name WARN before the loop is followed.
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

    // V1: a link loop whose name holds a C1 control or a Unicode line or paragraph separator.
    // The failure behind the WARN quotes the raw path, and the WARN shows both the name and that failure with the
    // character replaced.
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

    // V1: the startup order of migrate(), the single-user move and then the metainfo conversion of every user folder.
    // The move skips a user folder that links out of the workspace root (row A12). The conversion skips it and a user
    // folder that links into another user's workspace (row A16), each with one WARN, so nothing behind either link is
    // read, written or deleted, while the legacy project of an ordinary user folder is still converted.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void startupConversionSkipsUserFoldersThatLinkElsewhere(StdErr err) throws IOException {
        var ws = legacyLayout();
        var outsideTarget = Files.createDirectories(root.resolve("outside"));
        legacyProject(outsideTarget.resolve("Proj"));
        // V1: team is a plain folder of bob's workspace, so bob's own conversion never converts team/Proj.
        var bob = Files.createDirectories(ws.resolve("bob"));
        var team = Files.createDirectories(bob.resolve("team"));
        legacyProject(team.resolve("Proj"));
        var victim = Files.createSymbolicLink(ws.resolve("victim"), outsideTarget);
        var alice = Files.createSymbolicLink(ws.resolve("alice"), team);
        var jdoe = Files.createDirectories(ws.resolve("jdoe"));
        var repositoryId = legacyProject(jdoe.resolve("Proj"));
        var before = capture(ws, List.of(outsideTarget, bob), List.of(victim, alice));

        var thrown = invokeStartup(ws, "victim");

        assertContained(ws, before, thrown);
        assertRejected(ws, thrown);
        assertLegacyProjectKept(outsideTarget, "Proj");
        assertLegacyProjectKept(team, "Proj");
        assertSkipLogged(err, outsideRootMessage("victim"));
        assertSkipLogged(err, conversionOutsideRootMessage("victim"));
        assertSkipLogged(err, conversionOutsideRootMessage("alice"));
        assertEquals(2, countConversionSkips(err), "V1 rejection: only the two linked user folders are skipped.");
        assertConverted(jdoe, "Proj", repositoryId);
    }

    // V1: the startup order of migrate() for a valid single-user name, the move and then the conversion.
    // The legacy workspace moves to that name, and the conversion that follows records its legacy project there
    // without any skip.
    @Test
    @StdIo
    void startupConversionRecordsTheMovedWorkspace(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var repositoryId = legacyProject(ws.resolve("DEFAULT").resolve("Proj"));

        var thrown = invokeStartup(ws, "openl");

        assertNull(thrown, () -> "V1 rejection: the migration threw " + describe(thrown));
        assertFalse(Files.exists(ws.resolve("DEFAULT"), LinkOption.NOFOLLOW_LINKS),
                "The legacy DEFAULT workspace is moved.");
        var openl = ws.resolve("openl");
        assertTrue(Files.isRegularFile(openl.resolve("Proj").resolve("marker.txt"), LinkOption.NOFOLLOW_LINKS),
                "Uncommitted work is preserved under the resolved user name.");
        assertEquals(0, countConversionSkips(err), "V1 rejection: a valid user folder of its own is not skipped.");
        assertConverted(openl, "Proj", repositoryId);
    }

    // V1: the conversion skips a user folder whose name is not a valid workspace folder name.
    // Examples are a reserved name and a name holding a forbidden character. The folder gets the invalid-name WARN
    // and keeps its legacy files. Windows cannot create such a folder.
    @ParameterizedTest
    @ValueSource(strings = {"CON", "o'x", "a:b"})
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionSkipsUserFolderWithInvalidName(String name, StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var userDir = Files.createDirectories(ws.resolve(name));
        legacyProject(userDir.resolve("Proj"));
        var before = snapshot(userDir);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertEquals(before, snapshot(userDir), "V1 containment: the skipped user folder is unchanged.");
        assertLegacyProjectKept(userDir, "Proj");
        assertSkipLogged(err, conversionInvalidNameMessage(name));
        assertEquals(1, countConversionSkips(err), "V1 rejection: the invalid user folder is skipped once.");
    }

    // V1: the conversion skips a user folder that links out of the workspace root and has a line-breaking name.
    // The name holds a C1 control or a Unicode line or paragraph separator, and the escape WARN shows it with that
    // character replaced.
    @ParameterizedTest(name = "{0}")
    @MethodSource("lineBreakingPayloads")
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void replacesLineBreakersInConversionSkipWarning(String row, String name, String loggedName, StdErr err)
            throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var outsideTarget = Files.createDirectories(root.resolve("outside"));
        legacyProject(outsideTarget.resolve("Proj"));
        var link = Files.createSymbolicLink(linkPath(ws, name), outsideTarget);
        var before = snapshot(outsideTarget);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertEquals(before, snapshot(outsideTarget), "V1 containment: the outside directory is unchanged.");
        assertLegacyProjectKept(outsideTarget, "Proj");
        assertEquals(outsideTarget, Files.readSymbolicLink(link), "V1 containment: the link keeps its target.");
        assertSkipLogged(err, conversionOutsideRootMessage(loggedName));
        assertLogPrintable(err);
    }

    // V1: rows A13 and the link loop for the conversion.
    // Neither a dangling link nor a link loop is a folder, so the conversion never enters either one and never creates
    // the target of the dangling link.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionLeavesDanglingLinkAndLinkLoopAlone(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var ghostTarget = root.resolve("ghost-target");
        var ghost = Files.createSymbolicLink(ws.resolve("ghost"), ghostTarget);
        var loop = Files.createSymbolicLink(ws.resolve("loop"), ws.resolve("loop"));

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertFalse(Files.exists(ghostTarget, LinkOption.NOFOLLOW_LINKS),
                "V1 containment: the target of the dangling link is never created.");
        assertEquals(ghostTarget, Files.readSymbolicLink(ghost), "V1 containment: the dangling link keeps its target.");
        assertEquals(ws.resolve("loop"), Files.readSymbolicLink(loop), "V1 containment: the link loop is unchanged.");
        assertEquals(0, countConversionSkips(err),
                "V1 rejection: a link that is not a folder never reaches the checks.");
    }

    // V1: the conversion skips a user folder whose real path exceeds the platform path limit.
    // The link to the deep directory is a folder, yet its real path cannot be resolved. The WARN of a folder that
    // cannot be resolved names the file-system failure, and the legacy project behind the link stays untouched.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionSkipsUserFolderThatCannotBeResolved(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var hops = new ArrayList<Path>();
        try {
            var deep = deepChain(hops);
            legacyProject(deep.resolve("Proj"));
            var link = Files.createSymbolicLink(ws.resolve("deep"), deep);
            assertTrue(Files.isDirectory(link), "The linked deep directory is a folder, so the conversion lists it.");

            Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

            assertLegacyProjectKept(deep, "Proj");
            assertEquals(deep, Files.readSymbolicLink(link), "V1 containment: the link keeps its target.");
            assertConversionUnresolvableLogged(err, "deep");
            assertEquals(1, countConversionSkips(err), "V1 rejection: the unresolvable user folder is skipped once.");
        } finally {
            deleteDeepChain(hops);
        }
    }

    // V1: the conversion skips a project folder that links to a legacy project outside the workspace root.
    // Nothing outside changes, the user's registry records no outside repository and a regular project converts.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionSkipsProjectFolderThatLinksOutside(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var alice = Files.createDirectories(ws.resolve("alice"));
        var outsideTarget = Files.createDirectories(root.resolve("outside"));
        legacyProject(outsideTarget.resolve("Proj"));
        var escape = Files.createSymbolicLink(alice.resolve("Escape"), outsideTarget.resolve("Proj"));
        var repositoryId = legacyProject(alice.resolve("Plain"));
        var before = outside(root, ws);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertEquals(before, outside(root, ws), "V1 containment: nothing outside the workspace root changes.");
        assertLegacyProjectKept(outsideTarget, "Proj");
        assertEquals(outsideTarget.resolve("Proj"), Files.readSymbolicLink(escape),
                "V1 containment: the link keeps its target.");
        assertNotRecorded(alice, "Escape");
        assertSkipLogged(err, projectOutsideMessage("Escape", "alice"));
        assertEquals(1, countConversionSkips(err), "V1 rejection: only the linked project folder is skipped.");
        assertConverted(alice, "Plain", repositoryId);
    }

    // V1: the conversion skips a project folder that links into a plain sub-folder of another user's workspace.
    // The workspace of bob is unchanged: team is a project folder of bob without legacy metainfo of its own.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionSkipsProjectFolderThatLinksToSibling(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var bob = Files.createDirectories(ws.resolve("bob"));
        var team = Files.createDirectories(bob.resolve("team"));
        legacyProject(team.resolve("Q"));
        var alice = Files.createDirectories(ws.resolve("alice"));
        var sibling = Files.createSymbolicLink(alice.resolve("Sibling"), team.resolve("Q"));
        var repositoryId = legacyProject(alice.resolve("Plain"));
        var before = snapshot(bob);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertEquals(before, snapshot(bob), "V1 containment: the workspace of bob is unchanged.");
        assertLegacyProjectKept(team, "Q");
        assertEquals(team.resolve("Q"), Files.readSymbolicLink(sibling), "V1 containment: the link keeps its target.");
        assertNotRecorded(alice, "Sibling");
        assertSkipLogged(err, projectOutsideMessage("Sibling", "alice"));
        assertEquals(1, countConversionSkips(err), "V1 rejection: only the linked project folder is skipped.");
        assertConverted(alice, "Plain", repositoryId);
    }

    // V1: the conversion skips a project whose legacy metadata entry links to a valid copy of it outside the root.
    // Nothing outside changes, the project keeps its link and its files, and a regular project still converts.
    @ParameterizedTest
    @ValueSource(strings = {".studioProps", ".history", ".studioProps/.version", ".studioProps/file-properties"})
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionSkipsProjectWhoseMetadataLinksOutside(String entry, StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var alice = Files.createDirectories(ws.resolve("alice"));
        var project = alice.resolve("Proj");
        legacyProject(project);
        legacyFileProperties(project);
        var outsideTarget = Files.createDirectories(root.resolve("outside")).resolve("target");
        Files.move(project.resolve(entry), outsideTarget);
        var link = Files.createSymbolicLink(project.resolve(entry), outsideTarget);
        var repositoryId = legacyProject(alice.resolve("Plain"));
        var before = outside(root, ws);
        var projectBefore = snapshot(project);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertEquals(before, outside(root, ws), "V1 containment: nothing outside the workspace root changes.");
        assertEquals(projectBefore, snapshot(project), "V1 containment: the skipped project is unchanged.");
        assertEquals(outsideTarget, Files.readSymbolicLink(link), "V1 containment: the link keeps its target.");
        assertNotRecorded(alice, "Proj");
        assertSkipLogged(err, projectOutsideMessage("Proj", "alice"));
        assertEquals(1, countConversionSkips(err), "V1 rejection: only the project with the link is skipped.");
        assertConverted(alice, "Plain", repositoryId);
    }

    // V1: the conversion skips a project whose legacy metadata entry is a dangling link and never creates its target.
    @ParameterizedTest
    @ValueSource(strings = {".studioProps", ".history", ".studioProps/.version", ".studioProps/file-properties"})
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionSkipsProjectWhoseMetadataIsDanglingLink(String entry, StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var alice = Files.createDirectories(ws.resolve("alice"));
        var project = alice.resolve("Proj");
        legacyProject(project);
        legacyFileProperties(project);
        Files.move(project.resolve(entry), root.resolve("removed"));
        var ghostTarget = root.resolve("ghost-target");
        var link = Files.createSymbolicLink(project.resolve(entry), ghostTarget);
        var projectBefore = snapshot(project);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertFalse(Files.exists(ghostTarget, LinkOption.NOFOLLOW_LINKS),
                "V1 containment: the target of the dangling link is never created.");
        assertEquals(ghostTarget, Files.readSymbolicLink(link), "V1 containment: the dangling link keeps its target.");
        assertEquals(projectBefore, snapshot(project), "V1 containment: the skipped project is unchanged.");
        assertNotRecorded(alice, "Proj");
        assertSkipLogged(err, projectOutsideMessage("Proj", "alice"));
        assertEquals(1, countConversionSkips(err), "V1 rejection: the project with the dangling link is skipped once.");
    }

    // V1: the conversion skips a user folder whose .metainfo links outside the root or to another user's .metainfo.
    // No record is written behind either link, both user folders stay as they were and a regular user still converts.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionSkipsUserFolderWhoseMetainfoLinksElsewhere(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var outsideTarget = Files.createDirectories(root.resolve("outside"));
        var bob = Files.createDirectories(ws.resolve("bob"));
        var bobMetainfo = Files.createDirectories(bob.resolve(MetainfoRegistry.METAINFO_FOLDER));
        var alice = Files.createDirectories(ws.resolve("alice"));
        legacyProject(alice.resolve("Proj"));
        Files.createSymbolicLink(alice.resolve(MetainfoRegistry.METAINFO_FOLDER), outsideTarget);
        var carol = Files.createDirectories(ws.resolve("carol"));
        legacyProject(carol.resolve("Proj"));
        Files.createSymbolicLink(carol.resolve(MetainfoRegistry.METAINFO_FOLDER), bobMetainfo);
        var jdoe = Files.createDirectories(ws.resolve("jdoe"));
        var repositoryId = legacyProject(jdoe.resolve("Proj"));
        var before = outside(root, ws);
        var bobBefore = snapshot(bob);
        var aliceBefore = snapshot(alice);
        var carolBefore = snapshot(carol);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertEquals(before, outside(root, ws), "V1 containment: nothing is written outside the workspace root.");
        assertEquals(bobBefore, snapshot(bob), "V1 containment: nothing is written into the registry of bob.");
        assertEquals(aliceBefore, snapshot(alice), "V1 containment: the skipped folder of alice is unchanged.");
        assertEquals(carolBefore, snapshot(carol), "V1 containment: the skipped folder of carol is unchanged.");
        assertSkipLogged(err, metainfoOutsideMessage("alice"));
        assertSkipLogged(err, metainfoOutsideMessage("carol"));
        assertEquals(2, countConversionSkips(err), "V1 rejection: only the two user folders with a link are skipped.");
        assertConverted(jdoe, "Proj", repositoryId);
    }

    // V1: the conversion deletes a link planted as the temporary record entry instead of writing the record through it.
    // The file behind the link stays unchanged, the record is a regular file and the project still converts.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionNeverWritesThroughLinkPlantedAsTemporaryRecord(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var outsideTarget = Files.createDirectories(root.resolve("outside"));
        var outsideFile = Files.writeString(outsideTarget.resolve("target"),
                RandomStringUtils.secure().nextAlphanumeric(16));
        var alice = Files.createDirectories(ws.resolve("alice"));
        var repositoryId = legacyProject(alice.resolve("Proj"));
        var aliceMetainfo = Files.createDirectories(alice.resolve(MetainfoRegistry.METAINFO_FOLDER));
        var tmp = Files.createSymbolicLink(aliceMetainfo.resolve("Proj.properties.tmp"), outsideFile);
        var before = outside(root, ws);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertEquals(before, outside(root, ws), "V1 containment: nothing is written outside the workspace root.");
        assertFalse(Files.exists(tmp, LinkOption.NOFOLLOW_LINKS),
                "V1 containment: the planted link is deleted itself.");
        assertTrue(Files.isRegularFile(aliceMetainfo.resolve("Proj.properties"), LinkOption.NOFOLLOW_LINKS),
                "V1 containment: the record is a regular file, not a link.");
        assertEquals(0, countConversionSkips(err), "V1 rejection: a planted temporary entry skips no user folder.");
        assertConverted(alice, "Proj", repositoryId);
    }

    // V1: the conversion skips a user folder whose .metainfo is a link loop, with the WARN of an unresolvable entry.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionSkipsUserFolderWhoseMetainfoCannotBeResolved(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var alice = Files.createDirectories(ws.resolve("alice"));
        legacyProject(alice.resolve("Proj"));
        var loop = alice.resolve(MetainfoRegistry.METAINFO_FOLDER);
        Files.createSymbolicLink(loop, loop);
        var before = snapshot(alice);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertEquals(before, snapshot(alice), "V1 containment: the skipped folder of alice is unchanged.");
        assertUnresolvableSkipLogged(err, metainfoUnresolvableStart("alice"));
        assertEquals(1, countConversionSkips(err), "V1 rejection: the user folder is skipped once.");
    }

    // V1: the conversion never reads a file link inside file-properties, nor a file behind a folder link there.
    // The project still converts with its regular baseline, and the linked files outside stay unchanged.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionIgnoresLinksInsideFileProperties(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var alice = Files.createDirectories(ws.resolve("alice"));
        var project = alice.resolve("Proj");
        var repositoryId = legacyProject(project);
        var rules = legacyFileProperties(project);
        var outsideTarget = Files.createDirectories(root.resolve("outside"));
        var linkedFile = Files.writeString(outsideTarget.resolve("Linked.properties"), legacyBaseline());
        Files.createSymbolicLink(rules.resolve("Linked.xlsx"), linkedFile);
        var linkedFolder = Files.createDirectories(outsideTarget.resolve("folder"));
        Files.writeString(linkedFolder.resolve("Nested.xlsx"), legacyBaseline());
        Files.createSymbolicLink(rules.resolve("sub"), linkedFolder);
        var before = outside(root, ws);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertEquals(before, outside(root, ws), "V1 containment: nothing outside the workspace root changes.");
        assertEquals(0, countConversionSkips(err), "V1 rejection: a link inside file-properties skips no project.");
        assertConverted(alice, "Proj", repositoryId);
        var metainfo = MetainfoRegistry.open(alice).get("Proj");
        assertNotNull(metainfo, "The converted project is recorded in the registry.");
        assertEquals(Set.of("/rules/Main.xlsx"), metainfo.files().keySet(),
                "V1 containment: only the regular baseline is recorded; no linked file is read.");
    }

    // V1: the conversion skips a project folder whose real path exceeds the platform path limit.
    // The link to the deep directory is a folder, yet its real path cannot be resolved. The WARN names the file-system
    // failure, the legacy project behind the link stays untouched and a regular project still converts.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionSkipsProjectFolderThatCannotBeResolved(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var alice = Files.createDirectories(ws.resolve("alice"));
        var repositoryId = legacyProject(alice.resolve("Plain"));
        var hops = new ArrayList<Path>();
        try {
            var deep = deepChain(hops);
            legacyProject(deep.resolve("Proj"));
            var link = Files.createSymbolicLink(alice.resolve("deep"), deep.resolve("Proj"));
            assertTrue(Files.isDirectory(link), "The linked deep project is a folder, so the conversion lists it.");

            Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

            assertLegacyProjectKept(deep, "Proj");
            assertEquals(deep.resolve("Proj"), Files.readSymbolicLink(link),
                    "V1 containment: the link keeps its target.");
            assertNotRecorded(alice, "deep");
            assertUnresolvableSkipLogged(err, projectUnresolvableStart("deep", "alice"));
            assertEquals(1, countConversionSkips(err),
                    "V1 rejection: the unresolvable project folder is skipped once.");
            assertConverted(alice, "Plain", repositoryId);
        } finally {
            deleteDeepChain(hops);
        }
    }

    // V1: the project skip WARN shows a line-breaking character of the project folder name replaced.
    // The names hold a C1 control or a Unicode line or paragraph separator, and the project folder links outside.
    @ParameterizedTest(name = "{0}")
    @MethodSource("lineBreakingPayloads")
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void replacesLineBreakersInProjectSkipWarning(String row, String name, String loggedName, StdErr err)
            throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var alice = Files.createDirectories(ws.resolve("alice"));
        var outsideTarget = Files.createDirectories(root.resolve("outside"));
        legacyProject(outsideTarget.resolve("Proj"));
        var link = Files.createSymbolicLink(linkPath(alice, name), outsideTarget.resolve("Proj"));
        var before = snapshot(outsideTarget);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertEquals(before, snapshot(outsideTarget), "V1 containment: the outside directory is unchanged.");
        assertEquals(outsideTarget.resolve("Proj"), Files.readSymbolicLink(link),
                "V1 containment: the link keeps its target.");
        assertSkipLogged(err, projectOutsideMessage(loggedName, "alice"));
        assertLogPrintable(err);
    }

    // V1: the workspace root may be configured through a link, whose own path is trusted and followed.
    // The root is resolved once and each user folder is checked under the real root, so a regular user folder still
    // converts and a user folder that links out of the real root is still skipped with the escape WARN.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionThroughLinkedWorkspaceRootConvertsItsUserFolders(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var linkedRoot = Files.createSymbolicLink(root.resolve("ws-link"), ws);
        var outsideTarget = Files.createDirectories(root.resolve("outside"));
        legacyProject(outsideTarget.resolve("Proj"));
        var victim = Files.createSymbolicLink(ws.resolve("victim"), outsideTarget);
        var jdoe = Files.createDirectories(ws.resolve("jdoe"));
        var repositoryId = legacyProject(jdoe.resolve("Proj"));
        var before = snapshot(outsideTarget);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(linkedRoot);

        assertEquals(before, snapshot(outsideTarget), "V1 containment: the outside directory is unchanged.");
        assertLegacyProjectKept(outsideTarget, "Proj");
        assertEquals(outsideTarget, Files.readSymbolicLink(victim), "V1 containment: the link keeps its target.");
        assertSkipLogged(err, conversionOutsideRootMessage("victim"));
        assertEquals(1, countConversionSkips(err), "V1 rejection: only the linked user folder is skipped.");
        assertConverted(jdoe, "Proj", repositoryId);
    }

    // V1: a metadata entry of another kind than a file, a folder or a link, here a Unix domain socket as .history, is
    // resolved like a link, because it is not a plain entry. Its real path is its own place, so the project converts.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionAcceptsMetadataEntryOfAnotherKind(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var alice = Files.createDirectories(ws.resolve("alice"));
        var project = alice.resolve("Proj");
        var repositoryId = legacyProject(project);
        var history = project.resolve(".history");
        Files.move(history, root.resolve("removed"));
        // A socket path is limited to about 100 bytes, so the socket is bound through its path relative to the
        // working directory.
        var socketPath = Path.of("").toAbsolutePath().relativize(history.toAbsolutePath());
        try (var server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            try {
                server.bind(UnixDomainSocketAddress.of(socketPath));
            } catch (IOException e) {
                abort("V1: the platform cannot bind a Unix domain socket at the path of the project's .history.");
            }
            assertTrue(Files.readAttributes(history, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isOther(),
                    "The .history entry is neither a file, a folder nor a link.");

            Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);
        }

        assertEquals(0, countConversionSkips(err), "V1 rejection: an entry of another kind skips no project.");
        assertConverted(alice, "Proj", repositoryId);
    }

    // V1: a user folder and a project folder whose name the platform charset cannot decode are listed under a lossy
    // name, which designates another, absent place. Each is a link out of the workspace root, so the conversion skips
    // both instead of accepting the absent place and then following the listed link; a regular project converts.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    @StdIo
    void conversionSkipsLinkedFoldersWhoseNameDoesNotDecode(StdErr err) throws IOException {
        var ws = Files.createDirectories(root.resolve("ws"));
        var outsideUser = Files.createDirectories(root.resolve("outside-user"));
        legacyProject(outsideUser.resolve("Proj"));
        var outsideProject = Files.createDirectories(root.resolve("outside-project"));
        legacyProject(outsideProject.resolve("Proj"));
        var alice = Files.createDirectories(ws.resolve("alice"));
        var repositoryId = legacyProject(alice.resolve("Plain"));
        var userLink = undecodableLink(ws, outsideUser);
        var projectLink = undecodableLink(alice, outsideProject.resolve("Proj"));
        var before = outside(root, ws);

        Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);

        assertEquals(before, outside(root, ws), "V1 containment: nothing outside the workspace root changes.");
        assertLegacyProjectKept(outsideUser, "Proj");
        assertLegacyProjectKept(outsideProject, "Proj");
        assertEquals(outsideUser, Files.readSymbolicLink(userLink), "V1 containment: the user link keeps its target.");
        assertEquals(outsideProject.resolve("Proj"), Files.readSymbolicLink(projectLink),
                "V1 containment: the project link keeps its target.");
        assertEquals(2, countConversionSkips(err), "V1 rejection: both links with an undecodable name are skipped.");
        assertConverted(alice, "Plain", repositoryId);
    }

    // V1: helpers of the undecodable name check, private to this class.
    /**
     * Creates in the folder a link to the target named {@code x}, the byte {@code 0xE9} and {@code y}: not valid UTF-8,
     * so the platform charset decodes it lossily. Java cannot encode such a name, so the shell creates the link; the
     * test is aborted where the shell or the file system refuses the name.
     *
     * @return the link as the folder lists it
     */
    private static Path undecodableLink(Path folder, Path target) throws IOException {
        var process = new ProcessBuilder("sh", "-c", "ln -s \"$1\" \"$(printf 'x\\351y')\"", "sh", target.toString())
                .directory(folder.toFile())
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
        try {
            if (!process.waitFor(30, TimeUnit.SECONDS) || process.exitValue() != 0) {
                process.destroyForcibly();
                abort("V1: the platform cannot create a link whose name is not valid UTF-8.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while creating the link.", e);
        }
        try (var entries = Files.list(folder)) {
            var link = entries.filter(Files::isSymbolicLink).filter(entry -> isLinkTo(entry, target)).findFirst();
            return link.orElseGet(() -> abort("V1: the link whose name is not valid UTF-8 is not listed."));
        }
    }

    /** Whether the link points to the target; an unreadable link points nowhere. */
    private static boolean isLinkTo(Path link, Path target) {
        try {
            return target.equals(Files.readSymbolicLink(link));
        } catch (IOException e) {
            return false;
        }
    }

    // V1: helpers of the startup conversion checks, private to this class.
    /** The part of every conversion skip WARN that names the skip, whatever user folder it carries. */
    private static final String CONVERSION_SKIP_TEXT = "its metainfo migration is skipped.";

    /** The WARN of a user folder that leads outside its own place under the workspace root. */
    private static String conversionOutsideRootMessage(String loggedName) {
        return "The user workspace folder '" + loggedName + "' " + OUTSIDE_ROOT_TEXT + "; " + CONVERSION_SKIP_TEXT;
    }

    /** The WARN of a user folder whose name cannot name a workspace folder. */
    private static String conversionInvalidNameMessage(String loggedName) {
        return "The user workspace folder '" + loggedName + "' is not a valid workspace folder name; "
                + CONVERSION_SKIP_TEXT;
    }

    /** The number of captured lines that log a skipped user folder. */
    private static long countConversionSkips(StdErr err) {
        return Arrays.stream(err.capturedLines()).filter(line -> line.contains(CONVERSION_SKIP_TEXT)).count();
    }

    /**
     * Asserts that exactly one captured line logs at WARN that the user folder cannot be resolved, that it names the
     * file-system failure behind it and that it ends with the skip. The failure text quotes only the expected start.
     */
    private static void assertConversionUnresolvableLogged(StdErr err, String loggedName) {
        var start = "The user workspace folder '" + loggedName + "' cannot be resolved (";
        var lines = Arrays.stream(err.capturedLines()).filter(line -> line.contains(start)).toList();
        assertEquals(1, lines.size(), () -> "V1 rejection: exactly one line logs \"" + start + "...\".");
        var line = lines.get(0);
        assertTrue(line.contains("WARN"), () -> "V1 rejection: \"" + start + "...\" is logged at WARN.");
        assertTrue(line.contains("FileSystemException"),
                () -> "V1 rejection: \"" + start + "...\" names the file-system failure.");
        assertTrue(line.endsWith("); " + CONVERSION_SKIP_TEXT),
                () -> "V1 rejection: \"" + start + "...\" ends with the skip on the same line.");
    }

    // V1: helpers of the project and metainfo folder checks of the conversion, private to this class.
    /** The WARN of a project folder that, or whose legacy metainfo, leads outside its own place. */
    private static String projectOutsideMessage(String loggedProject, String loggedUser) {
        return "The project folder '" + loggedProject + "' of the user workspace folder '" + loggedUser
                + "', or its legacy metainfo, resolves outside its own place; " + CONVERSION_SKIP_TEXT;
    }

    /** The start of the WARN of a project folder that, or whose legacy metainfo, cannot be resolved. */
    private static String projectUnresolvableStart(String loggedProject, String loggedUser) {
        return "The project folder '" + loggedProject + "' of the user workspace folder '" + loggedUser
                + "', or its legacy metainfo, cannot be resolved (";
    }

    /** The WARN of a user folder whose metainfo folder leads outside its own place. */
    private static String metainfoOutsideMessage(String loggedUser) {
        return "The metainfo folder of the user workspace folder '" + loggedUser + "' resolves outside its own place; "
                + CONVERSION_SKIP_TEXT;
    }

    /** The start of the WARN of a user folder whose metainfo folder cannot be resolved. */
    private static String metainfoUnresolvableStart(String loggedUser) {
        return "The metainfo folder of the user workspace folder '" + loggedUser + "' cannot be resolved (";
    }

    /**
     * Asserts that exactly one captured line logs at WARN the given start of the skip of an entry that cannot be
     * resolved, that it names the file-system failure behind it and that it ends with the skip. The failure text
     * quotes only the expected start.
     */
    private static void assertUnresolvableSkipLogged(StdErr err, String start) {
        var lines = Arrays.stream(err.capturedLines()).filter(line -> line.contains(start)).toList();
        assertEquals(1, lines.size(), () -> "V1 rejection: exactly one line logs \"" + start + "...\".");
        var line = lines.get(0);
        assertTrue(line.contains("WARN"), () -> "V1 rejection: \"" + start + "...\" is logged at WARN.");
        assertTrue(line.contains("FileSystemException"),
                () -> "V1 rejection: \"" + start + "...\" names the file-system failure.");
        assertTrue(line.endsWith("); " + CONVERSION_SKIP_TEXT),
                () -> "V1 rejection: \"" + start + "...\" ends with the skip on the same line.");
    }

    /** Asserts that the user folder records no metainfo of the project; the check never opens the registry. */
    private static void assertNotRecorded(Path userDir, String projectName) {
        assertFalse(MetainfoRegistry.exists(userDir, projectName),
                () -> "V1 containment: " + userDir.getFileName() + " records no metainfo of " + projectName + ".");
    }

    /**
     * Adds {@code .studioProps/file-properties/rules/Main.xlsx}, a valid baseline, to a legacy project.
     *
     * @param project a project folder built by {@link #legacyProject(Path)}
     * @return the {@code rules} folder of the file properties
     */
    private static Path legacyFileProperties(Path project) throws IOException {
        var fileProperties = project.resolve(".studioProps").resolve("file-properties");
        var rules = Files.createDirectories(fileProperties.resolve("rules"));
        Files.writeString(rules.resolve("Main.xlsx"), legacyBaseline());
        return rules;
    }

    /** The properties of a valid legacy file baseline, with random values. */
    private static String legacyBaseline() {
        return """
                unique-id=%s
                size=%s
                modified-at-long=%s
                """.formatted(RandomStringUtils.secure().nextAlphanumeric(8),
                RandomStringUtils.secure().nextNumeric(4),
                RandomStringUtils.secure().nextNumeric(13));
    }

    /** The name of each directory of {@link #deepChain(List)}: 255 characters, the longest name ext4 and APFS hold. */
    private static final String DEEP_NAME = "d".repeat(255);

    /** The number of directories of {@link #deepChain(List)}. */
    private static final int DEEP_LEVELS = 20;

    /**
     * Builds a chain of nested directories whose real path holds more than 5,000 characters, above the path limit of
     * Linux (4,096 bytes) and of macOS (1,024 bytes). Each directory is created and linked through the short link to
     * its parent, {@code root/hop<k>}, so every path handed to the file system stays short; a lookup through a link to
     * the last one follows 21 nested links, within the 40 of Linux and the 32 of macOS.
     *
     * @param hops receives each link as it is created, so that {@link #deleteDeepChain(List)} can remove a partial
     *             chain
     * @return the link to the deepest directory
     */
    private Path deepChain(List<Path> hops) throws IOException {
        var parent = root;
        for (var level = 1; level <= DEEP_LEVELS; level++) {
            var directory = Files.createDirectory(parent.resolve(DEEP_NAME));
            parent = Files.createSymbolicLink(root.resolve("hop" + level), directory);
            hops.add(parent);
        }
        return parent;
    }

    /**
     * Deletes the chain of {@link #deepChain(List)} through its short links, deepest first, because the temporary
     * directory cleanup addresses each entry by its full nested path, which exceeds the platform path limit.
     */
    private void deleteDeepChain(List<Path> hops) throws IOException {
        for (var level = hops.size() - 1; level >= 0; level--) {
            var hop = hops.get(level);
            try (var entries = Files.walk(hop, FileVisitOption.FOLLOW_LINKS)) {
                for (var entry : entries.sorted(Comparator.reverseOrder()).filter(path -> !path.equals(hop)).toList()) {
                    Files.delete(entry);
                }
            }
            Files.delete(hop);
            Files.delete((level == 0 ? root : hops.get(level - 1)).resolve(DEEP_NAME));
        }
    }

    /**
     * Runs the startup order of {@code Migrator.migrate()}, the single-user move and then the metainfo conversion, and
     * captures whatever it throws, so that tier 1 judges the containment before tier 2 judges the rejection.
     */
    private static @Nullable Throwable invokeStartup(Path ws, String username) {
        try {
            Migrator.migrateSingleUserWorkspace("single", ws.toString(), username);
            Migrator.migrateUserWorkspacesToMetainfoRegistry(ws);
            return null;
        } catch (Throwable e) {
            return e;
        }
    }

    /**
     * Builds a legacy project as {@code MigratorWorkspaceTest} lays it out: {@code .studioProps/.version} links it to a
     * random repository, {@code .history} holds one edit, and the project holds a random marker file.
     *
     * @param project the project folder to create
     * @return the repository id the project is linked to
     */
    private static String legacyProject(Path project) throws IOException {
        var repositoryId = RandomStringUtils.secure().nextAlphanumeric(12);
        var studioProps = Files.createDirectories(project.resolve(".studioProps"));
        Files.writeString(studioProps.resolve(".version"), """
                repository-id=%s
                path-in-repository=DESIGN/rules/%s
                version=%s
                """.formatted(repositoryId, project.getFileName(), RandomStringUtils.secure().nextAlphanumeric(8)));
        var history = Files.createDirectories(project.resolve(".history").resolve("Main.xlsx"));
        Files.writeString(history.resolve(RandomStringUtils.secure().nextNumeric(13)),
                RandomStringUtils.secure().nextAlphanumeric(16));
        Files.writeString(project.resolve("marker.txt"), RandomStringUtils.secure().nextAlphanumeric(16));
        return repositoryId;
    }

    /** Asserts that the folder holds no metainfo registry and that its legacy project keeps its legacy files. */
    private static void assertLegacyProjectKept(Path userDir, String projectName) {
        assertFalse(Files.exists(userDir.resolve(MetainfoRegistry.METAINFO_FOLDER), LinkOption.NOFOLLOW_LINKS),
                () -> "V1 containment: no metainfo registry is written into " + userDir.getFileName() + ".");
        var project = userDir.resolve(projectName);
        assertTrue(Files.isRegularFile(project.resolve(".studioProps").resolve(".version"), LinkOption.NOFOLLOW_LINKS),
                () -> "V1 containment: the legacy metainfo of " + userDir.getFileName() + " is kept.");
        assertTrue(Files.isDirectory(project.resolve(".history"), LinkOption.NOFOLLOW_LINKS),
                () -> "V1 containment: the edit history of " + userDir.getFileName() + " is kept.");
    }

    /**
     * Asserts that the legacy project of the user folder is converted: its legacy files are gone and the registry
     * records its repository. The registry is opened last, because the first open reconciles the folder with it.
     */
    private static void assertConverted(Path userDir, String projectName, String repositoryId) {
        var project = userDir.resolve(projectName);
        assertFalse(Files.exists(project.resolve(".studioProps"), LinkOption.NOFOLLOW_LINKS),
                "The legacy .studioProps folder of the converted project is deleted.");
        assertFalse(Files.exists(project.resolve(".history"), LinkOption.NOFOLLOW_LINKS),
                "The in-project edit history of the converted project is deleted.");
        var metainfo = MetainfoRegistry.open(userDir).get(projectName);
        assertNotNull(metainfo, "The converted project is recorded in the registry.");
        assertEquals(repositoryId, metainfo.repositoryId(), "The record keeps the repository of the project.");
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

    // V1: line-breaking payloads, labelled with their row id and followed by the name as the skip logs it.
    // Both validators accept these names, although they hold a line separator, a paragraph separator or a C1
    // control (next line).
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
        assertEquals(before.outside(), outside(root, ws),
                "V1 containment: nothing outside the workspace root changes.");
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

package org.openl.rules.repository.git;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import static org.openl.rules.repository.git.GitRepositoryTest.readText;
import static org.openl.rules.repository.git.TestGitUtils.createFileData;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.api.errors.InvalidRefNameException;
import org.eclipse.jgit.errors.MissingObjectException;
import org.eclipse.jgit.lib.Constants;
import org.junit.jupiter.api.AutoClose;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.openl.rules.repository.api.ChangesetType;
import org.openl.rules.repository.api.ConflictResolveData;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Offset;
import org.openl.rules.repository.api.Pageable;
import org.openl.rules.repository.api.UserInfo;
import org.openl.util.IOUtils;

/**
 * Covers the {@link GitRepository} operations on a local repository: copying, deleting, multi-file saves, history
 * filters and versions, tags, branch creation and the resolution of merge conflicts, Excel files included. The V1
 * change, which made the class reveal its working tree, brought these paths under the per-class coverage target.
 */
class GitRepositoryOperationsTest {
    private static final String REPO_ID = "operations-coverage";
    private static final String TAG_PREFIX = "v";
    private static final String MISSING_COMMIT = "0123456789abcdef0123456789abcdef01234567";
    private static final UserInfo AUTHOR = new UserInfo("jsmith", "jsmith@email", "John Smith");
    private static final Path EXCEL_CASE = Path.of("test-resources/EPBDS-8483/10");

    @TempDir
    private File root;
    @AutoClose
    private GitRepository repo;
    private File local;

    @BeforeEach
    void setUp() throws IOException {
        local = new File(root, "design");
        repo = open(local, Constants.MASTER, true);
    }

    @Test
    @SuppressWarnings("NullAway") // a null version asks copyHistory for the current revision, as Repository documents
    void copyHistoryWithoutAVersionCopiesTheCurrentRevision() throws IOException {
        save("rules/a/file.txt", "current");

        var copy = repo.copyHistory("rules/a/file.txt",
                createFileData("rules/a/file-copy.txt", "", "Copy the current revision"),
                null);

        assertEquals("rules/a/file-copy.txt", copy.getName());
        assertEquals("Copy the current revision", copy.getComment());
        assertEquals("current", readText(repo.read("rules/a/file-copy.txt")));
        assertEquals("current", readText(repo.read("rules/a/file.txt")));
    }

    @Test
    @SuppressWarnings("NullAway") // a null version asks copyHistory for the current revision, as Repository documents
    void copyHistoryWithoutAVersionLeavesNoChangeWhenItFails() throws IOException, GitAPIException {
        save("rules/a/file.txt", "current");

        var missingSource = createFileData("rules/a/missing-copy.txt", "", "Copy a missing file");
        assertThrows(IOException.class, () -> repo.copyHistory("rules/a/missing.txt", missingSource, null));
        assertNull(repo.check("rules/a/missing-copy.txt"));

        var anonymous = new FileData();
        anonymous.setName("rules/a/anonymous-copy.txt");
        var e = assertThrows(IOException.class, () -> repo.copyHistory("rules/a/file.txt", anonymous, null));
        assertInstanceOf(IllegalArgumentException.class, e.getCause());
        assertNull(repo.check("rules/a/anonymous-copy.txt"));
        assertNoUncommittedChanges();
    }

    @Test
    void copyHistoryOfAnUnknownVersionFails() throws IOException {
        save("rules/a/file.txt", "current");

        var destination = createFileData("rules/a/copy.txt", "", "Copy an unknown version");
        assertThrows(IOException.class, () -> repo.copyHistory("rules/a/file.txt", destination, "no-such-version"));
        assertNull(repo.check("rules/a/copy.txt"));
    }

    @Test
    void saveUnderAFolderThatIsAFileFails() throws IOException {
        var saved = save("rules/a/file.txt", "current");
        save("rules/blocker", "a file where a folder is needed");

        var blocked = createFileData("rules/blocker/sub/file.txt", "", "Save under a file");
        var e = assertThrows(IOException.class, () -> repo.save(blocked, IOUtils.toInputStream("text")));
        assertTrue(String.valueOf(e.getMessage()).startsWith("Cannot create the folder "), e.getMessage());

        var copy = createFileData("rules/blocker/sub/copy.txt", "", "Copy under a file");
        var version = saved.getVersion();
        var copyError = assertThrows(IOException.class, () -> repo.copyHistory("rules/a/file.txt", copy, version));
        assertTrue(String.valueOf(copyError.getMessage()).startsWith("Cannot create the folder "),
                copyError.getMessage());
        assertEquals("a file where a folder is needed", readText(repo.read("rules/blocker")));
    }

    @Test
    void deleteOfSeveralFilesAnswersWhetherAnyOfThemExisted() throws IOException {
        save("rules/d/one.txt", "one");
        save("rules/d/two.txt", "two");
        var missing = createFileData("rules/d/missing.txt", "", "Delete a missing file");

        assertTrue(repo.delete(List.of(createFileData("rules/d/one.txt", "", "Delete one"), missing)));
        assertNull(repo.check("rules/d/one.txt"));
        assertEquals("two", readText(repo.read("rules/d/two.txt")));

        assertFalse(repo.delete(List.of(missing)));
        assertFalse(repo.delete(missing));
    }

    @Test
    void deleteWithoutAnAuthorFailsAndKeepsTheFile() throws IOException, GitAPIException {
        save("rules/d/kept.txt", "kept");
        var anonymous = new FileData();
        anonymous.setName("rules/d/kept.txt");

        var e = assertThrows(IOException.class, () -> repo.delete(anonymous));
        assertInstanceOf(IllegalArgumentException.class, e.getCause());
        assertEquals("kept", readText(repo.read("rules/d/kept.txt")));
        assertNoUncommittedChanges();
    }

    @Test
    void deleteHistoryDeletesOnlyTheCurrentRevision() throws IOException {
        var saved = save("rules/h/file.txt", "text");

        var version = createFileData("rules/h/file.txt", "", "Delete one version");
        version.setVersion(saved.getVersion());
        assertFalse(repo.deleteHistory(version));
        assertEquals("text", readText(repo.read("rules/h/file.txt")));

        assertTrue(repo.deleteHistory(createFileData("rules/h/file.txt", "", "Delete the file")));
        assertNull(repo.check("rules/h/file.txt"));
    }

    @Test
    void saveOfSeveralFilesCommitsAndTagsEachOfThem() throws IOException {
        var first = new FileItem(createFileData("rules/m/first.txt", "first", "First of two"),
                IOUtils.toInputStream("first"));
        var second = new FileItem(createFileData("rules/m/second.txt", "second", "Second of two"),
                IOUtils.toInputStream("second"));

        var saved = repo.save(List.of(first, second));

        assertEquals(List.of("rules/m/first.txt", "rules/m/second.txt"),
                saved.stream().map(FileData::getName).toList());
        assertEquals(List.of("v1", "v2"), saved.stream().map(FileData::getVersion).toList());
        assertEquals("first", readText(repo.read("rules/m/first.txt")));
        assertEquals("second", readText(repo.read("rules/m/second.txt")));
    }

    @Test
    void saveOfSeveralFilesWithoutAnAuthorCommitsNothing() throws IOException {
        save("rules/m/seed.txt", "seed");
        var anonymous = new FileData();
        anonymous.setName("rules/m/anonymous.txt");
        var item = new FileItem(anonymous, IOUtils.toInputStream("text"));

        var e = assertThrows(IOException.class, () -> repo.save(List.of(item)));
        assertInstanceOf(IllegalArgumentException.class, e.getCause());
        assertEquals(List.of("rules/m/seed.txt"), repo.list("").stream().map(FileData::getName).toList());
    }

    @Test
    void saveWithoutAnAuthorIsRefused() throws IOException {
        save("rules/a/seed.txt", "seed");
        var anonymous = new FileData();
        anonymous.setName("rules/a/anonymous.txt");

        var e = assertThrows(IOException.class, () -> repo.save(anonymous, IOUtils.toInputStream("text")));
        var cause = assertInstanceOf(IllegalArgumentException.class, e.getCause());
        assertEquals("Commit author name is blank.", cause.getMessage());
        assertNull(repo.check("rules/a/anonymous.txt"));
    }

    @Test
    void saveOfAFolderWithoutAnAuthorFails() throws IOException {
        save("rules/f/seed.txt", "seed");
        var folder = new FileData();
        folder.setName("rules/f");
        var change = new FileItem("rules/f/new.txt", IOUtils.toInputStream("new"));

        var e = assertThrows(IOException.class, () -> repo.save(folder, List.of(change), ChangesetType.DIFF));
        assertInstanceOf(IllegalArgumentException.class, e.getCause());
        assertNull(repo.check("rules/f/new.txt"));
    }

    @Test
    @SuppressWarnings("NullAway") // a null stream marks a file for deletion, as FileItem documents
    void saveOfAFolderSkipsAbsentFilesAndAbsentFolders() throws IOException {
        save("rules/f/seed.txt", "seed");

        var folder = createFileData("rules/f", "", "Delete a file that never existed");
        var saved = repo.save(folder, List.of(new FileItem("rules/f/never.txt", null)), ChangesetType.DIFF);
        assertEquals("rules/f", saved.getName());
        assertEquals("Delete a file that never existed", lastCommitMessage());

        var ghost = createFileData("rules/ghost", "", "Replace an absent folder with nothing");
        assertNull(repo.save(ghost, List.of(), ChangesetType.FULL));
        assertEquals("Replace an absent folder with nothing", lastCommitMessage());
        assertEquals(List.of("rules/f/seed.txt"), repo.list("").stream().map(FileData::getName).toList());
    }

    @Test
    void saveBasedOnAVersionOfAnotherFileIsNotAnOldVersion() throws IOException {
        var other = save("rules/v/other.txt", "other");

        var data = createFileData("rules/v/new.txt", "new", "New file based on another version");
        data.setVersion(other.getVersion());
        var saved = repo.save(data, IOUtils.toInputStream("new"));

        assertNotEquals(other.getVersion(), saved.getVersion());
        assertEquals("new", readText(repo.read("rules/v/new.txt")));
    }

    @Test
    void saveBasedOnAnUnknownVersionFails() throws IOException {
        save("rules/v/file.txt", "current");

        var data = createFileData("rules/v/file.txt", "stale", "Save on an unknown version");
        data.setVersion("no-such-version");
        assertThrows(IOException.class, () -> repo.save(data, IOUtils.toInputStream("stale")));
        assertEquals("current", readText(repo.read("rules/v/file.txt")));
    }

    @Test
    void saveWithAConflictResolutionMergesTheConflictingCommit() throws IOException {
        var path = "rules/s/file.txt";
        save(path, "base");
        repo.createRepositoryBranch("theirs", null);
        var their = repo.forBranch("theirs")
                .save(createFileData(path, "their", "Their change"), IOUtils.toInputStream("their"));

        var data = createFileData(path, "our", "Our change");
        data.addAdditionalData(
                new ConflictResolveData(their.getVersion(), List.of(item(path, "resolved")), "Resolve while saving"));
        repo.save(data, IOUtils.toInputStream("our"));

        assertEquals("resolved", readText(repo.read(path)));
        assertEquals("Resolve while saving", repo.check(path).getComment());
        assertTrue(repo.isMergedInto("theirs", Constants.MASTER));
    }

    @Test
    void listHistoryFiltersByAuthorMessageOrCommitId() throws IOException, GitAPIException {
        var path = "rules/p/file.txt";
        save(path, "1", "First change");
        var firstId = repo.getLastRevision().name();
        save(path, "2", "Second change");
        save(path, "3", "Fix [abc] bracket");

        assertEquals(List.of("First change", "Second change", "Fix [abc] bracket"), comments(path, "  "));
        assertEquals(List.of("Second change"), comments(path, "Second"));
        assertEquals(List.of("Second change"), comments(path, "Sec.*"));
        assertEquals(List.of("Fix [abc] bracket"), comments(path, "[abc"));
        assertEquals(List.of("First change"), comments(path, firstId.substring(0, 12)));
        // JGit takes '^' literally, so only a pattern with a regular expression character searches the ids by pattern.
        assertEquals(List.of(), comments(path, "^" + firstId.substring(0, 12)));
        assertEquals(List.of("First change"), comments(path, firstId.substring(0, 12) + ".*"));
        assertEquals(List.of(), comments(path, "Nobody wrote this"));
    }

    @Test
    void listHistoryMarksTechnicalRevisionsAndPages() throws IOException {
        var path = "rules/p/file.txt";
        save(path, "1", "First change");
        save("rules/other.txt", "x", "Unrelated change");
        save(path, "2", "Second change");

        var all = repo.listHistory(path, "", true, Pageable.unpaged());
        assertEquals(List.of("First change", "Unrelated change", "Second change"),
                all.stream().map(FileData::getComment).toList());
        assertEquals(List.of(false, true, false), all.stream().map(FileData::isTechnicalRevision).toList());

        var page = repo.listHistory(path, "", false, Offset.of(1, 1));
        assertEquals(List.of("First change"), page.stream().map(FileData::getComment).toList());
    }

    @Test
    void historyOfAnUnknownOrMissingVersionIsEmpty() throws IOException {
        var path = "rules/p/file.txt";
        save(path, "1");

        assertNull(repo.checkHistory(path, "no-such-version"));
        assertNull(repo.readHistory(path, "no-such-version"));
        assertEquals(List.of(), repo.listFiles("rules/p/", "no-such-version"));
        assertNull(repo.checkHistory(path, MISSING_COMMIT));
        assertNull(repo.readHistory(path, MISSING_COMMIT));
    }

    @Test
    void mergeQueriesOfUnknownRevisionsAnswerFalseAndMissingCommitsFail() throws IOException {
        save("rules/a.txt", "a");

        assertFalse(repo.isMergedInto("no-such-branch", Constants.MASTER));
        assertFalse(repo.isMergedInto(Constants.MASTER, "no-such-branch"));
        assertThrows(MissingObjectException.class, () -> repo.isMergedInto(MISSING_COMMIT, Constants.MASTER));
    }

    @Test
    void branchQueriesAnswerNothingForNoBranchesAndSkipUnreadableBranches() throws IOException {
        save("rules/b/file.txt", "b");
        assertEquals(Map.of(), repo.getBranchStatuses(List.of()));
        assertEquals(Map.of(), repo.getBranchTreeRevisions(List.of(), "rules/b"));

        writeLooseRef(Constants.R_HEADS + "broken", MISSING_COMMIT);

        assertEquals(Set.of(Constants.MASTER),
                repo.getBranchStatuses(List.of(Constants.MASTER, "broken")).keySet());
        assertEquals(Set.of(Constants.MASTER),
                repo.getBranchTreeRevisions(List.of(Constants.MASTER, "broken"), "rules/b/").keySet());
    }

    @Test
    void nextTagSkipsForeignAndNonNumericTagsAndLightweightTagsNameVersions() throws IOException, GitAPIException {
        save("rules/t/first.txt", "first");
        try (var git = Git.open(local)) {
            var repository = git.getRepository();
            var head = repository.parseCommit(repository.resolve(Constants.MASTER));
            for (var name : List.of("v10", "v9", "vX", "release")) {
                git.tag().setName(name).setAnnotated(false).setObjectId(head).call();
            }
        }

        var second = save("rules/t/second.txt", "second");

        assertEquals("v11", second.getVersion());
        var tagged = repo.checkHistory("rules/t/first.txt", "release");
        assertEquals("release", tagged.getVersion());
        assertEquals("first", readText(repo.readHistory("rules/t/first.txt", "release")));
    }

    @Test
    void localRepositoryNeedsNoRemoteToPullOrToReportItsLastRevision() throws IOException, GitAPIException {
        save("rules/a.txt", "a");

        repo.pull(AUTHOR);

        try (var git = Git.open(local)) {
            assertEquals(git.getRepository().resolve(Constants.MASTER), repo.getLastRevision());
        }
    }

    @Test
    void listIsEmptyWhenTheConfiguredBranchIsMissing() throws IOException {
        save("rules/a.txt", "a");
        repo.close();

        try (var other = open(local, "absent", false)) {
            assertEquals(List.of(), other.list(""));
            assertEquals(List.of(Constants.MASTER), other.listBranches());
        }
    }

    @Test
    void createRepositoryBranchKeepsExistingBranchesAndRollsBackFailures() throws IOException {
        save("rules/a.txt", "a");
        repo.createRepositoryBranch("from-current", null);
        save("rules/a.txt", "changed after branching");

        repo.createRepositoryBranch("from-current", Constants.MASTER);
        assertFalse(repo.isMergedInto(Constants.MASTER, "from-current"), "An existing branch must not move");

        var unresolvable = assertThrows(IOException.class,
                () -> repo.createRepositoryBranch("unresolvable", "no-such-start"));
        assertEquals("Cannot resolve no-such-start", unresolvable.getMessage());
        assertFalse(repo.listBranches().contains("unresolvable"));

        var invalid = assertThrows(IOException.class, () -> repo.createRepositoryBranch("bad..name", null));
        assertInstanceOf(InvalidRefNameException.class, invalid.getCause());
        assertEquals(List.of("from-current", Constants.MASTER), repo.listBranches());
    }

    @Test
    void resolvingAMergeThatHasNoConflictFails() throws IOException {
        save("rules/r/base.txt", "base");
        repo.createRepositoryBranch("clean", null);
        repo.forBranch("clean")
                .save(createFileData("rules/r/clean.txt", "clean", "Clean change"), IOUtils.toInputStream("clean"));

        var resolution = new ConflictResolveData("unused", List.of(), "Resolve nothing");
        var e = assertThrows(IOException.class, () -> repo.merge("clean", AUTHOR, resolution));
        assertEquals("There is no merge conflict, nothing to resolve.", e.getMessage());
        assertNull(repo.check("rules/r/clean.txt"));
    }

    @Test
    @SuppressWarnings("NullAway") // a null stream deletes a file and a null merge message asks for the default one
    void conflictResolutionStagesEveryMergedChangeAndUsesTheDefaultMessage() throws IOException {
        var folder = "rules/c/";
        repo.save(createFileData("rules/c", "", "Base"),
                List.of(item(folder + "a.txt", "base a"),
                        item(folder + "b.txt", "base b"),
                        item(folder + "c.txt", "base c"),
                        item(folder + "e.txt", "base e"),
                        item(folder + "f.txt", "base f")),
                ChangesetType.DIFF);
        repo.createRepositoryBranch("theirs", null);
        repo.forBranch("theirs")
                .save(createFileData("rules/c", "", "Their change"),
                        List.of(item(folder + "a.txt", "their a"),
                                new FileItem(folder + "b.txt", null),
                                new FileItem(folder + "c.txt", null),
                                item(folder + "d.txt", "their d"),
                                item(folder + "e.txt", "their e"),
                                item(folder + "f.txt", "their f"),
                                item(folder + "g.txt", "their g")),
                        ChangesetType.DIFF);
        save(folder + "a.txt", "our a");

        var conflict = assertThrows(MergeConflictException.class, () -> mergeWithoutResolution("theirs"));
        assertEquals(Set.of(folder + "a.txt"), Set.copyOf(conflict.getDetails().getConflictedFiles()));

        var resolved = List.of(item(folder + "a.txt", "resolved a"),
                item(folder + "b.txt", "restored b"),
                item(folder + "d.txt", "their d"),
                item(folder + "e.txt", "their e"));
        repo.merge("theirs", AUTHOR, new ConflictResolveData(conflict.getDetails().theirCommit(), resolved, null));

        assertEquals("Merge", repo.check(folder + "a.txt").getComment());
        assertEquals("resolved a", readText(repo.read(folder + "a.txt")));
        assertEquals("restored b", readText(repo.read(folder + "b.txt")));
        assertNull(repo.check(folder + "c.txt"));
        assertEquals("their d", readText(repo.read(folder + "d.txt")));
        assertEquals("their e", readText(repo.read(folder + "e.txt")));
        assertEquals("their f", readText(repo.read(folder + "f.txt")));
        assertEquals("their g", readText(repo.read(folder + "g.txt")));
    }

    @Test
    void excelFileAddedOnBothSidesIsNotAutoResolved() throws IOException {
        save("rules/x/seed.txt", "seed");
        repo.createRepositoryBranch("theirs", null);
        repo.forBranch("theirs")
                .save(createFileData("rules/x/book.xlsx", "", "Their book"), IOUtils.toInputStream("their book"));
        save("rules/x/book.xlsx", "our book");

        var e = assertThrows(MergeConflictException.class, () -> mergeWithoutResolution("theirs"));
        assertEquals(Set.of("rules/x/book.xlsx"), Set.copyOf(e.getDetails().getConflictedFiles()));
        assertEquals(Map.of(), e.getDetails().toAutoResolve());
    }

    @Test
    void excelFileDeletedOnOurSideAndChangedOnTheirsIsNotAutoResolved() throws IOException {
        assertExcelDeleteConflict(true);
    }

    @Test
    void excelFileChangedOnOurSideAndDeletedOnTheirsIsNotAutoResolved() throws IOException {
        assertExcelDeleteConflict(false);
    }

    @Test
    void unreadableExcelFileInConflictIsReportedAsAConflict() throws IOException {
        save("rules/x/book.xlsx", "base book");
        repo.createRepositoryBranch("theirs", null);
        repo.forBranch("theirs")
                .save(createFileData("rules/x/book.xlsx", "", "Their book"), IOUtils.toInputStream("their book"));
        save("rules/x/book.xlsx", "our book");

        var e = assertThrows(MergeConflictException.class, () -> mergeWithoutResolution("theirs"));
        assertEquals(Set.of("rules/x/book.xlsx"), Set.copyOf(e.getDetails().getConflictedFiles()));
        assertEquals("our book", readText(repo.read("rules/x/book.xlsx")));
    }

    @Test
    void excelChangesSavedOnAnOldVersionAreMergedSheetBySheet() throws IOException, GitAPIException {
        var path = "rules/excel/Main.xlsx";
        var base = repo.save(createFileData(path, "", "Base workbook"),
                Files.newInputStream(EXCEL_CASE.resolve("BASE/Main.xlsx")));
        var their = repo.save(createFileData(path, "", "Their workbook"),
                Files.newInputStream(EXCEL_CASE.resolve("THEIR/Main.xlsx")));

        var ours = createFileData(path, "", "Our workbook");
        ours.setVersion(base.getVersion());
        repo.save(ours, Files.newInputStream(EXCEL_CASE.resolve("OUR/Main.xlsx")));

        try (var git = Git.open(local)) {
            var repository = git.getRepository();
            var merge = repository.parseCommit(repository.resolve(Constants.MASTER));
            assertEquals(2, merge.getParentCount());
            var message = merge.getFullMessage();
            assertTrue(message.startsWith("Merge commit with "), message);
            assertTrue(message.contains("Automatically resolved conflicts:\n\t" + path + "\n"), message);
            assertTrue(message.contains("\t\tRules\n"), message);
            assertTrue(message.contains("\t\tSheet1 (master)"), message);
        }
        assertNotEquals(their.getVersion(), repo.check(path).getVersion());
    }

    private void assertExcelDeleteConflict(boolean deletedByUs) throws IOException {
        var path = "rules/x/book.xlsx";
        save(path, "base book");
        repo.createRepositoryBranch("theirs", null);
        var theirs = repo.forBranch("theirs");
        if (deletedByUs) {
            theirs.save(createFileData(path, "", "Their book"), IOUtils.toInputStream("their book"));
            assertTrue(repo.delete(createFileData(path, "", "Delete our book")));
        } else {
            assertTrue(theirs.delete(createFileData(path, "", "Delete their book")));
            save(path, "our book");
        }

        var e = assertThrows(MergeConflictException.class, () -> mergeWithoutResolution("theirs"));
        assertEquals(Set.of(path), Set.copyOf(e.getDetails().getConflictedFiles()));
        assertEquals(Map.of(), e.getDetails().toAutoResolve());
    }

    @SuppressWarnings("NullAway") // a null resolution asks merge to merge the branch, not to resolve a conflict
    private void mergeWithoutResolution(String branch) throws IOException {
        repo.merge(branch, AUTHOR, null);
    }

    private String lastCommitMessage() throws IOException {
        try (var git = Git.open(local)) {
            var repository = git.getRepository();
            return repository.parseCommit(repository.resolve(Constants.MASTER)).getFullMessage();
        }
    }

    private List<String> comments(String path, String globalFilter) throws IOException {
        return repo.listHistory(path, globalFilter, false, Pageable.unpaged())
                .stream()
                .map(FileData::getComment)
                .toList();
    }

    private FileData save(String path, String text) throws IOException {
        return save(path, text, "Save " + path);
    }

    private FileData save(String path, String text, String comment) throws IOException {
        return repo.save(createFileData(path, text, comment), IOUtils.toInputStream(text));
    }

    private static FileItem item(String path, String text) {
        return new FileItem(path, IOUtils.toInputStream(text));
    }

    private void assertNoUncommittedChanges() throws IOException, GitAPIException {
        try (var git = Git.open(local)) {
            assertEquals(Set.of(), git.status().call().getUncommittedChanges());
        }
    }

    private void writeLooseRef(String ref, String id) throws IOException {
        var file = new File(new File(local, Constants.DOT_GIT), ref);
        Files.createDirectories(file.getParentFile().toPath());
        Files.writeString(file.toPath(), id + "\n", StandardCharsets.UTF_8);
    }

    private GitRepository open(File folder, String branch, boolean empty) throws IOException {
        var repository = new GitRepository();
        repository.setId(REPO_ID);
        var uri = folder.getAbsolutePath();
        repository.setUri(uri);
        var repositoriesFolder = new File(root, "repositories").getAbsolutePath();
        repository.setLocalRepositoriesFolder(repositoriesFolder);
        repository.setBranch(branch);
        repository.setTagPrefix(TAG_PREFIX);
        repository.setGcAutoDetach(false);
        repository.initialize(TestGitUtils.mockGitRootFactory(REPO_ID, uri, folder, repositoriesFolder, false, empty));
        return repository;
    }
}

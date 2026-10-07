package org.openl.rules.repository.git;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import static org.openl.rules.repository.git.GitRepositoryTest.readText;
import static org.openl.rules.repository.git.TestGitUtils.createFileData;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.dircache.DirCache;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.transport.RefSpec;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AutoClose;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.openl.rules.repository.api.UserInfo;
import org.openl.util.FileUtils;
import org.openl.util.IOUtils;

/**
 * Covers how {@link GitRepository} keeps a clone in step with its remote: fetched fast-forwards, deleted and rewritten
 * branches, moved tags, local branches ahead of or behind the remote, refused pushes and a remote that has gone. The V1
 * change, which made the class reveal its working tree, brought these paths under the per-class coverage target.
 */
class GitRepositoryRemoteSyncTest {
    private static final String REPO_ID = "sync-coverage";
    private static final String FEATURE = "feature";
    private static final String MAIN_FILE = "rules/main.txt";
    private static final String FEATURE_FILE = "rules/feature.txt";
    private static final UserInfo AUTHOR = new UserInfo("jsmith", "jsmith@email", "John Smith");

    @TempDir
    private File root;
    @AutoClose
    private GitRemoteFixture remote;
    @AutoClose
    private GitRepository repo;
    private File local;
    private String repositoriesFolder;
    private RevCommit mainCommit;

    @BeforeEach
    void setUp() throws GitAPIException, IOException, URISyntaxException {
        remote = GitRemoteFixture.create(root);
        mainCommit = remote.commit(Constants.MASTER, MAIN_FILE, "main");
        remote.commit(FEATURE, FEATURE_FILE, "feature");
        var repositories = new File(root, "repositories");
        repositoriesFolder = repositories.getAbsolutePath();
        local = new File(repositories, "local");
        repo = open(Constants.MASTER, true);
    }

    @Test
    void fetchFastForwardsANonCurrentBranch() throws IOException, GitAPIException {
        var changed = remote.commit(FEATURE, FEATURE_FILE, "changed on the remote");

        assertEquals(mainCommit.getId(), repo.getLastRevision());

        assertEquals(changed.getId(), localRef(Constants.R_HEADS + FEATURE));
        assertEquals("changed on the remote", readText(repo.forBranch(FEATURE).read(FEATURE_FILE)));
    }

    @Test
    void fetchDeletesANonCurrentBranchDeletedOnTheRemote() throws IOException, GitAPIException {
        remote.deleteBranch(FEATURE);

        assertEquals(mainCommit.getId(), repo.getLastRevision());

        assertNull(localRef(Constants.R_HEADS + FEATURE));
        assertEquals(List.of(Constants.MASTER), repo.listBranches());
    }

    @Test
    void fetchLeavesTheCurrentBranchWhenTheRemoteDeletesIt() throws IOException, GitAPIException {
        repo.close();
        FileUtils.deleteQuietly(local);
        repo = open(FEATURE, true);
        remote.deleteBranch(FEATURE);

        assertNull(repo.getLastRevision(), "The deleted current branch has no revision any more");

        assertNull(localRef(Constants.R_HEADS + FEATURE));
        try (var git = Git.open(local)) {
            assertEquals(mainCommit.getName(), git.getRepository().getFullBranch(),
                    "HEAD must move to the remote HEAD");
        }
    }

    @Test
    void fetchResetsANonCurrentBranchRewrittenOnTheRemote() throws IOException, GitAPIException {
        var rewritten = remote.rewrite(FEATURE, FEATURE_FILE, "rewritten on the remote");

        assertEquals(mainCommit.getId(), repo.getLastRevision());

        assertEquals(rewritten.getId(), localRef(Constants.R_HEADS + FEATURE));
        assertEquals("rewritten on the remote", readText(repo.forBranch(FEATURE).read(FEATURE_FILE)));
    }

    @Test
    void fetchMovesALocalTagThatTheRemoteMoved() throws IOException, GitAPIException {
        remote.tag("release", mainCommit);
        repo.getLastRevision();
        assertEquals(mainCommit.getId(), peeledTag("release"));

        var next = remote.commit(Constants.MASTER, MAIN_FILE, "next");
        remote.tag("release", next);

        assertEquals(next.getId(), repo.getLastRevision());
        assertEquals(next.getId(), peeledTag("release"), "A fetched tag follows the remote tag");
        assertEquals(List.of(FEATURE, Constants.MASTER), repo.listBranches());
    }

    @Test
    void fetchKeepsALocalBranchThatIsAheadOfTheRemote() throws IOException, GitAPIException {
        RevCommit unpushed;
        try (var git = Git.open(local)) {
            Files.writeString(new File(local, MAIN_FILE).toPath(), "local only", StandardCharsets.UTF_8);
            git.add().addFilepattern(MAIN_FILE).call();
            unpushed = git.commit().setMessage("Unpushed").setCommitter("Local User", "local@example.org").call();
        }

        assertEquals(unpushed.getId(), repo.getLastRevision());
        assertEquals("local only", readText(repo.read(MAIN_FILE)));
    }

    @Test
    void fetchFastForwardsALocalBranchBehindAnAlreadyFetchedRemote() throws IOException, GitAPIException {
        var next = remote.commit(Constants.MASTER, MAIN_FILE, "fetched outside the repository");
        try (var git = Git.open(local)) {
            git.fetch()
                    .setRefSpecs(new RefSpec("+" + Constants.R_HEADS + "*:" + Constants.R_REMOTES
                            + Constants.DEFAULT_REMOTE_NAME + "/*"))
                    .call();
        }
        assertEquals(mainCommit.getId(), localRef(Constants.R_HEADS + Constants.MASTER));

        assertEquals(next.getId(), repo.getLastRevision());
        assertEquals("fetched outside the repository", readText(repo.read(MAIN_FILE)));
    }

    @Test
    void reopeningOnABranchMissingEverywhereListsAndPullsNothing() throws IOException {
        repo.close();

        try (var missing = open("absent", false)) {
            assertEquals(List.of(), missing.list(""));
            missing.pull(AUTHOR);
            assertEquals(List.of(), missing.list(""));
            assertEquals(List.of(FEATURE, Constants.MASTER), missing.listBranches());
        }
    }

    @Test
    void reopeningOnABranchThatExistsOnlyLocallyKeepsIt() throws IOException, GitAPIException {
        try (var git = Git.open(local)) {
            git.branchCreate().setName("local-only").call();
        }
        repo.close();

        try (var localOnly = open("local-only", false)) {
            assertEquals(mainCommit.getId(), localOnly.getLastRevision());
            assertEquals("main", readText(localOnly.read(MAIN_FILE)));
        }
        assertNull(remoteRef(Constants.R_HEADS + "local-only"));
    }

    @Test
    void branchPushOverAnUnfetchedRemoteBranchIsRejectedAsNonFastForward() throws IOException, GitAPIException {
        remote.commit("late", "rules/late.txt", "created on the remote after the clone");

        var e = assertThrows(IOException.class, () -> repo.createRepositoryBranch("late", null));
        assertEquals("Remote ref update was rejected, as it would cause non fast-forward update.", e.getMessage());
        assertNull(localRef(Constants.R_HEADS + "late"), "The rejected branch must be rolled back");
    }

    @Test
    void branchDeletionRefusedByTheRemoteReportsTheRemoteMessage() throws IOException {
        try (var bare = remote.openBare()) {
            var config = bare.getRepository().getConfig();
            config.setBoolean("receive", null, "denyDeletes", true);
            config.save();
        }

        // The remote still offers deletions and refuses this one itself, so its own reason is reported.
        var e = assertThrows(IOException.class, () -> repo.deleteRepositoryBranch(FEATURE));
        assertEquals("deletion prohibited", e.getMessage());
        assertNotNull(remoteRef(Constants.R_HEADS + FEATURE));
    }

    @Test
    void pushToALockedRemoteBranchIsReportedAndRolledBack() throws IOException {
        var lock = new File(remote.bare(), Constants.R_HEADS + Constants.MASTER + ".lock");
        Files.writeString(lock.toPath(), "locked by another writer", StandardCharsets.UTF_8);

        var saveError = assertThrows(IOException.class,
                () -> repo.save(createFileData(MAIN_FILE, "locked", "Save while locked"),
                        IOUtils.toInputStream("locked")));
        assertEquals("failed to lock", saveError.getMessage());
        assertEquals("main", readText(repo.read(MAIN_FILE)));

        var deleteError = assertThrows(IOException.class,
                () -> repo.delete(createFileData(MAIN_FILE, "", "Delete while locked")));
        assertEquals("failed to lock", deleteError.getMessage());
        assertEquals("main", readText(repo.read(MAIN_FILE)));
        assertEquals(mainCommit.getId(), remoteRef(Constants.R_HEADS + Constants.MASTER));
    }

    @Test
    void branchKnownOnlyAsARemoteRefIsDeletedOnTheRemote() throws IOException, GitAPIException {
        deleteLocalBranch(FEATURE);

        repo.deleteRepositoryBranch(FEATURE);

        assertNull(remoteRef(Constants.R_HEADS + FEATURE));
    }

    @Test
    void branchViewOfARemoteOnlyBranchCreatesItsLocalBranch() throws IOException, GitAPIException {
        deleteLocalBranch(FEATURE);

        var view = repo.forBranch(FEATURE);

        assertEquals(FEATURE, view.getBranch());
        assertNotNull(localRef(Constants.R_HEADS + FEATURE));
        assertEquals("feature", readText(view.read(FEATURE_FILE)));
    }

    @Test
    void resetReturnsADetachedHeadToTheBranch() throws IOException, GitAPIException {
        try (var git = Git.open(local)) {
            git.checkout().setName(mainCommit.getName()).call();
            assertEquals(mainCommit.getName(), git.getRepository().getFullBranch());
        }

        repo.createRepositoryBranch("from-detached", null);

        try (var git = Git.open(local)) {
            assertEquals(Constants.R_HEADS + Constants.MASTER, git.getRepository().getFullBranch());
        }
        assertEquals(mainCommit.getId(), remoteRef(Constants.R_HEADS + "from-detached"));
    }

    @Test
    void resetReplacesACorruptedIndex() throws IOException, GitAPIException {
        File index;
        try (var git = Git.open(local)) {
            index = git.getRepository().getIndexFile();
        }
        Files.writeString(index.toPath(), "not an index", StandardCharsets.UTF_8);

        repo.createRepositoryBranch("after-corruption", null);

        try (var git = Git.open(local)) {
            var repository = git.getRepository();
            assertEquals(1, DirCache.read(repository).getEntryCount(), "The index must be rebuilt from HEAD");
        }
        assertEquals(mainCommit.getId(), remoteRef(Constants.R_HEADS + "after-corruption"));
    }

    @Test
    void pullOfConflictingRemoteChangesIsReportedAsAConflict() throws IOException, GitAPIException {
        remote.commit(Constants.MASTER, MAIN_FILE, "remote change");
        try (var git = Git.open(local)) {
            Files.writeString(new File(local, MAIN_FILE).toPath(), "local change", StandardCharsets.UTF_8);
            git.add().addFilepattern(MAIN_FILE).call();
            git.commit().setMessage("Local change").setCommitter("Local User", "local@example.org").call();
        }

        var e = assertThrows(MergeConflictException.class, () -> repo.pull(AUTHOR));
        assertEquals(List.of(MAIN_FILE), List.copyOf(e.getDetails().getConflictedFiles()));
        assertEquals("local change", readText(repo.read(MAIN_FILE)));
    }

    @Test
    void operationsThatNeedTheRemoteFailWhenItHasGone() throws IOException {
        FileUtils.delete(remote.bare().toPath());

        var pullError = assertThrows(IOException.class, () -> repo.pull(AUTHOR));
        assertInstanceOf(GitAPIException.class, pullError.getCause());

        var deleteError = assertThrows(IOException.class, () -> repo.deleteRepositoryBranch(FEATURE));
        assertInstanceOf(GitAPIException.class, deleteError.getCause());
    }

    private GitRepository open(String branch, boolean empty) throws IOException {
        var repository = new GitRepository();
        repository.setId(REPO_ID);
        var uri = remote.uri();
        repository.setUri(uri);
        repository.setLocalRepositoriesFolder(repositoriesFolder);
        repository.setBranch(branch);
        repository.setGcAutoDetach(false);
        repository.initialize(TestGitUtils.mockGitRootFactory(REPO_ID, uri, local, repositoriesFolder, true, empty));
        return repository;
    }

    private void deleteLocalBranch(String branch) throws IOException, GitAPIException {
        try (var git = Git.open(local)) {
            git.branchDelete().setBranchNames(branch).setForce(true).call();
            assertNotNull(git.getRepository()
                    .exactRef(Constants.R_REMOTES + Constants.DEFAULT_REMOTE_NAME + "/" + branch));
        }
    }

    private @Nullable ObjectId localRef(String ref) throws IOException {
        try (var git = Git.open(local)) {
            var found = git.getRepository().exactRef(ref);
            return found == null ? null : found.getObjectId();
        }
    }

    private @Nullable ObjectId remoteRef(String ref) throws IOException {
        try (var bare = remote.openBare()) {
            var found = bare.getRepository().exactRef(ref);
            return found == null ? null : found.getObjectId();
        }
    }

    private @Nullable ObjectId peeledTag(String tag) throws IOException {
        try (var git = Git.open(local)) {
            var repository = git.getRepository();
            var ref = repository.exactRef(Constants.R_TAGS + tag);
            if (ref == null) {
                return null;
            }
            var peeled = repository.getRefDatabase().peel(ref).getPeeledObjectId();
            return peeled == null ? ref.getObjectId() : peeled;
        }
    }
}

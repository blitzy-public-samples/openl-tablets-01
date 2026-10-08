package org.openl.rules.repository.git;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

import static org.openl.rules.repository.git.TestGitUtils.createFileData;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.UUID;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.api.errors.InvalidRemoteException;
import org.eclipse.jgit.api.errors.TransportException;
import org.eclipse.jgit.lib.ConfigConstants;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.treewalk.TreeWalk;
import org.junit.jupiter.api.AutoClose;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import org.openl.util.FileUtils;
import org.openl.util.IOUtils;

/**
 * Covers the {@link GitRepository} paths that open a repository: the working-tree accessor of
 * {@link org.openl.rules.repository.LocalWorkingTree}, the errors a failed opening reports, credentials, Git LFS,
 * commit hooks and the remote refs it tracks. The V1 change, which made the class reveal its working tree, brought
 * these paths under the per-class coverage target.
 */
class GitRepositoryInitializationTest {
    private static final String REPO_ID = "init-coverage";
    private static final String README = "rules/readme.txt";
    private static final String README_TEXT = "plain text";
    private static final String LFS_ATTRIBUTES = "*.bin filter=lfs diff=lfs merge=lfs -text\n";
    private static final String GIT_LFS_PRE_PUSH = "#!/bin/sh\ngit lfs pre-push \"$@\"\n";
    private static final String NO_OP_HOOK = "#!/bin/sh\nexit 0\n";

    @TempDir
    private File root;
    @AutoClose
    private GitRemoteFixture remote;
    private File local;
    private String repositoriesFolder;

    @BeforeEach
    void setUp() throws GitAPIException, IOException, URISyntaxException {
        remote = GitRemoteFixture.create(root);
        remote.commit(Constants.MASTER, README, README_TEXT);
        var repositories = new File(root, "repositories");
        repositoriesFolder = repositories.getAbsolutePath();
        local = new File(repositories, "local");
    }

    @Test
    void workingTreeIsUnknownUntilInitializedAndSharedWithBranchViews() throws IOException {
        try (var repository = newRepository()) {
            assertNull(repository.getLocalWorkingTree());

            openRemote(repository, true);
            assertEquals(local.toPath(), repository.getLocalWorkingTree());

            repository.createRepositoryBranch("feature", null);
            var view = repository.forBranch("feature");
            assertEquals("feature", view.getBranch());
            assertEquals(local.toPath(), view.getLocalWorkingTree());
        }
    }

    @Test
    @SuppressWarnings("NullAway") // isValidBranchName must answer false for a missing name instead of failing
    void exposesItsConfigurationBeforeInitialization() {
        try (var repository = newRepository()) {
            repository.setName("Design");
            repository.setBranch("  ");
            // No monitor exists before initialize(), so the listener is not registered and nothing is scheduled.
            repository.setListener(() -> {
                throw new IllegalStateException("The listener must not be called before initialization.");
            });

            assertEquals(REPO_ID, repository.getId());
            assertEquals("Design", repository.getName());
            assertEquals(Constants.MASTER, repository.getBranch());
            assertEquals(Constants.MASTER, repository.getBaseBranch());
            assertTrue(repository.isValidBranchName("feature/one"));
            assertFalse(repository.isValidBranchName(null));

            var features = repository.supports();
            assertTrue(features.branches());
            assertTrue(features.folders());
            assertTrue(features.versions());
            assertTrue(features.uniqueFileId());
            assertTrue(features.searchable());
            assertFalse(features.mappedFolders());
            assertFalse(features.isLocal());
        }
    }

    @Test
    void closedRepositoryThatWasNeverInitializedHasNoGitFolder() {
        var repository = newRepository();
        repository.close();

        var e = assertThrows(IOException.class, repository::getClosableGit);
        assertEquals("Git repository is not initialized", e.getMessage());
    }

    @Test
    void unknownHostIsReportedWithItsName() throws IOException {
        var uri = "https://git.example.invalid/rules.git";
        var failure = new IOException("Cannot connect", new UnknownHostException("git.example.invalid"));
        try (var repository = failingRepository(uri, failure)) {
            var e = assertThrows(IllegalArgumentException.class, () -> repository.list(""));
            assertEquals("Unknown host (git.example.invalid) for URL " + uri + ".", e.getMessage());
        }
    }

    @Test
    void unknownHostWithoutANameIsReportedForTheUrl() throws IOException {
        var uri = "https://git.example.invalid/rules.git";
        var failure = new IOException("Cannot connect", new UnknownHostException());
        try (var repository = failingRepository(uri, failure)) {
            var e = assertThrows(IllegalArgumentException.class, () -> repository.list(""));
            assertEquals("Unknown host for URL " + uri + ".", e.getMessage());
        }
    }

    @Test
    void transportFailureForAnUrlWithoutSchemeReportsAnIncorrectUrl() throws IOException {
        try (var repository = failingRepository("rules/design.git", new TransportException("Cannot reach"))) {
            var e = assertThrows(IllegalStateException.class, () -> repository.list(""));
            assertEquals("Incorrect URL.", e.getMessage());
        }
    }

    @Test
    void transportFailureForAnUnparsableUrlReportsAnIncorrectUrl() throws IOException {
        try (var repository = failingRepository("", new TransportException("Cannot reach"))) {
            var e = assertThrows(IllegalStateException.class, () -> repository.list(""));
            assertEquals("Incorrect URL.", e.getMessage());
        }
    }

    @Test
    void transportFailureForAValidUrlIsReportedAsAFailedInitialization() throws IOException {
        var failure = new TransportException("Cannot reach");
        try (var repository = failingRepository("https://git.example.invalid/rules.git", failure)) {
            var e = assertThrows(IllegalStateException.class, () -> repository.list(""));
            assertEquals("Failed to initialize a repository: Cannot reach", e.getMessage());
            assertSame(failure, e.getCause());
        }
    }

    @Test
    void otherFailureIsReportedAsAFailedInitialization() throws IOException {
        var failure = new IOException("Disk is full");
        try (var repository = failingRepository("https://git.example.invalid/rules.git", failure)) {
            var e = assertThrows(IllegalStateException.class, () -> repository.list(""));
            assertEquals("Failed to initialize a repository: Disk is full", e.getMessage());
        }
    }

    @Test
    void missingRemoteIsReportedAsAbsentAndLeavesNoClone() throws IOException {
        var uri = new File(root, "absent.git").toURI().toString();
        var repository = newRepository();
        repository.setUri(uri);
        repository.initialize(TestGitUtils.mockGitRootFactory(REPO_ID, uri, local, repositoriesFolder, true, true));
        try (repository) {
            var e = assertThrows(IllegalArgumentException.class, () -> repository.list(""));
            assertEquals("Remote repository \"" + uri + "\" does not exist.", e.getMessage());
            assertFalse(local.exists(), "A failed clone must remove its folder");
        }
    }

    @Test
    void remoteDeletedAfterCloneIsReportedAsAbsentOnReopen() throws IOException {
        openRemote(newRepository(), true).close();
        FileUtils.delete(remote.bare().toPath());

        try (var repository = openRemote(newRepository(), false)) {
            var e = assertThrows(IllegalArgumentException.class, () -> repository.list(""));
            assertEquals("Remote repository \"" + remote.uri() + "\" does not exist.", e.getMessage());
            assertTrue(new File(local, Constants.DOT_GIT).isDirectory(), "The existing clone must be kept");
        }
    }

    @Test
    void localRepositoryUnderAFileCannotBeCreated() throws IOException {
        var file = new File(root, "not-a-folder");
        Files.writeString(file.toPath(), "a file, not a folder", StandardCharsets.UTF_8);

        try (var repository = openLocal(newRepository(), new File(file, "design"), true)) {
            var e = assertThrows(IllegalStateException.class, () -> repository.list(""));
            var message = String.valueOf(e.getMessage());
            assertTrue(message.startsWith("Failed to initialize a repository: "), message);
            assertTrue(file.isFile(), "The file in the way must be left as it is");
        }
    }

    @Test
    void credentialsAreUsedForEveryRemoteOperation() throws IOException, GitAPIException {
        var login = UUID.randomUUID().toString();
        var password = UUID.randomUUID().toString();
        var path = "rules/credentials.txt";
        try (var repository = newRepository()) {
            repository.setLogin(login);
            repository.setPassword(password);
            repository.setFailedAuthenticationSeconds(1);
            repository.setMaxAuthenticationAttempts(3);
            openRemote(repository, true);

            repository.save(createFileData(path, "pushed"), IOUtils.toInputStream("pushed"));
            repository.createRepositoryBranch("credentials-branch", null);
            repository.validateConnection();
            assertNotNull(repository.getLastRevision());
        }

        try (var reopened = newRepository()) {
            reopened.setLogin(login);
            reopened.setPassword(password);
            openRemote(reopened, false);
            assertEquals("pushed", GitRepositoryTest.readText(reopened.read(path)));
            assertTrue(reopened.listBranches().contains("credentials-branch"));
        }

        assertTrue(remoteHasFile(Constants.MASTER, path), "The save must be pushed with the credentials");
        try (var bare = remote.openBare()) {
            assertNotNull(bare.getRepository().exactRef(Constants.R_HEADS + "credentials-branch"));
        }
    }

    @Test
    void loginWithoutPasswordIsNotUsedAsCredentials() throws IOException {
        try (var repository = newRepository()) {
            repository.setLogin(UUID.randomUUID().toString());
            repository.setPassword("");
            openRemote(repository, true);

            assertEquals(README_TEXT, GitRepositoryTest.readText(repository.read(README)));
        }
    }

    @Test
    void validateConnectionFetchesOnlyFromARemote() throws IOException {
        try (var localRepository = openLocal(newRepository(), new File(root, "local-design"), true)) {
            localRepository.validateConnection();
        }

        try (var repository = openRemote(newRepository(), true)) {
            repository.validateConnection();

            FileUtils.delete(remote.bare().toPath());
            var e = assertThrows(IOException.class, repository::validateConnection);
            assertInstanceOf(InvalidRemoteException.class, e.getCause());
        }
    }

    @Test
    void lfsRepositoryIsClonedWithTheBuiltInFilterAndReadsRegularFiles() throws IOException, GitAPIException {
        remote.commit(Constants.MASTER, Constants.DOT_GIT_ATTRIBUTES, LFS_ATTRIBUTES);

        try (var repository = newRepository()) {
            repository.setLogin(UUID.randomUUID().toString());
            repository.setPassword(UUID.randomUUID().toString());
            openRemote(repository, true);

            assertEquals(README_TEXT, GitRepositoryTest.readText(repository.read(README)));
        }

        try (var git = Git.open(local)) {
            assertTrue(git.getRepository()
                    .getConfig()
                    .getBoolean(ConfigConstants.CONFIG_FILTER_SECTION,
                            ConfigConstants.CONFIG_SECTION_LFS,
                            ConfigConstants.CONFIG_KEY_USEJGITBUILTIN,
                            false));
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void lfsPrePushHookIsRenamedOnlyWhenItRunsGitLfs() throws IOException, GitAPIException {
        remote.commit(Constants.MASTER, Constants.DOT_GIT_ATTRIBUTES, LFS_ATTRIBUTES);
        openRemote(newRepository(), true).close();
        var hooks = new File(new File(local, Constants.DOT_GIT), Constants.HOOKS);
        var prePush = new File(hooks, "pre-push");
        var renamed = new File(hooks, "pre-push.renamed");

        writeHook(prePush, GIT_LFS_PRE_PUSH, true);
        openRemote(newRepository(), false).close();
        assertFalse(prePush.exists(), "A Git LFS pre-push hook must be renamed");
        assertEquals(GIT_LFS_PRE_PUSH, Files.readString(renamed.toPath(), StandardCharsets.UTF_8));

        // LFS is installed already, so reopening without a pre-push hook installs none and renames nothing.
        openRemote(newRepository(), false).close();
        assertFalse(prePush.exists());
        assertEquals(GIT_LFS_PRE_PUSH, Files.readString(renamed.toPath(), StandardCharsets.UTF_8));

        writeHook(prePush, NO_OP_HOOK, true);
        openRemote(newRepository(), false).close();
        assertEquals(NO_OP_HOOK, Files.readString(prePush.toPath(), StandardCharsets.UTF_8));

        Files.delete(renamed.toPath());
        Files.createDirectories(renamed.toPath());
        Files.writeString(renamed.toPath().resolve("occupied"), "occupied", StandardCharsets.UTF_8);
        writeHook(prePush, GIT_LFS_PRE_PUSH, true);
        try (var repository = openRemote(newRepository(), false)) {
            assertEquals(GIT_LFS_PRE_PUSH,
                    Files.readString(prePush.toPath(), StandardCharsets.UTF_8),
                    "The hook must stay when its new name is taken");
            assertEquals(README_TEXT, GitRepositoryTest.readText(repository.read(README)));
        }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void hooksRunWhenPreCommitAndCommitMsgAreBothExecutable() throws IOException, GitAPIException {
        var marker = new File(root, "hook-ran");
        assertTrue(saveWithHooks(marker, true, true, true));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void hooksAreSkippedWhenOnlyPreCommitExists() throws IOException, GitAPIException {
        var marker = new File(root, "hook-ran");
        assertFalse(saveWithHooks(marker, true, false, true));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void hooksAreSkippedWhenOnlyCommitMsgExists() throws IOException, GitAPIException {
        var marker = new File(root, "hook-ran");
        assertFalse(saveWithHooks(marker, false, true, true));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void hooksAreSkippedWhenTheyAreNotExecutable() throws IOException, GitAPIException {
        var marker = new File(root, "hook-ran");
        assertFalse(saveWithHooks(marker, true, true, false));
    }

    @Test
    void remoteRefsOutsideOriginAndSymbolicRefsAreNotBranches() throws IOException, GitAPIException {
        openRemote(newRepository(), true).close();
        String head;
        try (var git = Git.open(local)) {
            head = git.getRepository().resolve(Constants.MASTER).name();
        }
        var remotes = new File(new File(local, Constants.DOT_GIT), Constants.R_REMOTES);
        writeRef(new File(remotes, "upstream/side"), head + "\n");
        writeRef(new File(remotes, Constants.DEFAULT_REMOTE_NAME + "/" + Constants.HEAD),
                "ref: " + Constants.R_REMOTES + Constants.DEFAULT_REMOTE_NAME + "/" + Constants.MASTER + "\n");

        try (var repository = openRemote(newRepository(), false)) {
            var branches = repository.listBranches();
            assertTrue(branches.contains(Constants.MASTER));
            assertFalse(branches.contains("side"), "Only branches of the origin remote are tracked");
            assertFalse(branches.contains(Constants.HEAD), "A symbolic remote ref is not a branch");
            assertFalse(repository.getAvailableBranches().contains("side"));
        }
    }

    /**
     * Saves a file in a local repository whose hooks folder holds the chosen hooks, and answers whether a hook ran.
     */
    private boolean saveWithHooks(File marker,
                                  boolean preCommit,
                                  boolean commitMsg,
                                  boolean executable) throws IOException, GitAPIException {
        var folder = new File(root, "hooked");
        Git.init().setInitialBranch(Constants.MASTER).setDirectory(folder).call().close();
        var hooks = new File(new File(folder, Constants.DOT_GIT), Constants.HOOKS);
        var script = "#!/bin/sh\ntouch '" + marker.getAbsolutePath() + "'\n";
        if (preCommit) {
            writeHook(new File(hooks, "pre-commit"), script, executable);
        }
        if (commitMsg) {
            writeHook(new File(hooks, "commit-msg"), script, executable);
        }

        try (var repository = openLocal(newRepository(), folder, false)) {
            var saved = repository.save(createFileData("rules/hooked.txt", "hooked"), IOUtils.toInputStream("hooked"));
            assertEquals("rules/hooked.txt", saved.getName());
        }
        return marker.exists();
    }

    private GitRepository newRepository() {
        var repository = new GitRepository();
        repository.setId(REPO_ID);
        repository.setLocalRepositoriesFolder(repositoriesFolder);
        repository.setGcAutoDetach(false);
        return repository;
    }

    private GitRepository openRemote(GitRepository repository, boolean empty) throws IOException {
        var uri = remote.uri();
        repository.setUri(uri);
        repository.initialize(TestGitUtils.mockGitRootFactory(REPO_ID, uri, local, repositoriesFolder, true, empty));
        return repository;
    }

    private GitRepository openLocal(GitRepository repository, File folder, boolean empty) throws IOException {
        var uri = folder.getAbsolutePath();
        repository.setUri(uri);
        repository.initialize(TestGitUtils.mockGitRootFactory(REPO_ID, uri, folder, repositoriesFolder, false, empty));
        return repository;
    }

    private GitRepository failingRepository(String uri, Throwable failure) throws IOException {
        var gitRootFactory = mock(GitRootFactory.class);
        doAnswer(invocation -> {
            throw failure;
        }).when(gitRootFactory).create(REPO_ID, uri, repositoriesFolder);
        var repository = newRepository();
        repository.setUri(uri);
        repository.initialize(gitRootFactory);
        return repository;
    }

    private boolean remoteHasFile(String branch, String path) throws IOException {
        try (var bare = remote.openBare()) {
            var repository = bare.getRepository();
            var commit = repository.parseCommit(repository.resolve(branch));
            try (var walk = TreeWalk.forPath(repository, path, commit.getTree())) {
                return walk != null;
            }
        }
    }

    private static void writeHook(File hook, String script, boolean executable) throws IOException {
        Files.createDirectories(hook.getParentFile().toPath());
        Files.writeString(hook.toPath(), script, StandardCharsets.UTF_8);
        if (!hook.setExecutable(executable) && executable) {
            throw new IOException("Cannot make " + hook + " executable");
        }
    }

    private static void writeRef(File ref, String content) throws IOException {
        Files.createDirectories(ref.getParentFile().toPath());
        Files.writeString(ref.toPath(), content, StandardCharsets.UTF_8);
    }
}

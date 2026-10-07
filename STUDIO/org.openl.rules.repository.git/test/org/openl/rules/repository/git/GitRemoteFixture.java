package org.openl.rules.repository.git;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.ResetCommand;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.lib.PersonIdent;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.transport.PushResult;
import org.eclipse.jgit.transport.RefSpec;
import org.eclipse.jgit.transport.RemoteRefUpdate;
import org.eclipse.jgit.transport.URIish;

/**
 * A bare remote repository and a working clone that changes it, for tests that run {@link GitRepository} against a
 * remote it clones, fetches from and pushes to.
 *
 * <p>The remote is reached through a {@code file:} URI, so no network is used. Every change the working clone makes is
 * pushed at once, and a push the remote refuses fails the test setup instead of passing unnoticed.
 *
 * <p>It backs the tests of the {@link GitRepository} paths that the V1 change, which made the class reveal its working
 * tree, brought under the per-class coverage target.
 */
final class GitRemoteFixture implements AutoCloseable {
    private static final String COMMITTER = "Remote User";
    private static final String COMMITTER_EMAIL = "remote.user@example.org";

    private final File bare;
    private final Git worker;

    private GitRemoteFixture(File bare, Git worker) {
        this.bare = bare;
        this.worker = worker;
    }

    /**
     * Creates an empty bare remote under {@code root} and a working clone that pushes to it.
     */
    static GitRemoteFixture create(File root) throws GitAPIException, URISyntaxException {
        var bare = new File(root, "remote.git");
        Git.init().setBare(true).setInitialBranch(Constants.MASTER).setDirectory(bare).call().close();
        var worker = Git.init().setInitialBranch(Constants.MASTER).setDirectory(new File(root, "worker")).call();
        worker.remoteAdd().setName(Constants.DEFAULT_REMOTE_NAME).setUri(new URIish(bare.toURI().toString())).call();
        return new GitRemoteFixture(bare, worker);
    }

    File bare() {
        return bare;
    }

    String uri() {
        return bare.toURI().toString();
    }

    /**
     * Writes {@code text} to {@code path} on {@code branch}, commits it and pushes the branch. A missing branch is
     * created from the commit the working clone is on.
     */
    RevCommit commit(String branch, String path, String text) throws GitAPIException, IOException {
        checkout(branch);
        var file = new File(worker.getRepository().getWorkTree(), path);
        Files.createDirectories(file.getParentFile().toPath());
        Files.writeString(file.toPath(), text, StandardCharsets.UTF_8);
        worker.add().addFilepattern(path).call();
        var commit = worker.commit()
                .setMessage("Change " + path + " in " + branch)
                .setCommitter(COMMITTER, COMMITTER_EMAIL)
                .setAuthor(COMMITTER, COMMITTER_EMAIL)
                .call();
        push(Constants.R_HEADS + branch + ":" + Constants.R_HEADS + branch);
        return commit;
    }

    /**
     * Replaces the last commit of {@code branch} with a commit that is not its descendant, and force-pushes it.
     */
    RevCommit rewrite(String branch, String path, String text) throws GitAPIException, IOException {
        checkout(branch);
        worker.reset().setMode(ResetCommand.ResetType.HARD).setRef(Constants.HEAD + "~1").call();
        var file = new File(worker.getRepository().getWorkTree(), path);
        Files.createDirectories(file.getParentFile().toPath());
        Files.writeString(file.toPath(), text, StandardCharsets.UTF_8);
        worker.add().addFilepattern(path).call();
        var commit = worker.commit()
                .setMessage("Rewrite " + path + " in " + branch)
                .setCommitter(COMMITTER, COMMITTER_EMAIL)
                .setAuthor(COMMITTER, COMMITTER_EMAIL)
                .call();
        push("+" + Constants.R_HEADS + branch + ":" + Constants.R_HEADS + branch);
        return commit;
    }

    /**
     * Creates or moves the annotated tag {@code name} to {@code commit} and force-pushes it.
     */
    void tag(String name, RevCommit commit) throws GitAPIException {
        worker.tag()
                .setName(name)
                .setObjectId(commit)
                .setForceUpdate(true)
                .setTagger(new PersonIdent(COMMITTER, COMMITTER_EMAIL))
                .call();
        push("+" + Constants.R_TAGS + name + ":" + Constants.R_TAGS + name);
    }

    /**
     * Deletes {@code branch} on the remote.
     */
    void deleteBranch(String branch) throws GitAPIException {
        push(":" + Constants.R_HEADS + branch);
    }

    /**
     * Opens the bare remote itself, for changes no push can make. The caller closes it.
     */
    Git openBare() throws IOException {
        return Git.open(bare);
    }

    private void checkout(String branch) throws GitAPIException, IOException {
        var repository = worker.getRepository();
        if (!branch.equals(repository.getBranch())) {
            worker.checkout()
                    .setName(branch)
                    .setCreateBranch(repository.exactRef(Constants.R_HEADS + branch) == null)
                    .call();
        }
    }

    private void push(String refSpec) throws GitAPIException {
        Iterable<PushResult> results = worker.push()
                .setRemote(Constants.DEFAULT_REMOTE_NAME)
                .setRefSpecs(new RefSpec(refSpec))
                .call();
        for (var result : results) {
            for (var update : result.getRemoteUpdates()) {
                var status = update.getStatus();
                if (status != RemoteRefUpdate.Status.OK && status != RemoteRefUpdate.Status.UP_TO_DATE) {
                    throw new IllegalStateException(
                            "The remote refused '%s' with %s.".formatted(update.getRemoteName(), status));
                }
            }
        }
    }

    @Override
    public void close() {
        worker.close();
    }
}

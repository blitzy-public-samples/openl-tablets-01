package org.openl.rules.workspace.lw.impl;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.core.env.PropertyResolver;

import org.openl.rules.project.abstraction.LockEngine;
import org.openl.rules.project.impl.local.DummyLockEngine;
import org.openl.rules.project.impl.local.LockEngineImpl;
import org.openl.rules.project.impl.local.MetainfoRegistry;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.rules.workspace.lw.LocalWorkspace;
import org.openl.rules.workspace.lw.LocalWorkspaceListener;
import org.openl.rules.workspace.lw.LocalWorkspaceManager;
import org.openl.util.FileUtils;

/**
 * LocalWorkspaceManager implementation.
 *
 * @author Aleh Bykhavets
 */
@Slf4j
public class LocalWorkspaceManagerImpl implements LocalWorkspaceManager, LocalWorkspaceListener {

    // V1: the message of every rejected user id
    private static final String INVALID_USER_ID = "The user id is not a valid workspace folder name.";

    @Setter
    private String workspaceHome;
    @Setter
    private boolean enableLocks = true;
    // V1: extra user-id check injected by the web module; accepts every id by default
    private Predicate<String> folderNameCheck = name -> true;

    // User name -> user workspace
    private final Map<String, LocalWorkspaceImpl> localWorkspaces = new HashMap<>();

    // User name -> metainfo registry. Registries are shared by all sessions of a user and are retained
    // for the JVM lifetime, so workspace instance churn cannot fork the local-changes state.
    private final Map<String, MetainfoRegistry> metainfoRegistries = new ConcurrentHashMap<>();

    // Project type (rules/deployment) -> Lock Engine
    private final Map<String, LockEngine> lockEngines = new HashMap<>();
    private final DesignTimeRepository designTimeRepository;

    // for tests
    public LocalWorkspaceManagerImpl() {
        designTimeRepository = null;
    }

    public LocalWorkspaceManagerImpl(PropertyResolver propertyResolver, DesignTimeRepository designTimeRepository) {
        workspaceHome = propertyResolver.getProperty("user.workspace.home");
        this.designTimeRepository = designTimeRepository;
    }

    // V1: injection point for the web module's user-id check; null restores the accept-all default
    /**
     * Sets the check each user id must pass before it names a workspace folder.
     *
     * <p>The web module injects its {@code NameChecker}-backed {@code WorkspaceFolderNameCheck} here, because
     * this module cannot depend on the web module. {@code null} restores the default, which accepts every id.
     *
     * @param folderNameCheck returns {@code true} for an acceptable user id
     */
    public void setFolderNameCheck(@Nullable Predicate<String> folderNameCheck) {
        this.folderNameCheck = folderNameCheck != null ? folderNameCheck : name -> true;
    }

    /**
     * init-method
     */
    public void init() throws FileNotFoundException {
        if (workspaceHome == null) {
            log.warn("workspaceHome is not initialized. Default value is used.");
            workspaceHome = FileUtils.getTempDirectoryPath() + "/rules-workspaces/";
        }
        var location = new File(workspaceHome);
        if (!location.mkdirs() && !location.exists()) {
            final String message = MessageFormat.format("Cannot create workspace location ''{0}''", workspaceHome);
            throw new FileNotFoundException(message);
        }
        log.info("Location of Local Workspaces: {}", workspaceHome);
    }

    private LocalWorkspaceImpl createWorkspace(String userId) {
        var userWorkspace = userDir(userId).toFile();
        log.debug("Workspace for user ''{}'' will be located at ''{}''", userId, userWorkspace.getAbsolutePath());
        var workspace = new LocalWorkspaceImpl(userId,
                userWorkspace,
                designTimeRepository,
                registryOf(userId));
        workspace.addWorkspaceListener(this);
        return workspace;
    }

    private MetainfoRegistry registryOf(String userId) {
        return metainfoRegistries.computeIfAbsent(userId, id -> MetainfoRegistry.open(userDir(id)));
    }

    /**
     * Resolves the workspace directory of the user.
     *
     * <p>The user id comes from the authentication and is used as a folder name, so it must stay
     * a single path component right under the workspace root. Otherwise the workspace operations,
     * including the registry reconciliation, could read or delete files outside the root. Links under the root
     * are resolved as well, so the folder cannot lead into another user's folder or outside the root.
     */
    private Path userDir(String userId) {
        var root = getWorkspaceHome();
        try {
            var userDir = root.resolve(userId).toAbsolutePath().normalize();
            // V1: the lexical checks run first, then links under the root are resolved
            if (FolderHelper.isSafeFolderName(userId) && root.equals(userDir.getParent())
                    && isOwnWorkspaceFolder(root, userId, folderNameCheck)) {
                return userDir;
            }
        } catch (IllegalArgumentException e) {
            // V1: an id the path API cannot parse, such as one with a NUL byte, gets the same rejection, with the
            // parser failure as its cause
            throw new IllegalArgumentException(INVALID_USER_ID, e);
        }
        throw new IllegalArgumentException(INVALID_USER_ID);
    }

    // V1: real-path containment of the user's folder under the workspace home. No path check is shared between the
    // workspace, file, project and upload surfaces, so it stays private to this class, not in the dedicated file the
    // Minimal Change Rule prefers
    /**
     * Checks that the user folder is a real folder of its own right under the workspace root.
     *
     * <p>The id must pass {@link Repository#validatePath(String)} and the injected check. Then the folder must sit
     * at its own place under the real root: a link that leads into another user's folder or outside the root is
     * rejected, and so is a dangling link. Links in the root's own path are configured by the administrator and are
     * followed. A root or a folder that does not exist yet is accepted, because a missing entry contains no links.
     *
     * @param root the lexical workspace root
     * @param userId the user id, already known to be a single path component right under the root
     * @param check the injected user-id check
     * @return {@code true} if the folder cannot lead outside itself
     */
    private static boolean isOwnWorkspaceFolder(Path root, String userId, Predicate<String> check) {
        try {
            Repository.validatePath(userId);
            if (!check.test(userId)) {
                return false;
            }
            // The deepest existing ancestor of the root, walked down from the file-system root. A file-system root
            // that does not exist, such as a missing drive, makes toRealPath() fail below.
            var existing = root.getRoot();
            for (var name : root) {
                var next = existing.resolve(name);
                if (!Files.exists(next, LinkOption.NOFOLLOW_LINKS)) {
                    break;
                }
                existing = next;
            }
            var anchorReal = existing.toRealPath().resolve(existing.relativize(root));
            var boundary = anchorReal.resolve(userId).normalize();
            // A dangling link counts as existing here, so toRealPath() rejects it
            var walked = Files.exists(boundary, LinkOption.NOFOLLOW_LINKS) ? boundary.toRealPath() : boundary;
            return walked.startsWith(boundary);
        } catch (IOException | IllegalArgumentException | SecurityException e) {
            // V1: the caller turns the failure into the rejection
            return false;
        }
    }

    @Override
    public Path getWorkspaceHome() {
        return Path.of(workspaceHome).toAbsolutePath().normalize();
    }

    @Override
    public void refreshMetainfoRegistry(String userId) {
        var registry = metainfoRegistries.get(userId);
        if (registry == null) {
            // The first load performs the same reconciliation, so loading now is enough.
            registryOf(userId);
        } else {
            registry.refresh();
        }
    }

    @Override
    public LocalWorkspace getWorkspace(String userId) {
        var lwi = localWorkspaces.get(userId);
        if (lwi == null) {
            lwi = createWorkspace(userId);
            localWorkspaces.put(userId, lwi);
        }
        return lwi;
    }

    @Override
    public LockEngine getLockEngine(String type) {
        if (!enableLocks) {
            return new DummyLockEngine();
        }
        synchronized (lockEngines) {
            return lockEngines.computeIfAbsent(type, t -> LockEngineImpl.create(new File(workspaceHome), t));
        }
    }

    @Override
    public void workspaceReleased(LocalWorkspace workspace) {
        workspace.removeWorkspaceListener(this);
        localWorkspaces.remove(((LocalWorkspaceImpl) workspace).getUserId());
    }
}

package org.openl.rules.webstudio.security;

import java.io.IOException;
import java.util.function.Predicate;

import org.jspecify.annotations.Nullable;

import org.openl.rules.webstudio.util.NameChecker;

/**
 * Checks that a user id can name the user's workspace folder (V1, surface A: workspace directory).
 *
 * <p>{@code LocalWorkspaceManagerImpl} uses each user id as the name of a folder right under the workspace root.
 * The web module injects this check into it through {@code setFolderNameCheck}, wired in
 * {@code repository-beans.xml}. The workspace module cannot call {@link NameChecker} itself: the module that holds
 * {@code NameChecker} depends on the workspace module, so a direct call would create a module cycle.
 *
 * <p>Its single consumer is {@code LocalWorkspaceManagerImpl.userDir}, which runs it after
 * {@code FolderHelper.isSafeFolderName}, the check that the folder's parent is the workspace root and
 * {@code Repository.validatePath}, and before the real-path containment check of the user's folder. A rejection
 * becomes the {@code IllegalArgumentException} that {@code userDir} throws for every invalid user id.
 *
 * <p>A user id is accepted only if {@link NameChecker#validatePath(String)} accepts it. That rejects the characters
 * {@code \ : ; < > ? * % ' " | [ ]}, control characters, a doubled separator, a leading space, a trailing dot or
 * space, and the reserved names {@code CON}, {@code PRN}, {@code AUX}, {@code NUL}, {@code COM1} to {@code COM9}
 * and {@code LPT1} to {@code LPT9}. {@code NameChecker} reads {@code /}, and on Windows {@code \}, as a path
 * separator, so a user id that contains one relies on the caller's earlier checks, which reject separators.
 * {@code null} and the empty string are rejected without calling {@code NameChecker}.
 *
 * <p>The check is stateless and therefore thread-safe. It logs nothing and never reports the rejected id: the
 * caller turns a rejection into its own error.
 */
public final class WorkspaceFolderNameCheck implements Predicate<String> {

    /**
     * Tests whether the user id can name a workspace folder.
     *
     * @param name the user id
     * @return {@code true} only for a non-empty name that {@link NameChecker#validatePath(String)} accepts
     */
    @Override
    public boolean test(@Nullable String name) {
        // NameChecker.validatePath cannot take null, and an empty name cannot name a folder
        if (name == null || name.isEmpty()) {
            return false;
        }
        try {
            NameChecker.validatePath(name);
            return true;
        } catch (IOException | IllegalArgumentException e) {
            // IllegalArgumentException covers the InvalidPathException the path API raises for a name it cannot
            // parse, such as one with a NUL byte
            return false;
        }
    }
}

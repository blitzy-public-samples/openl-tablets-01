package org.openl.rules.repository;

import java.nio.file.Path;

import org.jspecify.annotations.Nullable;

// V1: lets path-containment checks find the local folder a repository writes saved files through
/**
 * A repository that writes the files it saves under a local directory, its working tree, before it records them.
 *
 * <p>The files of that directory are written through the local file system, so a link inside it leads a write
 * wherever the link points. Callers use the directory to compare a path's real location with its lexical one.
 */
public interface LocalWorkingTree {

    /**
     * Returns the local directory the repository writes the files it saves under.
     *
     * @return the working tree, or {@code null} when the repository is not initialized
     */
    @Nullable Path getLocalWorkingTree();
}

package org.openl.studio.projects.service.files;

import java.io.IOException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import org.jspecify.annotations.Nullable;
import org.slf4j.LoggerFactory;

import org.openl.rules.project.abstraction.AProject;
import org.openl.rules.project.abstraction.AProjectFolder;
import org.openl.rules.project.abstraction.RulesProject;
import org.openl.rules.repository.PathCheckedRepository;
import org.openl.rules.repository.api.ChangesetType;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.api.RepositoryDelegate;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.workspace.dtr.FolderMapper;
import org.openl.studio.projects.model.files.FsNode;

/**
 * A mount the files service operates on — a project's working copy or a repository subtree.
 *
 * <p>Hides where the artefact tree comes from and how access to the mount is authorized, so the
 * same service can serve both the {@code /projects/{id}/files} and {@code /repos/{id}/files} mounts.
 * Per-artefact permissions are checked separately and uniformly by the service.
 *
 * @author Yury Molchan
 */
public interface FileRoot {

    /**
     * Artefact tree to read from. A blank version reads the current state; a non-blank version
     * reads that historical revision. An unknown revision is reported as not found.
     */
    AProjectFolder readFolder(String version);

    /**
     * Writable artefact tree for the current state. Mutations applied to it are committed to the mount.
     */
    AProjectFolder writeFolder();

    /**
     * Verifies the current user may read the mount.
     */
    void requireReadable();

    /**
     * Verifies the mount can be modified now and the current user may write to it.
     */
    void requireModifiable();

    /**
     * Finds files named like the trailing segment of {@code lookupPath} by walking up from the anchor
     * to the repository root, returning the match at each level nearest to the anchor first. The walk
     * goes up only — descendants and sibling branches are not visited — and is not limited to the
     * mount's project scope.
     */
    List<FsNode> searchAncestors(String lookupPath);

    /**
     * Writes the given files as one atomic changeset, using {@code comment} as the commit message.
     * Each item's name is the mount-relative path; existing files at those paths are overwritten.
     *
     * <p>A {@code DIFF} changeset adds and overwrites the listed files, leaving others intact.
     * A {@code FULL} changeset makes the base folder contain exactly the listed files: files under
     * it that are absent from the list are deleted.
     *
     * @param basePath      mount-relative folder the changeset applies to; empty for the mount root
     * @param items         the files to write, named by their mount-relative paths
     * @param changesetType how the changeset treats files absent from the list
     * @param comment       the commit message
     */
    void writeBatch(String basePath, List<FileItem> items, ChangesetType changesetType, String comment);

    // V1: path containment of a mount backed by a local directory; other mounts accept every path.
    /**
     * Tells whether the path stays inside the mount's boundary once it is resolved on disk.
     *
     * <p>The path is mount-relative, in the same form the service uses for {@link #readFolder(String)}
     * lookups and that {@code AProjectArtefact.getInternalPath()} reports for entries of the mount; an
     * empty path denotes the mount root. A mount backed by a local directory returns {@code false}
     * when the real location of the path leaves the mount's boundary, through a link or otherwise.
     * Other mounts (Git, JDBC, S3, Azure Blob) accept every path, because their content is not read
     * through filesystem links.
     *
     * <p>The check only adds rejections: callers run it after the existing lexical validation.
     *
     * @param path mount-relative path; empty for the mount root
     * @return {@code false} when the path resolves outside the mount's boundary
     */
    default boolean contains(String path) {
        return true;
    }

    // V1: the local directory behind a repository, the anchor the containment checks resolve against.
    /**
     * Local root directory of a file-backed repository, as its real location.
     *
     * <p>The repository is unwrapped the way the ancestor lookup unwraps it: through every
     * {@link RepositoryDelegate} (such as {@code SecureRepository} and {@code SecureBranchRepository}),
     * then through one {@link FolderMapper}. That covers {@code SecureMappedRepository}, which
     * extends {@code SecureBranchRepository} and implements {@code FolderMapper}, and whose
     * {@code getOriginal()} leads to a {@code MappedRepository} whose {@code getDelegate()} is the
     * file repository. A repository built from its settings is wrapped in a
     * {@link PathCheckedRepository}, which is not a delegate and reveals only the root of the file
     * repository it wraps, through {@link PathCheckedRepository#getLocalRoot()}; when the unwrapping
     * ends at that wrapper, its root is used. The {@code repo-file} design repository
     * ({@code org.openl.rules.repository.file.LocalRepository}) and the user's working copy
     * ({@code org.openl.rules.project.impl.local.LocalRepository}) both extend
     * {@link FileSystemRepository}.
     *
     * <p>The unwrapped instance is only asked for its root directory. Every read and write still goes
     * through the (secured) wrapper the caller holds, so no ACL check is bypassed.
     *
     * <p>The configured root is the anchor: links in its own path are trusted and followed, so the
     * real location is returned. The root is resolved before it is normalized, so a parent segment
     * after a link in it, as in {@code <link>/..}, leads where the repository reads. A root that does
     * not exist yet is resolved through its deepest existing ancestor.
     *
     * <p>The repository mount holds its repository inside {@link AuthoringRepository}, which is unwrapped
     * first, here only, through {@code AuthoringRepository.getDelegate()}. It is not a
     * {@link RepositoryDelegate}, so other code that unwraps delegates, such as the ancestor lookup, keeps
     * reading through it and through the secured wrapper behind it. For a mapped repository it wraps the
     * {@link PathCheckedRepository} that {@code SecureMappedRepository.getDelegate()} returns; for a flat
     * one it wraps {@code SecureBranchRepository}, whose {@code getOriginal()} is that
     * {@link PathCheckedRepository}. Both reach the root.
     *
     * <p>Any other backend yields empty, including a {@link PathCheckedRepository} over a backend that
     * is not file-backed, such as Git, also when it is reached through {@code AuthoringRepository}: Git
     * reads blobs from its object database, never through working-tree links.
     *
     * @param repo the repository as the caller holds it, possibly wrapped; may be {@code null}
     * @return the real root directory, or empty when the repository is not file-backed
     */
    static Optional<Path> localRoot(@Nullable Repository repo) { // V1: a null repository is not file-backed
        var current = repo;
        // V1: the repository mount's author-stamping wrapper; only the root of the repository it wraps is read
        if (current instanceof AuthoringRepository authoring) {
            current = authoring.getDelegate();
        }
        while (current instanceof RepositoryDelegate delegate) {
            current = delegate.getOriginal();
        }
        if (current instanceof FolderMapper mapper) {
            current = mapper.getDelegate();
        }
        // V1: a repository built from its settings is path-checked, and that wrapper reveals only a file root
        if (current instanceof PathCheckedRepository pathChecked) {
            return Optional.ofNullable(pathChecked.getLocalRoot()).map(FileRoot::realLocation);
        }
        if (current instanceof FileSystemRepository fileSystem && fileSystem.getRoot() != null) {
            return Optional.of(realLocation(fileSystem.getRoot()));
        }
        return Optional.empty();
    }

    // V1: the directory a project mount may touch, lexically under the real anchor.
    /**
     * Folder of the project inside its local anchor directory.
     *
     * <p>An opened {@link RulesProject} is served from the user's working copy, at its folder path.
     * A closed one is served from its design repository, at its repository-internal path, flat or
     * mapped. Any other project is served from its own repository, at its real path. The relative
     * path is read only once the anchor is known to be file-backed, so projects on other backends
     * never compute it.
     *
     * <p>The boundary is lexical under the real anchor, so a project folder that is itself a link
     * fails {@link #resolvesInside(Path, String) resolvesInside(boundary, "")}. The boundary applies
     * to the current state: historical reads of an opened project are checked against its working
     * copy, which fails closed only when that working-copy path is a link leaving the project.
     *
     * @param project the project the mount serves; may be {@code null}
     * @return the project folder, or empty when the project is not stored in a local directory
     */
    static Optional<Path> projectBoundary(@Nullable AProject project) { // V1: a null project has no boundary
        if (project == null) {
            return Optional.empty();
        }
        if (project instanceof RulesProject rulesProject) {
            if (rulesProject.isOpened()) {
                return localRoot(rulesProject.getRepository())
                        .map(anchor -> under(anchor, rulesProject.getFolderPath()));
            }
            return localRoot(rulesProject.getDesignRepository())
                    .map(anchor -> under(anchor, rulesProject.getRealPath()));
        }
        return localRoot(project.getRepository()).map(anchor -> under(anchor, project.getRealPath()));
    }

    // V1: real-path containment of a path under a boundary; links may not lead out of it.
    /**
     * Tells whether the input, resolved under the boundary, stays inside the boundary on disk.
     *
     * <p>The input is first resolved under the boundary and normalized, and a normalized target outside
     * the boundary is rejected: parent segments that leave it, or an absolute input elsewhere. An
     * absolute input that already lies inside the boundary passes this step, so the callers validate a
     * requested path lexically beforehand with {@link Repository#validatePath(String)}, which rejects
     * absolute and non-normalized paths. The deepest existing entry of the result, a dangling link
     * included, is then resolved to its real location and the part still to be created is appended to
     * it. That part contains no links, because only existing entries can be links. The result must lie
     * under the boundary.
     *
     * <p>The boundary itself is compared lexically, so a boundary that is itself a link, or that sits
     * under a link, is rejected. With an empty input the check therefore means that the boundary sits
     * at its own lexical place. Links that stay inside the boundary are accepted; links to a sibling
     * project or outside are not. A dangling link, a link loop or an unparsable input is rejected.
     *
     * @param boundary absolute, normalized directory the input may not leave
     * @param input    path relative to the boundary; {@code null} or empty for the boundary itself
     * @return {@code true} only when the real location of the input lies under the boundary
     */
    static boolean resolvesInside(Path boundary, @Nullable String input) {
        try {
            var target = input == null || input.isEmpty() ? boundary : boundary.resolve(input).normalize();
            if (!target.startsWith(boundary)) {
                return false;
            }
            return resolveThroughDeepestExisting(target).map(real -> real.startsWith(boundary)).orElse(false);
        } catch (IOException | IllegalArgumentException | SecurityException e) {
            // V1: an unparsable input, an unresolvable entry or a denied lookup fails closed; others propagate.
            debugFailure("Path rejected by the containment check", e);
            return false;
        }
    }

    // V1: the per-path check of the repository mount and the ancestor search; no link leads to the path.
    /**
     * Tells whether the path under the root sits at its own lexical place on disk: neither the entry
     * nor any directory between {@code root} and it is a link, even one that stays under the root.
     *
     * <p>Links in the root's own path are trusted, because the root is a real location. A path that
     * does not exist yet is accepted when its deepest existing ancestor sits at its own place. A path
     * that leaves the root lexically, or that cannot be resolved (a dangling link, a loop, an
     * unparsable name), does not. The lexical guard is defensive: callers validate the path first, but
     * {@link #resolvesInside(Path, String) resolvesInside(target, "")} alone would accept a lexically
     * escaping target that is not a link.
     *
     * @param root     real directory the path is read from or written to
     * @param relative slash-separated path relative to the root; empty for the root itself
     * @return {@code true} only when no link lies between the root and the path, the path included
     */
    static boolean atOwnPath(Path root, String relative) {
        Path target;
        try {
            target = root.resolve(FilePaths.trimSlashes(relative)).normalize();
        } catch (IllegalArgumentException e) {
            // V1: an unparsable path, such as one holding a NUL byte, fails closed.
            debugFailure("Path rejected as unparsable", e);
            return false;
        }
        return target.startsWith(root) && resolvesInside(target, "");
    }

    // V1: the anchor's real location; an unresolvable anchor stays lexical so later checks fail closed.
    /**
     * Real location of the path, resolved through its deepest existing ancestor before it is
     * normalized, so a parent segment after a link is taken from the link's target, as the file
     * system takes it. When nothing can be resolved, the absolute normalized path is returned, and the
     * containment checks against it then fail closed.
     */
    private static Path realLocation(Path path) {
        // V1: normalizing first would drop '<link>/..' lexically and anchor a tree the repository never reads
        var absolute = path.toAbsolutePath();
        try {
            return resolveThroughDeepestExisting(absolute).orElse(absolute).normalize();
        } catch (IOException | SecurityException e) {
            // V1: an unresolvable link or a denied lookup keeps the lexical location; others propagate.
            debugFailure("Real location not resolved, the lexical location is kept", e);
            return absolute.normalize();
        }
    }

    // V1: the walk shared by realLocation and resolvesInside.
    /**
     * Resolves the path through its deepest existing entry: the real location of that entry with the
     * rest of the path appended. An entry exists when it is present itself, so a dangling link is
     * found and then fails to resolve.
     *
     * @return the resolved path, or empty when no ancestor of the path exists
     * @throws IOException when the deepest existing entry cannot be resolved, such as a dangling link
     */
    private static Optional<Path> resolveThroughDeepestExisting(Path path) throws IOException {
        var existing = path;
        while (existing != null && !Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
            existing = existing.getParent();
        }
        if (existing == null) {
            return Optional.empty();
        }
        return Optional.of(existing.toRealPath().resolve(existing.relativize(path)));
    }

    // V1: a slash-separated relative path resolved lexically under an anchor.
    private static Path under(Path anchor, String relative) {
        return anchor.resolve(FilePaths.trimSlashes(relative)).normalize();
    }

    // V1: the trace of a containment step that failed closed.
    /**
     * Logs at DEBUG that a containment step failed closed, naming the exception class and, for a path
     * or filesystem failure, its reason. The message, the stack trace and the path are left out,
     * because they repeat the raw input.
     */
    private static void debugFailure(String event, Exception e) {
        var log = LoggerFactory.getLogger(FileRoot.class);
        if (log.isDebugEnabled()) {
            String reason = switch (e) {
                case InvalidPathException invalid -> invalid.getReason();
                case FileSystemException fileSystem -> fileSystem.getReason();
                default -> null;
            };
            log.debug("{}: {}{}", event, e.getClass().getName(), reason == null ? "" : " (" + reason + ")");
        }
    }
}

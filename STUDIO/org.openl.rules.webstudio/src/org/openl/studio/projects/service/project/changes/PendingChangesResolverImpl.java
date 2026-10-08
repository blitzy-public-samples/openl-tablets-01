package org.openl.studio.projects.service.project.changes;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import org.openl.rules.project.abstraction.RulesProject;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
import org.openl.studio.projects.model.project.status.ChangeType;
import org.openl.studio.projects.model.project.status.FileChange;
import org.openl.studio.projects.model.project.status.PendingChanges;
import org.openl.studio.projects.service.files.FileRoot;

/**
 * Diffs the local working copy against the design revision the project is opened on.
 *
 * <p>Two design-side shapes are supported:
 * <ul>
 *   <li>folder repos ({@code supports().folders()}): list per-file {@link FileData}
 *       entries and diff by {@code uniqueId} equality;</li>
 *   <li>zip-based repos (JDBC and friends): read the project archive via
 *       {@code readHistory} and diff by zip-entry path, using the local
 *       {@code FileData.uniqueId} (cleared on local edits) as the modified marker.</li>
 * </ul>
 *
 * @author Vladyslav Pikus
 */
@Service
@Slf4j
public class PendingChangesResolverImpl implements PendingChangesResolver {

    private static final Comparator<FileChange> CHANGE_ORDER = Comparator.comparing(FileChange::type)
            .thenComparing(FileChange::path, String.CASE_INSENSITIVE_ORDER);

    /**
     * Hard cap on the number of entries inspected when listing a zip-based design project,
     * defending against malformed/zip-bomb archives that contain absurd entry counts. Real
     * OpenL projects don't approach this number.
     */
    private static final int MAX_ZIP_ENTRIES = 10_000;

    @Override
    public PendingChanges resolve(RulesProject project) {
        if (!project.isModified()) {
            return null;
        }
        try {
            var changes = computeChanges(project);
            if (changes.isEmpty()) {
                return null;
            }
            return new PendingChanges(changes.size(), changes);
        } catch (IOException e) {
            log.warn("Failed to compute pending changes for project '{}'", project.getBusinessName(), e);
            return null;
        }
    }

    private List<FileChange> computeChanges(RulesProject project) throws IOException {
        // Use the project's internal (real) path as the path prefix so that the resulting file
        // paths are consistent with the merge API which also exposes files as
        // "<projectRealPath>/<fileWithinProject>" (see ProjectsMergeConflictsServiceImpl /
        // ConflictGroup).
        var projectPath = normalize(project.getRealPath());
        var localRepository = project.getLocalRepository();
        var localPrefix = project.getLocalFolderName() + "/";
        // V1: a working-copy link leading out of the project folder is not a project file, as in the Files tree
        var localFiles = contained(localRepository.list(localPrefix),
                localPrefix,
                localRepository,
                project.getLocalFolderName());

        if (project.isLocalOnly()) {
            // No design counterpart yet; every local file is a new addition.
            return localFiles.stream()
                    .map(fileData -> projectScopedPath(fileData.getName(), localPrefix, projectPath))
                    .filter(Objects::nonNull)
                    .map(path -> new FileChange(path, ChangeType.ADDED))
                    .sorted(CHANGE_ORDER)
                    .toList();
        }

        if (project.getDesignRepository().supports().folders()) {
            return diffWithFolderDesign(project, localFiles, localPrefix, projectPath);
        }
        return diffWithZipDesign(project, localFiles, localPrefix, projectPath);
    }

    private List<FileChange> diffWithFolderDesign(RulesProject project,
                                                  List<FileData> localFiles,
                                                  String localPrefix,
                                                  String projectPath) throws IOException {
        var designRepository = project.getDesignRepository();
        var designPrefix = project.getDesignFolderName() + "/";
        var historyVersion = project.getHistoryVersion();
        var designFiles = designRepository.supports().versions() && historyVersion != null
                ? designRepository.listFiles(designPrefix, historyVersion)
                : designRepository.list(designPrefix);
        // V1: a design link leading out of the project folder is not copied on open, so it is not reported deleted
        designFiles = contained(designFiles, designPrefix, designRepository, projectPath);

        var designByPath = indexByProjectScopedPath(designFiles, designPrefix, projectPath);
        var visitedDesign = new HashSet<String>();
        var result = new ArrayList<FileChange>();

        for (FileData local : localFiles) {
            var path = projectScopedPath(local.getName(), localPrefix, projectPath);
            if (path == null) {
                continue;
            }
            var design = designByPath.get(path);
            if (design == null) {
                result.add(new FileChange(path, ChangeType.ADDED));
            } else {
                visitedDesign.add(path);
                var localUniqueId = local.getUniqueId();
                if (localUniqueId == null || !localUniqueId.equals(design.getUniqueId())) {
                    result.add(new FileChange(path, ChangeType.MODIFIED));
                }
            }
        }

        designByPath.forEach((path, ignored) -> {
            if (!visitedDesign.contains(path)) {
                result.add(new FileChange(path, ChangeType.DELETED));
            }
        });

        return result.stream().sorted(CHANGE_ORDER).toList();
    }

    /**
     * Zip-based design repos store the whole project as one archive blob — there is no
     * per-file {@code FileData} on the design side. Compare local file paths against the
     * archive's entry list; for matched paths, treat a cleared local {@code uniqueId}
     * (the local repository clears it on every edit) as the {@code MODIFIED} marker.
     */
    private List<FileChange> diffWithZipDesign(RulesProject project,
                                               List<FileData> localFiles,
                                               String localPrefix,
                                               String projectPath) throws IOException {
        var designPaths = readZippedDesignEntryPaths(project, projectPath);
        var visitedDesign = new HashSet<String>();
        var result = new ArrayList<FileChange>();

        for (FileData local : localFiles) {
            var path = projectScopedPath(local.getName(), localPrefix, projectPath);
            if (path == null) {
                continue;
            }
            if (!designPaths.contains(path)) {
                result.add(new FileChange(path, ChangeType.ADDED));
            } else {
                visitedDesign.add(path);
                if (local.getUniqueId() == null) {
                    result.add(new FileChange(path, ChangeType.MODIFIED));
                }
            }
        }

        designPaths.stream()
                .filter(path -> !visitedDesign.contains(path))
                .forEach(path -> result.add(new FileChange(path, ChangeType.DELETED)));

        return result.stream().sorted(CHANGE_ORDER).toList();
    }

    private static Set<String> readZippedDesignEntryPaths(RulesProject project, String projectPath) throws IOException {
        var fileItem = openDesignSnapshot(project);
        if (fileItem == null) {
            return Set.of();
        }
        var result = new HashSet<String>();
        try (var stream = fileItem.getStream(); var zip = new ZipInputStream(stream)) {
            ZipEntry entry;
            var processed = 0;
            while ((entry = zip.getNextEntry()) != null) {
                if (++processed > MAX_ZIP_ENTRIES) {
                    log.warn("Aborting pending-changes diff for project '{}': design archive exceeds {} entries",
                            project.getBusinessName(), MAX_ZIP_ENTRIES);
                    return Set.of();
                }
                collectDesignEntry(entry, project, projectPath, result);
            }
        }
        return result;
    }

    private static FileItem openDesignSnapshot(RulesProject project) throws IOException {
        var designRepository = project.getDesignRepository();
        var folderPath = project.getDesignFolderName();
        var historyVersion = project.getHistoryVersion();
        return designRepository.supports().versions() && historyVersion != null
                ? designRepository.readHistory(folderPath, historyVersion)
                : designRepository.read(folderPath);
    }

    private static void collectDesignEntry(ZipEntry entry,
                                           RulesProject project,
                                           String projectPath,
                                           Set<String> result) {
        if (entry.isDirectory()) {
            return;
        }
        var relative = normalize(entry.getName());
        // Reject path-traversal / absolute names that would let an attacker
        // poison the comparison map (and protect any future caller that
        // resolves these paths against the local filesystem).
        if (relative.contains("../") || relative.startsWith("/")) {
            log.warn("Skipping suspicious zip entry '{}' in project '{}'",
                    entry.getName(), project.getBusinessName());
            return;
        }
        result.add(projectPath.isEmpty() ? relative : projectPath + "/" + relative);
    }

    private static Map<String, FileData> indexByProjectScopedPath(List<FileData> files,
                                                                  String prefix,
                                                                  String projectPath) {
        var index = new HashMap<String, FileData>();
        for (FileData file : files) {
            var path = projectScopedPath(file.getName(), prefix, projectPath);
            if (path != null) {
                index.put(path, file);
            }
        }
        return index;
    }

    private static String projectScopedPath(String fullName, String prefix, String projectPath) {
        if (fullName == null) {
            return null;
        }
        var normalized = normalize(fullName);
        if (!normalized.startsWith(prefix)) {
            return null;
        }
        var relative = normalized.substring(prefix.length());
        return projectPath.isEmpty() ? relative : projectPath + "/" + relative;
    }

    private static String normalize(String path) {
        return path == null ? "" : path.replace('\\', '/');
    }

    // V1: the entries a file-backed repository lists whose real location stays inside their project folder
    /**
     * Keeps the entries whose real location stays inside the project folder, when the repository is file-backed.
     *
     * <p>The project folder is the folder resolved lexically under the repository's real root, so a folder that is
     * itself a link keeps no entry. An entry is kept when its name lies under the prefix and its real location, links
     * inside the folder followed, stays inside the folder: a link to another project or outside, or to nothing, is
     * left out. A repository that is not file-backed, such as Git or JDBC, keeps every entry and is not touched on
     * disk.
     *
     * <p>The real locations are resolved once per listing, through {@link FileRoot#resolvesInside(Path, String, Map)}:
     * the project folder is resolved once, each entry below it is read once without following a link at its end, and
     * only links are resolved. The verdicts are those of {@link FileRoot#resolvesInside(Path, String)}.
     *
     * @param files      the entries the repository lists under the prefix
     * @param prefix     the folder path the entries are listed under, ending with a slash
     * @param repository the repository the entries are listed from, possibly wrapped
     * @param folder     the project folder relative to the repository root
     * @return the entries that stay inside the project folder
     */
    private static List<FileData> contained(List<FileData> files, String prefix, Repository repository, String folder) {
        var anchor = FileRoot.localRoot(repository);
        if (anchor.isEmpty()) {
            return files;
        }
        Path boundary;
        try {
            boundary = anchor.get().resolve(folder.replaceAll("^/+|/+$", "")).normalize();
        } catch (IllegalArgumentException e) {
            // V1: a folder that is not a valid path keeps no entry
            return List.of();
        }
        if (!boundary.startsWith(anchor.get())) {
            return List.of();
        }
        // V1: the checks of one listing share the real locations they resolve, so each entry costs one read
        var realLocations = new HashMap<Path, Path>();
        return files.stream().filter(file -> {
            var name = normalize(file.getName());
            return name.startsWith(prefix)
                    && FileRoot.resolvesInside(boundary, name.substring(prefix.length()), realLocations);
        }).toList();
    }
}

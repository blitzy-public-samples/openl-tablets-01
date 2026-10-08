package org.openl.studio.projects.service.files;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.InvalidPathException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.RequiredArgsConstructor;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.AntPathMatcher;

import org.openl.rules.common.ProjectException;
import org.openl.rules.project.abstraction.AProjectArtefact;
import org.openl.rules.project.abstraction.AProjectFolder;
import org.openl.rules.project.abstraction.AProjectResource;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.rest.acl.service.AclProjectsHelper;
import org.openl.studio.common.exception.BadRequestException;
import org.openl.studio.projects.model.files.FsNode;
import org.openl.util.FileUtils;
import org.openl.util.StringUtils;

/**
 * Searches a mount for files and folders.
 *
 * <p>{@code SUBTREE} scope walks the mount tree and matches each entry by path pattern, extension,
 * type and a case-insensitive content substring. {@code ANCESTORS} scope walks up from the anchor
 * path to the repository root, returning the same-named file at each level — not limited to the
 * project — nearest first, each with its content.
 *
 * @author Yury Molchan
 */
@Component
@RequiredArgsConstructor
class FileSearchSupport {

    private static final long MAX_CONTENT_SEARCH_BYTES = 1024L * 1024L;

    private final AclProjectsHelper aclProjectsHelper;
    private final FileNodeMapper resourceMapper;
    // V1: the READ checks of one subtree search share one read-only transaction instead of opening one per entry.
    private final PlatformTransactionManager transactionManager;

    // V1: a subtree search runs in three phases, so its READ checks cost one transaction and precede every read.
    /**
     * Searches the mount.
     *
     * <p>{@code ANCESTORS} scope validates its lookup path and delegates to {@link FileRoot#searchAncestors(String)}.
     * {@code SUBTREE} scope runs in three phases. First, the walk keeps, in walk order, the entries that pass the
     * in-memory criteria and containment on disk, and reads nothing. Second, one read-only transaction decides
     * {@code READ} for each of them, so every ACL check joins it instead of opening its own. Third, outside that
     * transaction, the content of the readable entries alone is read when the query names content. So the content
     * of an entry the user may not read is never opened.
     *
     * @return the matching entries, folders first, then by name
     */
    List<FsNode> search(FileRoot root, FileSearchQuery query) {
        root.requireReadable();
        if (query.scope() == FileSearchQuery.Scope.ANCESTORS) {
            return searchAncestors(root, query);
        }
        var extensions = query.extensions().stream()
                .map(String::toLowerCase)
                .collect(Collectors.toSet());
        String pattern = StringUtils.isBlank(query.pattern()) ? null : query.pattern();
        AntPathMatcher matcher = pattern == null ? null : new AntPathMatcher();
        String contentNeedle = StringUtils.isBlank(query.content()) ? null : query.content().toLowerCase();

        // V1: the walk only collects the candidates, in walk order; no ACL check or content read runs yet.
        var candidates = new ArrayList<AProjectArtefact>();
        var queue = new ArrayDeque<AProjectFolder>();
        queue.add(root.readFolder(query.version()));
        while (!queue.isEmpty()) {
            var folder = queue.poll();
            for (AProjectArtefact artefact : folder.getArtefacts()) {
                // V1: an entry a link places outside the mount is not matched, read or descended into.
                // A folder the walk descends into is checked here; any other entry once its cheap criteria pass.
                boolean descend = query.recursive() && artefact.isFolder();
                if (descend && !root.contains(artefact.getInternalPath())) {
                    continue;
                }
                if (matchesSearch(artefact, query, pattern, matcher, extensions, root, !descend)) {
                    candidates.add(artefact);
                }
                if (descend) {
                    queue.add((AProjectFolder) artefact);
                }
            }
        }
        // V1: READ for all candidates in one transaction, then the content of the readable ones only, outside it.
        var result = new ArrayList<FsNode>();
        for (AProjectArtefact artefact : readableOf(candidates)) {
            if (contentNeedle == null || containsText(artefact, contentNeedle)) {
                result.add(resourceMapper.map(artefact));
            }
        }
        result.sort(FileNodeMapper.NODE_COMPARATOR);
        return result;
    }

    // V1: containment on disk runs after the in-memory criteria; the ACL and the content read follow after the walk.
    /**
     * Tests one artefact against the criteria of the walk. The in-memory criteria (type, extension,
     * pattern) run first, then containment on disk. The ACL and the content are not consulted here:
     * {@link #search} decides {@code READ} for the candidates this keeps, and then reads the content
     * of the readable ones only, so the content of an entry the user may not read is never opened.
     *
     * @param root             the mount the artefact belongs to
     * @param checkContainment whether the artefact still has to be checked with
     *                         {@link FileRoot#contains(String)}; a folder the search descends into
     *                         has been checked already
     */
    private boolean matchesSearch(AProjectArtefact artefact,
                                  FileSearchQuery query,
                                  String pattern,
                                  AntPathMatcher matcher,
                                  Set<String> extensions,
                                  FileRoot root,
                                  boolean checkContainment) {
        if (query.type() == FileSearchQuery.FileType.FILE && artefact.isFolder()) {
            return false;
        }
        if (query.type() == FileSearchQuery.FileType.FOLDER && !artefact.isFolder()) {
            return false;
        }
        if (!extensions.isEmpty() && !hasExtension(artefact, extensions)) {
            return false;
        }
        if (matcher != null && !matcher.match(pattern, artefact.getInternalPath())) {
            return false;
        }
        // V1: an entry a link places outside the mount is neither matched nor read.
        return !checkContainment || root.contains(artefact.getInternalPath());
    }

    // V1: READ runs before the content read, so a mount that checks no ACL itself never opens a denied file.
    /**
     * Keeps the candidates the user may read, in their order. One read-only transaction with the
     * default propagation decides {@code READ} for all of them, so each transactional ACL check joins
     * it instead of opening its own, and the connection it holds is released before any content is
     * read. Without candidates no transaction is opened. A failing check rolls the transaction back
     * and propagates.
     */
    private List<AProjectArtefact> readableOf(List<AProjectArtefact> candidates) {
        if (candidates.isEmpty()) {
            return candidates;
        }
        var readOnly = new TransactionTemplate(transactionManager);
        readOnly.setReadOnly(true);
        return readOnly.execute(status -> candidates.stream()
                .filter(artefact -> aclProjectsHelper.hasPermission(artefact, BasePermission.READ))
                .toList());
    }

    /** Whether the artefact is a file with one of the extensions. */
    private static boolean hasExtension(AProjectArtefact artefact, Set<String> extensions) {
        if (artefact.isFolder()) {
            return false;
        }
        String ext = FileUtils.getExtension(artefact.getName());
        return ext != null && extensions.contains(ext.toLowerCase());
    }

    /** Whether the artefact is a file whose text contains the needle, ignoring case. */
    private static boolean containsText(AProjectArtefact artefact, String contentNeedle) {
        if (artefact.isFolder()) {
            return false;
        }
        String text = readBoundedText((AProjectResource) artefact);
        return text != null && text.toLowerCase().contains(contentNeedle);
    }

    /**
     * Reads UTF-8 text from a file while keeping memory use bounded. Files larger than the limit
     * (or unreadable) yield {@code null} so they are treated as a content non-match.
     */
    private static String readBoundedText(AProjectResource resource) {
        try (var in = resource.getContent()) {
            if (in == null) {
                return null;
            }
            var data = in.readNBytes((int) MAX_CONTENT_SEARCH_BYTES + 1);
            if (data.length > MAX_CONTENT_SEARCH_BYTES) {
                return null;
            }
            return new String(data, StandardCharsets.UTF_8);
        } catch (ProjectException | IOException e) {
            return null;
        }
    }

    private static List<FsNode> searchAncestors(FileRoot root, FileSearchQuery query) {
        String leaf = StringUtils.isBlank(query.pattern()) ? "" : query.pattern();
        String lookupPath = StringUtils.isBlank(query.from()) ? leaf : query.from() + "/" + leaf;
        if (lookupPath.isEmpty()) {
            return List.of();
        }
        // Reject absolute paths and parent traversal before they are anchored to a mount path.
        try {
            Repository.validatePath(lookupPath);
        } catch (InvalidPathException e) {
            throw new BadRequestException("file.path.invalid.message");
        }
        return root.searchAncestors(lookupPath);
    }
}

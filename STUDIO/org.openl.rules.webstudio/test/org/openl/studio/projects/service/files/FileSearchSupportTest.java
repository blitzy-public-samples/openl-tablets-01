package org.openl.studio.projects.service.files;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.model.Permission;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;

import org.openl.rules.common.ProjectException;
import org.openl.rules.project.abstraction.AProjectArtefact;
import org.openl.rules.project.abstraction.AProjectFolder;
import org.openl.rules.project.abstraction.AProjectResource;
import org.openl.rules.rest.acl.service.AclProjectsHelper;
import org.openl.studio.projects.model.files.FileNode;
import org.openl.studio.projects.model.files.FsNode;

/**
 * Verifies how a subtree search orders its storage work: the walk applies the in-memory criteria and containment and
 * reads nothing, one read-only transaction then decides {@code READ} for every candidate, and the content of the
 * readable candidates alone is read after that transaction ends.
 *
 * <p>The mount is a mocked {@link FileRoot} over mocked artefacts. Every transaction boundary, permission check and
 * content read is appended to one event log, so each test asserts their exact sequence.
 */
class FileSearchSupportTest {

    private static final String NEEDLE = "needle-token";

    /** The transaction boundaries, permission checks and content reads, in the order they happen. */
    private final List<String> events = new ArrayList<>();
    /** The permission checks that fail, by the path of the artefact they check. */
    private final Map<String, RuntimeException> failures = new HashMap<>();
    /** The paths of the artefacts the user may not read. */
    private final Set<String> denied = new HashSet<>();
    private final AclProjectsHelper acl = mock(AclProjectsHelper.class);
    private final RecordingTransactionManager transactions = new RecordingTransactionManager();
    private final FileSearchSupport searchSupport = new FileSearchSupport(acl, new FileNodeMapperImpl(), transactions);
    private final FileRoot root = mock(FileRoot.class);

    @BeforeEach
    void setUp() {
        when(acl.hasPermission(any(AProjectArtefact.class), any())).thenAnswer(invocation -> {
            AProjectArtefact artefact = invocation.getArgument(0);
            Permission permission = invocation.getArgument(1);
            var path = artefact.getInternalPath();
            var kind = BasePermission.READ.equals(permission) ? "READ " : "mask " + permission.getMask() + " ";
            events.add(kind + path);
            var failure = failures.get(path);
            if (failure != null) {
                throw failure;
            }
            return !denied.contains(path);
        });
        when(root.contains(anyString())).thenReturn(true);
    }

    // V1: one read-only transaction holds every READ check of a content search, and no content is read inside it.
    @Test
    void contentSearchDecidesReadForEveryCandidateInOneReadOnlyTransactionAndReadsAfterIt() throws ProjectException {
        mount(tree());
        denied.add("docs/d.txt");

        var found = search(FileSearchQuery.builder().content(NEEDLE).recursive(true).build());

        assertEquals(List.of("a.txt", "docs/c.txt"), paths(found),
                "The content search finds, ignoring case, the readable files holding the needle");
        assertEquals(List.of("begin", "READ a.txt", "READ b.txt", "READ docs", "READ docs/c.txt", "READ docs/d.txt",
                "commit", "read a.txt", "read b.txt", "read docs/c.txt"), events,
                "Every candidate is checked in walk order inside one transaction, and only the readable files are "
                        + "read, after it ends");
        assertEquals(1, transactions.begun.size(), "The search begins one transaction");
        var definition = transactions.begun.getFirst();
        assertTrue(definition.isReadOnly(), "The transaction is read-only");
        assertEquals(TransactionDefinition.PROPAGATION_REQUIRED, definition.getPropagationBehavior(),
                "The transaction has the default propagation, so each transactional ACL check joins it");
    }

    // V1: a search without content checks READ in one transaction and opens no file.
    @Test
    void searchWithoutContentChecksReadInOneTransactionAndReadsNothing() throws ProjectException {
        mount(tree());
        denied.add("docs/d.txt");

        var found = search(FileSearchQuery.builder().type(FileSearchQuery.FileType.FILE).recursive(true).build());

        assertEquals(List.of("a.txt", "b.txt", "docs/c.txt"), paths(found),
                "The search by type finds the readable files");
        assertEquals(List.of("begin", "READ a.txt", "READ b.txt", "READ docs/c.txt", "READ docs/d.txt", "commit"),
                events, "The files the type keeps are checked inside one transaction, and no content is read");
    }

    // V1: a search whose criteria or containment keep no candidate opens no transaction and checks no permission.
    @Test
    void searchWithoutCandidatesOpensNoTransaction() throws ProjectException {
        mount(tree());
        var queries = Map.of(
                "by an extension no file has",
                FileSearchQuery.builder().extension("csv").content(NEEDLE).recursive(true).build(),
                "by a pattern no entry matches",
                FileSearchQuery.builder().pattern("nothing/**").content(NEEDLE).recursive(true).build());
        for (var query : queries.entrySet()) {
            assertEquals(List.of(), search(query.getValue()), "The search " + query.getKey() + " finds nothing");
        }
        when(root.contains(anyString())).thenReturn(false);
        assertEquals(List.of(), search(FileSearchQuery.builder().content(NEEDLE).recursive(true).build()),
                "The search of a mount that contains none of its entries finds nothing");
        mount(folder(""));
        assertEquals(List.of(), search(FileSearchQuery.builder().content(NEEDLE).recursive(true).build()),
                "The search of an empty mount finds nothing");

        assertEquals(List.of(), events, "No search begins a transaction, checks a permission or reads content");
        verifyNoInteractions(acl);
    }

    // V1: a failing READ check rolls the transaction back and propagates before any content is read.
    @Test
    void failingReadCheckRollsTheTransactionBackAndPropagates() throws ProjectException {
        mount(tree());
        var failure = new IllegalStateException("The ACL lookup failed");
        failures.put("b.txt", failure);

        var thrown = assertThrows(IllegalStateException.class,
                () -> search(FileSearchQuery.builder().content(NEEDLE).recursive(true).build()));

        assertSame(failure, thrown, "The failure of the check propagates as it is");
        assertEquals(List.of("begin", "READ a.txt", "READ b.txt", "rollback"), events,
                "The transaction is rolled back at the failing check, and no content is read");
    }

    // V1: an ancestor search returns what the mount finds and opens no transaction.
    @Test
    void ancestorSearchOpensNoTransaction() {
        List<FsNode> nodes = List.of(FileNode.builder().path("sub/AGENTS.md").name("AGENTS.md").build());
        when(root.searchAncestors("sub/AGENTS.md")).thenReturn(nodes);

        var found = search(FileSearchQuery.builder()
                .scope(FileSearchQuery.Scope.ANCESTORS)
                .pattern("AGENTS.md")
                .from("sub")
                .build());

        assertSame(nodes, found, "The ancestor search returns what the mount finds");
        assertEquals(List.of(), events, "The ancestor search begins no transaction and checks no permission");
        verifyNoInteractions(acl);
    }

    /** Serves the folder as the current state of the mount; it is built before the stubbing starts. */
    private void mount(AProjectFolder top) {
        when(root.readFolder(null)).thenReturn(top);
    }

    private List<FsNode> search(FileSearchQuery query) {
        return searchSupport.search(root, query);
    }

    /**
     * The mount tree: {@code a.txt} holds the needle in upper case, {@code b.txt} does not hold it, and the folder
     * {@code docs} holds {@code c.txt} and {@code d.txt}, which both hold it.
     */
    private AProjectFolder tree() throws ProjectException {
        return folder("",
                file("a.txt", "x " + NEEDLE.toUpperCase() + " y"),
                file("b.txt", "nothing to find"),
                folder("docs", file("docs/c.txt", NEEDLE), file("docs/d.txt", NEEDLE)));
    }

    private static AProjectFolder folder(String path, AProjectArtefact... children) {
        var folder = mock(AProjectFolder.class);
        when(folder.isFolder()).thenReturn(true);
        when(folder.getInternalPath()).thenReturn(path);
        when(folder.getName()).thenReturn(path.substring(path.lastIndexOf('/') + 1));
        when(folder.getArtefacts()).thenReturn(List.of(children));
        return folder;
    }

    /** A file whose content read is appended to the event log. */
    private AProjectResource file(String path, String content) throws ProjectException {
        var file = mock(AProjectResource.class);
        when(file.getInternalPath()).thenReturn(path);
        when(file.getName()).thenReturn(path.substring(path.lastIndexOf('/') + 1));
        when(file.getContent()).thenAnswer(invocation -> {
            events.add("read " + path);
            return new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
        });
        return file;
    }

    private static List<String> paths(List<FsNode> nodes) {
        return nodes.stream().map(FsNode::getPath).toList();
    }

    /** Appends each transaction it begins, commits or rolls back to the event log, and keeps each definition. */
    private final class RecordingTransactionManager implements PlatformTransactionManager {

        private final List<TransactionDefinition> begun = new ArrayList<>();

        @Override
        public TransactionStatus getTransaction(TransactionDefinition definition) {
            begun.add(definition);
            events.add("begin");
            return new SimpleTransactionStatus();
        }

        @Override
        public void commit(TransactionStatus status) {
            events.add("commit");
        }

        @Override
        public void rollback(TransactionStatus status) {
            events.add("rollback");
        }
    }
}

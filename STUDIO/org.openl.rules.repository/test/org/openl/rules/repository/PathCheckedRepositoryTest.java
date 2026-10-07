package org.openl.rules.repository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.InputStream;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import org.openl.rules.repository.api.BranchRepository;
import org.openl.rules.repository.api.BranchStatus;
import org.openl.rules.repository.api.BranchTreeRevision;
import org.openl.rules.repository.api.ChangesetType;
import org.openl.rules.repository.api.ConflictResolveData;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Listener;
import org.openl.rules.repository.api.Pageable;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.repository.file.FileSystemRepository;

class PathCheckedRepositoryTest {

    @Test
    void keepsBranchViewsPathChecked() throws Exception {
        var delegate = mock(BranchRepository.class);
        var target = mock(BranchRepository.class);
        when(delegate.isValidBranchName(anyString())).thenReturn(true);
        when(delegate.forBranch("feature")).thenReturn(target);
        var repository = new PathCheckedRepository(delegate);

        var branchView = repository.forBranch("feature");

        assertInstanceOf(PathCheckedRepository.class, branchView);
        assertThrows(InvalidPathException.class, () -> branchView.list("../outside"));
        verify(target, never()).list(anyString());
    }

    // V1: path-containment checks locate a file repository's root behind this wrapper, and nothing else
    @Test
    void revealsTheRootOfAWrappedFileRepository(@TempDir Path root) {
        var files = new FileSystemRepository();
        files.setRoot(root);

        assertEquals(root, new PathCheckedRepository(files).getLocalRoot());
    }

    @Test
    void revealsNoRootForOtherBackends() {
        var delegate = mock(BranchRepository.class);

        assertNull(new PathCheckedRepository(delegate).getLocalRoot());
        verifyNoInteractions(delegate);
    }

    // V1: the archive upload check locates the working tree a Git repository writes through, and nothing else
    @Test
    void revealsTheWorkingTreeOfAWrappedLocalWorkingTree(@TempDir Path workingTree) {
        var delegate = mock(BranchRepository.class, withSettings().extraInterfaces(LocalWorkingTree.class));
        when(((LocalWorkingTree) delegate).getLocalWorkingTree()).thenReturn(workingTree);

        assertEquals(workingTree, new PathCheckedRepository(delegate).getLocalWorkingTree());
    }

    @Test
    void revealsNoWorkingTreeForOtherBackends() {
        var delegate = mock(BranchRepository.class);

        assertNull(new PathCheckedRepository(delegate).getLocalWorkingTree());
        verifyNoInteractions(delegate);
    }

    // V1: every Repository call this wrapper forwards is path- or branch-checked first, and forwarded unchanged
    /** One call on a repository, with every argument fixed when the call is built. */
    @FunctionalInterface
    interface Call {
        @Nullable Object on(BranchRepository repository) throws Exception;
    }

    /** Builds the call of one method around the path or branch name that the wrapper checks. */
    @FunctionalInterface
    interface CheckedCall {
        Call with(String checked);
    }

    static Stream<Arguments> pathCalls() {
        return Stream.of(
                checked("list(String)",
                        path -> repository -> repository.list(path),
                        List.of(fileData("project/rules.xlsx"))),
                checked("check(String)", path -> repository -> repository.check(path), fileData("project/rules.xlsx")),
                checked("read(String)", path -> repository -> repository.read(path), fileItem("project/rules.xlsx")),
                checked("save(FileData, InputStream)", path -> {
                    var data = fileData(path);
                    var stream = InputStream.nullInputStream();
                    return repository -> repository.save(data, stream);
                }, fileData("project/rules.xlsx")),
                checked("save(List<FileItem>)", path -> {
                    var items = List.of(fileItem("project/main.xlsx"), fileItem(path));
                    return repository -> repository.save(items);
                }, List.of(fileData("project/main.xlsx"), fileData("project/rules.xlsx"))),
                checked("delete(FileData)", path -> {
                    var data = fileData(path);
                    return repository -> repository.delete(data);
                }, true),
                checked("delete(List<FileData>)", path -> {
                    var data = List.of(fileData("project/main.xlsx"), fileData(path));
                    return repository -> repository.delete(data);
                }, true),
                checked("listHistory(String)",
                        path -> repository -> repository.listHistory(path),
                        List.of(fileData("project/rules.xlsx"))),
                checked("checkHistory(String, String)",
                        path -> repository -> repository.checkHistory(path, "v1"),
                        fileData("project/rules.xlsx")),
                checked("readHistory(String, String)",
                        path -> repository -> repository.readHistory(path, "v1"),
                        fileItem("project/rules.xlsx")),
                checked("deleteHistory(FileData)", path -> {
                    var data = fileData(path);
                    return repository -> repository.deleteHistory(data);
                }, true),
                checked("copyHistory(String, FileData, String), source", path -> {
                    var destination = fileData("project/copy.xlsx");
                    return repository -> repository.copyHistory(path, destination, "v1");
                }, fileData("project/copy.xlsx")),
                checked("copyHistory(String, FileData, String), destination", path -> {
                    var destination = fileData(path);
                    return repository -> repository.copyHistory("project/original.xlsx", destination, "v1");
                }, fileData("project/rules.xlsx")),
                checked("listFolders(String)",
                        path -> repository -> repository.listFolders(path),
                        List.of(fileData("project/folder"))),
                checked("listFiles(String, String)",
                        path -> repository -> repository.listFiles(path, "v1"),
                        List.of(fileData("project/rules.xlsx"))),
                checked("save(FileData, Iterable<FileItem>, ChangesetType)", path -> {
                    var folder = fileData(path);
                    Iterable<FileItem> files = List.of(fileItem("project/main.xlsx"));
                    return repository -> repository.save(folder, files, ChangesetType.DIFF);
                }, fileData("project/rules.xlsx")));
    }

    static Stream<Arguments> branchCalls() {
        return Stream.of(
                checked("createRepositoryBranch(String, String)", branch -> repository -> {
                    repository.createRepositoryBranch(branch, "main");
                    return null;
                }, null),
                checked("deleteRepositoryBranch(String)", branch -> repository -> {
                    repository.deleteRepositoryBranch(branch);
                    return null;
                }, null),
                checked("getBranchTreeRevisions(Collection<String>, String)", branch -> {
                    var branches = List.of(branch);
                    return repository -> repository.getBranchTreeRevisions(branches, "project");
                }, Map.of("feature", new BranchTreeRevision("abc", "def"))),
                checked("branchExists(String)", branch -> repository -> repository.branchExists(branch), true),
                checked("merge(String, UserInfo, ConflictResolveData)", branch -> {
                    var author = new UserInfo("author");
                    var resolved = new ConflictResolveData("abc", List.of(), "Merge feature");
                    return repository -> {
                        repository.merge(branch, author, resolved);
                        return null;
                    };
                }, null));
    }

    static Stream<Arguments> uncheckedCalls() {
        var listener = mock(Listener.class);
        var author = new UserInfo("author");
        var branches = List.of("main");
        return Stream.of(
                unchecked("getId()", BranchRepository::getId, "design"),
                unchecked("getName()", BranchRepository::getName, "Design"),
                unchecked("setListener(Listener)", repository -> {
                    repository.setListener(listener);
                    return null;
                }, null),
                unchecked("supports()",
                        BranchRepository::supports,
                        new FeaturesBuilder(mock(BranchRepository.class)).build()),
                unchecked("close()", repository -> {
                    repository.close();
                    return null;
                }, null),
                unchecked("validateConnection()", repository -> {
                    repository.validateConnection();
                    return null;
                }, null),
                unchecked("isMergedInto(String, String)",
                        repository -> repository.isMergedInto("feature", "main"),
                        true),
                unchecked("getBranch()", BranchRepository::getBranch, "main"),
                unchecked("isBranchProtected(String)", repository -> repository.isBranchProtected("main"), true),
                unchecked("listBranches()", BranchRepository::listBranches, List.of("main", "feature")),
                unchecked("getBranchStatuses(Collection<String>)",
                        repository -> repository.getBranchStatuses(branches),
                        Map.of("main", new BranchStatus(author, Instant.EPOCH, "Initial commit", "abc", false))),
                unchecked("isValidBranchName(String)", repository -> repository.isValidBranchName("feature"), true),
                unchecked("getBaseBranch()", BranchRepository::getBaseBranch, "main"),
                unchecked("pull(UserInfo)", repository -> {
                    repository.pull(author);
                    return null;
                }, null),
                unchecked("listHistory(String, String, boolean, Pageable)",
                        repository -> repository.listHistory("project/rules.xlsx", "rules", true, Pageable.unpaged()),
                        List.of(fileData("project/rules.xlsx"))));
    }

    @ParameterizedTest
    @MethodSource("pathCalls")
    void forwardsAValidPathUnchanged(CheckedCall call, @Nullable Object result) throws Exception {
        var delegate = mock(BranchRepository.class);
        var valid = call.with("project/rules.xlsx");
        valid.on(doAnswer(invocation -> result).when(delegate));

        assertSame(result, valid.on(new PathCheckedRepository(delegate)));
        valid.on(verify(delegate));
        verifyNoMoreInteractions(delegate);
    }

    @ParameterizedTest
    @MethodSource("pathCalls")
    void rejectsATraversalPathBeforeTheDelegate(CheckedCall call, @Nullable Object result) throws Exception {
        var delegate = mock(BranchRepository.class);
        var traversal = call.with("../outside");
        traversal.on(doAnswer(invocation -> result).when(delegate));
        var repository = new PathCheckedRepository(delegate);

        assertThrows(InvalidPathException.class, () -> traversal.on(repository));
        verifyNoInteractions(delegate);
    }

    @ParameterizedTest
    @MethodSource("branchCalls")
    void forwardsAValidBranchUnchanged(CheckedCall call, @Nullable Object result) throws Exception {
        var delegate = mock(BranchRepository.class);
        when(delegate.isValidBranchName("feature")).thenReturn(true);
        var valid = call.with("feature");
        valid.on(doAnswer(invocation -> result).when(delegate));

        assertSame(result, valid.on(new PathCheckedRepository(delegate)));
        verify(delegate).isValidBranchName("feature");
        valid.on(verify(delegate));
        verifyNoMoreInteractions(delegate);
    }

    @ParameterizedTest
    @MethodSource("branchCalls")
    void rejectsAnInvalidBranchBeforeTheDelegate(CheckedCall call, @Nullable Object result) throws Exception {
        var delegate = mock(BranchRepository.class);
        when(delegate.isValidBranchName("bad..name")).thenReturn(false);
        var invalid = call.with("bad..name");
        invalid.on(doAnswer(invocation -> result).when(delegate));
        var repository = new PathCheckedRepository(delegate);

        assertThrowsExactly(IllegalArgumentException.class, () -> invalid.on(repository));
        verify(delegate).isValidBranchName("bad..name");
        verifyNoMoreInteractions(delegate);
    }

    @Test
    void forwardsTheCallsOfABranchViewToTheDelegatesBranchView() throws Exception {
        var delegate = mock(BranchRepository.class);
        var target = mock(BranchRepository.class);
        var files = List.of(fileData("project/rules.xlsx"));
        when(delegate.isValidBranchName("feature")).thenReturn(true);
        when(delegate.forBranch("feature")).thenReturn(target);
        when(target.list("project")).thenReturn(files);

        assertSame(files, new PathCheckedRepository(delegate).forBranch("feature").list("project"));
    }

    @Test
    void rejectsABranchViewOfAnInvalidBranch() throws Exception {
        var delegate = mock(BranchRepository.class);
        var repository = new PathCheckedRepository(delegate);

        assertThrowsExactly(IllegalArgumentException.class, () -> repository.forBranch("bad..name"));
        verify(delegate).isValidBranchName("bad..name");
        verifyNoMoreInteractions(delegate);
    }

    @Test
    void checksEveryBranchOfABranchTreeRevisionsRequest() throws Exception {
        var delegate = mock(BranchRepository.class);
        when(delegate.isValidBranchName("main")).thenReturn(true);
        var repository = new PathCheckedRepository(delegate);

        assertThrowsExactly(IllegalArgumentException.class,
                () -> repository.getBranchTreeRevisions(List.of("main", "bad..name"), "project"));
        verify(delegate).isValidBranchName("main");
        verify(delegate).isValidBranchName("bad..name");
        verifyNoMoreInteractions(delegate);
    }

    @Test
    void rejectsATraversalPathOfABranchTreeRevisionsRequest() throws Exception {
        var delegate = mock(BranchRepository.class);
        when(delegate.isValidBranchName(anyString())).thenReturn(true);
        var repository = new PathCheckedRepository(delegate);

        assertThrows(InvalidPathException.class,
                () -> repository.getBranchTreeRevisions(List.of("main", "feature"), "../outside"));
        verify(delegate, never()).getBranchTreeRevisions(anyCollection(), anyString());
    }

    @ParameterizedTest
    @MethodSource("uncheckedCalls")
    void forwardsACallWithoutPathOrBranchUnchanged(Call call, @Nullable Object result) throws Exception {
        var delegate = mock(BranchRepository.class);
        call.on(doAnswer(invocation -> result).when(delegate));

        assertSame(result, call.on(new PathCheckedRepository(delegate)));
        call.on(verify(delegate));
        verifyNoMoreInteractions(delegate);
    }

    private static Arguments checked(String method, CheckedCall call, @Nullable Object result) {
        return arguments(named(method, call), result);
    }

    private static Arguments unchecked(String method, Call call, @Nullable Object result) {
        return arguments(named(method, call), result);
    }

    private static FileData fileData(String name) {
        var data = new FileData();
        data.setName(name);
        return data;
    }

    private static FileItem fileItem(String name) {
        return new FileItem(name, InputStream.nullInputStream());
    }
}

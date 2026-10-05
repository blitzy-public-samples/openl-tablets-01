package org.openl.rules.repository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.openl.rules.repository.api.BranchRepository;
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
}

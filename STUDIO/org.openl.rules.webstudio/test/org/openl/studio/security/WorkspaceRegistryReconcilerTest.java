package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;

import org.openl.rules.workspace.lw.LocalWorkspaceManager;

/**
 * Unit tests for {@link WorkspaceRegistryReconciler}.
 *
 * @author Yury Molchan
 */
@ExtendWith(MockitoExtension.class)
class WorkspaceRegistryReconcilerTest {

    @Mock
    private LocalWorkspaceManager localWorkspaceManager;

    @Test
    void reconcilesTheWorkspaceRegistryOnInteractiveSignIn() {
        fireSignIn("jdoe");

        // The reconciliation runs in the background, so the call is awaited.
        verify(localWorkspaceManager, timeout(5_000)).refreshMetainfoRegistry("jdoe");
    }

    @Test
    void signInDoesNotFailWhenReconciliationFails() {
        doThrow(new IllegalStateException("The disk is broken")).when(localWorkspaceManager)
                .refreshMetainfoRegistry("jdoe");

        assertDoesNotThrow(() -> fireSignIn("jdoe"));
        verify(localWorkspaceManager, timeout(5_000)).refreshMetainfoRegistry("jdoe");
    }

    // V1: the workspace folder of "o'brien" is named "o(27)brien", the encoded user id
    @Test
    void reconcilesTheWorkspaceFolderNamedByTheEncodedUserId() {
        fireSignIn("o'brien");

        verify(localWorkspaceManager, timeout(5_000)).refreshMetainfoRegistry("o(27)brien");
        verify(localWorkspaceManager, never()).refreshMetainfoRegistry("o'brien");
    }

    // V1: a raw name equal to the encoded id of "o'brien" is encoded too, so it never reaches that user's folder
    @Test
    void doesNotReconcileTheWorkspaceOfTheUserWhoseEncodedIdEqualsTheRawName() {
        fireSignIn("o(27)brien");

        verify(localWorkspaceManager, timeout(5_000)).refreshMetainfoRegistry("o(28)27(29)brien");
        verify(localWorkspaceManager, never()).refreshMetainfoRegistry("o(27)brien");
    }

    private void fireSignIn(String username) {
        var event = new InteractiveAuthenticationSuccessEvent(
                new UsernamePasswordAuthenticationToken(username, "N/A"), getClass());
        new WorkspaceRegistryReconciler(localWorkspaceManager).onApplicationEvent(event);
    }
}

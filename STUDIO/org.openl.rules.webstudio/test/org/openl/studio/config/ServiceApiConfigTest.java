package org.openl.studio.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertyResolver;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpSession;

import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.Pageable;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.testmethod.TestSuiteExecutor;
import org.openl.rules.ui.WebStudio;
import org.openl.rules.ui.tree.view.Profile;
import org.openl.rules.webstudio.service.UserManagementService;
import org.openl.rules.webstudio.service.UserSettingManagementService;
import org.openl.rules.webstudio.web.Props;
import org.openl.rules.webstudio.web.repository.ProjectDescriptorArtefactResolver;
import org.openl.rules.webstudio.web.servlet.RulesUserSession;
import org.openl.rules.webstudio.web.util.Constants;
import org.openl.rules.workspace.MultiUserWorkspaceManager;
import org.openl.rules.workspace.WorkspaceUser;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.rules.workspace.lw.LocalWorkspace;
import org.openl.rules.workspace.uw.UserWorkspace;
import org.openl.security.acl.repository.RepositoryAclService;
import org.openl.security.acl.repository.SimpleRepositoryAclService;
import org.openl.studio.common.exception.ForbiddenException;
import org.openl.studio.projects.service.ProjectAccessService;
import org.openl.studio.projects.service.protection.ProtectedBranchBypassService;
import org.openl.studio.security.CurrentUserInfo;

class ServiceApiConfigTest {

    @TempDir
    private Path workspaceRoot;

    private Environment previousEnvironment;

    @BeforeEach
    void setUp() {
        previousEnvironment = Props.getEnvironment();
        Props.setEnvironment(new MockEnvironment());
    }

    @AfterEach
    void tearDown() {
        Props.setEnvironment(previousEnvironment);
    }

    @Test
    void rulesUserSession_isRegisteredInTheSession() {
        var session = new MockHttpSession();
        var workspace = workspace();
        var workspaceManager = mock(MultiUserWorkspaceManager.class);
        when(workspaceManager.getUserWorkspace(any(WorkspaceUser.class))).thenReturn(workspace);
        var userSettings = userSettings();
        var currentUserInfo = mock(CurrentUserInfo.class);
        when(currentUserInfo.getUserName()).thenReturn("admin");

        var rulesUserSession = new ServiceApiConfig(mock(PropertyResolver.class)).rulesUserSession(currentUserInfo,
                workspaceManager,
                mock(UserManagementService.class),
                mock(TestSuiteExecutor.class),
                userSettings,
                mock(RepositoryAclService.class),
                mock(SimpleRepositoryAclService.class),
                mock(ProjectDescriptorArtefactResolver.class),
                mock(PropertyResolver.class),
                mock(ApplicationEventPublisher.class),
                mock(ProtectedBranchBypassService.class),
                mock(ProjectAccessService.class),
                session);

        assertSame(rulesUserSession, session.getAttribute(Constants.RULES_USER_SESSION));
    }

    // V1: the workspace of a user id that is not a valid workspace folder name refuses the session with a 403
    @Test
    void rulesUserSession_ofAUserIdThatIsNotAValidWorkspaceFolderName_isRefused() {
        var session = new MockHttpSession();
        var rejection = new IllegalArgumentException("The user id is not a valid workspace folder name.");
        var workspaceManager = mock(MultiUserWorkspaceManager.class);
        when(workspaceManager.getUserWorkspace(any(WorkspaceUser.class))).thenThrow(rejection);
        var userSettings = mock(UserSettingManagementService.class);
        var currentUserInfo = mock(CurrentUserInfo.class);
        when(currentUserInfo.getUserName()).thenReturn("CON");
        var config = new ServiceApiConfig(mock(PropertyResolver.class));

        var refusal = assertThrows(ForbiddenException.class,
                () -> config.rulesUserSession(currentUserInfo,
                        workspaceManager,
                        mock(UserManagementService.class),
                        mock(TestSuiteExecutor.class),
                        userSettings,
                        mock(RepositoryAclService.class),
                        mock(SimpleRepositoryAclService.class),
                        mock(ProjectDescriptorArtefactResolver.class),
                        mock(PropertyResolver.class),
                        mock(ApplicationEventPublisher.class),
                        mock(ProtectedBranchBypassService.class),
                        mock(ProjectAccessService.class),
                        session));

        assertSame(rejection, refusal.getCause());
        assertEquals("openl.error.403.default.message", refusal.getErrorCode());
        assertNull(session.getAttribute(Constants.RULES_USER_SESSION));
        // The studio is never built for a refused session, so it reads no settings of the user.
        verifyNoInteractions(userSettings);
    }

    // V1: the other beans of the configuration the session refusal changed keep their wiring
    @Test
    void historyRepositoryMapper_readsTheCommentTemplatesOfItsRepository() throws IOException {
        var repository = mock(Repository.class);
        when(repository.getId()).thenReturn("design");
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).build());
        var revision = new FileData();
        revision.setName("Bank");
        revision.setVersion("1");
        revision.setComment("Copied from: Bank Rules");
        when(repository.listHistory("Bank")).thenReturn(List.of(revision));

        var history = new ServiceApiConfig(commentTemplates()).historyRepositoryMapper(repository)
                .getProjectHistory("Bank", "", false, Pageable.unpaged());

        assertEquals(1, history.getContent().size());
        assertEquals(List.of("Copied from: ", "Bank Rules", ""),
                history.getContent().iterator().next().commentParts());
    }

    @Test
    void commentService_readsTheTemplatesOfTheGivenRepository() {
        var config = new ServiceApiConfig(commentTemplates());

        assertEquals("Project Bank is created.", config.commentService("design").createProject("Bank"));
        assertEquals("Created Bank", config.commentService("production").createProject("Bank"));
    }

    @Test
    void userWorkspaceAndWebStudio_areThoseOfTheUserSession() {
        var workspace = workspace();
        var workspaceManager = mock(MultiUserWorkspaceManager.class);
        when(workspaceManager.getUserWorkspace(any(WorkspaceUser.class))).thenReturn(workspace);
        var webStudio = mock(WebStudio.class);
        var rulesUserSession = new RulesUserSession();
        rulesUserSession.setUserName("admin");
        rulesUserSession.setWorkspaceManager(workspaceManager);
        rulesUserSession.setWebStudio(webStudio);
        var config = new ServiceApiConfig(mock(PropertyResolver.class));

        assertSame(workspace, config.userWorkspace(rulesUserSession));
        assertSame(webStudio, config.webstudio(rulesUserSession));
    }

    private static MockEnvironment commentTemplates() {
        return new MockEnvironment()
                .withProperty("data.format.datetime", "yyyy-MM-dd HH:mm:ss")
                .withProperty("repository.design.comment-template.user-message.default.create",
                        "Project {project-name} is created.")
                .withProperty("repository.design.comment-template.user-message.default.copied-from",
                        "Copied from: {project-name}")
                .withProperty("repository.production.comment-template.user-message.default.create",
                        "Created {project-name}");
    }

    private UserWorkspace workspace() {
        var workspace = mock(UserWorkspace.class);
        var localWorkspace = mock(LocalWorkspace.class);
        var designTimeRepository = mock(DesignTimeRepository.class);

        when(workspace.getLocalWorkspace()).thenReturn(localWorkspace);
        when(localWorkspace.getLocation()).thenReturn(workspaceRoot.toFile());
        when(workspace.getDesignTimeRepository()).thenReturn(designTimeRepository);
        return workspace;
    }

    private UserSettingManagementService userSettings() {
        var userSettings = mock(UserSettingManagementService.class);
        when(userSettings.getStringProperty("admin", WebStudio.RULES_TREE_VIEW_DEFAULT))
                .thenReturn(Profile.PROFILES[0].getName());
        return userSettings;
    }
}

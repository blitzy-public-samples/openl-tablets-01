package org.openl.studio.repositories.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyIterable;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.endsWith;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.lang3.RandomStringUtils;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.FileMode;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;

import org.openl.rules.common.ProjectException;
import org.openl.rules.project.abstraction.AProject;
import org.openl.rules.project.abstraction.LockEngine;
import org.openl.rules.project.abstraction.ProjectStatus;
import org.openl.rules.project.abstraction.RulesProject;
import org.openl.rules.project.impl.local.DummyLockEngine;
import org.openl.rules.project.impl.local.LocalRepository;
import org.openl.rules.project.impl.local.MetainfoRegistry;
import org.openl.rules.project.impl.local.ProjectMetainfo;
import org.openl.rules.repository.LocalWorkingTree;
import org.openl.rules.repository.PathCheckedRepository;
import org.openl.rules.repository.RepositoryInstatiator;
import org.openl.rules.repository.api.BranchRepository;
import org.openl.rules.repository.api.ChangesetType;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.api.RepositoryDelegate;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.rest.acl.service.AclProjectsHelper;
import org.openl.rules.webstudio.util.NameChecker;
import org.openl.rules.webstudio.web.repository.project.ProjectFile;
import org.openl.rules.webstudio.web.repository.upload.ProjectUploader;
import org.openl.rules.webstudio.web.repository.upload.zip.ZipCharsetDetector;
import org.openl.rules.workspace.WorkspaceUser;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.rules.workspace.dtr.impl.FileMappingData;
import org.openl.rules.workspace.dtr.impl.MappedRepository;
import org.openl.rules.workspace.filter.PathFilter;
import org.openl.rules.workspace.lw.LocalWorkspace;
import org.openl.rules.workspace.uw.UserWorkspace;
import org.openl.security.acl.repository.RepositoryAclService;
import org.openl.security.acl.repository.RepositoryAclServiceProvider;
import org.openl.security.acl.repository.SecuredRepositoryFactory;
import org.openl.security.acl.repository.SimpleRepositoryAclService;
import org.openl.studio.common.exception.BadRequestException;
import org.openl.studio.common.exception.ConflictException;
import org.openl.studio.common.exception.ForbiddenException;
import org.openl.studio.common.exception.NotFoundException;
import org.openl.studio.tags.service.TagAssignmentValidator;
import org.openl.util.IOUtils;
import org.openl.util.StringUtils;

class ProjectCreationServiceTest {

    /**
     * V1: where the source project of a copy lives on disk, each reached the way the copy route receives it.
     */
    enum SourceLayout {
        /** A flat file design repository behind {@code SecureRepository}; the project is {@code DESIGN/rules/Src}. */
        FLAT,
        /** A mapped file design repository behind {@code SecureMappedRepository}; the project is in {@code catalog}. */
        MAPPED,
        /** The user's working copy of an opened project; the project is {@code Src}. */
        WORKING_COPY
    }

    /**
     * V1: the source project {@code Src} of a copy.
     *
     * @param repository the repository the copy reads the source through
     * @param files      the file repository underneath it, spied so reads can be verified
     * @param folderPath the path of the project in {@code repository}
     * @param listing    the folder of the project in {@code files}, as the copy lists it
     */
    private record CopySource(Repository repository, FileSystemRepository files, String folderPath, String listing) {
    }

    private AclProjectsHelper aclProjectsHelper;
    private RepositoryAclServiceProvider aclServiceProvider;
    private TagAssignmentValidator tagAssignmentValidator;
    private ProjectCreationService service;
    // V1: the real directories and repositories of the source-containment cases
    @TempDir
    Path tmp;
    private final List<Closeable> closeables = new ArrayList<>();
    // V1-C: the constructor arguments of every upload the uploader mock stood in for, in construction order
    private final List<List<?>> uploads = new ArrayList<>();
    // V1-C: the content of every file a real upload took, so its release can be checked
    private final List<TrackedStream> streams = new ArrayList<>();
    // V1-C: the branch a configured Git repository works on, and a branch an upload targets while it is not checked out
    private static final String BASE_BRANCH = "master";
    private static final String TARGET_BRANCH = "v1target";

    @BeforeEach
    void setUp() {
        aclProjectsHelper = mock(AclProjectsHelper.class);
        aclServiceProvider = mock(RepositoryAclServiceProvider.class);
        tagAssignmentValidator = mock(TagAssignmentValidator.class);
        service = new ProjectCreationService(aclProjectsHelper, aclServiceProvider,
                tagAssignmentValidator, mock(PathFilter.class), mock(ZipCharsetDetector.class), "");
    }

    // V1: releases the mapped repositories the source-containment cases open
    @AfterEach
    void closeRepositories() throws IOException {
        for (var closeable : closeables) {
            closeable.close();
        }
    }

    @Test
    void lists_predefined_templates_without_error() {
        // The custom resolver is not initialised outside a Spring context; listing must not fail.
        assertNotNull(service.listTemplates());
    }

    @Test
    void create_from_template_is_denied_without_create_permission() {
        assertThrows(ForbiddenException.class, () -> service.createFromTemplate("design", "Project", null,
                "predefined", "examples", "Example", "comment", null));
    }

    @Test
    void create_from_files_is_denied_without_create_permission() {
        List<ProjectFile> files = List.of();
        assertThrows(ForbiddenException.class, () -> service.createFromFiles("design", "Project", null,
                files, "comment", "rules/Models.xlsx", "rules/Algorithms.xlsx", "Models", "Algorithms", null));
    }

    @Test
    void copy_project_is_denied_without_create_permission() {
        var targetRepository = mock(Repository.class);
        when(targetRepository.getId()).thenReturn("design");
        var source = mock(RulesProject.class);
        assertThrows(ForbiddenException.class,
                () -> service.copyProject(targetRepository, "Copy", null, source, "comment", null));
    }


    @Test
    void copy_project_rejects_a_revision_the_source_has_no_state_at() throws Exception {
        when(aclProjectsHelper.hasCreateProjectPermission("design")).thenReturn(true);
        var acl = mock(RepositoryAclService.class);
        when(acl.isGranted(any(RulesProject.class), anyList())).thenReturn(true);
        when(aclServiceProvider.getDesignRepoAclService()).thenReturn(acl);

        var repository = mock(Repository.class);
        when(repository.getId()).thenReturn("design");
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setVersions(true).build());
        when(repository.check("DESIGN/Source")).thenReturn(fileData("9"));
        // A repository numbers revisions its own way and rejects a value it cannot read.
        when(repository.checkHistory("DESIGN/Source", "does-not-exist"))
                .thenThrow(new NumberFormatException("For input string: \"does-not-exist\""));
        var source = mock(RulesProject.class);
        when(source.getRepository()).thenReturn(repository);
        when(source.getFolderPath()).thenReturn("DESIGN/Source");

        var workspace = mock(UserWorkspace.class);
        service = serviceWithWorkspace(workspace);
        var targetRepository = mock(Repository.class);
        when(targetRepository.getId()).thenReturn("design");
        when(targetRepository.supports()).thenReturn(new FeaturesBuilder(targetRepository).build());

        assertThrows(NotFoundException.class, () -> service.copyProject(targetRepository, "Copy", null, source,
                "comment", "does-not-exist"));
    }

    @Test
    void copy_project_reads_the_source_at_the_requested_revision() throws Exception {
        when(aclProjectsHelper.hasCreateProjectPermission("design")).thenReturn(true);
        var acl = mock(RepositoryAclService.class);
        when(acl.isGranted(any(RulesProject.class), anyList())).thenReturn(true);
        when(aclServiceProvider.getDesignRepoAclService()).thenReturn(acl);

        var repository = mock(Repository.class);
        when(repository.getId()).thenReturn("design");
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setVersions(true).build());
        when(repository.check("DESIGN/Source")).thenReturn(fileData("9"));
        when(repository.checkHistory("DESIGN/Source", "5")).thenReturn(fileData("5"));
        var source = mock(RulesProject.class);
        when(source.getRepository()).thenReturn(repository);
        when(source.getFolderPath()).thenReturn("DESIGN/Source");

        var workspace = mock(UserWorkspace.class);
        service = serviceWithWorkspace(workspace);
        var targetRepository = mock(Repository.class);
        when(targetRepository.getId()).thenReturn("design");
        when(targetRepository.supports()).thenReturn(new FeaturesBuilder(targetRepository).build());

        // The target repository is not configured here, so the copy fails right after the source is read.
        assertThrows(RuntimeException.class, () -> service.copyProject(targetRepository, "Copy", null, source,
                "comment", "5"));

        verify(repository).checkHistory("DESIGN/Source", "5");
    }

    // V1: a path or name carrying a control character is rejected as received, before anything is written
    @ParameterizedTest
    @ValueSource(strings = {"Dir\u0000", "Dir\u0007"})
    void create_from_files_rejects_a_path_with_a_control_character(String path) {
        when(aclProjectsHelper.hasCreateProjectPermission("design")).thenReturn(true);
        var repository = mock(Repository.class);
        when(repository.getId()).thenReturn("design");
        var file = mock(ProjectFile.class);
        List<ProjectFile> files = List.of(file);

        var e = assertThrows(BadRequestException.class, () -> service.createFromFiles(repository, "Project", path,
                files, "comment", "rules/Models.xlsx", "rules/Algorithms.xlsx", "Models", "Algorithms", Map.of()));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        // The upload never runs, so the rejection releases the files the upload would have released.
        verify(file).destroy();
    }

    @Test
    void create_from_files_rejects_a_project_name_with_a_control_character() {
        when(aclProjectsHelper.hasCreateProjectPermission("design")).thenReturn(true);
        var repository = mock(Repository.class);
        when(repository.getId()).thenReturn("design");
        List<ProjectFile> files = List.of(mock(ProjectFile.class));

        var e = assertThrows(BadRequestException.class, () -> service.createFromFiles(repository, "Project\u0007",
                "Dir", files, "comment", "rules/Models.xlsx", "rules/Algorithms.xlsx", "Models", "Algorithms",
                Map.of()));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
    }

    // V1-C: a dot-leading name never reaches the upload, so the rejection releases the files the upload would have
    @Test
    void create_from_files_rejects_a_dot_leading_project_name_and_releases_its_files() {
        when(aclProjectsHelper.hasCreateProjectPermission("design")).thenReturn(true);
        var repository = mock(Repository.class);
        when(repository.getId()).thenReturn("design");
        var file = mock(ProjectFile.class);
        List<ProjectFile> files = List.of(file);

        var e = assertThrows(BadRequestException.class, () -> service.createFromFiles(repository, ".hidden", null,
                files, "comment", "rules/Models.xlsx", "rules/Algorithms.xlsx", "Models", "Algorithms", Map.of()));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        verify(file).destroy();
    }

    @Test
    void create_from_template_rejects_a_path_with_a_control_character() {
        when(aclProjectsHelper.hasCreateProjectPermission("design")).thenReturn(true);
        var repository = mock(Repository.class);
        when(repository.getId()).thenReturn("design");

        // The template exists, so the rejection comes from the path and not from the template lookup.
        var e = assertThrows(BadRequestException.class, () -> service.createFromTemplate(repository, "Project",
                "Dir\u0000", "predefined", "templates", "Sample Project", "comment", Map.of()));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
    }

    @Test
    void copy_project_rejects_a_target_with_a_control_character() throws Exception {
        when(aclProjectsHelper.hasCreateProjectPermission("design")).thenReturn(true);
        var acl = mock(RepositoryAclService.class);
        when(acl.isGranted(any(RulesProject.class), anyList())).thenReturn(true);
        when(aclServiceProvider.getDesignRepoAclService()).thenReturn(acl);

        var repository = mock(Repository.class);
        when(repository.getId()).thenReturn("design");
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setVersions(true).build());
        when(repository.check("DESIGN/Source")).thenReturn(fileData("9"));
        var source = mock(RulesProject.class);
        when(source.getRepository()).thenReturn(repository);
        when(source.getFolderPath()).thenReturn("DESIGN/Source");

        var workspace = mock(UserWorkspace.class);
        service = serviceWithWorkspace(workspace);
        var targetRepository = mock(Repository.class);
        when(targetRepository.getId()).thenReturn("design");
        when(targetRepository.supports()).thenReturn(new FeaturesBuilder(targetRepository).build());

        // A blank revision copies the latest state of the source.
        var pathError = assertThrows(BadRequestException.class, () -> service.copyProject(targetRepository, "Copy",
                "Dir\u0007", source, "comment", ""));
        var nameError = assertThrows(BadRequestException.class, () -> service.copyProject(targetRepository,
                "Copy\u0000", "Dir", source, "comment", ""));

        assertEquals("openl.error.400.file.path.invalid.message", pathError.getErrorCode());
        assertEquals("openl.error.400.file.path.invalid.message", nameError.getErrorCode());
        // Rejected before the copy resolves its destination, so nothing is written.
        verify(workspace, never()).getDesignTimeRepository();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"Dir ", "Dir/Nested"})
    void create_from_files_lets_a_path_without_control_characters_through(String path) {
        when(aclProjectsHelper.hasCreateProjectPermission("design")).thenReturn(true);
        var repository = mock(Repository.class);
        when(repository.getId()).thenReturn("design");
        var file = mock(ProjectFile.class);
        List<ProjectFile> files = List.of(file);

        // Past the check, the upload looks up the user workspace, which only the Spring container provides.
        assertThrows(UnsupportedOperationException.class, () -> service.createFromFiles(repository, "Project",
                path, files, "comment", "rules/Models.xlsx", "rules/Algorithms.xlsx", "Models", "Algorithms",
                Map.of()));

        verify(file, never()).destroy();
    }

    @Test
    void apply_status_opens_a_created_project_when_open_is_requested() throws Exception {
        var project = mock(RulesProject.class);
        when(project.isOpened()).thenReturn(false);
        var workspace = mock(UserWorkspace.class);
        when(workspace.getProject("design", "Alpha")).thenReturn(project);
        when(workspace.isOpenedOtherProject(project)).thenReturn(false);
        service = serviceWithWorkspace(workspace);

        // OPENED arrives as VIEWING through the status converter.
        service.applyStatusAfterCreate("design", "Alpha", ProjectStatus.VIEWING);

        verify(project).open();
        verify(workspace).refresh();
    }

    @Test
    void apply_status_opens_an_archive_project_the_workspace_does_not_list_yet() throws Exception {
        // An uploaded archive lands straight in the design repository: the workspace lookup fails, and
        // the project is assembled from its design state instead — like the legacy creator builds it.
        var workspace = mock(UserWorkspace.class);
        when(workspace.getProject("design", "Alpha"))
                .thenThrow(new ProjectException("Cannot find project 'Alpha'."));
        var designTimeRepository = mock(DesignTimeRepository.class);
        when(workspace.getDesignTimeRepository()).thenReturn(designTimeRepository);
        var designProject = mock(AProject.class);
        when(designTimeRepository.getProject("design", "Alpha")).thenReturn(designProject);

        var project = mock(RulesProject.class);
        when(project.isOpened()).thenReturn(false);
        var testService = new TestProjectCreationService(aclProjectsHelper, aclServiceProvider,
                mock(TagAssignmentValidator.class), mock(PathFilter.class), mock(ZipCharsetDetector.class), "",
                workspace);
        testService.designWorkspaceProject = project;

        testService.applyStatusAfterCreate("design", "Alpha", ProjectStatus.VIEWING);

        // The stale design-project cache is invalidated before the design lookup.
        verify(designTimeRepository).refresh();
        verify(project).open();
        verify(workspace).refresh();
    }

    @Test
    void apply_status_resolves_the_created_project_in_its_target_branch() throws Exception {
        var repository = mock(BranchRepository.class);
        when(repository.getId()).thenReturn("design");
        when(repository.getBranch()).thenReturn("feature");
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setBranches(true).build());
        var workspace = mock(UserWorkspace.class);
        var designTimeRepository = mock(DesignTimeRepository.class);
        when(workspace.getDesignTimeRepository()).thenReturn(designTimeRepository);
        var designProject = mock(AProject.class);
        when(designTimeRepository.getProject("design", "Alpha", "feature")).thenReturn(designProject);
        var project = mock(RulesProject.class);
        var testService = new TestProjectCreationService(aclProjectsHelper, aclServiceProvider,
                mock(TagAssignmentValidator.class), mock(PathFilter.class), mock(ZipCharsetDetector.class), "",
                workspace);
        testService.designWorkspaceProject = project;

        testService.applyStatusAfterCreate(repository, "Alpha", ProjectStatus.VIEWING);

        verify(designTimeRepository).getProject("design", "Alpha", "feature");
        verify(workspace, never()).getProject("design", "Alpha");
        verify(project).open();
    }

    @Test
    void apply_status_resolves_a_mapped_project_by_its_business_name() throws Exception {
        var repository = mock(BranchRepository.class);
        when(repository.getId()).thenReturn("design");
        when(repository.getBranch()).thenReturn("feature");
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setBranches(true).build());
        var workspace = mock(UserWorkspace.class);
        var designTimeRepository = mock(DesignTimeRepository.class);
        when(workspace.getDesignTimeRepository()).thenReturn(designTimeRepository);
        when(designTimeRepository.getProject("design", "Alpha", "feature"))
                .thenThrow(new ProjectException("Not found"));
        var indexedProject = mock(AProject.class);
        when(indexedProject.getBusinessName()).thenReturn("Alpha");
        when(indexedProject.getName()).thenReturn("Alpha:hash");
        doReturn(List.of(indexedProject)).when(designTimeRepository).getProjects("design");
        var designProject = mock(AProject.class);
        when(designTimeRepository.getProject("design", "Alpha:hash", "feature")).thenReturn(designProject);
        var project = mock(RulesProject.class);
        var testService = new TestProjectCreationService(aclProjectsHelper, aclServiceProvider,
                mock(TagAssignmentValidator.class), mock(PathFilter.class), mock(ZipCharsetDetector.class), "",
                workspace);
        testService.designWorkspaceProject = project;

        testService.applyStatusAfterCreate(repository, "Alpha", ProjectStatus.VIEWING);

        verify(designTimeRepository).getProject("design", "Alpha:hash", "feature");
        verify(project).open();
    }

    @Test
    void apply_status_closes_a_created_project_when_close_is_requested() throws Exception {
        var project = mock(RulesProject.class);
        when(project.isOpened()).thenReturn(true);
        var workspace = mock(UserWorkspace.class);
        when(workspace.getProject("design", "Alpha")).thenReturn(project);
        service = serviceWithWorkspace(workspace);

        service.applyStatusAfterCreate("design", "Alpha", ProjectStatus.CLOSED);

        verify(project).close();
        verify(workspace).refresh();
    }

    @Test
    void apply_status_leaves_an_already_open_project_alone() throws Exception {
        var project = mock(RulesProject.class);
        when(project.isOpened()).thenReturn(true);
        var workspace = mock(UserWorkspace.class);
        when(workspace.getProject("design", "Alpha")).thenReturn(project);
        service = serviceWithWorkspace(workspace);

        service.applyStatusAfterCreate("design", "Alpha", ProjectStatus.VIEWING);

        verify(project, never()).open();
        verify(workspace, never()).refresh();
    }

    @Test
    void apply_status_skips_opening_while_another_copy_of_the_project_is_open() throws Exception {
        var project = mock(RulesProject.class);
        when(project.isOpened()).thenReturn(false);
        var workspace = mock(UserWorkspace.class);
        when(workspace.getProject("design", "Alpha")).thenReturn(project);
        when(workspace.isOpenedOtherProject(project)).thenReturn(true);
        service = serviceWithWorkspace(workspace);

        service.applyStatusAfterCreate("design", "Alpha", ProjectStatus.VIEWING);

        verify(project, never()).open();
    }

    @Test
    void apply_status_never_fails_the_create_when_opening_fails() throws Exception {
        var project = mock(RulesProject.class);
        when(project.isOpened()).thenReturn(false);
        var workspace = mock(UserWorkspace.class);
        when(workspace.getProject("design", "Alpha")).thenReturn(project);
        when(workspace.isOpenedOtherProject(project)).thenReturn(false);
        doThrow(new ProjectException("disk full")).when(project).open();
        service = serviceWithWorkspace(workspace);

        // The project was created; a failed open is logged, never turned into a create error.
        assertDoesNotThrow(() -> service.applyStatusAfterCreate("design", "Alpha", ProjectStatus.VIEWING));
    }

    @Test
    void assembles_the_workspace_view_of_a_design_project_from_its_design_state() {
        var user = mock(WorkspaceUser.class);
        var localWorkspace = mock(LocalWorkspace.class);
        var localRepository = mock(LocalRepository.class);
        var lockEngine = mock(LockEngine.class);
        var workspace = mock(UserWorkspace.class);
        when(workspace.getUser()).thenReturn(user);
        when(workspace.getLocalWorkspace()).thenReturn(localWorkspace);
        when(localWorkspace.getRepository("design")).thenReturn(localRepository);
        when(workspace.getProjectsLockEngine()).thenReturn(lockEngine);

        var designRepository = mock(Repository.class);
        var designData = fileData("3");
        designData.setName("DESIGN/Alpha");
        var designProject = mock(AProject.class);
        when(designProject.getRepository()).thenReturn(designRepository);
        when(designProject.getFileData()).thenReturn(designData);

        var assembled = serviceWithWorkspace(workspace).newWorkspaceProject(workspace, "design", designProject);

        // The view reads from the design state — like the legacy creator's freshly created project.
        assertSame(designRepository, assembled.getDesignRepository());
        assertSame(designData, assembled.getFileData());
    }

    @Test
    void apply_status_leaves_the_project_alone_when_no_status_is_requested() {
        var workspace = mock(UserWorkspace.class);
        service = serviceWithWorkspace(workspace);

        service.applyStatusAfterCreate("design", "Alpha", null);

        verifyNoInteractions(workspace);
    }

    @Test
    void refreshes_the_workspace_after_a_design_change() {
        var workspace = mock(UserWorkspace.class);
        service = serviceWithWorkspace(workspace);

        service.refreshWorkspaceAfterDesignChange();

        verify(workspace).refresh();
    }

    @Test
    void workspace_refresh_failure_does_not_fail_a_finalized_design_change() {
        var workspace = mock(UserWorkspace.class);
        doThrow(new IllegalStateException("stale branch selection")).when(workspace).refresh();
        service = serviceWithWorkspace(workspace);

        assertDoesNotThrow(service::refreshWorkspaceAfterDesignChange);
    }

    @Test
    void waits_until_a_branch_write_is_published() {
        var repository = mock(BranchRepository.class);
        when(repository.getId()).thenReturn("design");
        when(repository.getBranch()).thenReturn("feature");
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setBranches(true).build());
        var designTimeRepository = mock(DesignTimeRepository.class);
        when(designTimeRepository.refreshBranch("design", "feature"))
                .thenReturn(CompletableFuture.completedFuture(null));
        var workspace = mock(UserWorkspace.class);
        when(workspace.getDesignTimeRepository()).thenReturn(designTimeRepository);

        serviceWithWorkspace(workspace).awaitProjectVisibility(repository);

        verify(designTimeRepository).refreshBranch("design", "feature");
    }

    @Test
    void reports_a_failed_branch_publication() {
        var repository = mock(BranchRepository.class);
        when(repository.getId()).thenReturn("design");
        when(repository.getBranch()).thenReturn("feature");
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setBranches(true).build());
        var designTimeRepository = mock(DesignTimeRepository.class);
        when(designTimeRepository.refreshBranch("design", "feature"))
                .thenReturn(CompletableFuture.failedFuture(new IllegalStateException("failed")));
        var workspace = mock(UserWorkspace.class);
        when(workspace.getDesignTimeRepository()).thenReturn(designTimeRepository);

        service = serviceWithWorkspace(workspace);
        assertThrows(ConflictException.class,
                () -> service.awaitProjectVisibility(repository));
    }

    // V1: the source project of a copy and every file the copy reads from it stay inside the project folder

    @ParameterizedTest
    @EnumSource(SourceLayout.class)
    @DisabledOnOs(OS.WINDOWS)
    void copy_project_rejects_a_source_file_linked_outside_the_project(SourceLayout layout) throws IOException {
        var project = layOutSource(layout);
        var secret = tmp.resolve("outside/secret.txt");
        write(secret, marker());
        Files.createSymbolicLink(project.resolve("leak.txt"), secret);
        var source = source(layout);
        var target = targetRepositoryMock();

        var e = assertThrows(BadRequestException.class, () -> copy(source, target));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        verify(source.files(), never()).read(endsWith("/leak.txt"));
        verifyNothingSaved(target);
    }

    @ParameterizedTest
    @EnumSource(SourceLayout.class)
    @DisabledOnOs(OS.WINDOWS)
    void copy_project_rejects_a_source_file_linked_into_a_sibling_project(SourceLayout layout) throws IOException {
        var project = layOutSource(layout);
        Files.createSymbolicLink(project.resolve("sibling.xml"), project.resolveSibling("Sib").resolve("rules.xml"));
        var source = source(layout);
        var target = targetRepositoryMock();

        var e = assertThrows(BadRequestException.class, () -> copy(source, target));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        verify(source.files(), never()).read(endsWith("/sibling.xml"));
        verifyNothingSaved(target);
    }

    @ParameterizedTest
    @EnumSource(SourceLayout.class)
    @DisabledOnOs(OS.WINDOWS)
    void copy_project_rejects_a_listed_source_link_that_resolves_nowhere(SourceLayout layout) throws IOException {
        var project = layOutSource(layout);
        var inside = project.resolve("sub/inside.txt");
        Files.createSymbolicLink(project.resolve("alias.txt"), inside);
        var source = source(layout);
        // The file the link points to disappears right after the listing, so the listed link dangles when checked.
        doAnswer(invocation -> {
            var listed = invocation.callRealMethod();
            Files.deleteIfExists(inside);
            return listed;
        }).when(source.files()).list(source.listing());
        var target = targetRepositoryMock();

        var e = assertThrows(BadRequestException.class, () -> copy(source, target));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        verify(source.files(), never()).read(endsWith("/alias.txt"));
        verifyNothingSaved(target);
    }

    @ParameterizedTest
    @EnumSource(value = SourceLayout.class, names = {"FLAT", "WORKING_COPY"})
    @DisabledOnOs(OS.WINDOWS)
    void copy_project_rejects_a_source_project_folder_that_is_a_dangling_link(SourceLayout layout)
            throws IOException {
        var project = layOutSource(layout);
        deleteTree(project);
        Files.createSymbolicLink(project, tmp.resolve("outside/missing"));
        var source = source(layout);
        var target = targetRepositoryMock();

        var e = assertThrows(BadRequestException.class, () -> copy(source, target));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        verify(source.files(), never()).list(source.listing());
        verifyNothingSaved(target);
    }

    @ParameterizedTest
    @EnumSource(SourceLayout.class)
    @DisabledOnOs(OS.WINDOWS)
    void copy_project_rejects_a_source_project_folder_that_is_a_link(SourceLayout layout) throws IOException {
        var project = layOutSource(layout);
        var elsewhere = tmp.resolve("outside/Src");
        Files.createDirectories(elsewhere.getParent());
        Files.move(project, elsewhere);
        Files.createSymbolicLink(project, elsewhere);
        var source = source(layout);
        var target = targetRepositoryMock();

        var e = assertThrows(BadRequestException.class, () -> copy(source, target));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        verify(source.files(), never()).list(source.listing());
        verifyNothingSaved(target);
    }

    @ParameterizedTest
    @EnumSource(SourceLayout.class)
    @DisabledOnOs(OS.WINDOWS)
    void copy_project_copies_a_source_whose_links_stay_inside_the_project(SourceLayout layout) throws IOException {
        var project = layOutSource(layout);
        Files.createSymbolicLink(project.resolve("alias.txt"), project.resolve("sub/inside.txt"));
        var targetRoot = tmp.resolve("target");

        assertNotNull(copy(source(layout), fileRepository(targetRoot)));

        var copied = targetRoot.resolve("DESIGN/rules/Copy");
        assertEquals(Files.readString(project.resolve("sub/inside.txt")),
                Files.readString(copied.resolve("alias.txt")));
        assertFalse(Files.isSymbolicLink(copied.resolve("alias.txt")), "The copy holds the content, not the link");
        assertEquals(Files.readString(project.resolve("src.txt")), Files.readString(copied.resolve("src.txt")));
    }

    @ParameterizedTest
    @EnumSource(SourceLayout.class)
    void copy_project_copies_an_ordinary_file_backed_source(SourceLayout layout) throws IOException {
        var project = layOutSource(layout);
        var targetRoot = tmp.resolve("target");

        assertNotNull(copy(source(layout), fileRepository(targetRoot)));

        var copied = targetRoot.resolve("DESIGN/rules/Copy");
        assertEquals(Files.readString(project.resolve("src.txt")), Files.readString(copied.resolve("src.txt")));
        assertEquals(Files.readString(project.resolve("sub/inside.txt")),
                Files.readString(copied.resolve("sub/inside.txt")));
        assertTrue(Files.isRegularFile(copied.resolve("rules.xml")), "The descriptor is copied");
    }

    @Test
    void copy_project_adds_no_repository_call_for_a_source_that_is_not_file_backed() throws IOException {
        var repository = mock(Repository.class);
        when(repository.getId()).thenReturn("design");
        when(repository.supports())
                .thenReturn(new FeaturesBuilder(repository).setVersions(false).setFolders(true).build());
        when(repository.check("DESIGN/Source")).thenReturn(fileData(null));
        var file = new FileData();
        file.setName("DESIGN/Source/data.txt");
        when(repository.list("DESIGN/Source/")).thenReturn(List.of(file));
        var content = marker();
        when(repository.read("DESIGN/Source/data.txt"))
                .thenReturn(new FileItem(file, new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8))));
        var targetRoot = tmp.resolve("target");

        assertNotNull(copy(secured(repository), "DESIGN/Source", fileRepository(targetRoot)));

        // The only listing is the one the copy reads; the containment check makes no call on such a backend.
        verify(repository, times(1)).list("DESIGN/Source/");
        assertEquals(content, Files.readString(targetRoot.resolve("DESIGN/rules/Copy/data.txt")));
    }


    // V1: the application builds its design repositories path-checked; the source is contained behind that wrapper too
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void copy_project_rejects_a_source_file_linked_outside_a_configured_file_repository() throws IOException {
        var project = layOutSource(SourceLayout.MAPPED);
        var secret = tmp.resolve("outside/secret.txt");
        write(secret, marker());
        Files.createSymbolicLink(project.resolve("leak.txt"), secret);
        var source = configuredFileRepository();
        var targetRoot = tmp.resolve("target");
        var target = fileRepository(targetRoot);

        var e = assertThrows(BadRequestException.class, () -> copy(source, mappedName(source, "Src"), target));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        assertFalse(Files.exists(targetRoot.resolve("DESIGN/rules/Copy")), "Nothing is written to the target");
    }

    @Test
    void copy_project_copies_an_ordinary_source_of_a_configured_file_repository() throws IOException {
        var project = layOutSource(SourceLayout.MAPPED);
        var source = configuredFileRepository();
        var targetRoot = tmp.resolve("target");

        assertNotNull(copy(source, mappedName(source, "Src"), fileRepository(targetRoot)));

        assertEquals(Files.readString(project.resolve("sub/inside.txt")),
                Files.readString(targetRoot.resolve("DESIGN/rules/Copy/sub/inside.txt")));
    }

    /**
     * V1: the file design repository in {@code tmp/design} as the application configures it: instantiated from its
     * settings (and so path-checked), mapped, and secured.
     */
    private Repository configuredFileRepository() throws IOException {
        var settings = Map.of("repository.design.factory", "repo-file",
                "repository.design.uri", tmp.resolve("design").toString());
        var configured = RepositoryInstatiator.newRepository("repository.design", settings::get);
        var mapped = MappedRepository.create(configured, "DESIGN/");
        closeables.add((Closeable) mapped);
        return secured(mapped);
    }

    // V1: a configured root holding '<link>/..' is resolved the way the repository resolves it, not lexically
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void copy_project_rejects_a_source_link_under_a_root_that_climbs_out_of_a_link() throws IOException {
        var root = rootThroughLinkAndParent("design");
        var project = root.toRealPath().resolve("DESIGN/rules/Src");
        write(project.resolve("rules.xml"), descriptor("Src"));
        var secret = tmp.resolve("outside/secret.txt");
        write(secret, marker());
        Files.createSymbolicLink(project.resolve("leak.txt"), secret);
        var files = spy(fileRepository(root));
        var target = targetRepositoryMock();

        var e = assertThrows(BadRequestException.class, () -> copy(secured(files), "DESIGN/rules/Src", target));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        verify(files, never()).read(endsWith("/leak.txt"));
        verifyNothingSaved(target);
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void copy_project_rejects_a_target_link_under_a_root_that_climbs_out_of_a_link() throws IOException {
        layOutSource(SourceLayout.FLAT);
        var targetRoot = rootThroughLinkAndParent("target");
        var outside = Files.createDirectories(tmp.resolve("outside/target"));
        var rules = Files.createDirectories(targetRoot.toRealPath().resolve("DESIGN/rules"));
        Files.createSymbolicLink(rules.resolve("Copy"), outside);
        var source = source(SourceLayout.FLAT);
        var target = fileRepository(targetRoot);

        var e = assertThrows(BadRequestException.class, () -> copy(source, target));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        try (var written = Files.list(outside)) {
            assertEquals(0, written.count(), "Nothing is written through the link");
        }
    }

    // V1: a listed name the copy could not place under the project folder fails closed
    @Test
    void copy_project_rejects_a_listed_source_file_outside_the_project_folder() throws IOException {
        layOutSource(SourceLayout.FLAT);
        var source = source(SourceLayout.FLAT);
        var stray = new FileData();
        stray.setName("DESIGN/rules/Sib/rules.xml");
        doReturn(List.of(stray)).when(source.files()).list(source.listing());
        var target = targetRepositoryMock();

        var e = assertThrows(BadRequestException.class, () -> copy(source, target));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        verify(source.files(), never()).read(anyString());
        verifyNothingSaved(target);
    }

    // V1: a project kept as one archive file is read as that file, so only its own place is checked
    @Test
    void copy_project_checks_only_the_project_entry_of_an_archived_source() throws IOException {
        var archive = tmp.resolve("design/DESIGN/rules/Src");
        Files.createDirectories(archive.getParent());
        try (var zip = new ZipOutputStream(Files.newOutputStream(archive))) {
            zip.putNextEntry(new ZipEntry("rules.xml"));
            zip.write(descriptor("Src").getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        var files = spy(fileRepository(tmp.resolve("design")));
        doReturn(new FeaturesBuilder(files).setVersions(false).build()).when(files).supports();
        var targetRoot = tmp.resolve("target");

        assertNotNull(copy(secured(files), "DESIGN/rules/Src", fileRepository(targetRoot)));

        verify(files, never()).list(anyString());
        assertTrue(Files.isRegularFile(targetRoot.resolve("DESIGN/rules/Copy/rules.xml")), "The archive is unpacked");
    }

    /**
     * V1: a root configured as {@code base/link/../<name>}, where {@code base/link} points to {@code physical/child}.
     * The repository reaches {@code physical/<name>} through the link, while the lexically normalized root
     * {@code base/<name>} does not exist.
     */
    private Path rootThroughLinkAndParent(String name) throws IOException {
        var physical = Files.createDirectories(tmp.resolve("physical"));
        Files.createDirectories(physical.resolve("child"));
        Files.createDirectories(physical.resolve(name));
        var link = Files.createDirectories(tmp.resolve("base")).resolve("link");
        if (!Files.exists(link, LinkOption.NOFOLLOW_LINKS)) {
            Files.createSymbolicLink(link, physical.resolve("child"));
        }
        return link.resolve("..").resolve(name);
    }


    /**
     * V1: lays out the source project {@code Src} (a descriptor, {@code src.txt} and {@code sub/inside.txt}) and
     * its sibling project {@code Sib} where the layout keeps them, and returns the folder of {@code Src}.
     */
    private Path layOutSource(SourceLayout layout) throws IOException {
        var parent = switch (layout) {
            case FLAT -> tmp.resolve("design/DESIGN/rules");
            case MAPPED -> tmp.resolve("design/catalog");
            case WORKING_COPY -> tmp.resolve("workspace");
        };
        write(parent.resolve("Src/rules.xml"), descriptor("Src"));
        write(parent.resolve("Src/src.txt"), marker());
        write(parent.resolve("Src/sub/inside.txt"), marker());
        write(parent.resolve("Sib/rules.xml"), descriptor("Sib"));
        return parent.resolve("Src");
    }

    /** V1: the source project {@code Src}, reached the way the copy route receives it in that layout. */
    private CopySource source(SourceLayout layout) throws IOException {
        return switch (layout) {
            case FLAT -> {
                var files = spy(fileRepository(tmp.resolve("design")));
                yield new CopySource(secured(files), files, "DESIGN/rules/Src", "DESIGN/rules/Src/");
            }
            case MAPPED -> {
                var files = spy(fileRepository(tmp.resolve("design")));
                var mapped = MappedRepository.create(files, "DESIGN/");
                closeables.add((Closeable) mapped);
                var secured = secured(mapped);
                yield new CopySource(secured, files, mappedName(secured, "Src"), "catalog/Src/");
            }
            case WORKING_COPY -> {
                var workspace = tmp.resolve("workspace");
                // Opening the registry deletes every project folder without a record, as a leftover.
                for (var projectName : List.of("Src", "Sib")) {
                    MetainfoRegistry.store(workspace, projectName,
                            new ProjectMetainfo("design", null, null, null, null, null, null, null, Map.of()));
                }
                var files = spy(new LocalRepository(workspace, MetainfoRegistry.open(workspace)));
                yield new CopySource(files, files, "Src", "Src/");
            }
        };
    }

    private FileData copy(CopySource source, Repository target) {
        return copy(source.repository(), source.folderPath(), target);
    }

    /**
     * V1: copies the source project into the target repository as {@code Copy}, for a user who may read the
     * source and create projects in the target, whose design repository keeps projects in {@code DESIGN/rules/}.
     */
    private FileData copy(Repository sourceRepository, String folderPath, Repository target) {
        when(aclProjectsHelper.hasCreateProjectPermission("design")).thenReturn(true);
        var acl = mock(RepositoryAclService.class);
        when(acl.isGranted(any(RulesProject.class), anyList())).thenReturn(true);
        when(aclServiceProvider.getDesignRepoAclService()).thenReturn(acl);
        var source = mock(RulesProject.class);
        when(source.getRepository()).thenReturn(sourceRepository);
        when(source.getFolderPath()).thenReturn(folderPath);

        var designTimeRepository = mock(DesignTimeRepository.class);
        when(designTimeRepository.getRulesLocation()).thenReturn("DESIGN/rules/");
        var localWorkspace = mock(LocalWorkspace.class);
        when(localWorkspace.getRepository("design")).thenReturn(mock(LocalRepository.class));
        var workspace = mock(UserWorkspace.class);
        when(workspace.getDesignTimeRepository()).thenReturn(designTimeRepository);
        when(workspace.getUser()).thenReturn(mock(WorkspaceUser.class));
        when(workspace.getLocalWorkspace()).thenReturn(localWorkspace);
        when(workspace.getProjectsLockEngine()).thenReturn(mock(LockEngine.class));

        return serviceWithWorkspace(workspace).copyProject(target, "Copy", null, source, "comment", null);
    }

    private static Repository targetRepositoryMock() {
        var target = mock(Repository.class);
        when(target.getId()).thenReturn("design");
        when(target.supports()).thenReturn(new FeaturesBuilder(target).setVersions(false).setFolders(true).build());
        return target;
    }

    private static void verifyNothingSaved(Repository target) throws IOException {
        verify(target, never()).save(any(FileData.class), any(InputStream.class));
        verify(target, never()).save(anyList());
        verify(target, never()).save(any(FileData.class), anyIterable(), any(ChangesetType.class));
    }

    private static String mappedName(Repository repository, String businessName) throws IOException {
        return repository.listFolders("DESIGN/")
                .stream()
                .map(FileData::getName)
                .filter(name -> name.startsWith("DESIGN/" + businessName + ":"))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Fixture: " + businessName + " is not mapped"));
    }

    private static Repository secured(Repository repository) {
        return SecuredRepositoryFactory.wrapToSecureRepo(repository, grantAllRepoAcl());
    }

    /** Grants every repository permission, so the secured wrappers behave as for a user who may do anything. */
    private static SimpleRepositoryAclService grantAllRepoAcl() {
        return mock(SimpleRepositoryAclService.class,
                invocation -> invocation.getMethod().getReturnType() == boolean.class
                        ? true
                        : Mockito.RETURNS_DEFAULTS.answer(invocation));
    }

    private static FileSystemRepository fileRepository(Path root) {
        var repository = new FileSystemRepository();
        repository.setRoot(root);
        repository.setId("design");
        repository.setName("Design");
        repository.initialize();
        return repository;
    }

    private static void deleteTree(Path folder) throws IOException {
        try (var paths = Files.walk(folder)) {
            for (var path : paths.sorted((a, b) -> b.compareTo(a)).toList()) {
                Files.delete(path);
            }
        }
    }

    private static String descriptor(String name) {
        return "<project><name>" + name + "</name></project>";
    }

    private static String marker() {
        return RandomStringUtils.secure().nextAlphanumeric(24);
    }

    private static void write(Path file, String content) throws IOException {
        Files.createDirectories(file.getParent());
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    // V1-C: the entry points through which the folder of a new project is chosen (0.6.2.3)
    enum Route {
        TEMPLATE,
        FILES,
        COPY
    }

    // V1-C: the design repository a new project is written to, reached the way the REST route receives it
    enum Backend {
        /** A mocked repository without a local directory, as JDBC, S3 and Azure Blob are: lexical checks only. */
        MOCK,
        /** A flat file repository in {@code tmp/repo} behind {@code SecureRepository}. */
        FLAT,
        /** A mapped file repository in {@code tmp/repo} behind {@code SecureMappedRepository}. */
        MAPPED
    }

    // V1-C: where a link inside the design repository points the folder of a new project (0.6.2.3 C12, C16)
    enum LinkTarget {
        /** A directory outside the repository root (C12). */
        OUTSIDE,
        /** The folder of another project in the same repository (C16). */
        SIBLING,
        /** A path that does not exist, so the link resolves nowhere. */
        DANGLING
    }

    // V1-C: payloads rejected on every backend (C1-C10, C13).
    // The path is checked as the route checks it: a back slash reads as a separator (C5), and a leading slash (C3),
    // given or read from a back slash, is never dropped.
    private static Stream<Arguments> rejectedPayloads() {
        return onEveryRoute(new Backend[]{Backend.MOCK, Backend.FLAT},
                new String[]{"C1", "NewProject", "../../outside"},
                new String[]{"C2", "NewProject", "./p"},
                new String[]{"C2", "NewProject", "a/./p"},
                new String[]{"C3", "NewProject", "/etc/p"},
                new String[]{"C3", "NewProject", "/a/b"},
                new String[]{"C3", "NewProject", "\\a\\b"},
                new String[]{"C4", "NewProject", "C:\\p"},
                new String[]{"C4", "C:p", null},
                new String[]{"C5", "NewProject", "a\\..\\..\\p"},
                new String[]{"C6", "NewProject", "a//p"},
                new String[]{"C7", "NewProject", "..%2Fp"},
                new String[]{"C7", "..%2Fp", null},
                new String[]{"C8", "%252e%252e", null},
                new String[]{"C9", "NewProject", "p\u0000"},
                new String[]{"C10", "NewProject", "p\u0007"},
                new String[]{"C10", "p\n", null},
                new String[]{"C13", "../../p", null});
    }

    // V1-C: Windows reserved names, held to the verdict NameChecker gives them today (0.6.2.3 C11)
    private static Stream<Arguments> reservedNamePayloads() {
        return onEveryRoute(new Backend[]{Backend.MOCK, Backend.FLAT},
                new String[]{"C11", "CON", null},
                new String[]{"C11", "NUL", null},
                new String[]{"C11", "NewProject", "NUL"});
    }

    // V1-C: look-alike separators are ordinary characters (C14), so the write keeps each payload inside the repository.
    // A payload is either rejected or written inside it.
    private static Stream<Arguments> containedPayloads() {
        return onEveryRoute(Backend.values(),
                new String[]{"C14", "..\u2215p", null},
                new String[]{"C14", "\uFF0E\uFF0E", null})
                .filter(ProjectCreationServiceTest::isWritable);
    }

    // V1-C: dot-leading names, a look-alike (C14) among them, on the template and file routes of every backend,
    // with and without a path; the upload stages each in a workspace folder the workspace hides as a service folder
    private static Stream<Arguments> dotLeadingNewProjects() {
        return Stream.of(".hidden", "..x", "..\u2215p")
                .flatMap(name -> Stream.of(Route.TEMPLATE, Route.FILES)
                        .flatMap(route -> Stream.of(Backend.values())
                                .flatMap(backend -> Stream.of(null, "a/b")
                                        .map(path -> Arguments.of(name, route, backend, path)))));
    }

    // V1-C: a '.git' segment stays inside the repository root, so its outcome is recorded only (0.6.2.3 C15, 0.6.5)
    private static Stream<Arguments> gitMetadataPayloads() {
        return onEveryRoute(Backend.values(), new String[]{"C15", "NewProject", ".git/hooks"})
                .filter(ProjectCreationServiceTest::isWritable);
    }

    // V1-C: every link a new project folder could be redirected through, on each route and file layout
    private static Stream<Arguments> linkedProjectFolders() {
        return Stream.of(LinkTarget.values())
                .flatMap(link -> Stream.of(Route.values())
                        .flatMap(route -> Stream.of(Backend.FLAT, Backend.MAPPED)
                                .map(backend -> Arguments.of(link, route, backend))));
    }

    // V1-C: valid new projects at the rules-location root, at the repository root and in a nested folder
    private static Stream<Arguments> validNewProjects() {
        return Stream.of(Route.TEMPLATE, Route.FILES)
                .flatMap(route -> Stream.of(Backend.values())
                        .flatMap(backend -> Stream.of(null, "", "a/b")
                                .map(path -> Arguments.of(route, backend, path))));
    }

    // V1-C: valid copy targets on both file layouts, with and without a path
    private static Stream<Arguments> validCopyTargets() {
        return Stream.of(Backend.FLAT, Backend.MAPPED)
                .flatMap(backend -> Stream.of(null, "a/b").map(path -> Arguments.of(backend, path)));
    }

    // V1-C: a parent path with back slashes, as given and with blanks around it, which the route validates as 'a/b'
    private static Stream<String> backSlashPaths() {
        return Stream.of("a\\b", " a\\b ");
    }

    // V1-C: new projects on the template and file routes of every backend whose parent path has back slashes
    private static Stream<Arguments> backSlashNewProjects() {
        return Stream.of(Route.TEMPLATE, Route.FILES)
                .flatMap(route -> Stream.of(Backend.values())
                        .flatMap(backend -> backSlashPaths().map(path -> Arguments.of(route, backend, path))));
    }

    // V1-C: every real upload to both file layouts whose parent path has back slashes
    private static Stream<Arguments> backSlashUploads() {
        return Stream.of(Upload.values())
                .flatMap(upload -> Stream.of(Backend.FLAT, Backend.MAPPED)
                        .flatMap(backend -> backSlashPaths().map(path -> Arguments.of(upload, backend, path))));
    }

    // V1-C: copy targets on both file layouts whose parent path has back slashes
    private static Stream<Arguments> backSlashCopyTargets() {
        return Stream.of(Backend.FLAT, Backend.MAPPED)
                .flatMap(backend -> backSlashPaths().map(path -> Arguments.of(backend, path)));
    }


    // V1-C: each payload row {id, name, path} on every route and each given backend
    private static Stream<Arguments> onEveryRoute(Backend[] backends, String[]... rows) {
        return Stream.of(rows)
                .flatMap(row -> Stream.of(Route.values())
                        .flatMap(route -> Stream.of(backends)
                                .map(backend -> Arguments.of(row[0], route, backend, row[1], row[2]))));
    }

    // V1-C: a copy is written for real, so it needs a file target; template and file routes run on every backend
    private static boolean isWritable(Arguments arguments) {
        return !(arguments.get()[1] == Route.COPY && arguments.get()[2] == Backend.MOCK);
    }

    // V1-C: a traversal payload never reaches the upload or the copy, and nothing is written (0.6.2.3)
    @ParameterizedTest(name = "{0} {1} on {2}")
    @MethodSource("rejectedPayloads")
    void rejects_a_traversal_payload_before_the_new_project_folder_is_written(String row, Route route,
                                                                              Backend backend, String name,
                                                                              String path) throws IOException {
        creatingUser();
        var target = target(backend);
        var source = sourceWithoutLocalDirectory();
        var before = snapshot(tmp);

        try (var uploaders = uploaders()) {
            assertPathRejected(() -> attempt(route, target, name, path, source));
            assertTrue(uploaders.constructed().isEmpty(), row + ": the upload never runs");
        }

        assertEquals(before, snapshot(tmp), row + ": nothing is created in the temporary directory");
        if (backend == Backend.MOCK) {
            verifyNothingSaved(target);
        }
    }

    // V1-C: a reserved name keeps today's NameChecker verdict, never a looser one (0.6.2.3 C11)
    @ParameterizedTest(name = "{0} {1} on {2}")
    @MethodSource("reservedNamePayloads")
    void keeps_the_name_checker_verdict_on_a_reserved_name(String row, Route route, Backend backend, String name,
                                                           String path) throws IOException {
        creatingUser();
        var target = target(backend);
        var source = sourceWithoutLocalDirectory();
        var effective = path == null || path.isEmpty() ? name : path + "/" + name;

        try (var uploaders = uploaders()) {
            if (isRejectedByNameChecker(effective)) {
                assertPathRejected(() -> attempt(route, target, name, path, source));
                assertTrue(uploaders.constructed().isEmpty(), row + ": the upload never runs");
            } else {
                assertFalse(outcomeOf(() -> attempt(route, target, name, path, source)) instanceof BadRequestException,
                        row + ": a name NameChecker accepts is not rejected as a path");
            }
        }
    }

    // V1-C: a payload the write keeps inside the repository is rejected or written inside it (C14)
    @ParameterizedTest(name = "{0} {1} on {2}")
    @MethodSource("containedPayloads")
    void rejects_or_contains_a_payload_the_write_keeps_inside_the_repository(String row, Route route,
                                                                             Backend backend, String name,
                                                                             String path) throws IOException {
        creatingUser();
        var target = target(backend);
        var source = route == Route.COPY ? sourceInFlatFileRepository() : null;
        var created = new FileData();

        try (var uploaders = uploaders(created)) {
            var outcome = outcomeOf(() -> attempt(route, target, name, path, source));
            if (outcome instanceof BadRequestException rejected) {
                assertEquals("openl.error.400.file.path.invalid.message", rejected.getErrorCode());
                assertTrue(uploaders.constructed().isEmpty(), row + ": the upload never runs");
            } else if (outcome != null) {
                throw new AssertionError(row + ": the call fails", outcome);
            } else if (route == Route.COPY) {
                assertCopiedInside(backend, name, path);
            } else {
                assertUploaded(target, name, path);
            }
        }
        assertNothingOutside("repo", "design");
    }

    // V1-C: a dot-leading name is rejected before the upload stages it, so no project is reported created while
    // nothing is saved and no access entry is granted for it (C14)
    @ParameterizedTest(name = "{0} {1} on {2} with path {3}")
    @MethodSource("dotLeadingNewProjects")
    void rejects_a_dot_leading_project_name_before_the_upload_stages_it(String name, Route route, Backend backend,
                                                                         String path) throws IOException {
        creatingUser();
        var target = target(backend);
        var before = snapshot(tmp);

        try (var uploaders = uploaders()) {
            assertPathRejected(() -> attempt(route, target, name, path, null));
            assertTrue(uploaders.constructed().isEmpty(), name + ": the upload never runs");
        }

        assertEquals(before, snapshot(tmp), name + ": nothing is created in the temporary directory");
        if (backend == Backend.MOCK) {
            verifyNothingSaved(target);
        }
    }

    // V1-C: a dot inside a name is an ordinary character, so such a new project reaches the upload unchanged
    @ParameterizedTest(name = "{0} on {1} with path {2}")
    @MethodSource("validNewProjects")
    void hands_a_project_name_with_an_inner_dot_to_the_upload(Route route, Backend backend, String path)
            throws IOException {
        creatingUser();
        var target = target(backend);
        var created = new FileData();

        try (var ignored = uploaders(created)) {
            assertSame(created, attempt(route, target, "My.Project", path, null));
        }

        assertUploaded(target, "My.Project", path);
    }

    // V1-C: a '.git' path is recorded only: no failure but a 400, and nothing outside the repositories (C15)
    @ParameterizedTest(name = "{0} {1} on {2}")
    @MethodSource("gitMetadataPayloads")
    void records_a_git_metadata_path_without_writing_outside_the_repository(String row, Route route,
                                                                            Backend backend, String name,
                                                                            String path) throws IOException {
        creatingUser();
        var target = target(backend);
        var source = route == Route.COPY ? sourceInFlatFileRepository() : null;

        try (var ignored = uploaders()) {
            var outcome = outcomeOf(() -> attempt(route, target, name, path, source));
            if (outcome != null && !(outcome instanceof BadRequestException)) {
                throw new AssertionError(row + ": the call fails", outcome);
            }
        }
        assertNothingOutside("repo", "design");
    }

    // V1-C: a link in the design repository never redirects the new project folder (C12, C16, dangling).
    // Flat, the project is named after the link in the rules location.
    // Mapped, the link is the parent path of project 'p'.
    @ParameterizedTest(name = "{0} {1} on {2}")
    @MethodSource("linkedProjectFolders")
    @DisabledOnOs(OS.WINDOWS)
    void rejects_a_new_project_folder_a_link_redirects(LinkTarget link, Route route, Backend backend)
            throws IOException {
        creatingUser();
        var flat = backend == Backend.FLAT;
        var root = Files.createDirectories(tmp.resolve("repo"));
        var outside = Files.createDirectories(tmp.resolve("outside"));
        // V1-C: a regular file with generated content outside the repository, so a write through the link is seen
        write(outside.resolve("sentinel.txt"), marker());
        var sibling = root.resolve(flat ? "DESIGN/rules/Sibling" : "projects/Sibling");
        write(sibling.resolve("rules.xml"), descriptor("Sibling"));
        var target = secureFileRepository(root, !flat);
        var linkName = link == LinkTarget.DANGLING ? "ghost" : "link";
        var linkFolder = Files.createDirectories(flat ? root.resolve("DESIGN/rules") : root);
        Files.createSymbolicLink(linkFolder.resolve(linkName), switch (link) {
            case OUTSIDE -> outside;
            case SIBLING -> sibling;
            case DANGLING -> outside.resolve("missing");
        });
        var name = flat ? linkName : "p";
        var path = flat ? null : linkName;
        var source = route == Route.COPY ? sourceInFlatFileRepository() : null;
        // V1-C: the complete outside, sibling and repository state, each compared again after the rejection
        var rootBefore = snapshot(root);
        var siblingBefore = snapshot(sibling);
        var outsideBefore = snapshot(outside);

        try (var uploaders = uploaders()) {
            assertPathRejected(() -> attempt(route, target, name, path, source));
            assertTrue(uploaders.constructed().isEmpty(), "The upload never runs");
        }

        assertEquals(outsideBefore, snapshot(outside), "Nothing is written through the link");
        assertEquals(siblingBefore, snapshot(sibling), "The sibling project is unchanged");
        assertEquals(rootBefore, snapshot(root), "Nothing is written to the repository");
    }

    // V1-C: a valid new project reaches the upload unchanged, also before the rules location exists (0.3.3.3)
    @ParameterizedTest(name = "{0} on {1} with path {2}")
    @MethodSource("validNewProjects")
    void hands_a_valid_new_project_to_the_upload(Route route, Backend backend, String path) throws IOException {
        creatingUser();
        var target = target(backend);
        assertFalse(Files.exists(tmp.resolve("repo/DESIGN")), "The rules location does not exist yet");
        var created = new FileData();

        try (var ignored = uploaders(created)) {
            assertSame(created, attempt(route, target, "NewProject", path, null));
        }

        assertUploaded(target, "NewProject", path);
        // V1-C: a file repository is written through the write check; a backend without a local folder is not
        assertEquals(backend != Backend.MOCK, uploadedRepository() != target, "Only a local folder is write-checked");
    }

    // V1-C: the check walks up from the deepest existing folder, so a repository root not created yet is accepted
    @ParameterizedTest
    @EnumSource(value = Route.class, names = {"TEMPLATE", "FILES"})
    void hands_a_new_project_to_the_upload_before_the_repository_root_exists(Route route) throws IOException {
        creatingUser();
        var target = secureFileRepository(tmp.resolve("absent/repo"), false);
        var created = new FileData();

        try (var ignored = uploaders(created)) {
            assertSame(created, attempt(route, target, "NewProject", null, null));
        }

        assertUploaded(target, "NewProject", null);
        assertFalse(Files.exists(tmp.resolve("absent"), LinkOption.NOFOLLOW_LINKS), "The check creates nothing");
    }

    // V1-C: a valid copy target passes the checks on a backend without a local directory, with and without a path.
    // The back slashes of a given path read as separators.
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"a/b", "a\\b"})
    void copy_project_passes_a_valid_target_on_a_backend_without_a_local_directory(String path) throws IOException {
        var workspace = creatingUser();
        var repository = mock(Repository.class);
        when(repository.getId()).thenReturn("design");
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setVersions(true).build());
        when(repository.check("DESIGN/Source")).thenReturn(fileData("9"));
        when(repository.checkHistory("DESIGN/Source", "5")).thenReturn(fileData("5"));
        var source = mock(RulesProject.class);
        when(source.getRepository()).thenReturn(repository);
        when(source.getFolderPath()).thenReturn("DESIGN/Source");
        var target = targetRepositoryMock();

        // The mocked target is not set up for a write, so the copy may fail after the checks, but never as a 400.
        var outcome = outcomeOf(() -> service.copyProject(target, "NewProject", path, source, "comment", "5"));

        assertFalse(outcome instanceof BadRequestException, "A valid target is not rejected as a path");
        verify(repository).checkHistory("DESIGN/Source", "5");
        // The user is looked up only after the path checks, so the copy got past them.
        verify(workspace).getUser();
    }

    // V1-C: a valid copy is written into its own physical folder of a flat or mapped file repository
    @ParameterizedTest(name = "{0} with path {1}")
    @MethodSource("validCopyTargets")
    void copy_project_writes_a_valid_copy_into_its_own_folder(Backend backend, String path) throws IOException {
        creatingUser();
        var target = target(backend);
        var source = sourceInFlatFileRepository();

        assertNotNull(service.copyProject(target, "NewProject", path, source, "comment", null));

        var copied = assertCopiedInside(backend, "NewProject", path);
        assertEquals(Files.readString(tmp.resolve("design/DESIGN/rules/Src/src.txt")),
                Files.readString(copied.resolve("src.txt")));
        assertNothingOutside("repo", "design");
    }

    // V1-C: the route reads the back slashes of a parent path as separators, so the new project is accepted.
    // It is handed to the upload with the path as the service passes it on, through the write check when a local
    // folder takes it.
    @ParameterizedTest(name = "{0} on {1} with path {2}")
    @MethodSource("backSlashNewProjects")
    void hands_a_new_project_whose_path_has_back_slashes_to_the_upload(Route route, Backend backend, String path)
            throws IOException {
        creatingUser();
        var target = target(backend);
        var created = new FileData();

        try (var ignored = uploaders(created)) {
            assertSame(created, attempt(route, target, "NewProject", path, null));
        }

        assertUploaded(target, "NewProject", path);
        assertEquals(backend != Backend.MOCK, uploadedRepository() != target, "Only a local folder is write-checked");
        assertNothingOutside("repo");
    }

    // V1-C: a real upload whose parent path has back slashes lands where the route's 'a/b' places it.
    // A mapped repository places it in folder a/b and a flat one in its rules location.
    // Nothing is written outside the repository.
    @ParameterizedTest(name = "{0} on {1} with path {2}")
    @MethodSource("backSlashUploads")
    void uploads_a_new_project_whose_path_has_back_slashes_where_the_route_places_it(Upload upload, Backend backend,
                                                                                      String path) throws IOException {
        realUploads();
        var target = target(backend);

        assertNotNull(upload(upload, target, "NewProject", path));

        var project = backend == Backend.MAPPED ? "repo/a/b/NewProject" : "repo/DESIGN/rules/NewProject";
        assertWrittenInside(tmp.resolve(project));
        assertNothingOutside("repo");
        assertReleased();
    }

    // V1-C: a copy whose parent path has back slashes is written where the route's 'a/b' places it
    @ParameterizedTest(name = "{0} with path {1}")
    @MethodSource("backSlashCopyTargets")
    void copy_project_writes_a_copy_whose_path_has_back_slashes_where_the_route_places_it(Backend backend, String path)
            throws IOException {
        creatingUser();
        var target = target(backend);
        var source = sourceInFlatFileRepository();

        assertNotNull(service.copyProject(target, "NewProject", path, source, "comment", null));

        var copied = assertCopiedInside(backend, "NewProject", "a/b");
        assertEquals(Files.readString(tmp.resolve("design/DESIGN/rules/Src/src.txt")),
                Files.readString(copied.resolve("src.txt")));
        assertNothingOutside("repo", "design");
    }

    // V1-C: a blank name is left to the bean validation that owns it, so the path check does not answer for it
    @ParameterizedTest
    @EnumSource(value = Route.class, names = {"TEMPLATE", "FILES"})
    void leaves_a_blank_project_name_to_the_bean_validation(Route route) throws IOException {
        creatingUser();
        var target = target(Backend.FLAT);

        try (var ignored = uploaders()) {
            assertFalse(outcomeOf(() -> attempt(route, target, " ", null, null)) instanceof BadRequestException,
                    "A blank name is not rejected as a path");
        }

        assertUploaded(target, " ", null);
    }

    // V1-C: a rules location that climbs out of the repository root places every new project folder outside it
    @ParameterizedTest
    @EnumSource(Route.class)
    void rejects_a_new_project_folder_when_the_rules_location_climbs_out_of_the_repository(Route route)
            throws IOException {
        creatingUser("../elsewhere/");
        var target = target(Backend.FLAT);
        var source = sourceWithoutLocalDirectory();
        var before = snapshot(tmp);

        try (var uploaders = uploaders()) {
            assertPathRejected(() -> attempt(route, target, "NewProject", null, source));
            assertTrue(uploaders.constructed().isEmpty(), "The upload never runs");
        }

        assertEquals(before, snapshot(tmp), "Nothing is created in the temporary directory");
    }

    // V1-C: an unknown template keeps its existing 404, which is decided before the path is checked
    @Test
    void keeps_the_not_found_answer_for_an_unknown_template_before_the_path_is_checked() {
        creatingUser();
        var target = targetRepositoryMock();

        try (var uploaders = uploaders()) {
            var e = assertThrows(NotFoundException.class, () -> service.createFromTemplate(target, "NewProject",
                    "../../outside", "predefined", "templates", "No Such Template", "comment", null));
            assertEquals("openl.error.404.project.template.not-found.message", e.getErrorCode());
            assertTrue(uploaders.constructed().isEmpty(), "The upload never runs");
        }
    }

    // V1-C: a repository failure after the path checks keeps its existing 409; only the path checks answer 400
    @ParameterizedTest
    @EnumSource(value = Route.class, names = {"TEMPLATE", "FILES"})
    void keeps_the_conflict_answer_for_an_upload_the_repository_fails_after_the_path_checks(Route route)
            throws IOException {
        creatingUser();
        var target = target(Backend.FLAT);

        try (var uploaders = Mockito.mockConstruction(ProjectUploader.class, (uploader, context) ->
                when(uploader.uploadProject()).thenThrow(new ProjectException("The repository refused the write.")))) {
            var e = assertThrows(ConflictException.class, () -> attempt(route, target, "NewProject", "a/b", null));
            assertEquals("openl.error.409.project.create.failed.message", e.getErrorCode());
            assertEquals(1, uploaders.constructed().size(), "The upload ran after the path checks");
        }
    }

    // V1-C: a copy the file repository cannot write keeps its existing 409, raised after the path checks passed
    @Test
    void keeps_the_conflict_answer_for_a_copy_the_repository_fails_to_write() throws IOException {
        creatingUser();
        var target = target(Backend.FLAT);
        // A regular file where the rules location belongs: inside the root, so contained, but not writable as a folder.
        write(tmp.resolve("repo/DESIGN"), marker());
        var source = sourceInFlatFileRepository();

        var e = assertThrows(ConflictException.class,
                () -> service.copyProject(target, "NewProject", null, source, "comment", null));

        assertEquals("openl.error.409.project.copy.failed.message", e.getErrorCode());
        assertNothingOutside("repo", "design");
    }

    // V1-C: a source folder that climbs out of its repository root is refused before anything is read from it
    @Test
    void copy_project_rejects_a_source_folder_that_climbs_out_of_its_repository() throws IOException {
        layOutSource(SourceLayout.FLAT);
        var files = spy(fileRepository(tmp.resolve("design")));
        var target = targetRepositoryMock();

        var e = assertThrows(BadRequestException.class, () -> copy(secured(files), "../escaped/Src", target));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        verify(files, never()).list(anyString());
        verify(files, never()).read(anyString());
        verifyNothingSaved(target);
    }

    // V1-C: a listed source name that climbs out of the project folder through '..' fails closed
    @Test
    void copy_project_rejects_a_listed_source_file_that_climbs_out_of_the_project_folder() throws IOException {
        layOutSource(SourceLayout.FLAT);
        var source = source(SourceLayout.FLAT);
        var stray = new FileData();
        stray.setName("DESIGN/rules/Src/../Sib/rules.xml");
        doReturn(List.of(stray)).when(source.files()).list(source.listing());
        var target = targetRepositoryMock();

        var e = assertThrows(BadRequestException.class, () -> copy(source, target));

        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        verify(source.files(), never()).read(anyString());
        verifyNothingSaved(target);
    }

    // V1-D: the design repository an upload overwrites project 'Existing' of, each writing through a local folder
    enum OverwriteBackend {
        /** A flat file repository in {@code tmp/repo} behind {@code SecureRepository}: {@code DESIGN/rules/}. */
        FLAT,
        /** A mapped file repository in {@code tmp/repo} behind {@code SecureMappedRepository}: {@code projects/}. */
        MAPPED,
        /** A file repository configured over {@code tmp/repo}, so path-checked, and secured: {@code DESIGN/rules/}. */
        CONFIGURED_FILE,
        /** A Git repository configured over {@code tmp/repo} and secured: {@code DESIGN/rules/} of its working tree. */
        GIT
    }

    // V1-C: the uploads of the REST route, each writing rules.xml and rules/Main.xlsx into the project folder
    enum Upload {
        /** The bundled empty template, which brings its own descriptor. */
        TEMPLATE,
        /** One uploaded workbook, for which the upload generates the descriptor. */
        FILES,
        /** An uploaded archive, as the last uploaded file. */
        ARCHIVE
    }

    // V1-C: an entry of project 'Existing' the overwrite writes through, and where a link there leads
    enum WriteThrough {
        /** The descriptor links to an outside file. */
        DESCRIPTOR_TO_OUTSIDE_FILE,
        /** The workbook folder links to an outside folder. */
        RULES_TO_OUTSIDE,
        /** The workbook folder links to the folder of the sibling project. */
        RULES_TO_SIBLING,
        /** The workbook folder links to nothing. */
        RULES_TO_NOTHING
    }

    // V1-C: where the target branch holds a link the upload of new project 'Fresh' writes through
    enum TargetLink {
        /** The project folder itself links to an outside folder. */
        PROJECT_FOLDER("DESIGN/rules/Fresh", false),
        /** The rules location the project folder sits in links to an outside folder. */
        ANCESTOR("DESIGN/rules", false),
        /** The workbook every upload writes links to an outside file. */
        WORKBOOK("DESIGN/rules/Fresh/rules/Main.xlsx", true);

        private final String path;
        private final boolean toFile;

        TargetLink(String path, boolean toFile) {
            this.path = path;
            this.toFile = toFile;
        }
    }

    // V1-C: each write-through link with the template on every backend, and the descriptor link with every upload
    private static Stream<Arguments> writesThroughLinks() {
        return Stream.of(WriteThrough.values())
                .flatMap(through -> Stream.of(Upload.values())
                        .filter(upload -> through == WriteThrough.DESCRIPTOR_TO_OUTSIDE_FILE
                                || upload == Upload.TEMPLATE)
                        .flatMap(upload -> Stream.of(OverwriteBackend.values())
                                .map(backend -> Arguments.of(through, upload, backend))));
    }

    // V1-C: every link of the target branch with every upload
    private static Stream<Arguments> targetBranchLinks() {
        return Stream.of(TargetLink.values())
                .flatMap(link -> Stream.of(Upload.values()).map(upload -> Arguments.of(link, upload)));
    }

    // V1-C: every link a Git working tree could redirect the folder of a copy through, flat and mapped
    private static Stream<Arguments> gitLinkedCopyFolders() {
        return Stream.of(LinkTarget.values())
                .flatMap(link -> Stream.of(false, true).map(mapped -> Arguments.of(link, mapped)));
    }

    // V1-C: valid copy targets of a Git repository, flat and mapped, with and without a path
    private static Stream<Arguments> validGitCopyTargets() {
        return Stream.of(false, true)
                .flatMap(mapped -> Stream.of(null, "a/b").map(path -> Arguments.of(mapped, path)));
    }

    // V1-C: a real overwrite runs when its folder holds a link to an outside file it neither writes through nor reads.
    // The outside file stays as it was.
    @ParameterizedTest
    @EnumSource(OverwriteBackend.class)
    @DisabledOnOs(OS.WINDOWS)
    void overwrites_a_project_whose_folder_holds_an_unused_link_to_an_outside_file(OverwriteBackend backend)
            throws Exception {
        realUploads();
        var target = overwriteTarget(backend);
        var project = uploadedProject(target, backend);
        var outside = outsideFolder();
        placeLink(backend, project.resolve("notes.txt"), outside.resolve("canary.txt"));
        var outsideBefore = snapshot(outside);

        assertNotNull(upload(Upload.TEMPLATE, target, "Existing", overwritePath(backend)));

        assertEquals(outsideBefore, snapshot(outside), "Nothing is written through the link");
        assertWrittenInside(project);
    }

    // V1-C: an overwrite that writes through a link its folder holds is refused, whatever the link leads to.
    // The save refuses it before anything is written through the link.
    // Nothing outside the project changes, and the uploaded files are released.
    @ParameterizedTest(name = "{0} by {1} on {2}")
    @MethodSource("writesThroughLinks")
    @DisabledOnOs(OS.WINDOWS)
    void refuses_an_overwrite_that_writes_through_a_link_its_folder_holds(WriteThrough through, Upload upload,
                                                                         OverwriteBackend backend) throws Exception {
        realUploads();
        var target = overwriteTarget(backend);
        var project = uploadedProject(target, backend);
        var outside = outsideFolder();
        var sibling = siblingProject(backend);
        switch (through) {
            case DESCRIPTOR_TO_OUTSIDE_FILE -> placeLink(backend, project.resolve("rules.xml"),
                    outside.resolve("canary.txt"));
            case RULES_TO_OUTSIDE -> placeLink(backend, project.resolve("rules"), outside);
            case RULES_TO_SIBLING -> placeLink(backend, project.resolve("rules"), sibling);
            case RULES_TO_NOTHING -> placeLink(backend, project.resolve("rules"), outside.resolve("missing"));
        }
        var outsideBefore = snapshot(outside);
        var siblingBefore = snapshot(sibling);

        assertPathRejected(() -> upload(upload, target, "Existing", overwritePath(backend)));

        assertEquals(outsideBefore, snapshot(outside), "Nothing is written through the link");
        assertEquals(siblingBefore, snapshot(sibling), "The sibling project is unchanged");
        assertReleased();
    }

    // V1-C: links that stay inside the existing project folder do not stop the real overwrite
    @ParameterizedTest
    @EnumSource(OverwriteBackend.class)
    @DisabledOnOs(OS.WINDOWS)
    void overwrites_a_project_whose_links_stay_inside_it(OverwriteBackend backend) throws Exception {
        realUploads();
        var target = overwriteTarget(backend);
        var project = uploadedProject(target, backend);
        placeLink(backend, project.resolve("alias"), project.resolve("rules"));
        placeLink(backend, project.resolve("self"), Path.of("."));
        placeLink(backend, project.resolve("rules/descriptor.xml"), Path.of("../rules.xml"));

        assertNotNull(upload(Upload.TEMPLATE, target, "Existing", overwritePath(backend)));

        assertWrittenInside(project);
        assertNothingOutside("repo");
    }

    // V1-C: an upload through a link only the target branch holds is refused while another branch is checked out.
    // A Git save checks out its target branch only when it writes, so the link is found in the tree the write goes
    // through, and no upload writes through it.
    @ParameterizedTest(name = "{0} by {1}")
    @MethodSource("targetBranchLinks")
    @DisabledOnOs(OS.WINDOWS)
    void refuses_an_upload_through_a_link_only_the_target_branch_holds(TargetLink link, Upload upload)
            throws Exception {
        realUploads();
        var root = tmp.resolve("repo");
        var repository = gitWithTargetBranch(root);
        var outside = outsideFolder();
        commitLink(root, TARGET_BRANCH, link.path, link.toFile ? outside.resolve("canary.txt") : outside);
        assertCheckedOut(root, BASE_BRANCH);
        assertFalse(Files.exists(root.resolve(link.path), LinkOption.NOFOLLOW_LINKS),
                "Fixture: the checked-out tree holds no link");
        var onTarget = repository.forBranch(TARGET_BRANCH);
        var outsideBefore = snapshot(outside);

        assertPathRejected(() -> upload(upload, onTarget, "Fresh", ""));

        assertEquals(outsideBefore, snapshot(outside), "Nothing is written through the link of the target branch");
        assertNull(onTarget.check("DESIGN/rules/Fresh/rules.xml"), "Nothing of the project is committed");
        assertReleased();
    }

    // V1-C: an upload to a clean target branch runs while only the checked-out branch holds a link.
    // The link is gone once the save checks out the target branch, so the project is written inside the repository.
    @ParameterizedTest
    @EnumSource(Upload.class)
    @DisabledOnOs(OS.WINDOWS)
    void uploads_to_a_clean_target_branch_while_the_checked_out_branch_holds_a_link(Upload upload) throws Exception {
        realUploads();
        var root = tmp.resolve("repo");
        var repository = gitWithTargetBranch(root);
        var outside = outsideFolder();
        commitLink(root, BASE_BRANCH, "DESIGN/rules/Fresh", outside);
        assertTrue(Files.isSymbolicLink(root.resolve("DESIGN/rules/Fresh")),
                "Fixture: the checked-out tree holds the link");
        var onTarget = repository.forBranch(TARGET_BRANCH);
        var outsideBefore = snapshot(outside);

        assertNotNull(upload(upload, onTarget, "Fresh", ""));

        assertEquals(outsideBefore, snapshot(outside), "Nothing is written outside the repository");
        assertNotNull(onTarget.check("DESIGN/rules/Fresh/rules.xml"), "The project is committed on the target branch");
        assertCheckedOut(root, TARGET_BRANCH);
        assertWrittenInside(root.resolve("DESIGN/rules/Fresh"));
    }

    // V1-C: a full Git overwrite is refused when its folder holds a folder link out of the project.
    // Nothing is written through the link.
    // The refusal holds because the full save descends into every folder link to remove what it does not carry.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void refuses_a_full_git_overwrite_whose_cleanup_would_enter_a_folder_link_out_of_the_project() throws Exception {
        realUploads();
        var target = fullChangesetGit();
        var project = uploadedProject(target, OverwriteBackend.GIT);
        var outside = outsideFolder();
        placeLink(OverwriteBackend.GIT, project.resolve("vendor"), outside);
        var outsideBefore = snapshot(outside);

        assertPathRejected(() -> upload(Upload.TEMPLATE, target, "Existing", ""));

        assertEquals(outsideBefore, snapshot(outside), "Nothing outside the project is touched");
        assertTrue(Files.isSymbolicLink(project.resolve("vendor")), "The project is left as it was");
    }

    // V1-C: a full Git overwrite runs when its folder holds only links its cleanup removes.
    // That cleanup removes only a link to a file, a link to nothing and a folder link that stays inside the project.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void runs_a_full_git_overwrite_whose_folder_holds_only_links_its_cleanup_removes() throws Exception {
        realUploads();
        var target = fullChangesetGit();
        var project = uploadedProject(target, OverwriteBackend.GIT);
        var outside = outsideFolder();
        placeLink(OverwriteBackend.GIT, project.resolve("notes.txt"), outside.resolve("canary.txt"));
        placeLink(OverwriteBackend.GIT, project.resolve("ghost"), outside.resolve("missing"));
        placeLink(OverwriteBackend.GIT, project.resolve("alias"), project.resolve("rules"));
        var outsideBefore = snapshot(outside);

        assertNotNull(upload(Upload.TEMPLATE, target, "Existing", ""));

        assertEquals(outsideBefore, snapshot(outside), "Nothing outside the project is touched");
        assertWrittenInside(project);
    }

    // V1-C: a copy into a Git repository never writes through a link its working tree holds (C12, C16, dangling).
    // The link is untracked, as one planted in the working tree by hand is.
    // Flat, the copy is named after the link in the rules location.
    // Mapped as Studio maps its design repository, the link is the parent path of copy 'p'.
    // The save refuses the copy in the tree it checks out: nothing outside or in the sibling changes, nothing is
    // committed.
    @ParameterizedTest(name = "{0} mapped: {1}")
    @MethodSource("gitLinkedCopyFolders")
    @DisabledOnOs(OS.WINDOWS)
    void refuses_a_git_copy_whose_folder_a_working_tree_link_redirects(LinkTarget link, boolean mapped)
            throws Exception {
        realUploads();
        var root = tmp.resolve("repo");
        var git = seededGit(root);
        var target = mapped ? mappedGit(git) : secured(git);
        var outside = outsideFolder();
        var sibling = root.resolve(mapped ? "projects/Sibling" : "DESIGN/rules/Sibling");
        write(sibling.resolve("rules.xml"), descriptor("Sibling"));
        var linkName = link == LinkTarget.DANGLING ? "ghost" : "link";
        var linkFolder = Files.createDirectories(mapped ? root : root.resolve("DESIGN/rules"));
        Files.createSymbolicLink(linkFolder.resolve(linkName), switch (link) {
            case OUTSIDE -> outside;
            case SIBLING -> sibling;
            case DANGLING -> outside.resolve("missing");
        });
        var name = mapped ? "p" : linkName;
        var path = mapped ? linkName : null;
        var source = sourceInFlatFileRepository();
        var outsideBefore = snapshot(outside);
        var siblingBefore = snapshot(sibling);

        assertPathRejected(() -> service.copyProject(target, name, path, source, "comment", null));

        assertEquals(outsideBefore, snapshot(outside), "Nothing is written through the link");
        assertEquals(siblingBefore, snapshot(sibling), "The sibling project is unchanged");
        var folder = mapped ? FileMappingData.internalPath(path, name) : "DESIGN/rules/" + name;
        assertNull(git.check(folder + "/rules.xml"), "Nothing of the copy is committed");
        assertNothingOutside("repo", "design", "outside");
    }

    // V1-C: a copy through a link only the target branch holds is refused while another branch is checked out.
    // A Git save checks out its target branch only when it writes, so the link is found in the tree the write goes
    // through, and nothing of the copy is written through it or committed.
    @ParameterizedTest
    @EnumSource(value = TargetLink.class, names = {"PROJECT_FOLDER", "ANCESTOR"})
    @DisabledOnOs(OS.WINDOWS)
    void refuses_a_copy_through_a_link_only_the_target_branch_holds(TargetLink link) throws Exception {
        realUploads();
        var root = tmp.resolve("repo");
        var repository = gitWithTargetBranch(root);
        var outside = outsideFolder();
        commitLink(root, TARGET_BRANCH, link.path, outside);
        assertCheckedOut(root, BASE_BRANCH);
        assertFalse(Files.exists(root.resolve(link.path), LinkOption.NOFOLLOW_LINKS),
                "Fixture: the checked-out tree holds no link");
        var onTarget = repository.forBranch(TARGET_BRANCH);
        var source = sourceInFlatFileRepository();
        var outsideBefore = snapshot(outside);

        assertPathRejected(() -> service.copyProject(onTarget, "Fresh", null, source, "comment", null));

        assertEquals(outsideBefore, snapshot(outside), "Nothing is written through the link of the target branch");
        assertNull(onTarget.check("DESIGN/rules/Fresh/rules.xml"), "Nothing of the copy is committed");
    }

    // V1-C: a copy into a file repository is refused when its folder becomes a link after the path check passed.
    // The whole changeset is checked before the repository takes any of it, by the workspace copy first, so the
    // refusal is still the 400, never a copy conflict, and nothing is written through the link.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void refuses_a_file_copy_whose_folder_a_link_redirects_after_the_path_check() throws IOException {
        creatingUser();
        var target = target(Backend.FLAT);
        var outside = outsideFolder();
        layOutSource(SourceLayout.FLAT);
        var copySource = source(SourceLayout.FLAT);
        var folder = tmp.resolve("repo/DESIGN/rules/NewProject");
        // The source is listed only after the folder of the copy was checked; the folder becomes a link right then.
        doAnswer(invocation -> {
            if (!Files.exists(folder, LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectories(folder.getParent());
                Files.createSymbolicLink(folder, outside);
            }
            return invocation.callRealMethod();
        }).when(copySource.files()).list(copySource.listing());
        var source = mock(RulesProject.class);
        when(source.getRepository()).thenReturn(copySource.repository());
        when(source.getFolderPath()).thenReturn(copySource.folderPath());
        var outsideBefore = snapshot(outside);

        assertPathRejected(() -> service.copyProject(target, "NewProject", null, source, "comment", null));

        assertEquals(outsideBefore, snapshot(outside), "Nothing is written through the link");
        // The source was read for the write, so the refusal came from the write check, not from the path check.
        verify(copySource.files()).read("DESIGN/rules/Src/src.txt");
    }

    // V1-C: a Git copy is refused when its folder, already in the working tree untracked, holds a file link out of it.
    // The workspace copy finds the link before the write check does, and its refusal is still the 400, never a copy
    // conflict. Nothing is written through the link and nothing of the copy is committed.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void refuses_a_git_copy_whose_workspace_check_finds_a_file_link_in_the_untracked_folder() throws Exception {
        realUploads();
        var root = tmp.resolve("repo");
        var git = seededGit(root);
        var target = secured(git);
        var outside = outsideFolder();
        var folder = Files.createDirectories(root.resolve("DESIGN/rules/NewProject"));
        Files.createSymbolicLink(folder.resolve("src.txt"), outside.resolve("canary.txt"));
        var source = sourceInFlatFileRepository();
        var outsideBefore = snapshot(outside);

        // A blank path and revision are read as none: the copy goes to the rules location from the latest state.
        assertPathRejected(() -> service.copyProject(target, "NewProject", "", source, "comment", ""));

        assertEquals(outsideBefore, snapshot(outside), "Nothing is written through the link");
        assertNull(git.check("DESIGN/rules/NewProject/rules.xml"), "Nothing of the copy is committed");
        assertTrue(Files.isSymbolicLink(folder.resolve("src.txt")), "The working tree is left as it was");
        assertNothingOutside("repo", "design", "outside");
    }

    // V1-C: a valid copy into a Git repository is committed in its own folder of the working tree.
    // Mapped as Studio maps its design repository, it lands at the repository root or in the nested path; flat, at
    // the root of the rules location. It holds the source content, and nothing is written outside the repositories.
    @ParameterizedTest(name = "mapped: {0} with path {1}")
    @MethodSource("validGitCopyTargets")
    void copy_project_commits_a_valid_copy_into_its_own_folder_of_a_git_working_tree(boolean mapped, String path)
            throws Exception {
        realUploads();
        var root = tmp.resolve("repo");
        var git = seededGit(root);
        var target = mapped ? mappedGit(git) : secured(git);
        var source = sourceInFlatFileRepository();

        assertNotNull(service.copyProject(target, "NewProject", path, source, "comment", null));

        var copied = assertCopiedInside(mapped ? Backend.MAPPED : Backend.FLAT, "NewProject", path);
        var original = tmp.resolve("design/DESIGN/rules/Src");
        for (var file : List.of("src.txt", "sub/inside.txt")) {
            assertEquals(Files.readString(original.resolve(file)), Files.readString(copied.resolve(file)),
                    file + " holds the source content");
        }
        var folder = root.relativize(copied).toString();
        for (var file : List.of("rules.xml", "src.txt", "sub/inside.txt")) {
            assertNotNull(git.check(folder + "/" + file), file + " is committed");
        }
        assertNothingOutside("repo", "design");
    }

    // V1-C: the template route resolves the new project folder once, so the rules location is read once.
    // The resolved folder is handed to the upload.
    @Test
    void resolves_the_folder_of_a_template_project_once() throws IOException {
        var workspace = creatingUser();
        var target = target(Backend.FLAT);

        try (var ignored = uploaders()) {
            assertNotNull(createFromTemplate(target, "NewProject", null));
        }

        assertUploaded(target, "NewProject", null);
        verify(workspace.getDesignTimeRepository(), times(1)).getRulesLocation();
    }

    // V1-C: the write check passes every call but the changeset save on as it is.
    // It unwraps to the repository it checks and is equal only to itself.
    @Test
    void the_write_check_passes_other_calls_on_and_unwraps_to_its_repository() throws IOException {
        creatingUser();
        var target = target(Backend.FLAT);
        try (var ignored = uploaders()) {
            createFromFiles(target, "NewProject", null);
        }
        var checked = uploadedRepository();
        var single = new FileData();
        single.setName("DESIGN/rules/NewProject/notes.txt");

        assertSame(target, ((RepositoryDelegate) checked).getOriginal());
        assertEquals(target.getId(), checked.getId());
        assertTrue(checked.equals(uploadedRepository()), "The write check equals itself");
        assertFalse(checked.equals(target), "The write check is not the repository it checks");
        assertEquals(System.identityHashCode(checked), checked.hashCode());
        assertEquals(target.toString(), checked.toString());
        assertNotNull(checked.save(single, new ByteArrayInputStream(marker().getBytes(StandardCharsets.UTF_8))));
        assertTrue(Files.isRegularFile(tmp.resolve("repo/DESIGN/rules/NewProject/notes.txt")),
                "A single-file save is passed on as it is");
    }

    // V1-C: a changeset naming a change outside the new project folder is refused before anything is written.
    // The change names another folder or climbs out of the project folder.
    @ParameterizedTest
    @ValueSource(strings = {"DESIGN/rules/Other/rules.xml", "DESIGN/rules/NewProject/../Other/rules.xml"})
    void the_write_check_refuses_a_change_named_outside_the_project_folder(String name) throws IOException {
        creatingUser();
        var target = target(Backend.FLAT);
        try (var ignored = uploaders()) {
            createFromFiles(target, "NewProject", null);
        }
        var checked = uploadedRepository();
        var stray = new FileItem(name, tracked(descriptor("Other")));

        var e = assertThrows(RuntimeException.class,
                () -> checked.save(folderData("DESIGN/rules/NewProject"), List.of(stray), ChangesetType.FULL));

        var refusal = assertInstanceOf(BadRequestException.class, e.getCause());
        assertEquals("openl.error.400.file.path.invalid.message", refusal.getErrorCode());
        assertFalse(Files.exists(tmp.resolve("repo/DESIGN/rules/Other"), LinkOption.NOFOLLOW_LINKS),
                "Nothing is written");
    }

    // V1-C: a one-pass changeset is checked change by change as a file repository takes it.
    // A refused change has its stream closed, and nothing is written through the link.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void the_write_check_checks_a_one_pass_changeset_as_a_file_repository_takes_it() throws IOException {
        creatingUser();
        var target = target(Backend.FLAT);
        try (var ignored = uploaders()) {
            createFromFiles(target, "NewProject", null);
        }
        var checked = uploadedRepository();
        var outside = outsideFolder();
        var project = tmp.resolve("repo/DESIGN/rules/NewProject");
        replaceWithLink(project.resolve("linked"), outside);
        var outsideBefore = snapshot(outside);
        var inside = new FileItem("DESIGN/rules/NewProject/rules.xml", tracked(descriptor("NewProject")));
        var through = new FileItem("DESIGN/rules/NewProject/linked/evil.xlsx", tracked(marker()));
        var folder = folderData("DESIGN/rules/NewProject");

        assertNotNull(checked.save(folder, () -> List.of(inside).iterator(), ChangesetType.DIFF));
        var e = assertThrows(RuntimeException.class,
                () -> checked.save(folder, () -> List.of(through).iterator(), ChangesetType.DIFF));

        assertInstanceOf(BadRequestException.class, e.getCause());
        assertTrue(Files.isRegularFile(project.resolve("rules.xml"), LinkOption.NOFOLLOW_LINKS),
                "An accepted change is written inside");
        assertEquals(outsideBefore, snapshot(outside), "Nothing is written through the link");
        assertTrue(((TrackedStream) through.getStream()).closed, "The refused change has its stream closed");
    }

    // V1-D: links that stay inside the existing project folder do not stop the overwrite
    @ParameterizedTest
    @EnumSource(OverwriteBackend.class)
    @DisabledOnOs(OS.WINDOWS)
    void hands_an_overwrite_whose_links_stay_inside_the_project_to_the_upload(OverwriteBackend backend)
            throws IOException {
        creatingUser();
        var target = overwriteTarget(backend);
        var project = existingProject(backend);
        Files.createSymbolicLink(project.resolve("alias"), project.resolve("rules"));
        Files.createSymbolicLink(project.resolve("rules/descriptor.xml"), Path.of("../rules.xml"));
        Files.createSymbolicLink(project.resolve("self"), Path.of("."));
        var created = new FileData();

        try (var ignored = uploaders(created)) {
            assertSame(created, overwrite(target, backend, List.of()));
        }

        assertUploaded(target, "Existing", overwritePath(backend));
    }

    // V1-D: an existing project folder without links is overwritten as before
    @ParameterizedTest
    @EnumSource(OverwriteBackend.class)
    void hands_an_overwrite_of_an_ordinary_existing_project_to_the_upload(OverwriteBackend backend)
            throws IOException {
        creatingUser();
        var target = overwriteTarget(backend);
        existingProject(backend);
        var created = new FileData();

        try (var ignored = uploaders(created)) {
            assertSame(created, overwrite(target, backend, List.of()));
        }

        assertUploaded(target, "Existing", overwritePath(backend));
    }

    // V1-D: links in the configured root's own path are trusted, so an ordinary overwrite below such a root runs
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void hands_an_overwrite_below_a_repository_root_reached_through_a_link_to_the_upload() throws IOException {
        creatingUser();
        var physical = Files.createDirectories(tmp.resolve("physical"));
        var root = Files.createSymbolicLink(tmp.resolve("repo"), physical);
        var target = secureFileRepository(root, false);
        write(physical.resolve("DESIGN/rules/Existing/rules.xml"), descriptor("Existing"));
        var created = new FileData();

        try (var ignored = uploaders(created)) {
            assertSame(created, overwrite(target, OverwriteBackend.FLAT, List.of()));
        }

        assertUploaded(target, "Existing", "");
    }

    // V1-D: a new project has no folder yet, so its upload runs and the check creates nothing
    @ParameterizedTest
    @EnumSource(OverwriteBackend.class)
    void hands_a_new_project_without_a_folder_yet_to_the_upload(OverwriteBackend backend) throws IOException {
        creatingUser();
        var target = overwriteTarget(backend);
        var folder = existingProject(backend).resolveSibling("Fresh");
        var created = new FileData();

        try (var ignored = uploaders(created)) {
            assertSame(created, service.createFromFiles(target, "Fresh", overwritePath(backend), List.of(), "comment",
                    "rules/Models.xlsx", "rules/Algorithms.xlsx", "Models", "Algorithms", Map.of()));
        }

        assertUploaded(target, "Fresh", overwritePath(backend));
        assertFalse(Files.exists(folder, LinkOption.NOFOLLOW_LINKS), "The check creates nothing");
    }

    // V1-D: a rules location that climbs out of a Git working tree places the project folder outside it
    @Test
    void rejects_an_upload_into_a_git_repository_whose_rules_location_climbs_out_of_it() throws IOException {
        creatingUser("../elsewhere/");
        var target = overwriteTarget(OverwriteBackend.GIT);

        try (var uploaders = uploaders()) {
            assertPathRejected(() -> overwrite(target, OverwriteBackend.GIT, List.of()));
            assertTrue(uploaders.constructed().isEmpty(), "The upload never runs");
        }

        assertNothingOutside("repo");
    }

    // V1-C: an unwrapped repository is asked for its working tree directly; its upload goes through the write check.
    // The checked-out tree is not inspected before the save checks out the branch it writes.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void hands_an_upload_into_the_working_tree_of_an_unwrapped_repository_to_the_write_check() throws IOException {
        creatingUser();
        var root = Files.createDirectories(tmp.resolve("repo"));
        var outside = Files.createDirectories(tmp.resolve("outside"));
        var project = existingProject(OverwriteBackend.GIT);
        Files.createSymbolicLink(project.resolve("link"), outside);
        var target = mock(Repository.class, Mockito.withSettings().extraInterfaces(LocalWorkingTree.class));
        when(target.getId()).thenReturn("design");
        when(target.supports()).thenReturn(new FeaturesBuilder(target).setVersions(false).setFolders(true).build());
        when(((LocalWorkingTree) target).getLocalWorkingTree()).thenReturn(root);

        try (var ignored = uploaders()) {
            assertNotNull(overwrite(target, OverwriteBackend.GIT, List.of()));
        }

        assertUploaded(target, "Existing", "");
        assertInstanceOf(RepositoryDelegate.class, uploadedRepository(), "The upload writes through the write check");
        verifyNothingSaved(target);
        assertEquals(Map.of(), snapshot(outside), "Nothing is written through the link");
    }

    // V1-D: a backend without a local folder (JDBC, S3, Azure Blob), configured or not, gets the lexical checks only
    @ParameterizedTest(name = "path-checked: {0}")
    @ValueSource(booleans = {false, true})
    void hands_an_overwrite_on_a_backend_without_a_local_folder_to_the_upload(boolean pathChecked) throws IOException {
        var workspace = creatingUser();
        var target = pathChecked ? pathCheckedRepositoryWithoutLocalFolder() : targetRepositoryMock();
        var created = new FileData();

        try (var ignored = uploaders(created)) {
            assertSame(created, overwrite(target, OverwriteBackend.FLAT, List.of()));
        }

        assertUploaded(target, "Existing", "");
        // V1-C: nothing is written through a local folder, so the upload gets the repository itself
        assertSame(target, uploadedRepository(), "No write check wraps a backend without a local folder");
        // The rules location is never looked up, so no folder was resolved and no file system call was made.
        verify(workspace, never()).getDesignTimeRepository();
        verifyNothingSaved(target);
    }

    // V1-D: uploads files over project 'Existing' of the backend, as the REST route does with overwrite=true
    private FileData overwrite(Repository target, OverwriteBackend backend, List<ProjectFile> files) {
        return service.createFromFiles(target, "Existing", overwritePath(backend), files, "comment",
                "rules/Models.xlsx", "rules/Algorithms.xlsx", "Models", "Algorithms", Map.of());
    }

    // V1-D: the repository of the backend over tmp/repo, reached the way the REST route receives it
    private Repository overwriteTarget(OverwriteBackend backend) throws IOException {
        var root = tmp.resolve("repo");
        return switch (backend) {
            case FLAT -> secureFileRepository(Files.createDirectories(root), false);
            case MAPPED -> secureFileRepository(Files.createDirectories(root), true);
            case CONFIGURED_FILE -> secured(configuredRepository("repo-file", Files.createDirectories(root)));
            case GIT -> secured(configuredRepository("repo-git", root));
        };
    }

    // V1-D: the path parameter that places a project in its folder: 'projects' when mapped, none ("") when flat
    private static String overwritePath(OverwriteBackend backend) {
        return backend == OverwriteBackend.MAPPED ? "projects" : "";
    }

    // V1-D: the folder of project 'Existing' on the backend, holding its descriptor and a workbook
    private Path existingProject(OverwriteBackend backend) throws IOException {
        var folder = projectsFolder(backend).resolve("Existing");
        write(folder.resolve("rules.xml"), descriptor("Existing"));
        write(folder.resolve("rules/Main.xlsx"), marker());
        return folder;
    }

    // V1-D: the folder of project 'Sibling' beside 'Existing' on the backend
    private Path siblingProject(OverwriteBackend backend) throws IOException {
        var folder = projectsFolder(backend).resolve("Sibling");
        write(folder.resolve("rules.xml"), descriptor("Sibling"));
        return folder;
    }

    // V1-D: where the backend keeps its projects in tmp/repo
    private Path projectsFolder(OverwriteBackend backend) {
        return tmp.resolve(backend == OverwriteBackend.MAPPED ? "repo/projects" : "repo/DESIGN/rules");
    }

    // V1-D: a design repository of the factory over the folder, built from its settings as the application builds it
    private Repository configuredRepository(String factory, Path root) {
        var settings = Map.of("repository.design.factory", factory, "repository.design.uri", root.toString());
        var configured = RepositoryInstatiator.newRepository("repository.design", settings::get);
        closeables.add(() -> IOUtils.closeQuietly(configured));
        assertTrue(configured instanceof PathCheckedRepository, "Fixture: the settings build a path-checked wrapper");
        return configured;
    }

    // V1-D: a configured repository whose backend keeps no local folder, as JDBC, S3 and Azure Blob are configured
    private static Repository pathCheckedRepositoryWithoutLocalFolder() {
        var repository = mock(PathCheckedRepository.class);
        when(repository.getId()).thenReturn("design");
        when(repository.supports())
                .thenReturn(new FeaturesBuilder(repository).setVersions(false).setFolders(true).build());
        return repository;
    }

    // V1-C: a user whose real upload runs, in a workspace whose rules location is DESIGN/rules/.
    // The upload gets a commit identity, project locks that are always granted, a project index that publishes at
    // once, granted ACLs, every file accepted and archives read as UTF-8.
    private void realUploads() {
        grantCreate();
        var acl = aclServiceProvider.getDesignRepoAclService();
        when(acl.createAcl(any(), anyList(), anyBoolean())).thenReturn(true);
        var user = mock(WorkspaceUser.class);
        when(user.getUserName()).thenReturn("jsmith");
        when(user.getUserInfo()).thenReturn(new UserInfo("jsmith"));
        var workspace = workspaceWithRulesLocation("DESIGN/rules/");
        when(workspace.getUser()).thenReturn(user);
        when(workspace.getProjectsLockEngine()).thenReturn(new DummyLockEngine());
        when(workspace.getDesignTimeRepository().refreshBranch(anyString(), anyString()))
                .thenReturn(CompletableFuture.completedFuture(null));
        var charsets = mock(ZipCharsetDetector.class);
        when(charsets.detectCharset(any(ZipCharsetDetector.ZipSource.class))).thenReturn(StandardCharsets.UTF_8);
        service = new TestProjectCreationService(aclProjectsHelper, aclServiceProvider, tagAssignmentValidator,
                path -> true, charsets, "", workspace);
    }

    // V1-C: uploads project 'name' the given way through the real upload, as the REST route does.
    // Files and archives carry generated content, and their streams are recorded so their release can be checked.
    private FileData upload(Upload upload, Repository target, String name, String path) throws IOException {
        return switch (upload) {
            case TEMPLATE -> createFromTemplate(target, name, path);
            case FILES -> service.createFromFiles(target, name, path,
                    new ArrayList<>(List.of(new ProjectFile("Main.xlsx", tracked(marker())))), "comment",
                    "rules/Models.xlsx", "rules/Algorithms.xlsx", "Models", "Algorithms", Map.of());
            case ARCHIVE -> service.createFromFiles(target, name, path,
                    new ArrayList<>(List.of(new ProjectFile("project.zip", tracked(archive(name))))), "comment",
                    "rules/Models.xlsx", "rules/Algorithms.xlsx", "Models", "Algorithms", Map.of());
        };
    }

    // V1-C: an archive holding a descriptor of the project and the workbook rules/Main.xlsx, both generated
    private static byte[] archive(String name) throws IOException {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("rules.xml"));
            zip.write(descriptor(name).getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
            zip.putNextEntry(new ZipEntry("rules/Main.xlsx"));
            zip.write(marker().getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return bytes.toByteArray();
    }

    // V1-C: creates project 'Existing' by a first real upload of the template and returns its folder in tmp/repo.
    // Created that way, the project is on the backend and a Git repository tracks it.
    private Path uploadedProject(Repository target, OverwriteBackend backend) throws IOException {
        assertNotNull(upload(Upload.TEMPLATE, target, "Existing", overwritePath(backend)),
                "Fixture: the project is created");
        var project = projectsFolder(backend).resolve("Existing");
        assertTrue(Files.isRegularFile(project.resolve("rules.xml"), LinkOption.NOFOLLOW_LINKS),
                "Fixture: the project folder holds its descriptor");
        return project;
    }

    // V1-C: a folder outside the repositories holding a file with generated content, so a write through a link is seen
    private Path outsideFolder() throws IOException {
        var outside = Files.createDirectories(tmp.resolve("outside"));
        write(outside.resolve("canary.txt"), marker());
        return outside;
    }

    // V1-C: a link in place of whatever tmp/repo holds there.
    // A Git repository has it committed on the branch its working tree holds, as a push from elsewhere brings it.
    private void placeLink(OverwriteBackend backend, Path link, Path target) throws Exception {
        if (backend == OverwriteBackend.GIT) {
            var root = tmp.resolve("repo");
            commitLink(root, checkedOutBranch(root), root.relativize(link).toString(), target);
        } else {
            replaceWithLink(link, target);
        }
    }

    // V1-C: a link in place of the file or folder at that place
    private static void replaceWithLink(Path link, Path target) throws IOException {
        if (Files.isDirectory(link, LinkOption.NOFOLLOW_LINKS)) {
            deleteTree(link);
        } else {
            Files.deleteIfExists(link);
        }
        Files.createDirectories(link.getParent());
        Files.createSymbolicLink(link, target);
    }

    // V1-C: a link committed on the given branch in place of what that branch holds there.
    // The previous branch is checked out again, so the working tree holds the link only while it holds that branch.
    private static void commitLink(Path workingTree, String branch, String linkPath, Path target) throws Exception {
        try (var git = Git.open(workingTree.toFile())) {
            var checkedOut = git.getRepository().getBranch();
            git.checkout().setName(branch).call();
            git.rm().setCached(true).addFilepattern(linkPath).call();
            replaceWithLink(workingTree.resolve(linkPath), target);
            git.add().addFilepattern(linkPath).call();
            git.commit()
                    .setMessage("Track a link")
                    .setAuthor("Test", "test@example.org")
                    .setCommitter("Test", "test@example.org")
                    .setSign(false)
                    .call();
            assertEquals(FileMode.SYMLINK, git.getRepository().readDirCache().getEntry(linkPath).getFileMode(),
                    "Fixture: the link is tracked as a link");
            git.checkout().setName(checkedOut).call();
        }
    }

    // V1-C: the branch the working tree holds, which is the one the last save or checkout left
    private static String checkedOutBranch(Path workingTree) throws IOException {
        try (var git = Git.open(workingTree.toFile())) {
            return git.getRepository().getBranch();
        }
    }

    // V1-C: the working tree holds the given branch
    private static void assertCheckedOut(Path workingTree, String branch) throws IOException {
        assertEquals(branch, checkedOutBranch(workingTree), "The branch the working tree holds");
    }

    // V1-C: a configured, secured Git repository in the folder, with the target branch created from its base branch.
    // The base branch holds one seed commit and is checked out.
    private BranchRepository gitWithTargetBranch(Path root) throws IOException {
        var repository = (BranchRepository) secured(configuredRepository("repo-git", root));
        assertNotNull(repository.save(folderData("seed.txt"),
                new ByteArrayInputStream(marker().getBytes(StandardCharsets.UTF_8))), "Fixture: the base is seeded");
        repository.createRepositoryBranch(TARGET_BRANCH, null);
        assertCheckedOut(root, BASE_BRANCH);
        return repository;
    }

    // V1-C: a configured Git repository in the folder whose checked-out base branch holds one seed commit.
    // A save to a branch without commits cleans the working tree first, which would remove a link planted there.
    private Repository seededGit(Path root) throws IOException {
        var git = configuredRepository("repo-git", root);
        assertNotNull(git.save(folderData("seed.txt"),
                new ByteArrayInputStream(marker().getBytes(StandardCharsets.UTF_8))), "Fixture: the base is seeded");
        assertCheckedOut(root, BASE_BRANCH);
        return git;
    }

    // V1-C: the Git repository mapped onto DESIGN/rules/ and secured, as Studio builds its design repository
    private Repository mappedGit(Repository git) throws IOException {
        var mapped = MappedRepository.create(git, "DESIGN/rules/");
        closeables.add((Closeable) mapped);
        return secured(mapped);
    }

    // V1-C: a configured, secured Git repository in tmp/repo that reports no unique file ids.
    // Each upload therefore saves it a full changeset.
    private Repository fullChangesetGit() {
        return secured(withoutUniqueFileIds(configuredRepository("repo-git", tmp.resolve("repo"))));
    }

    // V1-C: the repository as it reports itself without unique file ids.
    // The proxy unwraps to the repository, as the application's wrappers do.
    private static Repository withoutUniqueFileIds(Repository repository) {
        return (Repository) Proxy.newProxyInstance(ProjectCreationServiceTest.class.getClassLoader(),
                new Class<?>[]{BranchRepository.class, RepositoryDelegate.class},
                (proxy, method, args) -> {
                    if ("supports".equals(method.getName())) {
                        var features = repository.supports();
                        return new FeaturesBuilder(repository)
                                .setVersions(features.versions())
                                .setFolders(features.folders())
                                .setSearchable(features.searchable())
                                .setSupportsUniqueFileId(false)
                                .build();
                    }
                    if (method.getDeclaringClass() == RepositoryDelegate.class) {
                        return repository;
                    }
                    try {
                        return method.invoke(repository, args);
                    } catch (InvocationTargetException e) {
                        throw e.getTargetException();
                    }
                });
    }

    // V1-C: the data a save names a folder or a file by, with a commit identity
    private static FileData folderData(String name) {
        var data = new FileData();
        data.setName(name);
        data.setAuthor(new UserInfo("jsmith"));
        data.setComment("comment");
        return data;
    }

    // V1-C: the descriptor and the workbook the upload writes sit in the project folder, inside the repository root
    private void assertWrittenInside(Path project) throws IOException {
        for (var file : List.of("rules.xml", "rules/Main.xlsx")) {
            assertTrue(Files.isRegularFile(project.resolve(file), LinkOption.NOFOLLOW_LINKS), file + " is written");
        }
        assertTrue(project.toRealPath().startsWith(tmp.resolve("repo").toRealPath()),
                "The project stays inside the repository");
    }

    // V1-C: every uploaded stream a real upload took was released
    private void assertReleased() {
        assertTrue(streams.stream().allMatch(stream -> stream.closed), "The uploaded files are released");
    }

    // V1-C: an uploaded file's content, recorded so its release can be checked
    private TrackedStream tracked(String content) {
        return tracked(content.getBytes(StandardCharsets.UTF_8));
    }

    // V1-C: an uploaded file's content, recorded so its release can be checked
    private TrackedStream tracked(byte[] content) {
        var stream = new TrackedStream(content);
        streams.add(stream);
        return stream;
    }

    // V1-C: the content of an uploaded file, recording whether the upload released it
    private static final class TrackedStream extends ByteArrayInputStream {
        private boolean closed;

        private TrackedStream(byte[] content) {
            super(content);
        }

        @Override
        public void close() throws IOException {
            closed = true;
            super.close();
        }
    }


    // V1-C: a user who may create projects and read any source, in a workspace whose rules location is DESIGN/rules/
    private UserWorkspace creatingUser() {
        return creatingUser("DESIGN/rules/");
    }

    // V1-C: a user who may create projects and read any source, in a workspace with the given rules location
    private UserWorkspace creatingUser(String rulesLocation) {
        grantCreate();
        var workspace = workspaceWithRulesLocation(rulesLocation);
        service = serviceWithWorkspace(workspace);
        return workspace;
    }

    // V1-C: lets the permission checks pass, so the path checks decide
    private void grantCreate() {
        when(aclProjectsHelper.hasCreateProjectPermission(anyString())).thenReturn(true);
        var acl = mock(RepositoryAclService.class);
        when(acl.isGranted(any(RulesProject.class), anyList())).thenReturn(true);
        when(aclServiceProvider.getDesignRepoAclService()).thenReturn(acl);
    }

    // V1-C: a copy-ready workspace whose design repository keeps projects in the given rules location.
    private static UserWorkspace workspaceWithRulesLocation(String rulesLocation) {
        var designTimeRepository = mock(DesignTimeRepository.class);
        when(designTimeRepository.getRulesLocation()).thenReturn(rulesLocation);
        var localWorkspace = mock(LocalWorkspace.class);
        when(localWorkspace.getRepository(anyString())).thenReturn(mock(LocalRepository.class));
        var workspace = mock(UserWorkspace.class);
        when(workspace.getDesignTimeRepository()).thenReturn(designTimeRepository);
        when(workspace.getUser()).thenReturn(mock(WorkspaceUser.class));
        when(workspace.getLocalWorkspace()).thenReturn(localWorkspace);
        when(workspace.getProjectsLockEngine()).thenReturn(mock(LockEngine.class));
        return workspace;
    }

    // V1-C: the design repository a new project is written to; the file repositories keep their root in tmp/repo
    private Repository target(Backend backend) throws IOException {
        return switch (backend) {
            case MOCK -> targetRepositoryMock();
            case FLAT -> secureFileRepository(Files.createDirectories(tmp.resolve("repo")), false);
            case MAPPED -> secureFileRepository(Files.createDirectories(tmp.resolve("repo")), true);
        };
    }

    // V1-C: a file design repository behind the secured wrapper the REST route receives, mapped onto DESIGN/rules/
    private Repository secureFileRepository(Path root, boolean mapped) throws IOException {
        Repository repository = fileRepository(root);
        if (mapped) {
            repository = MappedRepository.create(repository, "DESIGN/rules/");
            closeables.add((Closeable) repository);
        }
        return secured(repository);
    }

    // V1-C: a source project in a repository without a local directory, copied at its latest state
    private static RulesProject sourceWithoutLocalDirectory() {
        var repository = mock(Repository.class);
        when(repository.getId()).thenReturn("design");
        var source = mock(RulesProject.class);
        when(source.getRepository()).thenReturn(repository);
        when(source.getFolderPath()).thenReturn("DESIGN/Source");
        return source;
    }

    // V1-C: the project Src of a flat file design repository in tmp/design, the source of a real copy
    private RulesProject sourceInFlatFileRepository() throws IOException {
        layOutSource(SourceLayout.FLAT);
        var copySource = source(SourceLayout.FLAT);
        var project = mock(RulesProject.class);
        when(project.getRepository()).thenReturn(copySource.repository());
        when(project.getFolderPath()).thenReturn(copySource.folderPath());
        return project;
    }

    // V1-C: chooses the folder of a new project through the given route, as the REST controller calls it
    private FileData attempt(Route route, Repository target, String name, String path, RulesProject copySource) {
        return switch (route) {
            case TEMPLATE -> createFromTemplate(target, name, path);
            case FILES -> createFromFiles(target, name, path);
            case COPY -> service.copyProject(target, name, path, copySource, "comment", null);
        };
    }

    // V1-C: creates a project from the bundled empty template
    private FileData createFromTemplate(Repository repository, String name, String path) {
        return service.createFromTemplate(repository, name, path, "predefined", "templates", "Empty Project",
                "comment", null);
    }

    // V1-C: creates a project from uploaded files; the upload itself is the uploader mock
    private FileData createFromFiles(Repository repository, String name, String path) {
        return service.createFromFiles(repository, name, path, List.of(), "comment", "rules/Models.xlsx",
                "rules/Algorithms.xlsx", "Models", "Algorithms", null);
    }

    // V1-C: the uploader mock for a call whose created project is not inspected
    private MockedConstruction<ProjectUploader> uploaders() {
        return uploaders(new FileData());
    }

    // V1-C: stands in for every ProjectUploader the service constructs, recording its constructor arguments.
    // It releases the files handed to it as the real upload does and returns a project carrying the given file data.
    private MockedConstruction<ProjectUploader> uploaders(FileData created) {
        var project = mock(RulesProject.class);
        when(project.getFileData()).thenReturn(created);
        return Mockito.mockConstruction(ProjectUploader.class, (uploader, context) -> {
            uploads.add(new ArrayList<>(context.arguments()));
            for (var file : (List<?>) context.arguments().get(1)) {
                ((ProjectFile) file).destroy();
            }
            when(uploader.uploadProject()).thenReturn(project);
        });
    }

    // V1-C: exactly one upload ran, for the target, the name as given and the path as the service passes it on.
    // A target written through a local folder is handed over behind the write check, which unwraps to the target.
    private void assertUploaded(Repository target, String name, String path) {
        var uploaded = uploadedRepository();
        if (uploaded != target) {
            var checked = assertInstanceOf(RepositoryDelegate.class, uploaded, "The upload writes through the check");
            assertSame(target, checked.getOriginal(), "The write check unwraps to the target");
        }
        var arguments = uploads.get(0);
        assertEquals(name, arguments.get(2));
        assertEquals(StringUtils.trimToEmpty(path), arguments.get(3));
    }

    // V1-C: the repository the one upload that ran was handed
    private Repository uploadedRepository() {
        assertEquals(1, uploads.size(), "The upload runs once");
        return (Repository) uploads.get(0).get(0);
    }

    // V1-C: the copy sits in its physical folder in tmp/repo, which resolves inside the real repository root
    private Path assertCopiedInside(Backend backend, String name, String path) throws IOException {
        var root = tmp.resolve("repo");
        var folder = backend == Backend.MAPPED
                ? root.resolve(FileMappingData.internalPath(path, name))
                : root.resolve("DESIGN/rules/" + name);
        assertTrue(Files.isRegularFile(folder.resolve("rules.xml"), LinkOption.NOFOLLOW_LINKS),
                "The copy is written to its own folder");
        assertTrue(folder.toRealPath().startsWith(root.toRealPath()), "The copy stays inside the repository root");
        return folder;
    }

    // V1-C: nothing appears in the temporary directory besides the repositories the test set up
    private void assertNothingOutside(String... roots) throws IOException {
        try (var entries = Files.list(tmp)) {
            var unexpected = entries.map(entry -> entry.getFileName().toString())
                    .filter(entry -> !List.of(roots).contains(entry))
                    .toList();
            assertEquals(List.of(), unexpected, "Nothing is written outside the repositories");
        }
    }

    // V1-C: the rejection every path check of a new project ends in: 400 with the existing invalid-path key
    private static void assertPathRejected(Executable call) {
        var e = assertThrows(BadRequestException.class, call);
        assertEquals("openl.error.400.file.path.invalid.message", e.getErrorCode());
        assertEquals(HttpStatus.BAD_REQUEST, e.getHttpStatus());
    }

    // V1-C: the exception a call ends with, or null when it completes
    private static @Nullable Throwable outcomeOf(Executable call) {
        try {
            call.execute();
            return null;
        } catch (Throwable e) {
            return e;
        }
    }

    // V1-C: today's NameChecker verdict on a path, the reference a reserved name is held to
    private static boolean isRejectedByNameChecker(String path) {
        try {
            NameChecker.validatePath(path);
            return false;
        } catch (IOException | IllegalArgumentException e) {
            return true;
        }
    }

    // V1-C: every entry below a folder, links never followed: kind, link target, file size and SHA-256; empty if absent
    private static Map<String, String> snapshot(Path dir) throws IOException {
        if (!Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
            return Map.of();
        }
        var entries = new TreeMap<String, String>();
        try (var paths = Files.walk(dir)) {
            for (var entry : paths.filter(p -> !p.equals(dir)).toList()) {
                String state;
                if (Files.isSymbolicLink(entry)) {
                    state = "link " + Files.readSymbolicLink(entry);
                } else if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
                    state = "dir";
                } else {
                    state = "file " + Files.size(entry) + " " + sha256(Files.readAllBytes(entry));
                }
                entries.put(dir.relativize(entry).toString(), state);
            }
        }
        return entries;
    }

    // V1-C: the SHA-256 of a file's content, so a snapshot holds a fingerprint and never the content itself
    private static String sha256(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private ProjectCreationService serviceWithWorkspace(UserWorkspace workspace) {
        return new TestProjectCreationService(aclProjectsHelper, aclServiceProvider,
                tagAssignmentValidator, mock(PathFilter.class), mock(ZipCharsetDetector.class), "",
                workspace);
    }

    private static FileData fileData(String version) {
        var data = new FileData();
        data.setName("DESIGN/Source");
        data.setVersion(version);
        return data;
    }

    private static class TestProjectCreationService extends ProjectCreationService {

        private final UserWorkspace workspace;
        /** When set, stands in for the workspace view assembled from a design project. */
        private RulesProject designWorkspaceProject;

        TestProjectCreationService(AclProjectsHelper aclProjectsHelper,
                                   RepositoryAclServiceProvider aclServiceProvider,
                                   TagAssignmentValidator tagAssignmentValidator,
                                   PathFilter zipFilter,
                                   ZipCharsetDetector zipCharsetDetector,
                                   String openlHome,
                                   UserWorkspace workspace) {
            super(aclProjectsHelper, aclServiceProvider, tagAssignmentValidator, zipFilter, zipCharsetDetector, openlHome);
            this.workspace = workspace;
        }

        @Override
        public UserWorkspace getUserWorkspace() {
            return workspace;
        }

        @Override
        protected RulesProject newWorkspaceProject(UserWorkspace workspace, String repositoryId, AProject designProject) {
            return designWorkspaceProject != null
                    ? designWorkspaceProject
                    : super.newWorkspaceProject(workspace, repositoryId, designProject);
        }
    }
}

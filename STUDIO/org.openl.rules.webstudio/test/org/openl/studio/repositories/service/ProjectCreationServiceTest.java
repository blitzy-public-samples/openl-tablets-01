package org.openl.studio.repositories.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
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
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
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
import org.openl.rules.project.impl.local.LocalRepository;
import org.openl.rules.project.impl.local.MetainfoRegistry;
import org.openl.rules.project.impl.local.ProjectMetainfo;
import org.openl.rules.repository.RepositoryInstatiator;
import org.openl.rules.repository.api.BranchRepository;
import org.openl.rules.repository.api.ChangesetType;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
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
import org.openl.util.StringUtils;

class ProjectCreationServiceTest {

    /**
     * V1: where the source project of a copy lives on disk, each reached the way the copy route receives it.
     */
    private enum SourceLayout {
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
                        ? Boolean.TRUE
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
    private enum Route {
        TEMPLATE,
        FILES,
        COPY
    }

    // V1-C: the design repository a new project is written to, reached the way the REST route receives it
    private enum Backend {
        /** A repository without a local directory, such as Git, JDBC, S3 or Azure Blob: lexical checks only. */
        MOCK,
        /** A flat file repository in {@code tmp/repo} behind {@code SecureRepository}. */
        FLAT,
        /** A mapped file repository in {@code tmp/repo} behind {@code SecureMappedRepository}. */
        MAPPED
    }

    // V1-C: where a link inside the design repository points the folder of a new project (0.6.2.3 C12, C16)
    private enum LinkTarget {
        /** A directory outside the repository root (C12). */
        OUTSIDE,
        /** The folder of another project in the same repository (C16). */
        SIBLING,
        /** A path that does not exist, so the link resolves nowhere. */
        DANGLING
    }

    // V1-C: payloads rejected as received on every backend (0.6.2.3 C1, C2, C4-C10, C13)
    private static Stream<Arguments> rejectedPayloads() {
        return onEveryRoute(new Backend[]{Backend.MOCK, Backend.FLAT},
                new String[]{"C1", "NewProject", "../../outside"},
                new String[]{"C2", "NewProject", "./p"},
                new String[]{"C2", "NewProject", "a/./p"},
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

    // V1-C: payloads the write itself keeps inside the repository: the leading slash is dropped (C3), and look-alike
    // separators are ordinary characters (C14), so each is either rejected or written inside (0.6.2.3). The service
    // checks the path as the write places it; the REST route keeps its existing 400 for C3 through @PathConstraint.
    private static Stream<Arguments> containedPayloads() {
        return onEveryRoute(Backend.values(),
                new String[]{"C3", "NewProject", "/etc/p"},
                new String[]{"C14", "..\u2215p", null},
                new String[]{"C14", "\uFF0E\uFF0E", null})
                .filter(ProjectCreationServiceTest::isWritable);
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
                        .flatMap(backend -> Stream.of(null, "", "a/b").map(path -> Arguments.of(route, backend, path))));
    }

    // V1-C: valid copy targets on both file layouts, with and without a path
    private static Stream<Arguments> validCopyTargets() {
        return Stream.of(Backend.FLAT, Backend.MAPPED)
                .flatMap(backend -> Stream.of(null, "a/b").map(path -> Arguments.of(backend, path)));
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

    // V1-C: a payload the write keeps inside the repository is rejected or written inside it (0.6.2.3 C3, C14)
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

    // V1-C: a link in the design repository never redirects the new project folder: flat, the project is named after
    // the link in the rules location; mapped, the link is the parent path of project 'p' (0.6.2.3 C12, C16, dangling)
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

    // V1-C: a valid copy target passes the checks on a backend without a local directory, with and without a path
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"a/b"})
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

    // V1-C: a workspace whose design repository keeps projects in the given rules location, ready for a copy to be written
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

    // V1-C: stands in for every ProjectUploader the service constructs: records its constructor arguments, releases
    // the files handed to it as the real upload does, and returns a project carrying the given file data
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

    // V1-C: exactly one upload ran, for the target, the name as given and the path as the service passes it on
    private void assertUploaded(Repository target, String name, String path) {
        assertEquals(1, uploads.size(), "The upload runs once");
        var arguments = uploads.get(0);
        assertSame(target, arguments.get(0));
        assertEquals(name, arguments.get(2));
        assertEquals(StringUtils.trimToEmpty(path), arguments.get(3));
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
    private static Throwable outcomeOf(Executable call) {
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

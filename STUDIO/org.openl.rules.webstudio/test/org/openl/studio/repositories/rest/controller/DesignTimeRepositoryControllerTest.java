package org.openl.studio.repositories.rest.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.util.List;
import jakarta.validation.Valid;
import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.Validator;
import org.springframework.validation.beanvalidation.SpringValidatorAdapter;
import org.springframework.web.multipart.MultipartFile;

import org.openl.rules.lock.LockManager;
import org.openl.rules.project.abstraction.AProject;
import org.openl.rules.project.abstraction.Comments;
import org.openl.rules.project.abstraction.ProjectStatus;
import org.openl.rules.project.abstraction.RulesProject;
import org.openl.rules.repository.api.BranchRepository;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.rest.acl.service.AclProjectsHelper;
import org.openl.security.acl.repository.RepositoryAclService;
import org.openl.studio.common.exception.BadRequestException;
import org.openl.studio.common.exception.ConflictException;
import org.openl.studio.common.exception.RestRuntimeException;
import org.openl.studio.common.exception.ValidationException;
import org.openl.studio.common.validation.BeanValidationProvider;
import org.openl.studio.projects.converter.ProjectIdentityConverter;
import org.openl.studio.projects.service.protection.ProtectedBranchBypassService;
import org.openl.studio.repositories.model.CreateFromProjectModel;
import org.openl.studio.repositories.model.CreateUpdateProjectModel;
import org.openl.studio.repositories.model.RepositoryConfigModel;
import org.openl.studio.repositories.service.DesignTimeRepositoryService;
import org.openl.studio.repositories.service.ProjectCreationService;
import org.openl.studio.repositories.service.ProjectCreationTargetResolver;
import org.openl.studio.repositories.service.ProjectRevisionService;
import org.openl.studio.repositories.service.RepositoryConfigService;
import org.openl.studio.repositories.service.ZipProjectSaveStrategy;
import org.openl.studio.repositories.validator.CreateUpdateProjectModelValidator;
import org.openl.studio.repositories.validator.ZipArchiveValidator;

// V1: new imports serve the V1-C/D rejection tests
class DesignTimeRepositoryControllerTest {

    private static final String REPOSITORY_ID = "design";
    private static final String BRANCH = "main";

    private BranchRepository repository;
    private RepositoryAclService designRepositoryAclService;
    private BeanValidationProvider validationProvider;
    private ZipProjectSaveStrategy zipProjectSaveStrategy;
    private AclProjectsHelper aclProjectsHelper;
    private ProtectedBranchBypassService bypassService;
    private ProjectCreationService projectCreationService;
    private ProjectCreationTargetResolver projectCreationTargetResolver;
    private RepositoryConfigService repositoryConfigService;
    private ProjectIdentityConverter projectIdentityConverter;
    private Comments comments;
    private DesignTimeRepositoryController controller;

    @BeforeEach
    void setUp() {
        repository = mock(BranchRepository.class);
        designRepositoryAclService = mock(RepositoryAclService.class);
        validationProvider = mock(BeanValidationProvider.class);
        zipProjectSaveStrategy = mock(ZipProjectSaveStrategy.class);
        repositoryConfigService = mock(RepositoryConfigService.class);
        projectIdentityConverter = mock(ProjectIdentityConverter.class);
        comments = mock(Comments.class);
        aclProjectsHelper = mock(AclProjectsHelper.class);
        bypassService = mock(ProtectedBranchBypassService.class);
        projectCreationService = mock(ProjectCreationService.class);
        projectCreationTargetResolver = mock(ProjectCreationTargetResolver.class);

        when(repository.getId()).thenReturn(REPOSITORY_ID);
        when(repository.getBranch()).thenReturn(BRANCH);
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).build());
        when(aclProjectsHelper.hasCreateProjectPermission(REPOSITORY_ID)).thenReturn(true);
        when(projectCreationTargetResolver.resolve(eq(repository), nullable(String.class))).thenReturn(repository);
        when(projectCreationTargetResolver.resolve(eq(repository), nullable(String.class), any(Boolean.class)))
                .thenReturn(repository);

        controller = new DesignTimeRepositoryController(
                designRepositoryAclService,
                validationProvider,
                mock(CreateUpdateProjectModelValidator.class),
                mock(ZipArchiveValidator.class),
                zipProjectSaveStrategy,
                "target",
                aclProjectsHelper,
                mock(DesignTimeRepositoryService.class),
                mock(ProjectRevisionService.class),
                bypassService,
                projectCreationService,
                projectCreationTargetResolver,
                repositoryConfigService,
                projectIdentityConverter) {
            // The comment service is a @Lookup bean, absent outside a Spring context.
            @Override
            protected Comments getCommentsService(String repoName) {
                return comments;
            }
        };

        // V1: generated credential (secret hygiene)
        var credential = RandomStringUtils.secure().nextAlphanumeric(16);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", credential));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void configOfTheRepositoryIsReadForTheCreateForms() {
        var config = new RepositoryConfigModel(null, new RepositoryConfigModel.Comment(null, null,
                new RepositoryConfigModel.Templates(null, "Project {project-name} is created.", null, null)));
        when(repositoryConfigService.getConfig(REPOSITORY_ID)).thenReturn(config);

        assertEquals(config, controller.getConfig(repository));
    }

    @Test
    void createProjectFromProjectRequiresBranchProtectionBypass() {
        var source = sourceProject("Source");
        when(projectCreationService.copyProject(repository, "Copy", null, source, "comment", "rev-1"))
                .thenReturn(new FileData());

        controller.createProjectFromProject(repository, "Copy",
                new CreateFromProjectModel(REPOSITORY_ID, "Source", null, "comment", "rev-1"));

        verify(bypassService).requireBypassOrThrow(repository, BRANCH, REPOSITORY_ID, false);
    }

    @Test
    void anOmittedCommentNamesTheProjectThatIsActuallyCopied() {
        // The request may address its source by an identifier, which is no name to put in a commit comment.
        var source = sourceProject("ZGVzaWduOlNvdXJjZTpoYXNo");
        when(source.getBusinessName()).thenReturn("Source");
        when(comments.copiedFrom("Source")).thenReturn("Copied from: Source.");
        when(projectCreationService.copyProject(repository, "Copy", null, source, "Copied from: Source.", null))
                .thenReturn(new FileData());

        controller.createProjectFromProject(repository, "Copy",
                new CreateFromProjectModel(REPOSITORY_ID, "ZGVzaWduOlNvdXJjZTpoYXNo", null, null, null));

        verify(comments).copiedFrom("Source");
    }

    @Test
    void projectCopyUsesTheResolvedTargetBranch() {
        var target = mock(BranchRepository.class);
        var data = new FileData();
        when(target.getId()).thenReturn(REPOSITORY_ID);
        when(target.supports()).thenReturn(new FeaturesBuilder(target).setBranches(true).build());
        when(projectCreationTargetResolver.resolve(repository, "feature/rates")).thenReturn(target);
        var source = sourceProject("Source");
        when(projectCreationService.copyProject(target, "Copy", null, source, "comment", null)).thenReturn(data);

        controller.createProjectFromProject(repository, "Copy",
                new CreateFromProjectModel(REPOSITORY_ID, "Source", null, "comment", null, "feature/rates"));

        verify(projectCreationTargetResolver).resolve(repository, "feature/rates");
        verify(projectCreationService).copyProject(target, "Copy", null, source, "comment", null);
    }

    @Test
    void copyChecksBranchProtectionBeforeResolvingTheTarget() {
        rejectRequestedBranch("protected/new");
        sourceProject("Source");
        var request = new CreateFromProjectModel(REPOSITORY_ID,
                "Source",
                null,
                "comment",
                null,
                "protected/new");

        assertThrows(ConflictException.class,
                () -> controller.createProjectFromProject(repository, "Copy", request));

        verify(projectCreationTargetResolver, never()).resolve(repository, "protected/new");
        verify(projectCreationService, never()).copyProject(any(Repository.class), any(), any(),
                any(RulesProject.class), any(), any());
    }

    @Test
    void createChecksBranchProtectionBeforeResolvingTheTarget() {
        rejectRequestedBranch("protected/new");

        assertThrows(ConflictException.class,
                () -> controller.createProject(repository,
                        "Project",
                        null,
                        "comment",
                        null,
                        "predefined",
                        "templates",
                        "Sample Project",
                        "Models",
                        "rules/Models.xlsx",
                        "Algorithms",
                        "rules/Algorithms.xlsx",
                        false,
                        null,
                        "protected/new",
                        false));

        verify(projectCreationTargetResolver, never()).resolve(repository, "protected/new", true);
        verify(projectCreationService, never()).createFromTemplate(any(Repository.class), any(), any(), any(), any(),
                any(), any(), any());
    }

    @Test
    void createProjectFromArchiveRegistersTagsFromDesignProject() throws Exception {
        when(aclProjectsHelper.hasCreateProjectPermission(REPOSITORY_ID)).thenReturn(true);
        var archive = mock(MultipartFile.class);
        when(archive.getOriginalFilename()).thenReturn("Project.zip");
        when(archive.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
        var data = new FileData();
        data.setName("Project");
        when(zipProjectSaveStrategy.save(eq(repository), any(CreateUpdateProjectModel.class), any(Path.class)))
                .thenReturn(data);

        controller.createProject(repository, "Project", null, "comment", List.of(archive), null, null, null,
                "Models", "rules/Models.xlsx", "Algorithms", "rules/Algorithms.xlsx", false, null, null, false);

        var order = inOrder(designRepositoryAclService, projectCreationService);
        order.verify(designRepositoryAclService).createAcl(any(AProject.class), anyList(), eq(true));
        order.verify(projectCreationService).registerExtensibleTags(any(AProject.class));
        order.verify(projectCreationService).awaitProjectVisibility(repository);
        order.verify(projectCreationService).refreshWorkspaceAfterDesignChange();
        verify(projectCreationService).applyStatusAfterCreate(repository, "Project", null);
    }

    @Test
    void contentCreationKeepsItsOpenedDefaultAndUsesTheIndexedProjectName() throws Exception {
        var data = new FileData();
        data.setName("Project:hash");
        when(projectCreationService.createFromTemplate(repository, "Project", null,
                "predefined", "templates", "Sample Project", "comment", null)).thenReturn(data);

        controller.createProject(repository, "Project", null, "comment", null, "predefined", "templates",
                "Sample Project", "Models", "rules/Models.xlsx", "Algorithms", "rules/Algorithms.xlsx",
                false, null, null, false);

        verify(projectCreationService).applyStatusAfterCreate(repository, "Project:hash", ProjectStatus.VIEWING);
    }

    @Test
    void archiveIndexFailureKeepsFinalizedAclAndTags() throws Exception {
        when(aclProjectsHelper.hasCreateProjectPermission(REPOSITORY_ID)).thenReturn(true);
        var archive = mock(MultipartFile.class);
        when(archive.getOriginalFilename()).thenReturn("Project.zip");
        when(archive.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
        var data = new FileData();
        data.setName("Project");
        when(zipProjectSaveStrategy.save(eq(repository), any(CreateUpdateProjectModel.class), any(Path.class)))
                .thenReturn(data);
        doThrow(new ConflictException("project.indexing.incomplete.message"))
                .when(projectCreationService).awaitProjectVisibility(repository);

        var archives = List.of(archive);
        assertThrows(ConflictException.class,
                () -> controller.createProject(repository, "Project", null, "comment", archives, null,
                        null, null, "Models", "rules/Models.xlsx", "Algorithms", "rules/Algorithms.xlsx",
                        false, null, null, false));

        verify(designRepositoryAclService).createAcl(any(AProject.class), anyList(), eq(true));
        verify(projectCreationService).registerExtensibleTags(any(AProject.class));
        verify(projectCreationService, never()).refreshWorkspaceAfterDesignChange();
    }

    @Test
    void createProjectFromProjectRequestBodyIsValidated() throws NoSuchMethodException {
        var method = DesignTimeRepositoryController.class.getMethod("createProjectFromProject", Repository.class,
                String.class, CreateFromProjectModel.class);
        var requestParameter = method.getParameters()[2];

        assertTrue(requestParameter.isAnnotationPresent(Valid.class));
    }

    // V1-C: a '/'-leading path keeps its bean-validation rejection (openl.constraints.path.1.message) before creation
    @Test
    void createWithALeadingSlashPathKeepsItsPathConstraintRejection() throws Exception {
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            var validating = controllerValidatingWith(factory);

            var ex = assertThrows(ValidationException.class,
                    () -> validating.createProject(repository, "Project", "/etc/p", "comment", null, "predefined",
                            "templates", "Sample Project", "Models", "rules/Models.xlsx", "Algorithms",
                            "rules/Algorithms.xlsx", false, null, null, false));

            var error = ex.getBindingResult().getFieldError("path");
            assertNotNull(error);
            assertEquals("The path in the repository cannot start with '/'.", error.getDefaultMessage());
            verify(projectCreationService, never()).createFromTemplate(any(Repository.class), any(), any(), any(),
                    any(), any(), any(), any());
            verify(projectCreationService, never()).createFromFiles(any(Repository.class), any(), any(), anyList(),
                    any(), any(), any(), any(), any(), any());
            verify(projectCreationService, never()).copyProject(any(Repository.class), any(), any(),
                    any(RulesProject.class), any(), any());
        }
    }

    // V1-C: a '..' segment in the path (payload C1) keeps its NameChecker bean-validation rejection before creation
    @Test
    void createWithADotDotPathKeepsItsNameCheckerRejection() throws Exception {
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            var validating = controllerValidatingWith(factory);

            var ex = assertThrows(ValidationException.class,
                    () -> validating.createProject(repository, "Project", "../../outside", "comment", null,
                            "predefined", "templates", "Sample Project", "Models", "rules/Models.xlsx",
                            "Algorithms", "rules/Algorithms.xlsx", false, null, null, false));

            var error = ex.getBindingResult().getFieldError("path");
            assertNotNull(error);
            var message = error.getDefaultMessage();
            assertNotNull(message);
            assertTrue(message.contains("Name cannot contain forbidden characters"));
            verify(projectCreationService, never()).createFromTemplate(any(Repository.class), any(), any(), any(),
                    any(), any(), any(), any());
            verify(projectCreationService, never()).createFromFiles(any(Repository.class), any(), any(), anyList(),
                    any(), any(), any(), any(), any(), any());
            verify(projectCreationService, never()).copyProject(any(Repository.class), any(), any(),
                    any(RulesProject.class), any(), any());
        }
    }

    // V1-C: a from-project copy to a '/'-leading path keeps its bean-validation rejection before any copy
    @Test
    void copyToALeadingSlashPathKeepsItsPathConstraintRejection() throws Exception {
        sourceProject("Source");
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            var validating = controllerValidatingWith(factory);
            var request = new CreateFromProjectModel(REPOSITORY_ID, "Source", "/etc/p", "comment", null);

            var ex = assertThrows(ValidationException.class,
                    () -> validating.createProjectFromProject(repository, "Copy", request));

            var error = ex.getBindingResult().getFieldError("path");
            assertNotNull(error);
            assertEquals("The path in the repository cannot start with '/'.", error.getDefaultMessage());
            verify(projectCreationService, never()).createFromTemplate(any(Repository.class), any(), any(), any(),
                    any(), any(), any(), any());
            verify(projectCreationService, never()).createFromFiles(any(Repository.class), any(), any(), anyList(),
                    any(), any(), any(), any(), any(), any());
            verify(projectCreationService, never()).copyProject(any(Repository.class), any(), any(),
                    any(RulesProject.class), any(), any());
        }
    }

    // V1-C: a repository failure on the template route keeps its 409 project.create.failed.message
    @Test
    void templateCreationFailureKeepsItsConflict() throws Exception {
        when(projectCreationService.createFromTemplate(eq(repository), eq("Project"), any(), any(), any(), any(),
                any(), any())).thenThrow(new ConflictException("project.create.failed.message"));

        var ex = assertThrows(ConflictException.class,
                () -> controller.createProject(repository, "Project", null, "comment", null, "predefined",
                        "templates", "Sample Project", "Models", "rules/Models.xlsx", "Algorithms",
                        "rules/Algorithms.xlsx", false, null, null, false));

        assertEquals("openl.error.409.project.create.failed.message", ex.getErrorCode());
        assertEquals(HttpStatus.CONFLICT, ex.getHttpStatus());
    }

    // V1-C: a repository failure on the from-project route keeps its 409 project.copy.failed.message
    @Test
    void projectCopyFailureKeepsItsConflict() throws Exception {
        var source = sourceProject("Source");
        when(projectCreationService.copyProject(repository, "Copy", null, source, "comment", null))
                .thenThrow(new ConflictException("project.copy.failed.message"));
        var request = new CreateFromProjectModel(REPOSITORY_ID, "Source", null, "comment", null);

        var ex = assertThrows(ConflictException.class,
                () -> controller.createProjectFromProject(repository, "Copy", request));

        assertEquals("openl.error.409.project.copy.failed.message", ex.getErrorCode());
        assertEquals(HttpStatus.CONFLICT, ex.getHttpStatus());
    }

    // V1-D: a rejected archive entry keeps its zip-archive.unknown.archive.path.message error and saves nothing
    @Test
    void archiveEntryRejectionKeepsItsZipArchiveKey() throws Exception {
        var archive = mock(MultipartFile.class);
        when(archive.getOriginalFilename()).thenReturn("Project.zip");
        when(archive.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
        var errors = new BeanPropertyBindingResult(new Object(), "archive");
        errors.reject("zip-archive.unknown.archive.path.message");
        var rejection = new ValidationException(errors);
        doThrow(rejection).when(validationProvider).validate(any(Path.class), any(Validator.class));
        var archives = List.of(archive);

        var ex = assertThrows(ValidationException.class,
                () -> controller.createProject(repository, "Project", null, "comment", archives, null, null, null,
                        "Models", "rules/Models.xlsx", "Algorithms", "rules/Algorithms.xlsx", false, null, null,
                        false));

        assertSame(rejection, ex);
        var globalError = ex.getBindingResult().getGlobalError();
        assertNotNull(globalError);
        assertEquals("zip-archive.unknown.archive.path.message", globalError.getCode());
        verify(zipProjectSaveStrategy, never()).save(any(), any(), any());
        verify(designRepositoryAclService, never()).createAcl(any(AProject.class), anyList(), any(Boolean.class));
    }

    // V1-C: the template route surfaces the new path guard as 400 file.path.invalid.message, never as a 409
    @Test
    void templateRoutePathGuardRejectionIsABadRequest() throws Exception {
        when(projectCreationService.createFromTemplate(eq(repository), eq("link"), any(), any(), any(), any(), any(),
                any())).thenThrow(new BadRequestException("file.path.invalid.message"));

        var ex = assertThrows(RestRuntimeException.class,
                () -> controller.createProject(repository, "link", null, "comment", null, "predefined", "templates",
                        "Sample Project", "Models", "rules/Models.xlsx", "Algorithms", "rules/Algorithms.xlsx",
                        false, null, null, false));

        assertPathRejected(ex);
        verify(projectCreationService, never()).applyStatusAfterCreate(any(Repository.class), any(), any());
    }

    // V1-C: the files route surfaces the new path guard as 400 file.path.invalid.message, never as a 409
    @Test
    void filesRoutePathGuardRejectionIsABadRequest() throws Exception {
        var file = mock(MultipartFile.class);
        when(file.getOriginalFilename()).thenReturn("notes.txt");
        when(file.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
        when(projectCreationService.createFromFiles(eq(repository), eq("link"), any(), anyList(), any(), any(), any(),
                any(), any(), any())).thenThrow(new BadRequestException("file.path.invalid.message"));
        var files = List.of(file);

        var ex = assertThrows(RestRuntimeException.class,
                () -> controller.createProject(repository, "link", null, "comment", files, null, null, null,
                        "Models", "rules/Models.xlsx", "Algorithms", "rules/Algorithms.xlsx", false, null, null,
                        false));

        assertPathRejected(ex);
        verify(projectCreationService, never()).applyStatusAfterCreate(any(Repository.class), any(), any());
    }

    // V1-D: the archive route surfaces the new destination guard as 400, finalizes nothing and releases its lock
    @Test
    void archiveRoutePathGuardRejectionIsABadRequestAndReleasesTheLock() throws Exception {
        var archive = mock(MultipartFile.class);
        when(archive.getOriginalFilename()).thenReturn("Project.zip");
        when(archive.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
        var data = new FileData();
        data.setName("Project");
        when(zipProjectSaveStrategy.save(eq(repository), any(CreateUpdateProjectModel.class), any(Path.class)))
                .thenThrow(new BadRequestException("file.path.invalid.message"))
                .thenReturn(data);
        var archives = List.of(archive);

        var ex = assertThrows(RestRuntimeException.class,
                () -> controller.createProject(repository, "Project", null, "comment", archives, null, null, null,
                        "Models", "rules/Models.xlsx", "Algorithms", "rules/Algorithms.xlsx", false, null, null,
                        false));

        assertPathRejected(ex);
        verify(designRepositoryAclService, never()).createAcl(any(AProject.class), anyList(), any(Boolean.class));
        verify(projectCreationService, never()).registerExtensibleTags(any(AProject.class));
        verify(projectCreationService, never()).awaitProjectVisibility(any(Repository.class));
        verify(projectCreationService, never()).refreshWorkspaceAfterDesignChange();
        verify(projectCreationService, never()).applyStatusAfterCreate(any(Repository.class), any(), any());
        // The same user may take a lock it already holds, so only the lock file itself proves the release.
        assertFalse(new LockManager(Path.of("target").resolve("locks/api"))
                .getLock("design/[branches]/main/Project")
                .info()
                .isLocked());

        controller.createProject(repository, "Project", null, "comment", archives, null, null, null, "Models",
                "rules/Models.xlsx", "Algorithms", "rules/Algorithms.xlsx", false, null, null, false);

        verify(projectCreationService).applyStatusAfterCreate(repository, "Project", null);
    }

    // V1-D: an archive overwrite (payload D15 route) passes its WRITE check, then surfaces the new guard as 400
    @Test
    void archiveOverwritePathGuardRejectionIsABadRequest() throws Exception {
        var archive = mock(MultipartFile.class);
        when(archive.getOriginalFilename()).thenReturn("Project.zip");
        when(archive.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
        when(designRepositoryAclService.isGranted(eq(REPOSITORY_ID), any(), eq(List.of(BasePermission.WRITE))))
                .thenReturn(true);
        when(zipProjectSaveStrategy.save(eq(repository), any(CreateUpdateProjectModel.class), any(Path.class)))
                .thenThrow(new BadRequestException("file.path.invalid.message"));
        var archives = List.of(archive);

        var ex = assertThrows(RestRuntimeException.class,
                () -> controller.createProject(repository, "Project", null, "comment", archives, null, null, null,
                        "Models", "rules/Models.xlsx", "Algorithms", "rules/Algorithms.xlsx", true, null, null,
                        false));

        assertPathRejected(ex);
        verify(designRepositoryAclService).isGranted(REPOSITORY_ID, "Project", List.of(BasePermission.WRITE));
    }

    // V1-C: the from-project route surfaces the new path guard as 400 file.path.invalid.message, never as a 409
    @Test
    void copyRoutePathGuardRejectionIsABadRequest() throws Exception {
        var source = sourceProject("Source");
        when(projectCreationService.copyProject(repository, "link", null, source, "comment", null))
                .thenThrow(new BadRequestException("file.path.invalid.message"));
        var request = new CreateFromProjectModel(REPOSITORY_ID, "Source", null, "comment", null);

        var ex = assertThrows(RestRuntimeException.class,
                () -> controller.createProjectFromProject(repository, "link", request));

        assertPathRejected(ex);
    }

    // V1-C: a '..' copy target (payload C13) that reaches the service is refused there as 400, never as a 409
    @Test
    void copyToADotDotTargetIsABadRequest() throws Exception {
        var source = sourceProject("Source");
        when(projectCreationService.copyProject(eq(repository), eq("link"), eq("../../p"), eq(source),
                eq("comment"), isNull())).thenThrow(new BadRequestException("file.path.invalid.message"));
        var request = new CreateFromProjectModel(REPOSITORY_ID, "Source", "../../p", "comment", null);

        var ex = assertThrows(RestRuntimeException.class,
                () -> controller.createProjectFromProject(repository, "link", request));

        assertPathRejected(ex);
    }

    /** The project the request names as its source, as the identity converter resolves it. */
    private RulesProject sourceProject(String identifier) {
        var source = mock(RulesProject.class);
        when(projectIdentityConverter.resolveProjectIdentity(identifier, REPOSITORY_ID)).thenReturn(source);
        return source;
    }


    private void rejectRequestedBranch(String branch) {
        when(repository.supports()).thenReturn(new FeaturesBuilder(repository).setBranches(true).build());
        doThrow(new ConflictException("repository.branch.message"))
                .when(bypassService)
                .requireBypassOrThrow(repository, branch, REPOSITORY_ID, false);
    }

    // V1-C: controller with real bean validation, built like setUp, so a request model meets its constraints
    private DesignTimeRepositoryController controllerValidatingWith(ValidatorFactory factory) {
        return new DesignTimeRepositoryController(
                designRepositoryAclService,
                new BeanValidationProvider(List.<Validator>of(new SpringValidatorAdapter(factory.getValidator()))),
                mock(CreateUpdateProjectModelValidator.class),
                mock(ZipArchiveValidator.class),
                zipProjectSaveStrategy,
                "target",
                aclProjectsHelper,
                mock(DesignTimeRepositoryService.class),
                mock(ProjectRevisionService.class),
                bypassService,
                projectCreationService,
                projectCreationTargetResolver,
                repositoryConfigService,
                projectIdentityConverter) {
            // The comment service is a @Lookup bean, absent outside a Spring context.
            @Override
            protected Comments getCommentsService(String repoName) {
                return comments;
            }
        };
    }

    // V1-C/D: a path guard rejection is a 400 with the existing file.path.invalid.message key, never a 409
    private static void assertPathRejected(RestRuntimeException ex) {
        assertInstanceOf(BadRequestException.class, ex);
        assertFalse(ex instanceof ConflictException);
        assertEquals(HttpStatus.BAD_REQUEST, ex.getHttpStatus());
        assertEquals("openl.error.400.file.path.invalid.message", ex.getErrorCode());
    }

}

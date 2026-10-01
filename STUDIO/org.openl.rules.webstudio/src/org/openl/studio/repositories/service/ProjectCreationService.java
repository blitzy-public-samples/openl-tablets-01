package org.openl.studio.repositories.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;
import jakarta.annotation.Nullable;
import jakarta.annotation.PostConstruct;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Lookup;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.stereotype.Service;

import org.openl.rules.common.ProjectException;
import org.openl.rules.project.abstraction.AProject;
import org.openl.rules.project.abstraction.ProjectStatus;
import org.openl.rules.project.abstraction.ProjectTags;
import org.openl.rules.project.abstraction.RulesProject;
import org.openl.rules.repository.PathCheckedRepository;
import org.openl.rules.repository.api.BranchRepository;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.api.RepositoryDelegate;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.rest.acl.service.AclProjectsHelper;
import org.openl.rules.webstudio.util.NameChecker;
import org.openl.rules.webstudio.web.CopyProjectTransformer;
import org.openl.rules.webstudio.web.repository.project.CustomTemplatesResolver;
import org.openl.rules.webstudio.web.repository.project.PredefinedTemplatesResolver;
import org.openl.rules.webstudio.web.repository.project.ProjectFile;
import org.openl.rules.webstudio.web.repository.project.TemplatesResolver;
import org.openl.rules.webstudio.web.repository.upload.ProjectUploader;
import org.openl.rules.webstudio.web.repository.upload.zip.ZipCharsetDetector;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.rules.workspace.dtr.FolderMapper;
import org.openl.rules.workspace.dtr.impl.FileMappingData;
import org.openl.rules.workspace.filter.PathFilter;
import org.openl.rules.workspace.uw.UserWorkspace;
import org.openl.security.acl.permission.AclRole;
import org.openl.security.acl.repository.RepositoryAclService;
import org.openl.security.acl.repository.RepositoryAclServiceProvider;
import org.openl.studio.common.exception.BadRequestException;
import org.openl.studio.common.exception.ConflictException;
import org.openl.studio.common.exception.ForbiddenException;
import org.openl.studio.common.exception.NotFoundException;
import org.openl.studio.repositories.model.ProjectTemplateGroup;
import org.openl.studio.tags.service.TagAssignmentValidator;
import org.openl.util.StringUtils;

/**
 * Creates projects the same way the legacy repository tab does, wrapping the reusable creation
 * primitives (template resolvers + {@link ExcelFilesProjectCreator}). The project is built in the
 * current user's workspace, granted a CONTRIBUTOR ACL, and the resulting file data is returned.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ProjectCreationService {

    private static final String CUSTOM_TYPE = "custom";
    private static final String PREDEFINED_TYPE = "predefined";
    private static final long PROJECT_INDEX_TIMEOUT_SECONDS = 30;

    private final AclProjectsHelper aclProjectsHelper;
    private final RepositoryAclServiceProvider aclServiceProvider;
    private final TagAssignmentValidator tagAssignmentValidator;
    @Qualifier("zipFilter")
    private final PathFilter zipFilter;
    private final ZipCharsetDetector zipCharsetDetector;
    @Value("${openl.home:}")
    private final String openlHome;

    private final TemplatesResolver predefinedTemplatesResolver = new PredefinedTemplatesResolver();
    private TemplatesResolver customTemplatesResolver;

    @PostConstruct
    void init() {
        customTemplatesResolver = new CustomTemplatesResolver(openlHome);
    }

    @Lookup
    public UserWorkspace getUserWorkspace() {
        // Spring overrides this method with a lookup of the bean; the stub itself never runs.
        throw new UnsupportedOperationException("Overridden by the Spring @Lookup container");
    }

    private void requireCreatePermission(String repositoryId) {
        if (!aclProjectsHelper.hasCreateProjectPermission(repositoryId)) {
            throw new ForbiddenException("default.message");
        }
    }

    // V1: the write trims control characters away silently, so a path or name carrying one is rejected as received
    private static void requireNoControlCharacters(@Nullable String path, @Nullable String projectName) {
        for (String value : new String[]{path, projectName}) {
            if (value != null && value.chars().anyMatch(ch -> ch < ' ')) {
                throw new BadRequestException("file.path.invalid.message");
            }
        }
    }

    /**
     * V1: keeps the folder of a new project inside the design repository it is written to.
     *
     * <p>The name and the optional parent path are joined the way the write joins them
     * ({@link FileMappingData#internalPath}, which trims and normalizes separators), so a value the write
     * accepts today is not newly rejected for its spacing. The joined path then passes
     * {@link Repository#validatePath} and {@link NameChecker#validatePath}.
     *
     * <p>When the repository keeps its content in a local directory, the physical project folder must also
     * sit at its own lexical place under the real repository root: a link inside the repository may not
     * redirect it to another project or outside the root. The folder and the rules location need not exist
     * yet. Other backends (Git, JDBC, S3, Azure Blob) get the lexical checks only, because they never follow
     * a working-tree link. The unwrapped repository is only asked for its root; the write still goes through
     * the secured wrapper, so no ACL check is bypassed.
     *
     * <p>A blank name is left to the bean validation that owns it. Every rejection is a 400
     * {@code file.path.invalid.message}, raised before any conflict mapping of the caller.
     *
     * <p>The checks are private to this class: each V1 surface guards its own inputs, and no component is
     * shared with the file, workspace or upload surfaces. This departs from the Minimal Change Rule's
     * clause to isolate new code in dedicated files, which the V1 instruction overrides.
     */
    private void requireContainedProjectFolder(Repository repository, String projectName, String path) {
        if (StringUtils.isBlank(projectName)) {
            return;
        }
        try {
            var relative = FileMappingData.internalPath(path, projectName);
            Repository.validatePath(relative);
            NameChecker.validatePath(relative);
            var root = localRoot(repository);
            if (root == null) {
                return;
            }
            // The rules location is read only for a local directory, so other backends never need a workspace.
            var physicalFolder = repository.supports().mappedFolders()
                    ? relative
                    : getUserWorkspace().getDesignTimeRepository().getRulesLocation() + projectName;
            if (!isContained(root, physicalFolder)) {
                log.debug("A new project folder resolves outside its place in the design repository.");
                throw new BadRequestException("file.path.invalid.message");
            }
        } catch (IOException | IllegalArgumentException e) {
            // IllegalArgumentException covers InvalidPathException, for example a NUL character in the path.
            log.debug("A new project folder is rejected: {}", e.getClass().getSimpleName());
            throw new BadRequestException("file.path.invalid.message");
        }
    }

    // V1: the root of a file-backed repository behind its secured and mapped wrappers, or null for other backends
    @Nullable
    private static Path localRoot(Repository repository) {
        var current = repository;
        while (current instanceof RepositoryDelegate delegate) {
            current = delegate.getOriginal();
        }
        if (current instanceof FolderMapper mapper) {
            current = mapper.getDelegate();
        }
        // V1: a configured repository is path-checked, and that wrapper reveals only the root of a file repository
        if (current instanceof PathCheckedRepository pathChecked) {
            return pathChecked.getLocalRoot();
        }
        return current instanceof FileSystemRepository fileSystem ? fileSystem.getRoot() : null;
    }

    /**
     * V1: whether the physical folder sits at its own lexical place under the real root.
     *
     * <p>Links in the root's own path are configured by an administrator and followed. Below the root, the
     * folder is compared with its real location, so a folder that is itself a link, or sits under one, is
     * refused. A dangling link fails to resolve and is refused by the caller.
     */
    private static boolean isContained(Path root, String physicalFolder) throws IOException {
        // V1: resolved before it is normalized, so a '<link>/..' in the root is followed as the repository follows it
        var anchorReal = realPathOf(root.toAbsolutePath()).normalize();
        var boundary = anchorReal.resolve(physicalFolder).normalize();
        if (!boundary.startsWith(anchorReal)) {
            return false;
        }
        return realPathOf(boundary).startsWith(boundary);
    }

    // V1: the real location of a path that may not exist yet: its deepest existing entry resolved, the rest appended
    private static Path realPathOf(Path target) throws IOException {
        for (var existing = target; existing != null; existing = existing.getParent()) {
            // NOFOLLOW_LINKS counts a dangling link as existing, so toRealPath() fails on it instead of skipping it.
            if (Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
                return existing.toRealPath().resolve(existing.relativize(target));
            }
        }
        return target;
    }

    /**
     * Grants the current user the CONTRIBUTOR role on a freshly created project, unless an ACL already
     * exists. Shared with create paths that build the project outside this service.
     */
    public static void grantContributorAclIfAbsent(RepositoryAclService acl, AProject project) {
        if (!acl.hasAcl(project)) {
            acl.createAcl(project, List.of(AclRole.CONTRIBUTOR.getCumulativePermission()), true);
        }
    }

    /**
     * Resyncs the user workspace with the design repository after a write.
     *
     * <p>The refresh keeps the project list metadata aligned for later open, branch and save operations.
     */
    public void refreshWorkspaceAfterDesignChange() {
        try {
            getUserWorkspace().refresh();
        } catch (RuntimeException e) {
            // The design write is already finalized and indexed. A stale user workspace must not report the
            // successful create or copy as failed.
            log.warn("The user workspace could not be refreshed after a design repository change.", e);
        }
    }

    /**
     * Waits until a branch-scoped design write is visible through the project index.
     *
     * <p>A normal response therefore guarantees that subsequent project reads can resolve the new content.
     */
    public void awaitProjectVisibility(Repository repository) {
        // The design-time repository is resolved only when there is something to wait for: a repository
        // without branches needs no wait, and looking one up requires a user workspace the caller may not have.
        awaitProjectVisibility(() -> getUserWorkspace().getDesignTimeRepository(), repository);
    }

    /**
     * Waits until a branch-scoped design write is visible through the project index, for a caller that already
     * holds the design-time repository.
     *
     * <p>A start-up task has no user workspace to look up, so it supplies the repository it works with.
     */
    public void awaitProjectVisibility(DesignTimeRepository designTimeRepository, Repository repository) {
        awaitProjectVisibility(() -> designTimeRepository, repository);
    }

    private void awaitProjectVisibility(Supplier<DesignTimeRepository> designTimeRepository, Repository repository) {
        if (!(repository instanceof BranchRepository branchRepository) || !repository.supports().branches()) {
            return;
        }
        try {
            designTimeRepository.get()
                    .refreshBranch(repository.getId(), branchRepository.getBranch())
                    .toCompletableFuture()
                    .get(PROJECT_INDEX_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ConflictException("project.indexing.incomplete.message");
        } catch (ExecutionException | TimeoutException e) {
            log.warn("Project index did not publish branch '{}' in repository '{}'.",
                    branchRepository.getBranch(), repository.getId(), e);
            throw new ConflictException("project.indexing.incomplete.message");
        }
    }

    /**
     * Configures the tag values a project brought with it in its {@code tags.properties} file: a value of
     * an extensible tag type that is not configured yet becomes configured, so the project shows the tag
     * it carries. A value of any other tag type, and an unknown tag type, need an administrator and are
     * left as they are.
     *
     * <p>Archive upload keeps the project closed, so the tags are read from the repository artefact.
     */
    public void registerExtensibleTags(AProject project) {
        tagAssignmentValidator.applicable(new ProjectTags(project).getTags());
    }

    /**
     * Configures the tag values of a workspace project, collected from both its design and local copies so
     * every create path is covered: publishing a local project exposes them through the local copy, while
     * an archive or copy create exposes them through the design copy.
     */
    void registerExtensibleTags(RulesProject project) {
        tagAssignmentValidator.applicable(collectProjectTags(project));
    }

    private static Map<String, String> collectProjectTags(RulesProject project) {
        var tags = new HashMap<String, String>();
        try {
            tags.putAll(project.getDesignTags());
        } catch (RuntimeException e) {
            log.warn("Cannot read design tags of project '{}'", project.getName(), e);
        }
        try {
            tags.putAll(project.getLocalTags());
        } catch (RuntimeException e) {
            log.warn("Cannot read local tags of project '{}'", project.getName(), e);
        }
        return tags;
    }

    /** List the available predefined (bundled) and custom project templates, grouped by category. */
    public List<ProjectTemplateGroup> listTemplates() {
        var groups = new ArrayList<ProjectTemplateGroup>();
        addGroups(groups, PREDEFINED_TYPE, predefinedTemplatesResolver);
        addGroups(groups, CUSTOM_TYPE, customTemplatesResolver);
        return groups;
    }

    private static void addGroups(List<ProjectTemplateGroup> groups, String type, TemplatesResolver resolver) {
        if (resolver == null) {
            return;
        }
        for (String category : resolver.getCategories()) {
            var templates = resolver.getTemplates(category);
            if (!templates.isEmpty()) {
                groups.add(ProjectTemplateGroup.builder().type(type).category(category).templates(templates).build());
            }
        }
    }

    /**
     * Create a project from a bundled or custom template, granting the creator a CONTRIBUTOR ACL. The
     * template's Excel files become the project content.
     *
     * @return the created project's file data (branch/revision)
     */
    public FileData createFromTemplate(String repositoryId, String projectName, String path,
                                       String type, String category, String template,
                                       String comment, Map<String, String> tags) {
        requireCreatePermission(repositoryId);
        return createFromTemplate(getUserWorkspace().getDesignTimeRepository().getRepository(repositoryId),
                projectName, path, type, category, template, comment, tags);
    }

    public FileData createFromTemplate(Repository repository, String projectName, String path,
                                       String type, String category, String template,
                                       String comment, Map<String, String> tags) {
        var repositoryId = repository.getId();
        requireCreatePermission(repositoryId);
        var resolver = CUSTOM_TYPE.equals(type) ? customTemplatesResolver : predefinedTemplatesResolver;
        var files = resolver.getProjectFiles(category, template);
        if (files.length == 0) {
            throw new NotFoundException("project.template.not-found.message");
        }
        // V1: contain the new project folder inside the design repository root. A rejection releases the template
        // files here, because the upload that would release them never runs.
        try {
            requireContainedProjectFolder(repository, projectName, path);
        } catch (BadRequestException e) {
            for (var file : files) {
                file.destroy();
            }
            throw e;
        }
        return createFromFiles(repository, projectName, path, new ArrayList<>(List.of(files)), comment,
                "rules/Models.xlsx", "rules/Algorithms.xlsx", "Models", "Algorithms", tags);
    }

    /**
     * Creates a project from uploaded files and grants the creator a CONTRIBUTOR ACL.
     *
     * <p>The upload dispatcher recognises a single ZIP archive, one or more Excel files, or a single OpenAPI file.
     * An OpenAPI upload builds a data-types module and a rules module at the requested paths.
     *
     * <p>When Excel files do not supply {@code rules.xml}, their workbooks are stored in the standard project layout
     * and a descriptor is created. An archive without {@code rules.xml} keeps its paths and receives a descriptor for
     * root-level workbooks.
     *
     * @return the created project's file data (branch/revision)
     */
    public FileData createFromFiles(String repositoryId, String projectName, String path, List<ProjectFile> files,
                                    String comment, String modelsPath, String algorithmsPath, String modelsModuleName,
                                    String algorithmsModuleName, Map<String, String> tags) {
        requireCreatePermission(repositoryId);
        return createFromFiles(getUserWorkspace().getDesignTimeRepository().getRepository(repositoryId),
                projectName, path, files, comment, modelsPath, algorithmsPath, modelsModuleName,
                algorithmsModuleName, tags);
    }

    public FileData createFromFiles(Repository repository, String projectName, String path, List<ProjectFile> files,
                                    String comment, String modelsPath, String algorithmsPath, String modelsModuleName,
                                    String algorithmsModuleName, Map<String, String> tags) {
        var repositoryId = repository.getId();
        requireCreatePermission(repositoryId);
        // V1: a rejected path or name never reaches the upload, so the files it would have released are released here
        try {
            requireNoControlCharacters(path, projectName);
            // V1: contain the new project folder inside the design repository root
            requireContainedProjectFolder(repository, projectName, path);
        } catch (BadRequestException e) {
            files.forEach(ProjectFile::destroy);
            throw e;
        }
        try {
            var created = new ProjectUploader(repository, files, projectName, StringUtils.trimToEmpty(path),
                    getUserWorkspace(), aclServiceProvider.getDesignRepoAclService(), comment, zipFilter,
                    zipCharsetDetector, modelsPath, algorithmsPath, modelsModuleName, algorithmsModuleName,
                    tags != null ? tags : Map.of(), this::registerExtensibleTags,
                    () -> awaitProjectVisibility(repository)).uploadProject();
            return created.getFileData();
        } catch (ProjectException e) {
            throw new ConflictException("project.create.failed.message");
        }
    }

    /**
     * Sets the status a freshly created project should have in the user's workspace: opened so the creator
     * can start working on it at once, or closed. A {@code null} status leaves whatever the create path
     * produced (an archive stays closed, other sources stay opened), so existing API callers are unaffected.
     *
     * <p>The wire codes {@code OPENED} and {@code CLOSED} arrive as {@link ProjectStatus#VIEWING} and
     * {@link ProjectStatus#CLOSED}; any other value is ignored.
     */
    public void applyStatusAfterCreate(String repositoryId, String projectName, @Nullable ProjectStatus status) {
        applyStatusAfterCreate(null, repositoryId, projectName, status);
    }

    /**
     * Sets the status of a freshly created project using the exact repository branch that received the write.
     */
    public void applyStatusAfterCreate(Repository repository,
                                       String projectName,
                                       @Nullable ProjectStatus status) {
        applyStatusAfterCreate(repository, repository.getId(), projectName, status);
    }

    private void applyStatusAfterCreate(@Nullable Repository repository,
                                        String repositoryId,
                                        String projectName,
                                        @Nullable ProjectStatus status) {
        if (status != ProjectStatus.VIEWING && status != ProjectStatus.CLOSED) {
            return;
        }
        var workspace = getUserWorkspace();
        // The project is already committed by the time this runs; setting its workspace status is a
        // convenience on top. A failure here (or a same-named project already open elsewhere, which blocks
        // opening) must not turn a successful create into an error — log it and leave the project created.
        try {
            var project = resolveCreatedProject(workspace, repository, repositoryId, projectName);
            if (status == ProjectStatus.VIEWING) {
                if (project.isOpened()) {
                    return;
                }
                if (workspace.isOpenedOtherProject(project)) {
                    log.info("Created project '{}' stays closed: a project with the same name is open elsewhere.",
                            projectName);
                    return;
                }
                project.open();
                workspace.refresh();
            } else if (project.isOpened()) {
                project.close();
                workspace.refresh();
            }
        } catch (ProjectException | RuntimeException e) {
            log.warn("Created project '{}' could not be set to status '{}'.", projectName, status, e);
        }
    }

    /**
     * The just-created project. The workspace copy is used when the create path already registered one
     * (Excel, OpenAPI, template). An uploaded archive is written straight to the design repository and the
     * workspace may not list it yet — then the project is assembled from its design state directly, the
     * same way the legacy project creator and the copy flow build theirs.
     */
    private RulesProject resolveCreatedProject(UserWorkspace workspace,
                                               @Nullable Repository repository,
                                               String repositoryId,
                                               String projectName)
            throws ProjectException {
        if (repository instanceof BranchRepository branchRepository && repository.supports().branches()) {
            var designTimeRepository = workspace.getDesignTimeRepository();
            var designProject = resolveBranchedDesignProject(designTimeRepository,
                    repositoryId,
                    projectName,
                    branchRepository.getBranch());
            return newWorkspaceProject(workspace, repositoryId, designProject);
        }
        try {
            return workspace.getProject(repositoryId, projectName);
        } catch (ProjectException e) {
            var designTimeRepository = workspace.getDesignTimeRepository();
            designTimeRepository.refresh();
            var designProject = designTimeRepository.getProject(repositoryId, projectName);
            return newWorkspaceProject(workspace, repositoryId, designProject);
        }
    }

    private AProject resolveBranchedDesignProject(DesignTimeRepository designTimeRepository,
                                                  String repositoryId,
                                                  String projectName,
                                                  String branch) throws ProjectException {
        try {
            return designTimeRepository.getProject(repositoryId, projectName, branch);
        } catch (ProjectException e) {
            var indexedProject = designTimeRepository.getProjects(repositoryId)
                    .stream()
                    .filter(project -> project.getBusinessName().equalsIgnoreCase(projectName))
                    .findFirst()
                    .orElseThrow(() -> e);
            return designTimeRepository.getProject(repositoryId, indexedProject.getName(), branch);
        }
    }

    /** The workspace view of a design project that has no local copy yet. A seam for tests. */
    protected RulesProject newWorkspaceProject(UserWorkspace workspace, String repositoryId, AProject designProject) {
        return new RulesProject(workspace.getUser(),
                workspace.getLocalWorkspace().getRepository(repositoryId),
                null,
                designProject.getRepository(),
                designProject.getFileData(),
                workspace.getProjectsLockEngine());
    }

    /**
     * Copy an existing project into a design repository under a new name, entirely server-side (the
     * project's folder is copied in the repository, not downloaded and re-uploaded). The descriptor is
     * renamed, the creator is granted a CONTRIBUTOR ACL, and the workspace is refreshed so the copy is
     * indexed.
     *
     * @return the created copy's file data (branch/revision)
     */
    public FileData copyProject(Repository targetRepository, String newName, String path,
                                RulesProject source, String comment, String revision) {
        var targetRepositoryId = targetRepository.getId();
        requireCreatePermission(targetRepositoryId);
        var workspace = getUserWorkspace();
        var designRepoAclService = aclServiceProvider.getDesignRepoAclService();
        try {
            if (!designRepoAclService.isGranted(source, List.of(BasePermission.READ))) {
                throw new ForbiddenException("default.message");
            }
            // The state to copy is resolved first: a revision the source has none at fails before anything
            // is written to the target repository.
            var sourceCopy = sourceAtRevision(source, revision);
            // V1: control characters in path or name are rejected unchecked, never mapped to a copy failure below
            requireNoControlCharacters(path, newName);
            var designTimeRepository = workspace.getDesignTimeRepository();
            var designPath = designTimeRepository.getRulesLocation() + newName;
            // V1: contain the copy's folder inside the target repository root; the 400 is never mapped to a conflict
            requireContainedProjectFolder(targetRepository, newName, path);
            // V1: contain the source project and every file the copy reads; the 400 is never mapped to a conflict
            requireContainedSource(sourceCopy);
            var designData = new FileData();
            designData.setName(designPath);
            designData.setComment(comment);
            if (targetRepository.supports().mappedFolders()) {
                designData.addAdditionalData(FileMappingData.forProject(designPath, path, newName));
            }
            var user = workspace.getUser();
            var targetProject = new AProject(targetRepository, designData);
            targetProject.setResourceTransformer(new CopyProjectTransformer(newName, Map.of()));
            targetProject.update(sourceCopy, user);
            targetProject.setResourceTransformer(null);
            var copied = new RulesProject(user, workspace.getLocalWorkspace().getRepository(targetRepositoryId),
                    null, targetRepository, targetProject.getFileData(), workspace.getProjectsLockEngine());
            grantContributorAclIfAbsent(designRepoAclService, copied);
            registerExtensibleTags(copied);
            awaitProjectVisibility(targetRepository);
            refreshWorkspaceAfterDesignChange();
            return copied.getFileData();
        } catch (ProjectException e) {
            // The answer carries a code only, so without this the failure leaves no trace anywhere.
            log.error("Failed to copy project '{}' into repository '{}'.", newName, targetRepositoryId, e);
            throw new ConflictException("project.copy.failed.message");
        }
    }

    /**
     * The state of the source project to copy: its latest one for a blank revision, otherwise the state it
     * had at that revision.
     *
     * <p>A revision the project has no state at is rejected, whatever the repository makes of the value.
     */
    private AProject sourceAtRevision(RulesProject source, @Nullable String revision) {
        var version = StringUtils.trimToNull(revision);
        var sourceCopy = new AProject(source.getRepository(), source.getFolderPath(), version);
        if (version == null) {
            return sourceCopy;
        }
        try {
            if (sourceCopy.getFileData() != null) {
                return sourceCopy;
            }
        } catch (RuntimeException e) {
            // A repository numbers its revisions its own way and may reject the value outright.
            log.debug("Revision '{}' cannot be read from the repository.", version, e);
        }
        throw new NotFoundException("project.revision.message", version);
    }

    /**
     * V1: keeps the source of a copy inside its own project folder before anything is read from it.
     *
     * <p>When the source repository keeps its content in a local directory (a file design repository, flat or
     * mapped, or the user's working copy of an opened project), the copy reads every file the repository lists
     * under the project, and a file repository lists a link to a regular file and follows it on read. So the
     * physical project folder ({@link AProject#getRealPath()} under the real repository root) must sit at its
     * own lexical place, and every listed file must resolve inside that folder: a link to a sibling project, to
     * a place outside the root, or to nothing is refused. Links that stay inside the project folder are
     * accepted. The listing is the one the copy reads, taken through the secured wrapper; the unwrapped
     * repository is only asked for its root. A file repository keeps no history, so its current state is the
     * one copied. Other backends (Git, JDBC, S3, Azure Blob) never follow a working-tree link and get no check.
     *
     * <p>Every rejection is a 400 {@code file.path.invalid.message}, raised before anything is read from the
     * source or written to the target, so it is never mapped to a copy conflict.
     *
     * <p>The check is private to this class: each V1 surface guards its own inputs, and no component is
     * shared with the file, workspace or upload surfaces. This departs from the Minimal Change Rule's clause
     * to isolate new code in dedicated files, which the V1 instruction overrides.
     */
    private static void requireContainedSource(AProject sourceCopy) {
        var repository = sourceCopy.getRepository();
        var root = localRoot(repository);
        if (root == null) {
            return;
        }
        try {
            // Resolved before it is normalized, so a '<link>/..' in the root is followed as the repository follows it.
            var anchorReal = realPathOf(root.toAbsolutePath()).normalize();
            var boundary = anchorReal.resolve(sourceCopy.getRealPath().replaceAll("^/+|/+$", "")).normalize();
            if (!boundary.startsWith(anchorReal) || !realPathOf(boundary).startsWith(boundary)) {
                log.debug("A source project folder resolves outside its place in the repository.");
                throw new BadRequestException("file.path.invalid.message");
            }
            if (!sourceCopy.isFolder()) {
                return;
            }
            var prefix = sourceCopy.getFolderPath() + "/";
            for (var file : repository.list(prefix)) {
                var name = file.getName();
                // A listed name outside the project cannot be placed under its folder, so it fails closed.
                var target = name.startsWith(prefix)
                        ? boundary.resolve(name.substring(prefix.length())).normalize()
                        : null;
                if (target == null || !target.startsWith(boundary) || !realPathOf(target).startsWith(boundary)) {
                    log.debug("A file of the source project resolves outside the project folder.");
                    throw new BadRequestException("file.path.invalid.message");
                }
            }
        } catch (IOException | IllegalArgumentException e) {
            // IllegalArgumentException covers InvalidPathException; IOException covers a link that resolves nowhere.
            log.debug("A source project is rejected: {}", e.getClass().getSimpleName());
            throw new BadRequestException("file.path.invalid.message");
        }
    }

}

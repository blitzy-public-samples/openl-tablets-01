package org.openl.studio.repositories.service;

// V1: Iterator, LinkOption, Nullable, LocalWorkingTree, PathCheckedRepository, RepositoryDelegate,
// FileSystemRepository, NameChecker, FolderMapper and BadRequestException serve the upload destination guard; the
// import block itself cannot hold a comment, as Spotless rewrites it.
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import org.openl.rules.project.model.Module;
import org.openl.rules.project.model.ProjectDescriptor;
import org.openl.rules.repository.LocalWorkingTree;
import org.openl.rules.repository.PathCheckedRepository;
import org.openl.rules.repository.api.AdditionalData;
import org.openl.rules.repository.api.ChangesetType;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.api.RepositoryDelegate;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.repository.folder.FileChangesFromFolder;
import org.openl.rules.webstudio.service.UserManagementService;
import org.openl.rules.webstudio.util.NameChecker;
import org.openl.rules.webstudio.web.repository.upload.zip.ZipCharsetDetector;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.rules.workspace.dtr.FolderMapper;
import org.openl.rules.workspace.dtr.impl.FileMappingData;
import org.openl.rules.workspace.filter.PathFilter;
import org.openl.studio.common.exception.BadRequestException;
import org.openl.studio.repositories.model.CreateUpdateProjectModel;
import org.openl.util.FileTypeHelper;
import org.openl.util.FileUtils;
import org.openl.util.IOUtils;
import org.openl.util.StringUtils;
import org.openl.util.ZipUtils;

@Component
public class ZipProjectSaveStrategy {

    private static final String ROOT_XLSX_MODULE_PATTERN = "*.xlsx";

    private final DesignTimeRepository designTimeRepository;
    private final PathFilter zipFilter;
    private final ZipCharsetDetector zipCharsetDetector;
    private final UserManagementService userManagementService;

    public ZipProjectSaveStrategy(DesignTimeRepository designTimeRepository,
                                  @Qualifier("zipFilter") PathFilter zipFilter,
                                  ZipCharsetDetector zipCharsetDetector,
                                  UserManagementService userManagementService) {
        this.designTimeRepository = designTimeRepository;
        this.zipFilter = zipFilter;
        this.zipCharsetDetector = zipCharsetDetector;
        this.userManagementService = userManagementService;
    }

    public FileData save(Repository repository, CreateUpdateProjectModel model, Path zipArchive) throws IOException {
        var author = Optional.ofNullable(userManagementService.getUser(model.getAuthor()))
                .map(user -> new UserInfo(user.getUsername(), user.getEmail(), user.getDisplayName()))
                .orElse(new UserInfo(model.getAuthor()));
        var projectData = new FileData();
        projectData.setName(designTimeRepository.getRulesLocation() + model.getProjectName());
        projectData.setComment(StringUtils.trimToEmpty(model.getComment()));
        projectData.setAuthor(author);
        if (repository.supports().mappedFolders()) {
            AdditionalData<FileMappingData> additionalData = new FileMappingData(projectData.getName(),
                    model.getFullPath());
            projectData.addAdditionalData(additionalData);
        }
        // V1: keep the uploaded project inside its design repository folder
        var boundary = requireContainedDestination(repository, model);
        var adaptor = new ProjectDescriptorNameAdaptor(model.getProjectName());
        Predicate<Path> filter = p -> zipFilter.accept(p.toString());
        var charset = zipCharsetDetector.detectCharset(() -> Files.newInputStream(zipArchive));
        try (FileSystem fs = FileSystems.newFileSystem(ZipUtils.toJarURI(zipArchive),
                Map.of("encoding", charset.name()))) {

            final var root = fs.getPath("/");
            var generatedRulesXml = Files.exists(root.resolve(ProjectDescriptor.FILE_NAME))
                    ? Optional.<byte[]>empty()
                    : Optional.of(rulesXml(root, filter, model.getProjectName()));
            // V1: an overwritten project folder may already hold links, so no entry may be written through one
            if (boundary != null && Files.isDirectory(boundary, LinkOption.NOFOLLOW_LINKS)) {
                requireContainedEntries(boundary, root, filter, generatedRulesXml.isPresent());
            }
            if (repository.supports().folders()) {
                try (var changes = new FileChangesFromFolder(root,
                        projectData.getName(),
                        filter,
                        adaptor)) {
                    var projectChanges = generatedRulesXml.isPresent()
                            ? appendProjectDescriptor(changes, projectData.getName(), generatedRulesXml.orElseThrow())
                            : changes;
                    // V1: each entry is checked again as the repository writes it, in the tree of its target branch
                    var savedChanges = boundary == null
                            ? projectChanges
                            : containedChanges(boundary, projectData.getName(), projectChanges);
                    return saveContained(repository, projectData, savedChanges);
                }
            }

            return saveAsArchive(repository, projectData, root, filter, adaptor, generatedRulesXml);
        }
    }

    private static FileData saveAsArchive(Repository repository,
                                          FileData projectData,
                                          Path projectRoot,
                                          Predicate<Path> filter,
                                          ProjectDescriptorNameAdaptor adaptor,
                                          Optional<byte[]> generatedRulesXml) throws IOException {
        Path tmp = FileUtils.createPrivateTempFile(FileUtils.getBaseName(projectData.getName()), ".zip");
        try {
            try (var zos = new ZipOutputStream(Files.newOutputStream(tmp))) {
                try (var changes = new FileChangesFromFolder(projectRoot, filter, adaptor)) {
                    for (FileItem fileItem : changes) {
                        var name = fileItem.getData().getName();
                        if (name.charAt(0) == '/') {
                            name = name.substring(1);
                        }
                        var entry = new ZipEntry(name);
                        zos.putNextEntry(entry);
                        var is = fileItem.getStream();
                        if (is != null) {
                            is.transferTo(zos);
                            IOUtils.closeQuietly(is);
                        }
                    }
                }
                if (generatedRulesXml.isPresent()) {
                    zos.putNextEntry(new ZipEntry(ProjectDescriptor.FILE_NAME));
                    zos.write(generatedRulesXml.orElseThrow());
                }
            }
            try (InputStream is = Files.newInputStream(tmp)) {
                repository.save(projectData, is);
                return repository.check(projectData.getName());
            }
        } finally {
            FileUtils.deleteQuietly(tmp);
        }
    }

    private static Iterable<FileItem> appendProjectDescriptor(Iterable<FileItem> changes,
                                                              String projectFolder,
                                                              byte[] rulesXml) {
        var descriptor = new FileItem(projectFolder + "/" + ProjectDescriptor.FILE_NAME,
                new ByteArrayInputStream(rulesXml));
        return () -> Stream.concat(StreamSupport.stream(changes.spliterator(), false), Stream.of(descriptor))
                .iterator();
    }

    private static byte[] rulesXml(Path projectRoot, Predicate<Path> filter, String projectName) throws IOException {
        var modules = new ArrayList<Module>();
        modules.add(module(ROOT_XLSX_MODULE_PATTERN));
        try (var files = Files.list(projectRoot)) {
            files.filter(Files::isRegularFile)
                    .filter(filter)
                    .map(Path::getFileName)
                    .map(Path::toString)
                    .filter(FileTypeHelper::isExcelFile)
                    .filter(fileName -> !fileName.toLowerCase(Locale.ROOT).endsWith(".xlsx"))
                    .filter(fileName -> !fileName.startsWith("._"))
                    .map(ZipProjectSaveStrategy::module)
                    .forEach(modules::add);
        }
        var descriptor = new ProjectDescriptor();
        descriptor.setName(projectName);
        descriptor.setModules(modules);
        return descriptor.toBytes();
    }

    private static Module module(String path) {
        var module = new Module();
        module.setRulesRootPath(path);
        return module;
    }

    // V1: this class keeps its own copy of the guard, because the path surfaces must share no component
    /**
     * Rejects an upload whose project folder would leave its design repository.
     *
     * <p>The path the project is stored under passes {@link Repository#validatePath(String)} and
     * {@link NameChecker#validatePath(String)}: the full internal path in a repository with mapped folders, the
     * project name in a flat one. When the repository keeps its files in a local folder, the project folder must
     * also sit at its own place below the repository root, so no link can lead it outside the root or into
     * another project. Links in the path of the configured root itself are trusted. Neither the rules location
     * nor the project folder has to exist yet, so a first save is accepted.
     *
     * @param repository the repository the project is saved to, possibly behind secured wrappers
     * @param model      the upload request
     * @return the project folder on the local file system, or {@code null} when the repository keeps no local
     *         folder (JDBC, S3, Azure Blob) and only the lexical checks apply
     * @throws BadRequestException {@code file.path.invalid.message} when the destination is rejected
     */
    private @Nullable Path requireContainedDestination(Repository repository, CreateUpdateProjectModel model) {
        try {
            boolean mapped = repository.supports().mappedFolders();
            var input = mapped ? model.getFullPath() : model.getProjectName();
            if (StringUtils.isBlank(input)) {
                return null;
            }
            Repository.validatePath(input);
            NameChecker.validatePath(input);
            var root = localRoot(repository);
            if (root == null) {
                return null;
            }
            // The folder the save writes to: the internal path of the file mapping, or the external project name.
            var folder = mapped
                    ? StringUtils.trimToEmpty(model.getFullPath())
                    : designTimeRepository.getRulesLocation() + model.getProjectName();
            // V1: resolved before it is normalized, so a '<link>/..' in the root leads where the repository writes
            var anchor = realPathOf(root.toAbsolutePath()).normalize();
            var boundary = anchor.resolve(folder).normalize();
            // Lexically inside the root, and no link between the root and the project folder.
            if (!boundary.startsWith(anchor) || !realPathOf(boundary).startsWith(boundary)) {
                throw new BadRequestException("file.path.invalid.message");
            }
            return boundary;
        } catch (IOException | IllegalArgumentException e) {
            // NameChecker failures, dangling links and unparsable paths (InvalidPathException) are all rejections.
            throw new BadRequestException("file.path.invalid.message");
        }
    }

    // V1: finds the local root of a file-system or Git repository behind its secured and mapping wrappers
    /**
     * Returns the local folder the given repository writes saved files to: the root folder of a file-system
     * repository, or the working tree of a {@link LocalWorkingTree} such as a Git repository.
     *
     * <p>The secured wrappers are unwrapped through {@link RepositoryDelegate}, then a {@link FolderMapper} through
     * its delegate. A repository built from its settings ends there in a {@link PathCheckedRepository}, which is
     * not a delegate and reveals only the root of a file repository or the working tree of a repository it wraps.
     * The unwrapped repository is only asked for that folder: every write still goes through the wrapper the
     * caller passed, so no access check is bypassed.
     *
     * @return the local folder, or {@code null} when the repository does not write its files to a local folder
     */
    private static @Nullable Path localRoot(Repository repository) {
        var current = repository;
        while (current instanceof RepositoryDelegate delegate) {
            current = delegate.getOriginal();
        }
        if (current instanceof FolderMapper mapper) {
            current = mapper.getDelegate();
        }
        // V1: a Git repository writes saved files through its local working tree, which may hold links
        if (current instanceof PathCheckedRepository pathChecked) {
            var fileRoot = pathChecked.getLocalRoot();
            return fileRoot != null ? fileRoot : pathChecked.getLocalWorkingTree();
        }
        if (current instanceof LocalWorkingTree workingTree) {
            return workingTree.getLocalWorkingTree();
        }
        return current instanceof FileSystemRepository fileSystem ? fileSystem.getRoot() : null;
    }

    // V1: resolves the existing part of a path through its links; the part still to be created holds none
    /**
     * Resolves the deepest existing ancestor of the path, the path itself included, to its real location and
     * appends the rest. A dangling link counts as existing, so its resolution fails.
     *
     * @param target an absolute path
     * @return the real location the path leads to, or the path itself when none of its ancestors exists
     * @throws IOException if an existing ancestor cannot be resolved, such as a dangling link
     */
    private static Path realPathOf(Path target) throws IOException {
        for (var existing = target; existing != null; existing = existing.getParent()) {
            if (Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
                return existing.toRealPath().resolve(existing.relativize(target));
            }
        }
        return target;
    }

    // V1: an archive overwriting an existing project must not write through a link the project folder holds
    /**
     * Rejects the archive when one of the entries the save writes, or the descriptor it generates, would land
     * outside the existing project folder through a link in that folder.
     *
     * <p>Entries are selected by the same filter as the save. Folders are checked as well as files. A failure to
     * read the archive propagates as it is; a rejected entry is a {@link BadRequestException}.
     *
     * @param boundary                the existing project folder, at its own place below the repository root
     * @param zipRoot                 the root of the uploaded archive
     * @param filter                  the filter the save applies to archive entries
     * @param withGeneratedDescriptor whether the save adds a generated project descriptor
     * @throws IOException if the archive cannot be read
     */
    private static void requireContainedEntries(Path boundary,
                                                Path zipRoot,
                                                Predicate<Path> filter,
                                                boolean withGeneratedDescriptor) throws IOException {
        try (var entries = Files.walk(zipRoot)) {
            entries.filter(entry -> !zipRoot.equals(entry))
                    .filter(filter)
                    .forEach(entry -> requireContainedEntry(boundary, zipRoot.relativize(entry).toString()));
        }
        if (withGeneratedDescriptor) {
            requireContainedEntry(boundary, ProjectDescriptor.FILE_NAME);
        }
    }

    // V1: one entry of an overwriting archive, resolved against the existing project folder
    private static void requireContainedEntry(Path boundary, String name) {
        try {
            var target = boundary.resolve(name).normalize();
            if (!target.startsWith(boundary) || !realPathOf(target).startsWith(boundary)) {
                throw new BadRequestException("file.path.invalid.message");
            }
        } catch (IOException | IllegalArgumentException e) {
            // A dangling link or a name the local file system cannot represent is a rejection, not a 500.
            throw new BadRequestException("file.path.invalid.message");
        }
    }

    // V1: the entries of an upload, each checked against the project folder right before the repository writes it
    /**
     * The changes of the save, each checked against the project folder when the repository takes it.
     *
     * <p>A Git repository checks out the branch it saves to only once it holds its write lock, and that branch may
     * hold links the tree checked out before did not. So a change is checked when the repository asks for it, which
     * is right before the repository writes it, against the tree it writes the change through. The changes are read
     * out of the archive in one pass, so they are passed on one at a time and never collected. A refused change has
     * its stream closed and ends the save with an {@link EntryRefused}.
     *
     * @param boundary      the project folder, at its own place below the repository root
     * @param projectFolder the name of the project folder in the repository, which every change is named under
     * @param changes       the changes of the save
     * @return the same changes in the same order, each checked as it is taken
     */
    private static Iterable<FileItem> containedChanges(Path boundary,
                                                       String projectFolder,
                                                       Iterable<FileItem> changes) {
        var prefix = projectFolder + "/";
        return () -> new Iterator<>() {
            private final Iterator<FileItem> source = changes.iterator();

            @Override
            public boolean hasNext() {
                return source.hasNext();
            }

            @Override
            public FileItem next() {
                var change = source.next();
                try {
                    requireContainedEntry(boundary, entryName(change));
                    return change;
                } catch (BadRequestException e) {
                    IOUtils.closeQuietly(change.getStream());
                    throw new EntryRefused(e);
                }
            }

            // V1: only the project folder is checked, so a change named anywhere else is refused
            private String entryName(FileItem change) {
                var name = change.getData().getName();
                if (!name.startsWith(prefix)) {
                    throw new BadRequestException("file.path.invalid.message");
                }
                return name.substring(prefix.length());
            }
        };
    }

    // V1: a refused entry ends the save with that refusal, however the repository reported it
    /**
     * Saves the changes as the full content of the project folder, and reports a change refused while the repository
     * was taking them as the rejection it is.
     *
     * <p>A file repository lets the refusal through as it is. A Git repository resets its working tree and reports it
     * as a failure of its own, so the refusal is looked for among the causes. Only a refusal raised by
     * {@link #containedChanges} counts: any other failure is the repository's own and propagates unchanged.
     *
     * @throws BadRequestException {@code file.path.invalid.message} when a change is refused
     * @throws IOException         if the repository fails to save the changes
     */
    private static FileData saveContained(Repository repository,
                                          FileData projectData,
                                          Iterable<FileItem> changes) throws IOException {
        try {
            return repository.save(projectData, changes, ChangesetType.FULL);
        } catch (EntryRefused e) {
            throw e.refusal;
        } catch (IOException e) {
            for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
                if (cause instanceof EntryRefused refused) {
                    throw refused.refusal;
                }
            }
            throw e;
        }
    }

    // V1: marks a refusal raised while the repository takes the entries, to tell it apart from the repository's own
    /** A change refused by {@link #containedChanges} while the repository was already taking the changes. */
    private static final class EntryRefused extends RuntimeException {
        private final BadRequestException refusal;

        private EntryRefused(BadRequestException refusal) {
            super(refusal);
            this.refusal = refusal;
        }
    }
}

package org.openl.rules.project.abstraction;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;

import org.openl.rules.common.ArtefactPath;
import org.openl.rules.common.CommonUser;
import org.openl.rules.common.ProjectException;
import org.openl.rules.common.impl.ArtefactPathImpl;
import org.openl.rules.repository.PathCheckedRepository;
import org.openl.rules.repository.api.ChangesetType;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.repository.api.RepositoryDelegate;
import org.openl.rules.repository.file.FileSystemRepository;
import org.openl.rules.workspace.dtr.FolderMapper;
import org.openl.rules.workspace.dtr.impl.FileMappingData;
import org.openl.util.IOUtils;

@Slf4j
public class AProjectFolder extends AProjectArtefact implements IProjectFolder {

    private Map<String, AProjectArtefact> artefacts;
    @Getter
    private ResourceTransformer resourceTransformer;
    @Getter
    @Setter
    private String folderPath;
    @Getter
    @Setter
    private String historyVersion;

    public AProjectFolder(AProject project, Repository repository, String folderPath, String historyVersion) {
        super(project, repository, null);
        if (folderPath.startsWith("/")) {
            folderPath = folderPath.substring(1);
        }
        this.folderPath = folderPath;
        this.historyVersion = historyVersion;
    }

    /**
     * Create a folder with pre-initialised content
     *
     * @param artefacts pre-initialized artefact collection
     */
    public AProjectFolder(Map<String, AProjectArtefact> artefacts,
                          AProject project,
                          Repository repository,
                          String folderPath) {
        this(project, repository, folderPath, null);
        this.artefacts = artefacts;
    }

    @Override
    public String getName() {
        return folderPath.substring(folderPath.lastIndexOf('/') + 1);
    }

    @Override
    public AProjectArtefact getArtefact(String name) throws ProjectException {
        var artefact = getArtefactsInternal().get(name);
        if (artefact == null) {
            throw new ProjectException("Cannot find project artefact ''{0}''", null, name);
        }

        return artefact;
    }

    public void deleteArtefact(String name) throws ProjectException {
        getProject().tryLockOrThrow();

        getArtefact(name).delete();
        getArtefactsInternal().remove(name);
    }

    public boolean hasArtefact(String name) {
        return getArtefactsInternal().containsKey(name);
    }

    public AProjectFolder addFolder(String name) throws ProjectException {
        getProject().tryLockOrThrow();

        var createdFolder = new AProjectFolder(getProject(), getRepository(), folderPath + "/" + name, null);
        getArtefactsInternal().put(name, createdFolder);
        createdFolder.setResourceTransformer(resourceTransformer);
        return createdFolder;
    }

    public AProjectResource addResource(String name, InputStream content) throws ProjectException {
        try {
            getProject().tryLockOrThrow();

            var fileData = new FileData();
            var fullName = folderPath + "/" + name;
            fileData.setName(fullName);
            var repository = getRepository();
            if (repository.check(fullName) != null) {
                throw new ProjectException("The file '%s' exists in the folder.".formatted(name),
                        new IOException());
            }
            fileData = repository.save(fileData, content);
            var createdResource = new AProjectResource(getProject(), repository, fileData);
            getArtefactsInternal().put(name, createdResource);
            return createdResource;
        } catch (IOException ex) {
            throw new ProjectException("Cannot add a resource", ex);
        } finally {
            IOUtils.closeQuietly(content);
        }
    }

    /**
     * Adds artefact to the folder creating needed subfolders (parent folders for artefact)
     *
     * @param artefact artefact to add
     */
    public void addArtefact(AProjectArtefact artefact) {
        Map<String, AProjectArtefact> artefactsInternal = getArtefactsInternal();
        if (artefact instanceof AProjectFolder) {
            // Add folders as is. They are split to sub-folders already.
            artefactsInternal.put(artefact.getName(), artefact);
            return;
        }

        var path = getFolderPath();
        var artefactPath = artefact.getFileData().getName();

        var subFolderNameStart = path.length() + 1;
        var subFolderNameEnd = artefactPath.indexOf('/', subFolderNameStart);
        if (subFolderNameEnd > -1) {
            // Has subfolder
            var name = artefactPath.substring(subFolderNameStart, subFolderNameEnd);
            var folder = (AProjectFolder) artefactsInternal.computeIfAbsent(name,
                    k -> new AProjectFolder(new HashMap<>(),
                            artefact.getProject(),
                            artefact.getRepository(),
                            path + "/" + name));
            folder.addArtefact(artefact);
        } else {
            artefactsInternal.put(artefact.getName(), artefact);
        }
    }

    public synchronized Collection<AProjectArtefact> getArtefacts() {
        return getArtefactsInternal().values();
    }

    @Override
    public boolean isFolder() {
        return true;
    }

    @Override
    public void update(AProjectArtefact newFolder, CommonUser user) throws ProjectException {
        super.update(newFolder, user);
        if (this.isFolder()) {
            var from = (AProjectFolder) newFolder;
            // V1: decided once, before anything is read, which source files stay inside the source project folder
            var contained = containedFiles(from);

            List<FileItem> changes = new ArrayList<>();
            try {
                ChangesetType changesetType;
                String fromProjectVersion = null;

                var fromRepository = from.getRepository();
                var toRepository = getRepository();
                if (fromRepository.supports().uniqueFileId() && toRepository.supports().uniqueFileId()) {
                    changesetType = ChangesetType.DIFF;
                    fromProjectVersion = findDiffChanges(from, contained, changes); // V1: only contained files
                } else {
                    changesetType = ChangesetType.FULL;
                    findChanges(from, contained, changes); // V1: only contained files
                }
                if (getResourceTransformer() != null) {
                    changes = getResourceTransformer().transformChangedFiles(getFolderPath(), changes);
                }

                var fileData = getFileData();
                fileData.setAuthor(user == null ? null : user.getUserInfo());
                if (fromProjectVersion != null) {
                    fileData.setVersion(fromProjectVersion);
                }
                setFileData(getRepository().save(fileData, changes, changesetType));
            } catch (IOException e) {
                throw new ProjectException(e.getMessage(), e);
            } finally {
                for (FileItem change : changes) {
                    IOUtils.closeQuietly(change.getStream());
                }
            }
        }
    }

    /**
     * Collects the files that are added, modified or deleted in the given folder compared to this one.
     *
     * @return the version of the given folder the files are read from, or {@code null} if there is none
     */
    private @Nullable String findDiffChanges(AProjectFolder from,
                                             Predicate<String> contained, // V1: the source files a copy may read
                                             List<FileItem> changes) throws IOException, ProjectException {
        String fromProjectVersion = null;

        var fromRepository = from.getRepository();
        var fromFilePath = from.getFolderPath() + "/";
        List<FileData> fromList;
        if (fromRepository.supports().versions()) {
            if (from.isHistoric()) {
                fromProjectVersion = from.getHistoryVersion();
                fromList = fromRepository.listFiles(fromFilePath, fromProjectVersion);
            } else {
                var fileData = fromRepository.check(from.getFolderPath());
                if (fileData == null) {
                    fromList = List.of();
                } else {
                    fromProjectVersion = fileData.getVersion();
                    fromList = fromRepository.listFiles(fromFilePath, fromProjectVersion);
                }
            }
        } else {
            fromList = fromRepository.list(fromFilePath);
        }
        // V1: a source file whose real location leaves the source project folder is neither read nor compared
        fromList = fromList.stream().filter(fromData -> contained.test(fromData.getName())).toList();

        var toRepository = getRepository();
        var toFilePath = getFolderPath() + "/";
        List<FileData> toList = isHistoric() ? toRepository.listFiles(toFilePath, getHistoryVersion())
                : toRepository.list(toFilePath);

        // Search added and modified files
        findAddedAndModifiedFiles(from, fromList, fromProjectVersion, toList, changes);
        // Search deleted files
        findDeletedFiles(from, fromList, toList, changes);
        return fromProjectVersion;
    }

    private void findAddedAndModifiedFiles(AProjectFolder from,
                                           List<FileData> fromList,
                                           @Nullable String fromProjectVersion,
                                           List<FileData> toList,
                                           List<FileItem> changes) throws IOException, ProjectException {
        var fromRepository = from.getRepository();
        var transformer = getResourceTransformer();

        for (FileData fromData : fromList) {
            var nameFrom = fromData.getName();
            var nameTo = getFolderPath() + nameFrom.substring(from.getFolderPath().length());

            var fromUniqueId = fromData.getUniqueId();
            if (fromUniqueId == null) {
                // The file was modified or added
                FileItem read = fromRepository.supports().versions()
                        ? fromRepository.readHistory(nameFrom, fromProjectVersion)
                        : fromRepository.read(nameFrom);
                changes.add(new FileItem(nameTo, read.getStream()));
            } else {
                FileData toData = find(toList, nameTo);
                if (toData == null || !fromUniqueId.equals(toData.getUniqueId())) {
                    // The file is absent in destination. Add it.
                    // Or different revision of a file.
                    var data = copyAndChangeName(fromData, nameTo);
                    changes.add(new FileItem(data, readContent(from, nameFrom, fromProjectVersion, transformer)));
                }
                // Otherwise the file is same, no need to save it
            }
        }
    }

    private static InputStream readContent(AProjectFolder from,
                                           String nameFrom,
                                           @Nullable String fromProjectVersion,
                                           @Nullable ResourceTransformer transformer)
            throws IOException, ProjectException {
        var fromRepository = from.getRepository();
        if (transformer != null) {
            FileData fileData = fromRepository.supports().versions() ? fromRepository
                    .checkHistory(nameFrom, fromProjectVersion) : fromRepository.check(nameFrom);
            return transformer.transform(new AProjectResource(from.getProject(), fromRepository, fileData));
        }
        FileItem read = fromRepository.supports().versions() ? fromRepository
                .readHistory(nameFrom, fromProjectVersion) : fromRepository.read(nameFrom);
        return read.getStream();
    }

    private void findDeletedFiles(AProjectFolder from,
                                  List<FileData> fromList,
                                  List<FileData> toList,
                                  List<FileItem> changes) {
        for (FileData toData : toList) {
            var nameTo = toData.getName();
            var nameFrom = from.getFolderPath() + nameTo.substring(getFolderPath().length());

            FileData fromData = find(fromList, nameFrom);
            if (fromData == null) {
                // File was deleted
                changes.add(new FileItem(toData, null));
            }
        }
    }

    private FileData copyAndChangeName(FileData data, String newName) {
        // Keep only required fields. The fields uniqueId and name are required. Fields like author, modifiedAt
        // aren't required for file saving, but retrieving that fields can be slow for a big amount of files.
        var copy = new FileData();
        copy.setName(newName);
        copy.setUniqueId(data.getUniqueId());

        return copy;
    }

    private static FileData find(List<FileData> list, String name) {
        for (FileData fileData : list) {
            if (fileData.getName().equals(name)) {
                return fileData;
            }
        }

        return null;
    }

    private void findChanges(AProjectFolder from,
                             Predicate<String> contained, // V1: the source files a copy may read
                             List<FileItem> files) throws ProjectException {
        var transformer = getResourceTransformer();
        var path = getFolderPath();

        for (AProjectArtefact artefact : from.getArtefacts()) {
            if (artefact instanceof AProjectResource resource) {
                // V1: a source file whose real location leaves the source project folder is not read
                if (!contained.test(resource.getFileData().getName())) {
                    continue;
                }
                InputStream content = transformer != null ? transformer.transform(resource) : resource.getContent();
                files.add(new FileItem(path + "/" + artefact.getInternalPath(), content));
            } else {
                findChanges((AProjectFolder) artefact, contained, files); // V1: the same source files
            }
        }
    }

    // V1: real-path containment of the files a copy reads from a file-backed source project folder. It is private
    // to this copy routine, not a dedicated class as the Minimal Change Rule asks for new code: the path-containment
    // fix forbids a component shared between path surfaces, and this module cannot reach the FileRoot helpers of the
    // files service.
    /**
     * Tells which files of the source folder a copy may read: those whose real location stays inside the source
     * project folder.
     *
     * <p>The source repository is unwrapped through every {@link RepositoryDelegate}, then through one
     * {@link FolderMapper}, down to a {@link PathCheckedRepository} or a {@link FileSystemRepository}, which is only
     * asked for its root directory. That root is the anchor: links in its own path are trusted and followed. The
     * boundary is the source's real path, resolved lexically under the anchor's real location. A file is accepted
     * when its name lies under the source folder path and its real location, links inside the boundary followed,
     * stays under the boundary. A link to another project or outside, a dangling link, a link loop and a name that is
     * not a valid path are not. A file that a concurrent save is replacing is accepted, so a copy never leaves it out.
     * Any other backend, such as Git or JDBC, is not read through filesystem links, so it accepts every file and is
     * never asked for its real path or touched on disk.
     *
     * @param from the folder a copy reads from
     * @return the test over the full file names the source repository lists, such as {@code <folder>/rules/Main.xlsx}
     * @throws ProjectException when the source project folder itself is reached through a link or cannot be
     *                          resolved, so the copy is refused before anything is read or written
     */
    static Predicate<String> containedFiles(AProjectFolder from) throws ProjectException {
        var root = localRoot(from.getRepository());
        if (root == null) {
            return name -> true;
        }
        var anchor = realLocation(root);
        var folderPath = from.getFolderPath();
        Path boundary;
        try {
            boundary = anchor.resolve(trimSlashes(from.getRealPath())).normalize();
        } catch (IllegalArgumentException e) {
            throw new ProjectException("The folder of the project '%s' is not a valid path.".formatted(folderPath),
                    e);
        }
        if (!boundary.startsWith(anchor) || !staysInside(boundary, "")) {
            throw new ProjectException(
                    "The folder of the project '%s' is reached through a link or cannot be resolved.".formatted(
                            folderPath));
        }
        // The prefix the source lists its files under, as createInternalArtefacts() builds it
        var prefix = folderPath.isEmpty() || folderPath.endsWith("/") ? folderPath : folderPath + "/";
        return name -> name.startsWith(prefix) && staysInside(boundary, name.substring(prefix.length()));
    }

    // V1: the root directory behind a file-backed repository, unwrapped the way the files service unwraps it
    private static @Nullable Path localRoot(Repository repository) {
        var current = repository;
        while (current instanceof RepositoryDelegate delegate) {
            current = delegate.getOriginal();
        }
        if (current instanceof FolderMapper mapper) {
            current = mapper.getDelegate();
        }
        if (current instanceof PathCheckedRepository pathChecked) {
            return pathChecked.getLocalRoot();
        }
        return current instanceof FileSystemRepository fileSystem ? fileSystem.getRoot() : null;
    }

    // V1: the anchor's real location; an unresolvable anchor stays lexical, so the containment checks fail closed
    private static Path realLocation(Path root) {
        var absolute = root.toAbsolutePath();
        try {
            return realThroughDeepestExisting(absolute).normalize();
        } catch (IOException | SecurityException e) {
            return absolute.normalize();
        }
    }

    // V1: whether a path relative to the boundary stays under it on disk; anything unresolvable fails closed
    private static boolean staysInside(Path boundary, String relative) {
        try {
            var target = boundary.resolve(relative).normalize();
            return target.startsWith(boundary) && realThroughDeepestExisting(target).startsWith(boundary);
        } catch (IOException | IllegalArgumentException | SecurityException e) {
            return false;
        }
    }

    // V1: the real location of the deepest existing entry, a dangling link included, with the missing tail appended.
    // An entry that is not a link and vanishes before it is resolved, as a file does while a save replaces it, is
    // walked past and resolved through its parent; an entry still a link when it fails to resolve is a dangling link.
    private static Path realThroughDeepestExisting(Path path) throws IOException {
        for (var existing = deepestExisting(path); existing != null; existing = deepestExisting(existing.getParent())) {
            try {
                return existing.toRealPath().resolve(existing.relativize(path));
            } catch (NoSuchFileException e) {
                if (Files.isSymbolicLink(existing)) {
                    throw e;
                }
            }
        }
        return path;
    }

    // V1: the path itself or its nearest ancestor present without following a link at its end, or null if none is
    private static @Nullable Path deepestExisting(@Nullable Path path) {
        var existing = path;
        while (existing != null && !Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
            existing = existing.getParent();
        }
        return existing;
    }

    // V1: a slash-separated repository path as a relative filesystem path
    private static String trimSlashes(String path) {
        return path.replaceAll("^/+|/+$", "");
    }

    private final Object lock = new Object();

    protected Map<String, AProjectArtefact> getArtefactsInternal() {
        synchronized (lock) {
            if (artefacts == null) {
                this.artefacts = createInternalArtefacts();
            }
        }
        return artefacts;
    }

    protected Map<String, AProjectArtefact> createInternalArtefacts() {
        var internalArtefacts = new HashMap<String, AProjectArtefact>();
        Collection<FileData> fileDatas = new ArrayList<>();
        var path = getFolderPath();
        if (!path.isEmpty() && !path.endsWith("/")) {
            path += "/";
        }
        try {
            if (isHistoric()) {
                if (getRepository().supports().folders()) {
                    var fileData = getFileData();
                    if (fileData != null) {
                        fileDatas = getRepository().listFiles(path, fileData.getVersion());
                    }
                } else {
                    throw new UnsupportedOperationException(
                            "Cannot get internal artifacts for historic project version");
                }
            } else {
                fileDatas = getRepository().list(path);
            }
            for (FileData fileData : fileDatas) {
                if (!fileData.getName().equals(path) && !fileData.isDeleted()) {
                    var artefactName = fileData.getName().substring(path.length());
                    internalArtefacts.put(artefactName, new AProjectResource(getProject(), getRepository(), fileData));
                }
            }
        } catch (IOException ex) {
            log.error(ex.getMessage(), ex);
        }
        return internalArtefacts;
    }

    @Override
    public void refresh() {
        super.refresh();
        synchronized (lock) {
            artefacts = null;
        }
    }

    public void setResourceTransformer(ResourceTransformer resourceTransformer) {
        this.resourceTransformer = resourceTransformer;

        if (artefacts != null) {
            for (AProjectArtefact artefact : artefacts.values()) {
                if (artefact instanceof AProjectFolder folder) {
                    folder.setResourceTransformer(resourceTransformer);
                } else if (artefact instanceof AProjectResource resource) {
                    resource.setResourceTransformer(resourceTransformer);
                }
            }
        }
    }

    public String getRealPath() {
        var path = getFolderPath();
        var repository = getRepository();
        if (repository.supports().mappedFolders()) {
            final var fileData = getFileData();
            if (fileData != null) {
                var mappingData = fileData.getAdditionalData(FileMappingData.class);

                if (mappingData != null && path.equals(mappingData.getExternalPath())) {
                    return mappingData.getInternalPath();
                }
            }

            return ((FolderMapper) repository).getRealPath(path);
        } else {
            return path;
        }
    }

    @Override
    public boolean isHistoric() {
        return historyVersion != null && isRepositoryVersionable();
    }

    protected boolean isRepositoryVersionable() {
        return getRepository().supports().versions();
    }

    @Override
    public void setFileData(FileData fileData) {
        setFileData(fileData, true);
    }

    /**
     * Associates repository data with this folder.
     *
     * <p>Callers that publish current repository listings can defer version metadata. The metadata is resolved when
     * the project version is requested.
     */
    protected final void setFileData(FileData fileData, boolean resolveHistoryVersion) {
        super.setFileData(fileData);
        if (fileData != null) {
            setFolderPath(fileData.getName());
            if (resolveHistoryVersion) {
                setHistoryVersion(fileData.getVersion());
            }
        }
    }

    @Override
    public ArtefactPath getArtefactPath() {
        return new ArtefactPathImpl(getFolderPath());
    }

    @Override
    public String getInternalPath() {
        var projectPath = getProject().getFileData().getName();
        return folderPath.startsWith(projectPath + "/") ? folderPath.substring(projectPath.length() + 1) : folderPath;
    }

    @Override
    public void delete() throws ProjectException {
        for (AProjectArtefact artefact : getArtefacts()) {
            artefact.delete();
        }
        refresh();
    }

    public boolean hasArtefacts() {
        return !getArtefacts().isEmpty();
    }
}

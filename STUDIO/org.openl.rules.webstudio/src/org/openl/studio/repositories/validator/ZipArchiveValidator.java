package org.openl.studio.repositories.validator;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.Charset;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.eclipse.jgit.errors.CorruptObjectException;
import org.eclipse.jgit.util.SystemReader;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import org.openl.rules.project.resolving.ProjectResolver;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.webstudio.util.NameChecker;
import org.openl.rules.webstudio.web.repository.upload.zip.ZipCharsetDetector;
import org.openl.rules.workspace.filter.PathFilter;
import org.openl.studio.common.validation.FileIntegrityValidator;
import org.openl.util.FileSignatureHelper;
import org.openl.util.RuntimeExceptionWrapper;
import org.openl.util.StringUtils;
import org.openl.util.ZipUtils;

@Slf4j
@Component
public class ZipArchiveValidator implements Validator {

    // V1: one violation already refuses the archive, so the cap bounds memory and the 400 body whatever the entry count
    private static final int MAX_RAW_VIOLATIONS = 10;

    private final PathFilter zipFilter;
    private final ZipCharsetDetector zipCharsetDetector;

    public ZipArchiveValidator(@Qualifier("zipFilter") PathFilter zipFilter, ZipCharsetDetector zipCharsetDetector) {
        this.zipFilter = zipFilter;
        this.zipCharsetDetector = zipCharsetDetector;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return Path.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        var archive = (Path) target;
        if (!validateSignature(archive, errors) || !validateIntegrity(archive, errors)) {
            return;
        }
        var charset = zipCharsetDetector.detectCharset(() -> Files.newInputStream(archive));
        if (charset == null) {
            errors.reject("zip-archive.unknown.charset.message");
            return;
        }
        // V1: raw entry names, validated before the zipfs view below normalizes them or fails on them
        var rawViolations = rawEntryNameViolations(archive, charset);
        var errorsBefore = errors.getErrorCount(); // V1: the count before the zipfs checks, to tell if they reject

        try (FileSystem fs = FileSystems.newFileSystem(ZipUtils.toJarURI(archive),
                Map.of("encoding", charset.name()))) {

            var walkRoot = fs.getPath("/");
            if (ProjectResolver.getInstance().isRulesProject(walkRoot) == null) {
                errors.reject("zip-archive.unknown.project.structure.message");
                return;
            }

            var rejectedPaths = new HashSet<Path>();
            try (var stream = Files.walk(walkRoot)
                    .filter(p -> !walkRoot.equals(p))
                    .filter(p -> zipFilter.accept(p.toString()))) {

                stream.forEach(path -> validateEntryPath(path, rejectedPaths, errors));
            }
        } catch (IOException e) {
            // V1: a crafted name that breaks the zipfs view (e.g. a '..' segment) is a path rejection, not a 500.
            // Unchecked failures are left to propagate: the InvalidPathException of a NUL byte keeps its existing 400
            if (rejectRawEntryNames(rawViolations, errors)) {
                return;
            }
            throw RuntimeExceptionWrapper.wrap(e);
        }
        // V1: reported only when the zipfs checks found nothing, so their errors take precedence
        if (errors.getErrorCount() == errorsBefore) {
            rejectRawEntryNames(rawViolations, errors);
        }
    }

    /**
     * Rejects a path of the archive that is not a valid path, unless a path above or below it is rejected already.
     */
    private static void validateEntryPath(Path path, Set<Path> rejectedPaths, Errors errors) {
        if (rejectedPaths.stream().noneMatch(r -> r.startsWith(path) || path.startsWith(r))) {
            for (var i = 0; i < path.getNameCount(); i++) {
                try {
                    NameChecker.validatePath(path.getName(i).toString());
                } catch (IOException e) {
                    errors.reject("zip-archive.unknown.archive.path.message",
                            new String[]{e.getMessage()},
                            e.getMessage());
                    rejectedPaths.add(path);
                    return;
                }
            }
            try {
                var p = path.toString().replace('\\', '/');
                if (p.charAt(0) == '/') {
                    p = p.substring(1);
                }
                if (p.charAt(p.length() - 1) == '/') {
                    p = p.substring(0, p.length() - 1);
                }
                SystemReader.getInstance().checkPath(p);
            } catch (CorruptObjectException e) {
                String defaultMessage = StringUtils.capitalize(e.getMessage());
                errors.reject("zip-archive.invalid.path.message",
                        new String[]{defaultMessage},
                        defaultMessage);
                rejectedPaths.add(path);
            }
        }
    }

    // V1: not in a dedicated component as the Minimal Change Rule prefers, because surfaces share no path component
    /**
     * V1: collects the violations of the raw entry names, read before the zipfs view normalizes them, with
     * {@code \} read as {@code /} and the trailing {@code /} of a folder entry dropped.
     *
     * <p>The zipfs view the other checks walk normalizes a name such as {@code a//x.xlsx} or {@code /etc/x}, and
     * refuses to open an archive with a {@code .} or {@code ..} segment at all, so a crafted name is never checked
     * there. Each raw name is therefore run through {@link Repository#validatePath(String)} (absolute paths,
     * {@code .} and {@code ..} segments, {@code //}), which catches a backslash traversal such as {@code ..\x} as a
     * {@code ..} segment, and {@link NameChecker#validatePath(String)} (forbidden and control characters, reserved
     * names, trailing dots and spaces). Names decode with the charset the archive was detected with, as in the zipfs
     * view. Entries the upload filter drops get the {@link Repository#validatePath(String)} check only: they are never
     * written, but a {@code .} or {@code ..} segment in one still stops the zipfs view from opening. Reading stops once
     * {@value #MAX_RAW_VIOLATIONS} distinct violations are collected, because any one of them refuses the archive.
     *
     * <p>Private to this validator: V1 allows no path component shared between surfaces, so the upload-project
     * surface keeps its own path guard.
     *
     * @return the distinct violation messages, in the order of the entries, at most {@value #MAX_RAW_VIOLATIONS}
     */
    private Set<String> rawEntryNameViolations(Path archive, Charset charset) {
        var violations = new LinkedHashSet<String>();
        try (var zip = ZipFile.builder()
                .setPath(archive)
                .setCharset(charset)
                .setUseUnicodeExtraFields(false)
                .get()) {
            var entries = zip.getEntries();
            while (entries.hasMoreElements() && violations.size() < MAX_RAW_VIOLATIONS) {
                var name = entries.nextElement().getName().replace('\\', '/');
                // The filter sees the raw name, trailing '/' of a folder entry included, as the other uploaders do.
                // V1: a dropped entry is never written, yet a '.' or '..' segment in it still breaks the zipfs view
                var written = zipFilter.accept(name);
                // Only the '/' that marks a folder entry is dropped: a leading '/' is an absolute name.
                if (name.endsWith("/")) {
                    name = name.substring(0, name.length() - 1);
                }
                if (name.isEmpty()) {
                    continue;
                }
                try {
                    Repository.validatePath(name);
                    // V1: content rules only for a written name, so dropped SVN/CVS metadata is not newly refused
                    if (written) {
                        NameChecker.validatePath(name);
                    }
                } catch (IOException | IllegalArgumentException e) {
                    // InvalidPathException, thrown for a traversal or a NUL byte, is an IllegalArgumentException.
                    violations.add(e.getMessage());
                }
            }
        } catch (IOException e) {
            throw RuntimeExceptionWrapper.wrap(e);
        }
        return violations;
    }

    /**
     * V1: rejects every raw entry name violation with the key the zipfs view check uses for a name failure.
     *
     * @return {@code true} when at least one violation was rejected
     */
    private static boolean rejectRawEntryNames(Set<String> violations, Errors errors) {
        for (var message : violations) {
            errors.reject("zip-archive.unknown.archive.path.message", new String[]{message}, message);
        }
        return !violations.isEmpty();
    }

    private boolean validateSignature(Path archive, Errors errors) {
        var isValid = true;
        if (!Files.isRegularFile(archive)) {
            errors.reject("zip-archive.invalid.archive.message");
            isValid = false;
        } else {
            var sign = readSignature(archive);
            if (!FileSignatureHelper.isArchiveSign(sign)) {
                errors.reject("zip-archive.invalid.archive.message");
                isValid = false;
            } else if (FileSignatureHelper.isEmptyArchive(sign)) {
                errors.reject("zip-archive.empty.archive.message");
                isValid = false;
            }
        }
        return isValid;
    }

    /**
     * Verifies that the archive arrived complete: its own directory is read, and every entry is
     * matched against the size and the checksum recorded for it. An upload that was cut short keeps
     * a valid signature, so the signature alone does not tell a whole archive from a part of one.
     */
    private static boolean validateIntegrity(Path archive, Errors errors) {
        try {
            FileIntegrityValidator.verifyArchive(archive);
            return true;
        } catch (IOException e) {
            log.debug("The uploaded archive did not pass the integrity check.", e);
            errors.reject("zip-archive.damaged.archive.message", new String[]{e.getMessage()}, e.getMessage());
            return false;
        }
    }

    private static int readSignature(Path path) {
        try (var raf = new RandomAccessFile(path.toFile(), "r")) {
            return raf.readInt();
        } catch (IOException ignored) {
            return -1;
        }
    }

}

package org.openl.rules.webstudio.web.repository.upload;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.lang3.RandomStringUtils;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedConstruction;

import org.openl.rules.common.ProjectException;
import org.openl.rules.project.impl.local.DummyLockEngine;
import org.openl.rules.repository.api.FeaturesBuilder;
import org.openl.rules.repository.api.Repository;
import org.openl.rules.webstudio.web.repository.upload.zip.ZipCharsetDetector;
import org.openl.rules.workspace.WorkspaceUser;
import org.openl.rules.workspace.dtr.DesignTimeRepository;
import org.openl.rules.workspace.filter.PathFilter;
import org.openl.rules.workspace.uw.UserWorkspace;

/**
 * V1, surface D (upload project), on the {@link ProjectUploader} route: the ZIP entry names of an uploaded archive, as
 * {@link ZipFileProjectCreator} stages them into a new project.
 *
 * <p>The parameterized rows are the upload-project payload matrix D1-D14 (traversal and dot segments, absolute POSIX
 * and Windows names, backslashes, double slashes, percent-encoded and double-encoded separators, a null byte, a control
 * character, reserved names, a Unix symlink entry, a nested zip-slip name whose last segment is valid, and look-alike
 * separators). D15, an overwrite through a link an existing project folder holds, is a case of the REST archive route
 * and is covered by {@code ZipProjectSaveStrategyTest}. Every row is checked in two tiers:
 * <ul>
 * <li><b>Containment</b> decides whether the surface reproduces. No runtime exception escapes: an archive is either
 * staged, refused by the constructor with an {@link IOException}, or refused by
 * {@link ZipFileProjectCreator#getProjectBuilder()} with a {@link ProjectException}. And nothing named after the
 * row's random token exists outside a staging directory, in the temporary directory, in its parent, at the absolute
 * target of D3, or in a canary directory a second symlink row points at, both after staging and after clean-up.</li>
 * <li><b>Rejection</b> is the contract of the fix: every row whose full entry name is not a valid relative path is
 * refused with the existing "incorrect names" {@link ProjectException}, which the project creation service maps to
 * its existing 409 {@code project.create.failed.message}. The symlink rows carry valid names and only have to be
 * refused somehow. The dot-segment, reserved-name and look-alike rows either yield a literal name inside the project
 * or are refused, which is stricter and allowed, so containment is their whole contract.</li>
 * </ul>
 *
 * <p>On this route the boundary is the staging directory: {@link RulesProjectBuilder} stages every entry in a freshly
 * created {@code openl-create*} temporary directory, which cannot hold a pre-existing link, before the project is
 * saved to the design repository. So a row is contained when nothing it names is created, read or modified outside
 * that directory, and the directory itself is gone after clean-up.
 *
 * <p>Two existing issues are noted here and neither asserted nor fixed. The size check compares an entry with a
 * {@code MAX_FILE_SIZE} of 1000 MB while its message says 100 MB; the upload caps stay as they are, so the oversized
 * entry case asserts the refusal only. And when the charset cannot be detected or the archive is empty, the constructor
 * throws before it can delete its copy of the upload, so the copy stays in the temporary directory; the cases that
 * reach those branches remove it themselves.
 *
 * <p>The cases for the handlers of an archive that fails after it has opened replace the {@link ZipFile} the creator
 * opens with a mock that fails at the chosen step (listing, finding or reading an entry, or closing the archive), which
 * gives each selected fault site deterministic coverage.
 */
class ZipFileProjectCreatorTest {

    // The descriptor at the root of every crafted archive. A root-level file also keeps RootFolderExtractor from
    // stripping a folder all other entries share.
    private static final String RULES_XML = "<project><name>P</name></project>";

    // The upload file name is the prefix of the copy the creator keeps; it never contains a row token.
    private static final String UPLOAD_NAME = "p.zip";

    private static final String PROJECT_NAME = "P";

    private static final String COMMENT = "c";

    // RulesProjectBuilder stages a new project in a temporary directory named with this prefix.
    private static final String STAGING_PREFIX = "openl-create";

    // The fragment of the existing rejection the fix reports an invalid entry name with.
    private static final String INCORRECT_NAMES_MESSAGE = "incorrect names";

    private static final int CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;

    private static final int CENTRAL_DIRECTORY_HEADER_LENGTH = 46;

    private static final int CENTRAL_DIRECTORY_SIZE_OFFSET = 24;

    private static final int CENTRAL_DIRECTORY_NAME_LENGTH_OFFSET = 28;

    private static final int LOCAL_HEADER_SIGNATURE = 0x04034b50;

    private static final int LOCAL_HEADER_LENGTH = 30;

    private static final int LOCAL_HEADER_NAME_LENGTH_OFFSET = 26;

    private static final int UNIX_SYMLINK_MODE = 0120777;

    private static final int UNIX_FILE_MODE = 0100644;

    // The staging directory sits directly in the temporary directory; three levels cover anything a payload could
    // place next to it or one or two folders below it.
    private static final int TMP_SCAN_DEPTH = 3;

    // Exception messages quoted in assertion messages are cut to this length.
    private static final int MAX_DESCRIPTION_LENGTH = 200;

    private Repository repository;
    private DesignTimeRepository designTimeRepository;
    private UserWorkspace workspace;
    private PathFilter acceptAllFilter;
    private ZipCharsetDetector utf8Detector;
    private String repositoryId;

    @BeforeEach
    void setUp() {
        repositoryId = random();
        repository = mock(Repository.class);
        when(repository.getId()).thenReturn(repositoryId);
        // Built before the stubbing, from the plain mock: no branches, no mapped folders.
        var features = new FeaturesBuilder(repository).build();
        when(repository.supports()).thenReturn(features);

        designTimeRepository = mock(DesignTimeRepository.class);
        when(designTimeRepository.getRulesLocation()).thenReturn("DESIGN/rules/");
        when(designTimeRepository.getRepository(repositoryId)).thenReturn(repository);

        var user = mock(WorkspaceUser.class);
        when(user.getUserName()).thenReturn(random());

        workspace = mock(UserWorkspace.class);
        when(workspace.getDesignTimeRepository()).thenReturn(designTimeRepository);
        when(workspace.getUser()).thenReturn(user);
        // Adding a resource or a folder locks the project, and cancelling reads the lock back.
        when(workspace.getProjectsLockEngine()).thenReturn(new DummyLockEngine());

        acceptAllFilter = mock(PathFilter.class);
        when(acceptAllFilter.accept(anyString())).thenReturn(true);

        // A fixed charset keeps every row deterministic; the positive case uses the real detector.
        utf8Detector = mock(ZipCharsetDetector.class);
        when(utf8Detector.detectCharset(any(ZipCharsetDetector.ZipSource.class))).thenReturn(StandardCharsets.UTF_8);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("payloadRows")
    void uploadedEntryNamesStayInsideTheStagingDirectory(String rowId,
                                                         Payload payload,
                                                         Expectation expectation,
                                                         @TempDir Path canary) throws IOException {
        var token = random();
        Files.writeString(canary.resolve("canary.txt"), "canary");
        var canaryBefore = snapshot(canary);
        var archive = archive(payload.entries(token, canary));
        var stagingBefore = stagingDirectories();
        var uploadsBefore = uploadedCopies();

        var outcome = upload(archive, utf8Detector, acceptAllFilter);
        try {
            assertContained(rowId, "staged", token, canary, canaryBefore);
        } finally {
            cleanUp(outcome);
        }

        var containment = "V1 containment: " + rowId + ": ";
        if (outcome.escaped() != null) {
            fail(containment + "a runtime exception escaped: " + describe(outcome));
        }
        assertContained(rowId, "cleaned up", token, canary, canaryBefore);
        assertEquals(stagingBefore, stagingDirectories(), containment + "the staging directory must be removed");
        assertEquals(uploadsBefore, uploadedCopies(), containment + "the copy of the upload must be removed");

        assertTrue(expectation.accepts(outcome),
                "V1 rejection: " + rowId + ": expected " + expectation.description + ", got " + describe(outcome));
    }

    // The upload-project rows, as (row id, payload of the row token and the canary directory, expectation).
    static Stream<Arguments> payloadRows() {
        return Stream.of(
                row("D1", Expectation.INCORRECT_NAMES, (t, c) -> List.of(Entry.file("../evil-" + t + ".xlsx"))),
                row("D2", Expectation.CONTAINED_ONLY,
                        (t, c) -> List.of(Entry.file("./rules.xml"), Entry.file("a/./x-" + t + ".xlsx"))),
                row("D3", Expectation.INCORRECT_NAMES, (t, c) -> List.of(Entry.file("/etc/cron.d/evil-" + t))),
                row("D4", Expectation.INCORRECT_NAMES,
                        (t, c) -> List.of(Entry.raw("C:\\evil-" + t + ".xlsx"), Entry.file("C:evil-" + t + ".xlsx"))),
                row("D5", Expectation.INCORRECT_NAMES, (t, c) -> List.of(Entry.raw("..\\..\\evil-" + t + ".xlsx"))),
                row("D6", Expectation.INCORRECT_NAMES, (t, c) -> List.of(Entry.file("a//evil-" + t + ".xlsx"))),
                row("D7", Expectation.INCORRECT_NAMES, (t, c) -> List.of(Entry.file("..%2Fevil-" + t + ".xlsx"))),
                row("D8", Expectation.INCORRECT_NAMES, (t, c) -> List.of(Entry.file("..%252Fevil-" + t + ".xlsx"))),
                row("D9", Expectation.INCORRECT_NAMES,
                        (t, c) -> List.of(Entry.file("evil-" + t + ".xlsx\u0000.txt"))),
                row("D10", Expectation.INCORRECT_NAMES, (t, c) -> List.of(Entry.file("ev\u0007il-" + t + ".xlsx"))),
                row("D11", Expectation.CONTAINED_ONLY, (t, c) -> List.of(Entry.file("CON.xlsx"), Entry.file("NUL"))),
                row("D12", Expectation.ANY_REJECTION,
                        (t, c) -> List.of(Entry.symlink("link-" + t, "/etc"), Entry.file("link-" + t + "/passwd"))),
                // The same symlink entry pointing at the canary directory, so following it would change the canary.
                row("D12-canary", Expectation.ANY_REJECTION,
                        (t, c) -> List.of(Entry.symlink("link-" + t, c.toString()),
                                Entry.file("link-" + t + "/passwd"))),
                row("D13", Expectation.INCORRECT_NAMES, (t, c) -> List.of(Entry.file("a/../../evil-" + t + ".xlsx"))),
                row("D14", Expectation.CONTAINED_ONLY,
                        (t, c) -> List.of(Entry.file("..\u2215evil-" + t + ".xlsx"),
                                Entry.file("\uFF0E\uFF0E\uFF0Fevil-" + t + ".xlsx"))));
    }

    // Normal first-time upload: the archive is staged as a project inside its own staging directory, which clean-up
    // removes along with the copy of the upload.
    @Test
    void anOrdinaryArchiveIsStagedInsideItsOwnStagingDirectory() throws IOException {
        var token = random();
        var detector = new ZipCharsetDetector(new String[]{"IBM437"}, acceptAllFilter);
        var archive = archive(List.of(Entry.directory("rules/"), Entry.file("rules/Main-" + token + ".xlsx", "x")));
        var stagingBefore = stagingDirectories();
        var uploadsBefore = uploadedCopies();

        var outcome = upload(archive, detector, acceptAllFilter);
        Path staging;
        try {
            assertNotNull(outcome.builder(), "positive: the archive must be staged, got " + describe(outcome));
            var created = new TreeSet<>(stagingDirectories());
            created.removeAll(stagingBefore);
            assertEquals(1, created.size(), "positive: exactly one staging directory must be created");
            staging = created.first();
            assertTrue(containsFileNamed(staging, "Main-" + token + ".xlsx"),
                    "positive: the file must be staged in the staging directory");
            assertEquals(List.of(), entriesOutsideStaging(tmpDir(), token, TMP_SCAN_DEPTH),
                    "positive: nothing may be staged outside the staging directory");
        } finally {
            cleanUp(outcome);
        }

        assertFalse(Files.exists(staging, LinkOption.NOFOLLOW_LINKS),
                "positive: clean-up removes the staging directory");
        assertEquals(stagingBefore, stagingDirectories(), "positive: no staging directory is left");
        assertEquals(uploadsBefore, uploadedCopies(), "positive: the copy of the upload is removed");
    }

    // The overload taking a repository id resolves the design repository through the workspace, then stages as usual.
    @Test
    void theRepositoryIdOverloadResolvesTheDesignRepository() throws Exception {
        var archive = archive(List.of(Entry.file("Main-" + random() + ".xlsx", "x")));
        var stagingBefore = stagingDirectories();

        var creator = new ZipFileProjectCreator(repositoryId,
                UPLOAD_NAME,
                new ByteArrayInputStream(archive),
                PROJECT_NAME,
                "",
                workspace,
                COMMENT,
                acceptAllFilter,
                utf8Detector,
                Map.of());
        RulesProjectBuilder builder = null;
        try {
            builder = creator.getProjectBuilder();
            assertNotNull(builder, "repository id: the archive must be staged");
            verify(designTimeRepository).getRepository(repositoryId);
        } finally {
            if (builder != null) {
                builder.cancel();
            }
            creator.destroy();
        }
        assertEquals(stagingBefore, stagingDirectories(), "repository id: no staging directory is left");
    }

    // A folder entry with a name the name checker refuses is reported with the existing incorrect-names rejection,
    // before anything is staged.
    @Test
    void anInvalidFolderNameIsReportedAsAnIncorrectName() throws IOException {
        var token = random();
        var stagingBefore = stagingDirectories();

        var outcome = upload(archive(List.of(Entry.directory("bad%-" + token + "/"))), utf8Detector, acceptAllFilter);
        cleanUp(outcome);

        assertInstanceOf(ProjectException.class, outcome.rejection(), "folder name: got " + describe(outcome));
        assertTrue(outcome.rejection().getMessage().contains(INCORRECT_NAMES_MESSAGE),
                "folder name: got " + describe(outcome));
        assertEquals(stagingBefore, stagingDirectories(), "folder name: nothing may be staged");
        assertEquals(List.of(), entriesOutsideStaging(tmpDir(), token, TMP_SCAN_DEPTH),
                "folder name: nothing may be created");
    }

    // An entry that fails without a message is reported by its name, and the staged project is cancelled.
    @Test
    void anEntryThatFailsWithoutAMessageIsReportedByItsName() throws IOException {
        var token = random();
        var name = "boom-" + token + ".xlsx";
        PathFilter failingFilter = path -> {
            if (path.contains(token)) {
                throw new IllegalStateException();
            }
            return true;
        };
        var stagingBefore = stagingDirectories();

        var outcome = upload(archive(List.of(Entry.file(name, "x"))), utf8Detector, failingFilter);
        cleanUp(outcome);

        assertInstanceOf(ProjectException.class, outcome.rejection(), "entry failure: got " + describe(outcome));
        assertEquals("Bad zip entry '" + name + "'", outcome.rejection().getMessage(),
                "entry failure: the entry is named");
        assertEquals(stagingBefore, stagingDirectories(), "entry failure: the staging directory must be removed");
    }

    // An entry declared larger than the size limit is refused before it is read, and the staged project is cancelled.
    @Test
    void anOversizedEntryIsRefusedBeforeItIsRead() throws IOException {
        var token = random();
        var name = "big-" + token + ".xlsx";
        var archive = withDeclaredSize(archive(List.of(Entry.file(name, "x"))), name, Integer.MAX_VALUE);
        var stagingBefore = stagingDirectories();

        var outcome = upload(archive, utf8Detector, acceptAllFilter);
        cleanUp(outcome);

        assertInstanceOf(ProjectException.class, outcome.rejection(), "oversized entry: got " + describe(outcome));
        assertEquals(stagingBefore, stagingDirectories(), "oversized entry: the staging directory must be removed");
        assertEquals(List.of(), entriesOutsideStaging(tmpDir(), token, TMP_SCAN_DEPTH),
                "oversized entry: nothing may be created");
    }

    // An archive whose charset cannot be detected is refused by the constructor.
    @Test
    void anArchiveWhoseCharsetCannotBeDetectedIsRefused() throws IOException {
        var undetectable = mock(ZipCharsetDetector.class);
        var uploadsBefore = uploadedCopies();
        Outcome outcome = null;
        try {
            outcome = upload(archive(List.of(Entry.file("Main.xlsx", "x"))), undetectable, acceptAllFilter);

            assertInstanceOf(IOException.class, outcome.rejection(), "charset: got " + describe(outcome));
            assertTrue(outcome.rejection().getMessage().contains("Cannot detect a charset"),
                    "charset: got " + describe(outcome));
        } finally {
            if (outcome != null) {
                cleanUp(outcome);
            }
            removeUploadedCopiesCreatedSince(uploadsBefore);
        }
    }

    // An archive without entries is refused by the constructor.
    @Test
    void anEmptyArchiveIsRefused() throws IOException {
        var uploadsBefore = uploadedCopies();
        Outcome outcome = null;
        try {
            outcome = upload(zip(List.of()), utf8Detector, acceptAllFilter);

            assertInstanceOf(IOException.class, outcome.rejection(), "empty archive: got " + describe(outcome));
            assertTrue(outcome.rejection().getMessage().contains("Zip file is empty"),
                    "empty archive: got " + describe(outcome));
        } finally {
            if (outcome != null) {
                cleanUp(outcome);
            }
            removeUploadedCopiesCreatedSince(uploadsBefore);
        }
    }

    // An archive cut off before its central directory still yields its first entry to a stream reader, so it is not
    // empty, but it cannot be opened: the constructor removes the copy of the upload and refuses it.
    @Test
    void anArchiveWithoutItsCentralDirectoryIsRefused() throws IOException {
        var complete = archive(List.of(Entry.file("Main.xlsx", "x")));
        var truncated = Arrays.copyOf(complete, centralDirectoryOffset(complete));
        var uploadsBefore = uploadedCopies();

        var outcome = upload(truncated, utf8Detector, acceptAllFilter);
        cleanUp(outcome);

        assertInstanceOf(IOException.class, outcome.rejection(), "truncated archive: got " + describe(outcome));
        assertEquals(uploadsBefore, uploadedCopies(), "truncated archive: the copy of the upload must be removed");
    }

    // An archive whose first entry header announces a name it does not hold cannot even be read as a stream; it is
    // not taken for an empty archive, and the constructor refuses it when it is opened.
    @Test
    void aDamagedArchiveIsRefusedWhenItIsOpened() throws IOException {
        var damaged = ByteBuffer.allocate(LOCAL_HEADER_LENGTH).order(ByteOrder.LITTLE_ENDIAN);
        damaged.putInt(LOCAL_HEADER_SIGNATURE);
        damaged.putShort(LOCAL_HEADER_NAME_LENGTH_OFFSET, (short) 100);
        var uploadsBefore = uploadedCopies();

        var outcome = upload(damaged.array(), utf8Detector, acceptAllFilter);
        cleanUp(outcome);

        assertInstanceOf(IOException.class, outcome.rejection(), "damaged archive: got " + describe(outcome));
        assertNull(outcome.creator(), "damaged archive: the constructor must refuse it");
        assertEquals(uploadsBefore, uploadedCopies(), "damaged archive: the copy of the upload must be removed");
    }

    // Destroying a creator twice logs the second delete instead of failing.
    @Test
    void destroyCanBeCalledTwice() throws IOException {
        var uploadsBefore = uploadedCopies();
        var creator = new ZipFileProjectCreator(repository,
                UPLOAD_NAME,
                new ByteArrayInputStream(archive(List.of(Entry.file("Main.xlsx", "x")))),
                PROJECT_NAME,
                "",
                workspace,
                COMMENT,
                acceptAllFilter,
                utf8Detector,
                Map.of());

        creator.destroy();
        assertEquals(uploadsBefore, uploadedCopies(), "destroy: the copy of the upload must be removed");
        assertDoesNotThrow(creator::destroy, "destroy: a second call must not throw");
    }

    // An entry the opened archive cannot list is logged and skipped, both when the names are sorted and when they are
    // checked, and the entries listed after it are still staged.
    @Test
    void anEntryTheOpenedArchiveCannotListIsSkipped() throws IOException {
        var descriptor = new ZipEntry("rules.xml");
        var stagingBefore = stagingDirectories();

        var upload = uploadThroughStubbedArchive((zipFile, context) -> {
            when(zipFile.entries()).thenAnswer(invocation -> failingFirst(descriptor));
            when(zipFile.getEntry(descriptor.getName())).thenReturn(descriptor);
            when(zipFile.getInputStream(descriptor))
                    .thenAnswer(invocation -> new ByteArrayInputStream(RULES_XML.getBytes(StandardCharsets.UTF_8)));
        });
        var outcome = upload.outcome();
        try {
            assertEquals(1, upload.archives().size(), "unlisted entry: the creator must read the stubbed archive");
            assertNotNull(outcome.builder(),
                    "unlisted entry: the listed entries must be staged, got " + describe(outcome));
            var created = new TreeSet<>(stagingDirectories());
            created.removeAll(stagingBefore);
            assertEquals(1, created.size(), "unlisted entry: exactly one staging directory must be created");
            assertTrue(containsFileNamed(created.first(), descriptor.getName()),
                    "unlisted entry: the entry listed after the failure must be staged");
        } finally {
            cleanUp(outcome);
        }
        assertEquals(stagingBefore, stagingDirectories(), "unlisted entry: no staging directory is left");
    }

    // An entry the opened archive lists but cannot find is reported as a broken archive, and the staged project is
    // cancelled.
    @Test
    void anEntryTheOpenedArchiveCannotFindIsReportedAsBroken() throws IOException {
        var name = "gone-" + random() + ".xlsx";
        var stagingBefore = stagingDirectories();

        var upload = uploadThroughStubbedArchive((zipFile, context) -> when(zipFile.entries())
                .thenAnswer(invocation -> Collections.enumeration(List.of(new ZipEntry(name)))));
        var outcome = upload.outcome();
        cleanUp(outcome);

        assertEquals(1, upload.archives().size(), "missing entry: the creator must read the stubbed archive");
        assertInstanceOf(ProjectException.class, outcome.rejection(), "missing entry: got " + describe(outcome));
        assertEquals("Cannot read zip entry '" + name + "'. Possible broken zip.",
                outcome.rejection().getMessage(),
                "missing entry: the entry is named");
        assertEquals(stagingBefore, stagingDirectories(), "missing entry: the staging directory must be removed");
    }

    // An entry the opened archive cannot read is reported as an extraction error, and the staged project is cancelled.
    @Test
    void anEntryTheOpenedArchiveCannotReadIsReportedAsAnExtractionError() throws IOException {
        var entry = new ZipEntry("unreadable-" + random() + ".xlsx");
        var failure = new ZipException("invalid LOC header");
        var stagingBefore = stagingDirectories();

        var upload = uploadThroughStubbedArchive((zipFile, context) -> {
            when(zipFile.entries()).thenAnswer(invocation -> Collections.enumeration(List.of(entry)));
            when(zipFile.getEntry(entry.getName())).thenReturn(entry);
            when(zipFile.getInputStream(entry)).thenThrow(failure);
        });
        var outcome = upload.outcome();
        cleanUp(outcome);

        assertEquals(1, upload.archives().size(), "unreadable entry: the creator must read the stubbed archive");
        assertInstanceOf(ProjectException.class, outcome.rejection(), "unreadable entry: got " + describe(outcome));
        assertEquals("Error extracting zip archive", outcome.rejection().getMessage(),
                "unreadable entry: the extraction error is reported");
        assertNotNull(outcome.rejection().getCause(), "unreadable entry: the extraction error is kept as the cause");
        assertSame(failure, outcome.rejection().getCause().getCause(),
                "unreadable entry: the read failure is kept as its cause");
        assertEquals(stagingBefore, stagingDirectories(), "unreadable entry: the staging directory must be removed");
    }

    // A failure to close the opened archive is logged; destroy still removes the copy of the upload.
    @Test
    void aFailureToCloseTheArchiveIsLoggedAndTheCopyIsStillRemoved() throws IOException {
        var uploadsBefore = uploadedCopies();

        var upload = uploadThroughStubbedArchive((zipFile, context) -> {
            when(zipFile.entries()).thenAnswer(invocation -> Collections.emptyEnumeration());
            doThrow(new IOException("close failed")).when(zipFile).close();
        });
        var outcome = upload.outcome();

        assertDoesNotThrow(() -> cleanUp(outcome), "close failure: clean-up must not throw");
        assertEquals(1, upload.archives().size(), "close failure: the creator must read the stubbed archive");
        verify(upload.archives().get(0)).close();
        assertEquals(uploadsBefore, uploadedCopies(), "close failure: the copy of the upload must be removed");
    }

    private static Arguments row(String rowId, Expectation expectation, Payload payload) {
        return Arguments.of(rowId, payload, expectation);
    }

    // Runs the route as ProjectUploader does up to the staged project, and records how it ended. Only an IOException
    // of the constructor and a ProjectException of getProjectBuilder() are rejections; anything else escaped.
    private Outcome upload(byte[] archive, ZipCharsetDetector detector, PathFilter filter) {
        ZipFileProjectCreator creator;
        try {
            creator = new ZipFileProjectCreator(repository,
                    UPLOAD_NAME,
                    new ByteArrayInputStream(archive),
                    PROJECT_NAME,
                    "",
                    workspace,
                    COMMENT,
                    filter,
                    detector,
                    Map.of());
        } catch (IOException e) {
            return new Outcome(null, null, e, null);
        } catch (RuntimeException e) {
            return new Outcome(null, null, null, e);
        }
        return stage(creator);
    }

    // Stages the project of a created creator, and records how it ended.
    private static Outcome stage(ZipFileProjectCreator creator) {
        try {
            return new Outcome(creator, creator.getProjectBuilder(), null, null);
        } catch (ProjectException e) {
            return new Outcome(creator, null, e, null);
        } catch (RuntimeException e) {
            return new Outcome(creator, null, null, e);
        }
    }

    // Creates the creator while every ZipFile this thread opens is a mock the stubbing configures, then stages its
    // project, and keeps the archives opened, so a case can prove that its stub is the archive the creator read. The
    // stub fails at the step the stubbing chooses after the archive has opened (listing, finding or reading an entry,
    // or closing the archive), which gives that fault site deterministic coverage.
    private StubbedUpload uploadThroughStubbedArchive(MockedConstruction.MockInitializer<ZipFile> stubbing)
            throws IOException {
        var archive = archive(List.of());
        // A JarFile is a ZipFile, so while the stub is in place this thread cannot open a jar either. A real upload
        // first loads every class the constructor uses, the stub covers the constructor alone, and the project is
        // staged after the stub is gone.
        cleanUp(upload(archive, utf8Detector, acceptAllFilter));
        ZipFileProjectCreator creator;
        List<ZipFile> archives;
        try (var opened = mockConstruction(ZipFile.class, stubbing)) {
            creator = new ZipFileProjectCreator(repository,
                    UPLOAD_NAME,
                    new ByteArrayInputStream(archive),
                    PROJECT_NAME,
                    "",
                    workspace,
                    COMMENT,
                    acceptAllFilter,
                    utf8Detector,
                    Map.of());
            archives = List.copyOf(opened.constructed());
        }
        return new StubbedUpload(stage(creator), archives);
    }

    // A failure where a damaged central directory record would be, then the entries; the failure consumes its element,
    // so a reader that skips it goes on to the entries.
    private static Enumeration<ZipEntry> failingFirst(ZipEntry... entries) {
        var listed = List.of(entries).iterator();
        return new Enumeration<>() {
            private boolean failed;

            @Override
            public boolean hasMoreElements() {
                return !failed || listed.hasNext();
            }

            @Override
            public ZipEntry nextElement() {
                if (!failed) {
                    failed = true;
                    throw new IllegalStateException("damaged central directory record");
                }
                return listed.next();
            }
        };
    }

    // Cancels a staged project, which removes its staging directory, and destroys the creator, which removes the copy
    // of the upload.
    private static void cleanUp(Outcome outcome) {
        if (outcome.builder() != null) {
            outcome.builder().cancel();
        }
        if (outcome.creator() != null) {
            outcome.creator().destroy();
        }
    }

    // Tier 1: nothing named after the row token exists outside a staging directory, and the canary is unchanged.
    private static void assertContained(String rowId,
                                        String stage,
                                        String token,
                                        Path canary,
                                        SortedMap<String, String> canaryBefore) throws IOException {
        var prefix = "V1 containment: " + rowId + " (" + stage + "): ";
        var tmp = tmpDir();
        assertEquals(List.of(), entriesOutsideStaging(tmp, token, TMP_SCAN_DEPTH),
                prefix + "nothing may be created in the temporary directory outside the staging directory");
        var parent = tmp.getParent();
        if (parent != null) {
            assertEquals(List.of(), entriesOutsideStaging(parent, token, 1),
                    prefix + "nothing may be created next to the temporary directory");
        }
        assertFalse(Files.exists(Path.of("/etc/cron.d/evil-" + token), LinkOption.NOFOLLOW_LINKS),
                prefix + "nothing may be created at the absolute entry name");
        assertEquals(canaryBefore, snapshot(canary), prefix + "the canary directory must stay unchanged");
    }

    // The files, folders and links below start, down to maxDepth, whose name contains the token, leaving out the
    // content of every staging directory. Links are reported, never followed.
    private static List<String> entriesOutsideStaging(Path start, String token, int maxDepth) throws IOException {
        var found = new ArrayList<String>();
        Files.walkFileTree(start, Set.of(), maxDepth, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (dir.equals(start)) {
                    return FileVisitResult.CONTINUE;
                }
                if (dir.getFileName().toString().startsWith(STAGING_PREFIX)) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                check(dir);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                check(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }

            private void check(Path path) {
                var name = path.getFileName();
                if (name != null && name.toString().contains(token)) {
                    found.add(sanitize(path.toString()));
                }
            }
        });
        return found;
    }

    private static boolean containsFileNamed(Path dir, String name) throws IOException {
        try (var paths = Files.walk(dir)) {
            return paths.anyMatch(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && name
                    .equals(path.getFileName().toString()));
        }
    }

    // Every entry below dir, links included and not followed, with its kind, size and modification time.
    private static SortedMap<String, String> snapshot(Path dir) throws IOException {
        var entries = new TreeMap<String, String>();
        try (var paths = Files.walk(dir)) {
            for (var path : (Iterable<Path>) paths::iterator) {
                var attributes = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                var kind = attributes.isSymbolicLink() ? "link" : attributes.isDirectory() ? "folder" : "file";
                entries.put(sanitize(dir.relativize(path).toString()),
                        kind + ":" + attributes.size() + ":" + attributes.lastModifiedTime());
            }
        }
        return entries;
    }

    private static SortedSet<Path> stagingDirectories() throws IOException {
        return tmpEntries(path -> path.getFileName().toString().startsWith(STAGING_PREFIX) && Files
                .isDirectory(path, LinkOption.NOFOLLOW_LINKS));
    }

    // The copies of uploads the creator keeps in the temporary directory while it lives.
    private static SortedSet<Path> uploadedCopies() throws IOException {
        return tmpEntries(path -> path.getFileName().toString().startsWith(UPLOAD_NAME) && Files
                .isRegularFile(path, LinkOption.NOFOLLOW_LINKS));
    }

    private static SortedSet<Path> tmpEntries(Predicate<Path> filter) throws IOException {
        try (var paths = Files.list(tmpDir())) {
            return paths.filter(filter).collect(Collectors.toCollection(TreeSet::new));
        }
    }

    // Removes the copies of uploads a refused constructor left behind (see the class description).
    private static void removeUploadedCopiesCreatedSince(Set<Path> before) throws IOException {
        for (var copy : uploadedCopies()) {
            if (!before.contains(copy)) {
                Files.deleteIfExists(copy);
            }
        }
    }

    private static Path tmpDir() {
        return Path.of(System.getProperty("java.io.tmpdir")).toAbsolutePath();
    }

    private static String random() {
        return RandomStringUtils.secure().nextAlphanumeric(12);
    }

    // A root rules.xml followed by the payload entries.
    private static byte[] archive(List<Entry> payload) throws IOException {
        var entries = new ArrayList<Entry>();
        entries.add(Entry.file("rules.xml", RULES_XML));
        entries.addAll(payload);
        return zip(entries);
    }

    // Writes the entries under their names exactly as given, then reads the names back to prove it.
    private static byte[] zip(List<Entry> entries) throws IOException {
        var bytes = new ByteArrayOutputStream();
        try (var out = new ZipArchiveOutputStream(bytes)) {
            out.setEncoding(StandardCharsets.UTF_8.name());
            for (var entry : entries) {
                out.putArchiveEntry(zipEntry(entry));
                if (!entry.directory()) {
                    out.write(entry.content().getBytes(StandardCharsets.UTF_8));
                }
                out.closeArchiveEntry();
            }
            out.finish();
        }
        var archive = bytes.toByteArray();
        var expected = entries.stream().map(Entry::name).toList();
        var written = entryNames(archive);
        assertTrue(expected.equals(written),
                () -> "archive: the entry names must be written as given, expected " + sanitize(expected)
                        + " but was " + sanitize(written));
        return archive;
    }

    private static ZipArchiveEntry zipEntry(Entry entry) {
        var name = entry.name();
        if (entry.raw()) {
            // On the default FAT platform commons-compress turns '\' into '/' in a name without '/'. Switching to the
            // UNIX platform first keeps the backslash payloads as they are.
            return new ZipArchiveEntry(name) {
                {
                    setUnixMode(UNIX_FILE_MODE);
                    setName(name);
                }
            };
        }
        var zipEntry = new ZipArchiveEntry(name);
        if (entry.symlink()) {
            zipEntry.setUnixMode(UNIX_SYMLINK_MODE);
        }
        return zipEntry;
    }

    private static List<String> entryNames(byte[] archive) throws IOException {
        var names = new ArrayList<String>();
        try (var in = new ZipInputStream(new ByteArrayInputStream(archive), StandardCharsets.UTF_8)) {
            for (var entry = in.getNextEntry(); entry != null; entry = in.getNextEntry()) {
                names.add(entry.getName());
            }
        }
        return names;
    }

    private static int centralDirectoryOffset(byte[] archive) {
        var buffer = ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN);
        for (var i = 0; i + Integer.BYTES <= archive.length; i++) {
            if (buffer.getInt(i) == CENTRAL_DIRECTORY_SIGNATURE) {
                return i;
            }
        }
        return fail("archive: no central directory");
    }

    // The archive with the uncompressed size its central directory declares for the entry replaced; the local header
    // and the content stay as they are.
    private static byte[] withDeclaredSize(byte[] archive, String entryName, int declaredSize) {
        var patched = archive.clone();
        var buffer = ByteBuffer.wrap(patched).order(ByteOrder.LITTLE_ENDIAN);
        var name = entryName.getBytes(StandardCharsets.UTF_8);
        for (var i = 0; i + CENTRAL_DIRECTORY_HEADER_LENGTH <= patched.length; i++) {
            if (buffer.getInt(i) == CENTRAL_DIRECTORY_SIGNATURE) {
                var nameLength = Short.toUnsignedInt(buffer.getShort(i + CENTRAL_DIRECTORY_NAME_LENGTH_OFFSET));
                var nameStart = i + CENTRAL_DIRECTORY_HEADER_LENGTH;
                if (nameStart + nameLength <= patched.length && Arrays
                        .equals(patched, nameStart, nameStart + nameLength, name, 0, name.length)) {
                    buffer.putInt(i + CENTRAL_DIRECTORY_SIZE_OFFSET, declaredSize);
                    return patched;
                }
            }
        }
        return fail("archive: no central directory header for the entry");
    }

    private static String describe(Outcome outcome) {
        if (outcome.escaped() != null) {
            return "escaped " + describe(outcome.escaped());
        }
        if (outcome.rejection() == null) {
            return "staged";
        }
        return (outcome.creator() == null ? "constructor " : "getProjectBuilder ") + describe(outcome.rejection());
    }

    private static String describe(Throwable e) {
        var text = sanitize(e.getClass().getSimpleName() + ": " + e.getMessage());
        return text.length() > MAX_DESCRIPTION_LENGTH ? text.substring(0, MAX_DESCRIPTION_LENGTH) + "..." : text;
    }

    // Escapes control characters, so payload names cannot corrupt an assertion message or the test report.
    private static String sanitize(String text) {
        var sanitized = new StringBuilder(text.length());
        for (var i = 0; i < text.length(); i++) {
            var c = text.charAt(i);
            if (c < ' ' || c == 0x7F) {
                sanitized.append("\\u%04x".formatted((int) c));
            } else {
                sanitized.append(c);
            }
        }
        return sanitized.toString();
    }

    private static List<String> sanitize(List<String> texts) {
        return texts.stream().map(ZipFileProjectCreatorTest::sanitize).toList();
    }

    // How one upload ended: staged (builder), refused (rejection), or with a runtime exception that escaped.
    record Outcome(@Nullable ZipFileProjectCreator creator,
                   @Nullable RulesProjectBuilder builder,
                   @Nullable Exception rejection,
                   @Nullable RuntimeException escaped) {
    }

    // An upload run against a stubbed archive, with the archives the creator opened.
    private record StubbedUpload(Outcome outcome, List<ZipFile> archives) {
    }

    // One crafted entry: a regular file, a folder, a Unix symlink whose content is its target, or a regular file whose
    // name keeps its backslashes.
    record Entry(String name, String content, boolean directory, boolean symlink, boolean raw) {

        static Entry file(String name) {
            return file(name, "");
        }

        static Entry file(String name, String content) {
            return new Entry(name, content, false, false, false);
        }

        static Entry directory(String name) {
            return new Entry(name, "", true, false, false);
        }

        static Entry symlink(String name, String target) {
            return new Entry(name, target, false, true, false);
        }

        static Entry raw(String name) {
            return new Entry(name, "", false, false, true);
        }
    }

    // The payload entries of a row, built from the row token and the canary directory of the invocation.
    @FunctionalInterface
    interface Payload {
        List<Entry> entries(String token, Path canary);
    }

    // The tier-2 contract of a row.
    enum Expectation {
        INCORRECT_NAMES("an incorrect-names ProjectException or a constructor IOException"),
        ANY_REJECTION("a ProjectException or a constructor IOException"),
        CONTAINED_ONLY("the archive staged or refused");

        private final String description;

        Expectation(String description) {
            this.description = description;
        }

        boolean accepts(Outcome outcome) {
            var rejection = outcome.rejection();
            return switch (this) {
                case INCORRECT_NAMES -> (outcome.creator() == null && rejection instanceof IOException)
                        || (rejection instanceof ProjectException && String.valueOf(rejection.getMessage())
                        .contains(INCORRECT_NAMES_MESSAGE));
                case ANY_REJECTION -> rejection != null;
                case CONTAINED_ONLY -> outcome.escaped() == null;
            };
        }
    }
}

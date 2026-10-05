package org.openl.studio.repositories.validator;

// V1-D: imports of the upload-project path matrix
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipException;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;

import org.openl.rules.webstudio.web.repository.upload.zip.ZipCharsetDetector;
import org.openl.rules.workspace.filter.AndPathFilter;
import org.openl.rules.workspace.filter.FileNamePathFilter;
import org.openl.rules.workspace.filter.FolderNamePathFilter;
import org.openl.studio.common.validation.AbstractConstraintValidatorTest;

@SpringJUnitConfig(classes = MockConfiguration.class)
class ZipArchiveValidatorTest extends AbstractConstraintValidatorTest {

    // V1-D: the key an invalid entry name is rejected with, by the zipfs walk and by the raw-name check alike.
    private static final String UNKNOWN_ARCHIVE_PATH = "zip-archive.unknown.archive.path.message";

    // V1-D: the descriptor at the root of every crafted archive, so it is recognized as a rules project.
    private static final String RULES_XML = "<project><name>P</name></project>";

    @Autowired
    private ZipArchiveValidator validator;

    // V1-D: the detector of the context, for validators built with their own upload filter.
    @Autowired
    private ZipCharsetDetector zipCharsetDetector;

    // V1-D: the crafted archives of one test are written here and removed after it.
    @TempDir
    Path tmp;

    // V1-D: numbers the crafted archives of one test, so each gets its own file.
    private int counter;

    @Test
    void testArchives_NotOpenLProject() {
        var bindingResult = validateAndGetResult(Path.of("test-resources/upload/zip/test-rules-xml.zip"),
                validator);
        assertEquals(0, bindingResult.getFieldErrorCount());
        assertEquals(1, bindingResult.getGlobalErrorCount());
        assertObjectError("Unknown project structure.", bindingResult.getGlobalError());

        bindingResult = validateAndGetResult(Path.of("test-resources/XSSFOptimizerTest.xlsx"), validator);
        assertEquals(0, bindingResult.getFieldErrorCount());
        assertEquals(1, bindingResult.getGlobalErrorCount());
        assertObjectError("Unknown project structure.", bindingResult.getGlobalError());
    }

    @Test
    void testArchives_NotArchive() {
        var bindingResult = validateAndGetResult(Path.of("test-resources/test/export/trivial"), validator);
        assertEquals(0, bindingResult.getFieldErrorCount());
        assertEquals(1, bindingResult.getGlobalErrorCount());
        assertObjectError("The provided file is not an archive.", bindingResult.getGlobalError());

        bindingResult = validateAndGetResult(Path.of("test-resources/log4j2-test.properties"), validator);
        assertEquals(0, bindingResult.getFieldErrorCount());
        assertEquals(1, bindingResult.getGlobalErrorCount());
        assertObjectError("The provided file is not an archive.", bindingResult.getGlobalError());
    }

    @Test
    void testArchives() {
        assertNull(validateAndGetResult(Path.of("test-resources/upload/zip/test-workspace.zip"), validator));
        assertNull(validateAndGetResult(Path.of("test-resources/upload/zip/project.zip"), validator));
    }

    // V1-D: positive control - a crafted archive with valid names passes, so the rows below reach the entry checks.
    @Test
    void helperArchive_isValid() throws IOException {
        assertNull(validate("control", archive("rules/Main.xlsx")), "control: a valid archive must be accepted");
    }

    // V1-D: every traversal, separator, encoding, control-character and reserved-name entry is rejected as a path.
    @ParameterizedTest(name = "{0}")
    @MethodSource("rejectedEntryNames")
    void testArchives_RejectedEntryName(String rowId, String rawName) throws IOException {
        assertEntryRejected(rowId, validate(rowId, archive(rawName)), UNKNOWN_ARCHIVE_PATH);
    }

    // V1-D: the rejected rows of the upload-project matrix, as (row id, raw entry name).
    static Stream<Arguments> rejectedEntryNames() {
        return Stream.of(Arguments.of("D1 dot-dot segment", "../evil.xlsx"),
                Arguments.of("D2 leading dot segment", "./rules.xml"),
                Arguments.of("D2 inner dot segment", "a/./x.xlsx"),
                Arguments.of("D3 absolute POSIX path", "/etc/cron.d/evil"),
                Arguments.of("D4 Windows drive and backslash", "C:\\evil.xlsx"),
                Arguments.of("D4 Windows drive-relative name", "C:evil.xlsx"),
                Arguments.of("D5 backslash separators", "..\\..\\evil.xlsx"),
                Arguments.of("D6 double slash", "a//evil.xlsx"),
                Arguments.of("D7 percent-encoded separator", "..%2Fevil.xlsx"),
                Arguments.of("D8 double-encoded separator", "..%252Fevil.xlsx"),
                Arguments.of("D9 null byte", "evil.xlsx\u0000.txt"),
                Arguments.of("D10 control character", "ev\u0007il.xlsx"),
                Arguments.of("D11 reserved name", "NUL"),
                Arguments.of("D13 nested zip-slip", "a/../../evil.xlsx"));
    }

    // V1-D: a name that only starts with a reserved word is accepted today and stays accepted (no rule is loosened
    // or tightened beyond the matrix).
    @Test
    void testArchives_ReservedWordPrefixAccepted() throws IOException {
        assertNull(validate("D11 reserved-word prefix", archive("CON.xlsx")),
                "D11 reserved-word prefix: the name must stay accepted");
    }

    // V1-D: a Unix symlink entry is a regular name here: 'link' and 'link/passwd' are valid names. That no link is
    // created and nothing is written outside the project is proven where the archive is saved
    // (ZipProjectSaveStrategyTest) and by the upload ITEST, not by this validator.
    @Test
    void testArchives_SymlinkEntry() throws IOException {
        var result = validate("D12 symlink entry",
                archive(List.of(new Entry("link", "/etc", 0120777), Entry.empty("link/passwd"))));
        assertNull(result, "D12 symlink entry: the entry names are valid");
    }

    // V1-D: look-alike separators are ordinary characters, so each name stays one literal name inside the project.
    @ParameterizedTest(name = "{0}")
    @MethodSource("lookAlikeSeparatorNames")
    void testArchives_LookAlikeSeparatorIsLiteral(String rowId, String rawName) throws IOException {
        assertNull(validate(rowId, archive(rawName)), rowId + ": a look-alike separator is a literal character");
    }

    // V1-D: the look-alike rows of the upload-project matrix, as (row id, raw entry name).
    static Stream<Arguments> lookAlikeSeparatorNames() {
        return Stream.of(Arguments.of("D14 division slash", "..\u2215evil.xlsx"),
                Arguments.of("D14 fullwidth dots and solidus", "\uFF0E\uFF0E\uFF0Fevil.xlsx"));
    }

    // V1-D: when the zipfs walk already rejected a name, the raw-name check adds nothing, so an existing rejection
    // keeps exactly its errors ('a//d.xlsx' is normalized by zipfs and caught by the raw check only).
    @Test
    void testArchives_ExistingRejectionKeepsItsErrors() throws IOException {
        var result = validate("zipfs error present", archive("b%c.xlsx", "a//d.xlsx"));
        assertEntryRejected("zipfs error present", result, UNKNOWN_ARCHIVE_PATH);
        assertEquals(1, result.getGlobalErrorCount(), "zipfs error present: only the zipfs walk error is reported");
    }

    // V1-D: an archive the zipfs view cannot open ('.' segment) is rejected by its raw names, one error for each
    // distinct violation: the Repository.validatePath one and the NameChecker one.
    @Test
    void testArchives_UnopenableArchiveRejectedByRawNames() throws IOException {
        var result = validate("zipfs cannot open", archive("./a.xlsx", "b%c.xlsx"));
        assertEntryRejected("zipfs cannot open", result, UNKNOWN_ARCHIVE_PATH);
        assertEquals(2, result.getGlobalErrorCount(), "zipfs cannot open: one error for each raw violation");
        for (ObjectError error : result.getGlobalErrors()) {
            assertEquals(UNKNOWN_ARCHIVE_PATH, error.getCode(), "zipfs cannot open: raw violations use the path key");
        }
    }

    // V1-D: 15 distinct traversal names still reject the archive, with the raw-name errors capped at 10 (the
    // validator's MAX_RAW_VIOLATIONS), so the entry count cannot grow the 400 body.
    @Test
    void testArchives_RawViolationsCapped() throws IOException {
        var names = new String[15];
        for (var i = 0; i < names.length; i++) {
            names[i] = "../a%02d.xlsx".formatted(i);
        }
        var result = validate("raw violations capped", archive(names));
        assertEntryRejected("raw violations capped", result, UNKNOWN_ARCHIVE_PATH);
        assertEquals(10, result.getGlobalErrorCount(), "raw violations capped: at most 10 errors are reported");
        for (ObjectError error : result.getGlobalErrors()) {
            assertEquals(UNKNOWN_ARCHIVE_PATH, error.getCode(), "raw violations capped: errors use the path key");
        }
    }

    // V1-D: a name JGit refuses keeps its existing code and single error; the raw-name check adds nothing to it.
    @Test
    void testArchives_GitMetadataKeepsItsCode() throws IOException {
        var result = validate("git metadata", archive(".git/config"));
        assertEntryRejected("git metadata", result, "zip-archive.invalid.path.message");
        assertEquals(1, result.getGlobalErrorCount(), "git metadata: only the existing JGit error is reported");
    }

    // V1-D: a root folder entry '/' names no path below the project, so the raw-name check skips it.
    @Test
    void testArchives_RootFolderEntryAccepted() throws IOException {
        assertNull(validate("root folder entry", archive("/")), "root folder entry: nothing to reject");
    }

    // V1-D: an entry the upload filter drops is never written, so its raw name gets no NameChecker check ('%').
    @Test
    void testArchives_FilteredEntryNameRulesNotChecked() throws IOException {
        var filtering = new ZipArchiveValidator(path -> !path.contains("filtered"), zipCharsetDetector);
        assertNull(validateAndGetResult(archive("filtered%.xlsx"), filtering),
                "filtered entry: a dropped entry gets no NameChecker check");
    }

    // V1-D: a traversal name the upload filter drops is still rejected as a path: the filter decides what is written,
    // not what is safe, and the '..' segment would otherwise stop the zipfs view from opening the archive (a 500).
    @Test
    void testArchives_FilteredTraversalRejected() throws IOException {
        var filtering = new ZipArchiveValidator(path -> !path.contains("filtered"), zipCharsetDetector);
        var file = archive("../filtered.xlsx");
        var result = assertDoesNotThrow(() -> validateAndGetResult(file, filtering),
                "filtered traversal: validation must not throw");
        assertEntryRejected("filtered traversal", result, UNKNOWN_ARCHIVE_PATH);
    }

    // V1-D: with the upload filter of the application, a traversal inside the SVN or CVS metadata it drops is
    // rejected as a path, never answered with a 500.
    @ParameterizedTest(name = "{0}")
    @MethodSource("uploadFilteredTraversalNames")
    void testArchives_UploadFilteredTraversalRejected(String rowId, String rawName) throws IOException {
        var file = archive(rawName);
        var result = assertDoesNotThrow(() -> validateAndGetResult(file, uploadFilterValidator()),
                rowId + ": validation must not throw");
        assertEntryRejected(rowId, result, UNKNOWN_ARCHIVE_PATH);
    }

    // V1-D: traversal names the upload filter drops, as (row id, raw entry name).
    static Stream<Arguments> uploadFilteredTraversalNames() {
        return Stream.of(Arguments.of("dot-dot out of .svn", ".svn/../../evil-svn.txt"),
                Arguments.of("dot-dot out of CVS", "CVS/../evil-cvs.txt"),
                Arguments.of("dot segment inside CVS", "CVS/./x.txt"),
                Arguments.of("dot-dot onto .cvsignore", "x/../.cvsignore"));
    }

    // V1-D: SVN and CVS metadata the upload filter drops stays accepted: it is never written, so only its traversal
    // is checked and a name NameChecker refuses (':') is not newly rejected.
    @Test
    void testArchives_UploadFilteredMetadataAccepted() throws IOException {
        var file = archive(".svn/", ".svn/entries", "CVS/Root", ".cvsignore", ".svn/a:b");
        assertNull(validateAndGetResult(file, uploadFilterValidator()),
                "filtered metadata: SVN and CVS metadata must stay accepted");
    }

    // V1-D: when the zipfs view cannot open the archive for a reason no raw name explains, the zipfs failure
    // propagates as the cause instead of being turned into a path rejection.
    @Test
    void testArchives_UnopenableArchiveWithoutRawViolationPropagates() throws IOException {
        var file = archive("rules/Main.xlsx");
        var failure = new ZipException("zipfs cannot open the archive");
        try (var fileSystems = mockStatic(FileSystems.class, CALLS_REAL_METHODS)) {
            fileSystems.when(() -> FileSystems.newFileSystem(any(URI.class), anyMap())).thenThrow(failure);
            var e = assertThrows(RuntimeException.class, () -> validateAndGetResult(file, validator));
            assertSame(failure, e.getCause(), "the zipfs failure is kept as the cause");
        }
    }

    // V1-D: an unchecked failure of the zipfs walk with no raw violation to report (the filter drops the raw name,
    // which has no leading '/', but keeps the zipfs path, which has one) propagates unchanged.
    @Test
    void testArchives_WalkFailureWithoutRawViolationPropagates() throws IOException {
        var rawNamesFiltered = new ZipArchiveValidator(path -> path.startsWith("/") || !path.contains("\u0000"),
                zipCharsetDetector);
        var file = archive("evil\u0000.txt");
        assertThrows(InvalidPathException.class, () -> validateAndGetResult(file, rawNamesFiltered));
    }

    // V1-D: the checks before the entry names keep their codes - an empty archive.
    @Test
    void testArchives_EmptyArchive() throws IOException {
        var file = tmp.resolve("empty.zip");
        try (var out = new ZipArchiveOutputStream(file)) {
            out.finish();
        }
        var result = validate("empty archive", file);
        assertEntryRejected("empty archive", result, "zip-archive.empty.archive.message");
        assertEquals(1, result.getGlobalErrorCount(), "empty archive: one error");
    }

    // V1-D: the checks before the entry names keep their codes - a file too short to hold a signature.
    @Test
    void testArchives_FileWithoutSignature() throws IOException {
        var file = Files.write(tmp.resolve("short.zip"), new byte[]{'P', 'K'});
        var result = validate("no signature", file);
        assertEntryRejected("no signature", result, "zip-archive.invalid.archive.message");
        assertEquals(1, result.getGlobalErrorCount(), "no signature: one error");
    }

    // V1-D: the checks before the entry names keep their codes - an archive cut short keeps its signature only.
    @Test
    void testArchives_TruncatedArchive() throws IOException {
        var content = Files.readAllBytes(archive("rules/Main.xlsx"));
        var file = Files.write(tmp.resolve("truncated.zip"), Arrays.copyOf(content, content.length / 2));
        var result = validate("truncated archive", file);
        assertEntryRejected("truncated archive", result, "zip-archive.damaged.archive.message");
        assertEquals(1, result.getGlobalErrorCount(), "truncated archive: one error");
    }

    // V1-D: the checks before the entry names keep their codes - a name no configured charset decodes to a valid
    // name (ISO-8859-1 bytes with a ':' are no UTF-8 and hold a forbidden character in every other charset).
    @Test
    void testArchives_UnknownCharset() throws IOException {
        var file = archive(StandardCharsets.ISO_8859_1, List.of(Entry.empty("a:\u00FF.xlsx")));
        var result = validate("unknown charset", file);
        assertEntryRejected("unknown charset", result, "zip-archive.unknown.charset.message");
        assertEquals(1, result.getGlobalErrorCount(), "unknown charset: one error");
    }

    // V1-D: validates a crafted archive; an exception fails the row, naming the row only, never the raw name.
    private BindingResult validate(String rowId, Path archive) {
        return assertDoesNotThrow(() -> validateAndGetResult(archive, validator),
                rowId + ": validation must not throw");
    }

    // V1-D: a validator with the upload filter the application configures ('zipFilter' in webstudio.xml), which drops
    // the SVN and CVS metadata folders and the '.cvsignore' files.
    private ZipArchiveValidator uploadFilterValidator() {
        var uploadFilter = new AndPathFilter(List.of(new FolderNamePathFilter(Set.of(".svn", "CVS")),
                new FileNamePathFilter(Set.of(".cvsignore"))));
        return new ZipArchiveValidator(uploadFilter, zipCharsetDetector);
    }

    // V1-D: the archive is rejected as a whole (global errors only), every error is an archive error, and one of
    // them carries the expected code when one is given.
    private static void assertEntryRejected(String rowId, BindingResult result, String expectedCode) {
        assertNotNull(result, rowId + ": the archive must be rejected");
        assertEquals(0, result.getFieldErrorCount(), rowId + ": no field error is expected");
        assertTrue(result.getGlobalErrorCount() >= 1, rowId + ": at least one global error is expected");
        for (ObjectError error : result.getGlobalErrors()) {
            var code = error.getCode();
            assertTrue(code != null && code.startsWith("zip-archive."), rowId + ": unexpected error code " + code);
        }
        if (expectedCode != null) {
            assertTrue(result.getGlobalErrors().stream().anyMatch(e -> expectedCode.equals(e.getCode())),
                    rowId + ": no global error has the code " + expectedCode);
        }
    }

    // V1-D: an archive with a root rules.xml and one empty entry for each raw name.
    private Path archive(String... payloadNames) throws IOException {
        return archive(Stream.of(payloadNames).map(Entry::empty).toList());
    }

    // V1-D: writes a root rules.xml and the payload entries, each under its name exactly as given.
    private Path archive(List<Entry> payload) throws IOException {
        return archive(null, payload);
    }

    // V1-D: the same, with the names encoded in the given charset instead of UTF-8 when one is given.
    private Path archive(Charset nameEncoding, List<Entry> payload) throws IOException {
        var file = tmp.resolve("payload-" + counter++ + ".zip");
        try (var out = new ZipArchiveOutputStream(file)) {
            if (nameEncoding != null) {
                out.setEncoding(nameEncoding.name());
            }
            write(out, new Entry("rules.xml", RULES_XML, null));
            for (var entry : payload) {
                write(out, entry);
            }
            out.finish();
        }
        return file;
    }

    // V1-D: writes one entry with its content, and with its Unix mode when one is given.
    private static void write(ZipArchiveOutputStream out, Entry entry) throws IOException {
        var zipEntry = new RawNameEntry(entry.name());
        if (entry.unixMode() != null) {
            zipEntry.setUnixMode(entry.unixMode());
        }
        out.putArchiveEntry(zipEntry);
        out.write(entry.content().getBytes(StandardCharsets.UTF_8));
        out.closeArchiveEntry();
    }

    // V1-D: one payload entry. Payload content stays empty, because the integrity check opens a non-empty entry with
    // an Excel name as a workbook, which would hide the entry-name checks.
    private record Entry(String name, String content, Integer unixMode) {

        // V1-D: an empty regular entry.
        static Entry empty(String name) {
            return new Entry(name, "", null);
        }
    }

    // V1-D: an entry that keeps its name as given. On the default FAT platform commons-compress turns '\' into '/'
    // in a name without '/', which would rewrite the backslash payloads before they reach the validator.
    private static final class RawNameEntry extends ZipArchiveEntry {

        RawNameEntry(String name) {
            super(name);
            setPlatform(PLATFORM_UNIX);
            setName(name);
        }
    }

}

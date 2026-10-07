package org.openl.studio.projects.service.files;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import org.openl.rules.repository.api.BranchRepository;
import org.openl.rules.repository.api.ChangesetType;
import org.openl.rules.repository.api.FileData;
import org.openl.rules.repository.api.FileItem;
import org.openl.rules.repository.api.RepositoryDelegate;
import org.openl.rules.repository.api.UserInfo;
import org.openl.rules.security.User;
import org.openl.rules.webstudio.service.UserManagementService;

/**
 * Verifies that {@link AuthoringRepository} stamps the configured author on every write and leaves
 * non-write operations untouched.
 *
 * @author Yury Molchan
 */
class AuthoringRepositoryTest {

    private BranchRepository delegate;
    private UserInfo author;
    private AuthoringRepository repository;

    @BeforeEach
    void setUp() {
        delegate = mock(BranchRepository.class);
        author = new UserInfo("tester", "tester@example.com", "Tester");
        repository = new AuthoringRepository(delegate, author);
    }

    private static FileData named(String name) {
        var data = new FileData();
        data.setName(name);
        return data;
    }

    private static InputStream emptyStream() {
        return new ByteArrayInputStream(new byte[0]);
    }

    // V1: resolves the author while the given user is authenticated, and leaves no authentication behind.
    private static UserInfo currentAuthorAs(String username, UserManagementService userManagementService) {
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new TestingAuthenticationToken(username, null));
        SecurityContextHolder.setContext(context);
        try {
            return AuthoringRepository.currentAuthor(userManagementService);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    void saveSingleFileStampsAuthorAndPassesStreamThrough() throws Exception {
        var data = named("rules/file.txt");
        var stream = emptyStream();

        repository.save(data, stream);

        var captor = ArgumentCaptor.forClass(FileData.class);
        verify(delegate).save(captor.capture(), eq(stream));
        assertSame(author, captor.getValue().getAuthor());
        assertEquals("rules/file.txt", captor.getValue().getName());
        assertEquals("Save file.txt", captor.getValue().getComment());
    }

    @Test
    void existingCommentIsPreserved() throws Exception {
        var data = named("rules/file.txt");
        data.setComment("Custom message");

        repository.save(data, emptyStream());

        var captor = ArgumentCaptor.forClass(FileData.class);
        verify(delegate).save(captor.capture(), any());
        assertEquals("Custom message", captor.getValue().getComment());
    }

    @Test
    void saveFileItemListStampsAuthorOnEveryItem() throws Exception {
        var items = List.of(new FileItem(named("a.txt"), emptyStream()),
                new FileItem(named("b.txt"), emptyStream()));

        repository.save(items);

        verify(delegate).save(items);
        items.forEach(item -> assertSame(author, item.getData().getAuthor()));
    }

    @Test
    void saveFolderStampsAuthorOnFolderAndEntries() throws Exception {
        var folder = named("folder");
        var entries = List.of(new FileItem(named("folder/a.txt"), emptyStream()));

        repository.save(folder, entries, ChangesetType.FULL);

        verify(delegate).save(folder, entries, ChangesetType.FULL);
        assertSame(author, folder.getAuthor());
        entries.forEach(item -> assertSame(author, item.getData().getAuthor()));
    }

    @Test
    void deleteSingleStampsAuthor() throws Exception {
        var data = named("rules/file.txt");

        repository.delete(data);

        var captor = ArgumentCaptor.forClass(FileData.class);
        verify(delegate).delete(captor.capture());
        assertSame(author, captor.getValue().getAuthor());
        assertEquals("Delete file.txt", captor.getValue().getComment());
    }

    @Test
    void deleteListStampsAuthorOnEveryItem() throws Exception {
        var data = List.of(named("a"), named("b"));

        repository.delete(data);

        verify(delegate).delete(data);
        data.forEach(item -> assertSame(author, item.getAuthor()));
    }

    @Test
    void deleteHistoryStampsAuthor() throws Exception {
        var data = named("rules/file.txt");

        repository.deleteHistory(data);

        var captor = ArgumentCaptor.forClass(FileData.class);
        verify(delegate).deleteHistory(captor.capture());
        assertSame(author, captor.getValue().getAuthor());
    }

    @Test
    void copyHistoryStampsAuthorOnDestination() throws Exception {
        var destination = named("destination");

        repository.copyHistory("source", destination, "v1");

        var captor = ArgumentCaptor.forClass(FileData.class);
        verify(delegate).copyHistory(eq("source"), captor.capture(), eq("v1"));
        assertSame(author, captor.getValue().getAuthor());
    }

    @Test
    void forBranchReturnsAuthoringWrapperThatKeepsStampingAuthor() throws Exception {
        var branchDelegate = mock(BranchRepository.class);
        when(delegate.forBranch("dev")).thenReturn(branchDelegate);

        var branchRepository = repository.forBranch("dev");

        assertNotSame(repository, branchRepository);
        assertInstanceOf(AuthoringRepository.class, branchRepository);

        branchRepository.save(named("x"), emptyStream());
        var captor = ArgumentCaptor.forClass(FileData.class);
        verify(branchDelegate).save(captor.capture(), any());
        assertSame(author, captor.getValue().getAuthor());
    }

    @Test
    void readOperationsDelegateUnchanged() {
        when(delegate.getName()).thenReturn("design");
        when(delegate.getId()).thenReturn("design-flat");

        assertEquals("design", repository.getName());
        assertEquals("design-flat", repository.getId());
        verify(delegate).getName();
        verify(delegate).getId();
    }

    // V1: the wrapper reveals the repository it wraps, so the containment checks of the repository mount reach the
    // local root of a file repository behind it.
    @Test
    void getDelegateReturnsTheWrappedRepository() {
        assertSame(delegate, repository.getDelegate());
    }

    // V1: a branch of the mount is wrapped again, and that wrapper reveals the branch repository.
    @Test
    void forBranchWrapperReturnsTheBranchRepositoryAsItsDelegate() throws Exception {
        var branch = RandomStringUtils.secure().nextAlphanumeric(12);
        var branchDelegate = mock(BranchRepository.class);
        when(delegate.forBranch(branch)).thenReturn(branchDelegate);

        var branchRepository = repository.forBranch(branch);

        assertSame(branchDelegate, assertInstanceOf(AuthoringRepository.class, branchRepository).getDelegate());
    }

    // V1: code that unwraps delegates to read, such as the ancestor lookup, keeps reading through this wrapper and
    // through the secured wrapper behind it, so the wrapper must not be a delegate.
    @Test
    void isNotARepositoryDelegate() {
        assertFalse(repository instanceof RepositoryDelegate,
                "Only the containment anchor may look behind the authoring wrapper");
    }

    // V1: a save without file data reaches the wrapped repository as it is, with its stream and result untouched.
    @ParameterizedTest
    @NullSource
    void saveWithoutFileDataPassesNullAndStreamThrough(FileData missing) throws Exception {
        var stream = emptyStream();
        var saved = named("rules/file.txt");
        when(delegate.save(missing, stream)).thenReturn(saved);

        assertSame(saved, repository.save(missing, stream));

        verify(delegate).save(missing, stream);
    }

    // V1: a file without a usable name still gets the author and the default save comment.
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void saveFileWithoutNameStampsAuthorAndDefaultComment(String name) throws Exception {
        repository.save(named(name), emptyStream());

        var captor = ArgumentCaptor.forClass(FileData.class);
        verify(delegate).save(captor.capture(), any());
        assertSame(author, captor.getValue().getAuthor());
        assertEquals("Save files", captor.getValue().getComment());
    }

    // V1: a file without a usable name still gets the author and the default delete comment.
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void deleteFileWithoutNameStampsAuthorAndDefaultComment(String name) throws Exception {
        repository.delete(named(name));

        var captor = ArgumentCaptor.forClass(FileData.class);
        verify(delegate).delete(captor.capture());
        assertSame(author, captor.getValue().getAuthor());
        assertEquals("Delete files", captor.getValue().getComment());
    }

    // V1: a folder save without folder data passes the missing data through and still stamps every entry.
    @ParameterizedTest
    @NullSource
    void saveFolderWithoutFolderDataStampsEntriesAndPassesNullThrough(FileData missing) throws Exception {
        var entries = List.of(new FileItem(named("folder/a.txt"), emptyStream()));

        repository.save(missing, entries, ChangesetType.DIFF);

        verify(delegate).save(missing, entries, ChangesetType.DIFF);
        entries.forEach(item -> {
            assertSame(author, item.getData().getAuthor());
            assertEquals("Save a.txt", item.getData().getComment());
        });
    }

    // V1: a delete list may hold a missing entry, which is passed through while the other entries are stamped.
    @Test
    void deleteListPassesMissingEntryThroughAndStampsTheOthers() throws Exception {
        var file = named("rules/file.txt");
        var data = Arrays.asList(null, file);

        repository.delete(data);

        verify(delegate).delete(data);
        assertNull(data.get(0));
        assertSame(author, file.getAuthor());
        assertEquals("Delete file.txt", file.getComment());
    }

    // V1: the author of a repository mount carries the stored name, email and display name of the current user.
    @Test
    void currentAuthorCarriesTheStoredUserDetails() {
        var username = RandomStringUtils.secure().nextAlphanumeric(12);
        var email = username + "@example.com";
        var displayName = "Display " + username;
        var user = mock(User.class);
        when(user.getUsername()).thenReturn(username);
        when(user.getEmail()).thenReturn(email);
        when(user.getDisplayName()).thenReturn(displayName);
        var userManagementService = mock(UserManagementService.class);
        when(userManagementService.getUser(username)).thenReturn(user);

        var currentAuthor = currentAuthorAs(username, userManagementService);

        assertEquals(new UserInfo(username, email, displayName), currentAuthor);
        assertEquals(displayName, currentAuthor.getName());
    }

    // V1: a current user with no stored record is the author by the authenticated name alone.
    @Test
    void currentAuthorFallsBackToTheAuthenticatedNameWhenNoUserIsStored() {
        var username = RandomStringUtils.secure().nextAlphanumeric(12);
        var userManagementService = mock(UserManagementService.class);

        var currentAuthor = currentAuthorAs(username, userManagementService);

        assertEquals(new UserInfo(username), currentAuthor);
        assertNull(currentAuthor.getEmail());
        verify(userManagementService).getUser(username);
    }
}

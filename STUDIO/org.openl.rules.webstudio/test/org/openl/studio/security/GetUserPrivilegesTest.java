package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import org.apache.commons.lang3.RandomStringUtils;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.openl.rules.security.Group;
import org.openl.rules.security.Privileges;
import org.openl.rules.security.SimpleGroup;
import org.openl.rules.security.User;
import org.openl.rules.webstudio.service.GroupManagementService;
import org.openl.rules.webstudio.service.UserManagementService;

/**
 * Unit tests for {@link GetUserPrivileges}.
 *
 * <p>V12: an external (IdP) group whose name matches an OpenL group holding {@code ADMIN} makes {@link
 * GetUserPrivileges#apply} log one WARN, while {@link GetUserPrivileges#withoutAdminMatchWarning()} maps
 * identically and stays silent. Every case also compares the mapping with {@link #expectedPreChange}, an
 * independent copy of the mapping rule as it stood before V12, because the warning must not change the returned
 * authorities.
 *
 * <p>The warning names the external group, the user and the matched OpenL group with every ISO control character
 * and the Unicode line and paragraph separators replaced by {@code '_'}, so a name the identity provider supplies
 * cannot end the warning line and start a forged one. The mapping still looks up and returns the names as they
 * were supplied.
 */
@ExtendWith(MockitoExtension.class)
class GetUserPrivilegesTest {

    /** Unique to the V12 warning, so a line containing it is that warning and nothing else. */
    private static final String ADMIN_MATCH_MARKER = "holds ADMIN";

    /** A forged audit line, which an identity provider could append to a name after a line break. */
    private static final String FORGED_LINE = "WARN org.openl.security.audit - event=auth.success outcome=success";

    /** An ADMIN-holding OpenL group name carrying CR LF and the forged line, as the IdP sends it. */
    private static final String CRAFTED_GROUP = "openl-admin\r\n" + FORGED_LINE;
    private static final String CRAFTED_GROUP_LOGGED = "openl-admin__" + FORGED_LINE;

    /** A user name carrying LF, TAB, U+2028, U+2029 and the C1 control NEL (U+0085), as the IdP sends it. */
    private static final String CRAFTED_USER = "mallory\n\tforged-user\u2028\u2029\u0085end";
    private static final String CRAFTED_USER_LOGGED = "mallory__forged-user___end";

    private static final String USER = "alice";
    private static final String USER_WITHOUT_DB_RECORD = "bob";
    private static final String NO_DEFAULT_GROUP = "";
    private static final String DEFAULT_GROUP = "openl-default";
    private static final String DEFAULT_GROUP_DESCRIPTION = "A default group for authenticated users";

    @Mock
    private UserManagementService userManagementService;

    @Mock
    private GroupManagementService groupManagementService;

    @Mock
    private User dbUser;

    /** The OpenL groups known to the mocked group service, by name. Both the mock and the oracle read it. */
    private final Map<String, Group> groups = new HashMap<>();

    /** The DB user's password, generated per run: no captured line may contain it. */
    private final String dbPassword = RandomStringUtils.secure().nextAlphanumeric(16);

    private final GrantedAuthority dbPrivilege = new SimpleGrantedAuthority("db-privilege");
    private final List<GrantedAuthority> dbAuthorities = List.of(dbPrivilege);

    private final Group adminGroup = new SimpleGroup("openl-admin", List.<GrantedAuthority>of(Privileges.ADMIN));
    private final Group baGroup = new SimpleGroup("openl-ba",
            List.<GrantedAuthority>of(new SimpleGrantedAuthority("VIEW_PROJECTS")));
    private final Group nestedAdminGroup = new SimpleGroup("openl-nested-admin",
            List.<GrantedAuthority>of(new SimpleGrantedAuthority("EDIT_PROJECTS"), adminGroup));
    private final Group defaultGroup = new SimpleGroup(DEFAULT_GROUP,
            List.<GrantedAuthority>of(new SimpleGrantedAuthority("VIEW_PROJECTS")));
    private final Group craftedAdminGroup = new SimpleGroup(CRAFTED_GROUP, List.<GrantedAuthority>of(Privileges.ADMIN));

    @BeforeEach
    void setUp() {
        groups.put(adminGroup.getAuthority(), adminGroup);
        groups.put(baGroup.getAuthority(), baGroup);
        groups.put(nestedAdminGroup.getAuthority(), nestedAdminGroup);
        groups.put(defaultGroup.getAuthority(), defaultGroup);
        groups.put(craftedAdminGroup.getAuthority(), craftedAdminGroup);
        // "unmatched" has no OpenL group, so the lookup answers null for it.
        lenient().when(groupManagementService.getGroupByName(anyString()))
                .thenAnswer(invocation -> groups.get(invocation.<String>getArgument(0)));
        lenient().when(userManagementService.getUser(USER)).thenReturn(dbUser);
        lenient().doReturn(dbAuthorities).when(dbUser).getAuthorities();
        lenient().when(dbUser.getPassword()).thenReturn(dbPassword);
    }

    // ---------------------------------------------------------------------------------------------------------
    // apply(): the IdP-backed login path
    // ---------------------------------------------------------------------------------------------------------

    @Test
    @StdIo
    void adminGroupMatchLogsOneWarning(StdErr err) {
        var external = authorities("openl-admin");

        var result = new GetUserPrivileges(userManagementService, groupManagementService, NO_DEFAULT_GROUP)
                .apply(USER, external);

        assertNoPasswordLogged(err);
        var warnings = adminMatchWarnings(err);
        assertEquals(1, warnings.size(), "Expected exactly one ADMIN name-match warning");
        var warning = warnings.get(0);
        assertTrue(warning.contains("WARN"), "The ADMIN name-match warning must be logged at WARN");
        assertTrue(warning.contains("'" + USER + "'"), "The ADMIN name-match warning must name the user");
        assertTrue(warning.contains("'openl-admin'"), "The ADMIN name-match warning must name the matched group");
        assertEquals(List.of(adminGroup, dbPrivilege), List.copyOf(result));
        assertEquals(expectedPreChange(null, external, dbAuthorities), List.copyOf(result));
    }

    @Test
    @StdIo
    void nestedAdminGroupMatchLogsOneWarning(StdErr err) {
        var external = authorities("openl-nested-admin");

        var result = new GetUserPrivileges(userManagementService, groupManagementService, NO_DEFAULT_GROUP)
                .apply(USER, external);

        assertNoPasswordLogged(err);
        var warnings = adminMatchWarnings(err);
        assertEquals(1, warnings.size(), "A group holding ADMIN through a nested group must warn too");
        assertTrue(warnings.get(0).contains("'openl-nested-admin'"),
                "The ADMIN name-match warning must name the nested group");
        assertEquals(List.of(nestedAdminGroup, dbPrivilege), List.copyOf(result));
        assertEquals(expectedPreChange(null, external, dbAuthorities), List.copyOf(result));
    }

    @Test
    @StdIo
    void nonAdminGroupDoesNotWarn(StdErr err) {
        var external = authorities("openl-ba");

        var result = new GetUserPrivileges(userManagementService, groupManagementService, NO_DEFAULT_GROUP)
                .apply(USER, external);

        assertNoPasswordLogged(err);
        assertEquals(0, adminMatchWarnings(err).size(), "A group without ADMIN must not warn");
        assertEquals(List.of(baGroup, dbPrivilege), List.copyOf(result));
        assertEquals(expectedPreChange(null, external, dbAuthorities), List.copyOf(result));
    }

    @Test
    @StdIo
    void unmatchedAuthorityDoesNotWarnAndIsKept(StdErr err) {
        var external = authorities("unmatched");

        var result = List.copyOf(new GetUserPrivileges(userManagementService, groupManagementService,
                NO_DEFAULT_GROUP).apply(USER, external));

        assertNoPasswordLogged(err);
        assertEquals(0, adminMatchWarnings(err).size(), "An unmatched authority must not warn");
        assertEquals(2, result.size());
        assertSame(external.get(0), result.get(0), "An unmatched external authority is kept as it is");
        assertSame(dbPrivilege, result.get(1));
        assertEquals(expectedPreChange(null, external, dbAuthorities), result);
    }

    @Test
    @StdIo
    void mixedAuthoritiesWarnOnceAndKeepTheirOrder(StdErr err) {
        var external = authorities("openl-admin", "openl-ba", "unmatched");

        var result = List.copyOf(new GetUserPrivileges(userManagementService, groupManagementService,
                NO_DEFAULT_GROUP).apply(USER, external));

        assertNoPasswordLogged(err);
        var warnings = adminMatchWarnings(err);
        assertEquals(1, warnings.size(), "Only the ADMIN-holding match warns");
        assertTrue(warnings.get(0).contains("'openl-admin'"),
                "The ADMIN name-match warning must name the matched group");
        assertEquals(4, result.size());
        assertSame(adminGroup, result.get(0));
        assertSame(baGroup, result.get(1));
        assertSame(external.get(2), result.get(2));
        assertSame(dbPrivilege, result.get(3));
        assertEquals(expectedPreChange(null, external, dbAuthorities), result);
    }

    @Test
    void defaultGroupIsPrepended() {
        var external = authorities("openl-ba");

        var result = List.copyOf(new GetUserPrivileges(userManagementService, groupManagementService,
                DEFAULT_GROUP).apply(USER, external));

        assertSame(defaultGroup, result.get(0), "The default group comes first");
        assertEquals(List.of(defaultGroup, baGroup, dbPrivilege), result);
        assertEquals(expectedPreChange(defaultGroup, external, dbAuthorities), result);
        verify(groupManagementService, never()).addGroup(anyString(), anyString());
    }

    @Test
    void absentDefaultGroupIsCreatedAndPrepended() {
        groups.remove(DEFAULT_GROUP);
        var created = new SimpleGroup(DEFAULT_GROUP, List.of());
        // Creating the group makes the second lookup find it, as the real service does.
        doAnswer(invocation -> groups.put(DEFAULT_GROUP, created)).when(groupManagementService)
                .addGroup(DEFAULT_GROUP, DEFAULT_GROUP_DESCRIPTION);
        var external = authorities("openl-ba");

        var result = List.copyOf(new GetUserPrivileges(userManagementService, groupManagementService,
                DEFAULT_GROUP).apply(USER, external));

        verify(groupManagementService).addGroup(DEFAULT_GROUP, DEFAULT_GROUP_DESCRIPTION);
        assertSame(created, result.get(0), "The created default group comes first");
        assertEquals(expectedPreChange(created, external, dbAuthorities), result);
    }

    @Test
    void defaultGroupThatCannotBeCreatedIsSkipped() {
        groups.remove(DEFAULT_GROUP);
        var external = authorities("openl-ba");

        var result = List.copyOf(new GetUserPrivileges(userManagementService, groupManagementService,
                DEFAULT_GROUP).apply(USER, external));

        verify(groupManagementService).addGroup(DEFAULT_GROUP, DEFAULT_GROUP_DESCRIPTION);
        assertEquals(List.of(baGroup, dbPrivilege), result);
        assertEquals(expectedPreChange(null, external, dbAuthorities), result);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void blankDefaultGroupIsNeitherLookedUpNorCreated(String blankDefaultGroup) {
        var external = authorities("openl-ba");

        var result = List.copyOf(new GetUserPrivileges(userManagementService, groupManagementService,
                blankDefaultGroup).apply(USER, external));

        assertEquals(List.of(baGroup, dbPrivilege), result);
        assertEquals(expectedPreChange(null, external, dbAuthorities), result);
        verify(groupManagementService, never()).addGroup(anyString(), anyString());
        verify(groupManagementService).getGroupByName("openl-ba");
        verify(groupManagementService, never()).getGroupByName(blankDefaultGroup);
    }

    @Test
    void unknownDbUserAddsNothing() {
        var external = authorities("openl-admin", "openl-ba");

        var result = List.copyOf(new GetUserPrivileges(userManagementService, groupManagementService,
                NO_DEFAULT_GROUP).apply(USER_WITHOUT_DB_RECORD, external));

        verify(userManagementService).getUser(USER_WITHOUT_DB_RECORD);
        assertEquals(List.of(adminGroup, baGroup), result);
        assertEquals(expectedPreChange(null, external, null), result);
    }

    @Test
    @StdIo
    void lineBreaksInIdentityProviderNamesStayOnTheWarningLine(StdErr err) {
        var external = authorities(CRAFTED_GROUP);

        var result = List.copyOf(new GetUserPrivileges(userManagementService, groupManagementService,
                NO_DEFAULT_GROUP).apply(CRAFTED_USER, external));

        assertNoPasswordLogged(err);
        var forged = Stream.of(err.capturedLines()).filter(line -> line.contains(FORGED_LINE)).toList();
        assertEquals(1, forged.size(), "The forged text must stay inside the one warning line");
        var warning = forged.get(0);
        assertTrue(warning.contains("WARN"), "The ADMIN name-match warning must be logged at WARN");
        assertTrue(warning.contains(ADMIN_MATCH_MARKER), "The forged text must stay inside the ADMIN warning");
        assertTrue(warning.endsWith("External group '" + CRAFTED_GROUP_LOGGED + "' of user '" + CRAFTED_USER_LOGGED
                + "' matches OpenL group '" + CRAFTED_GROUP_LOGGED + "', which holds ADMIN; "
                + "the user gains administrator rights through this name match."),
                "The warning must name the sanitized group, user and matched group");
        // The warning is one of the captured lines, so a single captured line is the warning itself.
        assertEquals(1, err.capturedLines().length, "The warning is the only line written");
        assertTrue(Stream.of(err.capturedLines()).noneMatch(line -> line.startsWith(FORGED_LINE)),
                "No captured line may start with the forged text");
        // The mapping looks up and returns the names as the IdP sent them; only the logged copies change.
        verify(groupManagementService).getGroupByName(CRAFTED_GROUP);
        verify(userManagementService).getUser(CRAFTED_USER);
        assertSame(craftedAdminGroup, result.get(0));
        assertEquals(List.of(craftedAdminGroup), result);
        assertEquals(expectedPreChange(null, external, null), result);
    }

    // ---------------------------------------------------------------------------------------------------------
    // withoutAdminMatchWarning(): the path that replays stored groups (personal access tokens)
    // ---------------------------------------------------------------------------------------------------------

    @Test
    @StdIo
    void withoutAdminMatchWarningNeverWarns(StdErr err) {
        var external = authorities("openl-admin", "openl-nested-admin", "openl-ba", "unmatched");

        var result = List.copyOf(new GetUserPrivileges(userManagementService, groupManagementService,
                NO_DEFAULT_GROUP).withoutAdminMatchWarning().apply(USER, external));

        assertNoPasswordLogged(err);
        assertEquals(0, adminMatchWarnings(err).size(), "withoutAdminMatchWarning() must not warn");
        assertEquals(expectedPreChange(null, external, dbAuthorities), result);
    }

    @Test
    @StdIo
    void withoutAdminMatchWarningLogsNothingForCraftedNames(StdErr err) {
        var external = authorities(CRAFTED_GROUP);

        var result = List.copyOf(new GetUserPrivileges(userManagementService, groupManagementService,
                NO_DEFAULT_GROUP).withoutAdminMatchWarning().apply(CRAFTED_USER, external));

        assertNoPasswordLogged(err);
        assertEquals(0, err.capturedLines().length, "withoutAdminMatchWarning() must log nothing");
        assertSame(craftedAdminGroup, result.get(0));
        assertEquals(expectedPreChange(null, external, null), result);
    }

    @ParameterizedTest
    @MethodSource("mappingScenarios")
    @StdIo
    void withoutAdminMatchWarningMapsExactlyLikeApply(String defaultGroupName,
            List<String> externalNames,
            StdErr err) {
        var external = authorities(externalNames.toArray(String[]::new));
        var privileges = new GetUserPrivileges(userManagementService, groupManagementService, defaultGroupName);

        var silent = List.copyOf(privileges.withoutAdminMatchWarning().apply(USER, external));
        assertNoPasswordLogged(err);
        assertEquals(0, adminMatchWarnings(err).size(), "withoutAdminMatchWarning() must not warn");
        var warned = List.copyOf(privileges.apply(USER, external));
        assertNoPasswordLogged(err);

        var expected = expectedPreChange(
                NO_DEFAULT_GROUP.equals(defaultGroupName) ? null : defaultGroup,
                external,
                dbAuthorities);
        assertEquals(expected, silent);
        assertEquals(expected, warned);
        assertEquals(warned, silent);
    }

    static Stream<Arguments> mappingScenarios() {
        return Stream.of(Arguments.of(NO_DEFAULT_GROUP, List.of("openl-admin")),
                Arguments.of(NO_DEFAULT_GROUP, List.of("openl-ba")),
                Arguments.of(NO_DEFAULT_GROUP, List.of("unmatched")),
                Arguments.of(NO_DEFAULT_GROUP, List.of("openl-admin", "openl-ba", "unmatched")),
                Arguments.of(DEFAULT_GROUP, List.of("openl-admin")),
                Arguments.of(DEFAULT_GROUP, List.of("openl-ba", "unmatched")),
                Arguments.of(DEFAULT_GROUP, List.of()));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------------------

    /**
     * The mapping rule as it stood before V12, written independently of {@link GetUserPrivileges}: the default
     * group (when there is one), then each external authority replaced by the OpenL group of the same name or
     * kept as it is, then the user's authorities from the database (when the user has a record).
     *
     * @param defaultGroup  the resolved default group, or {@code null} when none applies
     * @param external      the authorities the identity provider supplied
     * @param dbAuthorities the user's database authorities, or {@code null} when the user has no record
     * @return the authorities the pre-V12 code returned, in order
     */
    private List<GrantedAuthority> expectedPreChange(@Nullable Group defaultGroup,
            Collection<? extends GrantedAuthority> external,
            @Nullable Collection<? extends GrantedAuthority> dbAuthorities) {
        var expected = new ArrayList<GrantedAuthority>();
        if (defaultGroup != null) {
            expected.add(defaultGroup);
        }
        for (GrantedAuthority authority : external) {
            expected.add(Objects.requireNonNullElse(groups.get(authority.getAuthority()), authority));
        }
        if (dbAuthorities != null) {
            expected.addAll(dbAuthorities);
        }
        return List.copyOf(expected);
    }

    private static List<GrantedAuthority> authorities(String... names) {
        return Stream.of(names).<GrantedAuthority>map(SimpleGrantedAuthority::new).toList();
    }

    private static List<String> adminMatchWarnings(StdErr err) {
        return Stream.of(err.capturedLines()).filter(line -> line.contains(ADMIN_MATCH_MARKER)).toList();
    }

    /**
     * The mapping logs only names, so no captured line may even mention a password, let alone contain the DB user's
     * generated one.
     */
    private void assertNoPasswordLogged(StdErr err) {
        assertEquals(0,
                Stream.of(err.capturedLines())
                        .filter(line -> line.toLowerCase(Locale.ROOT).contains("password"))
                        .count(),
                "A captured line mentions a password");
        assertEquals(0,
                Stream.of(err.capturedLines()).filter(line -> line.contains(dbPassword)).count(),
                "A captured line contains the generated password");
    }
}

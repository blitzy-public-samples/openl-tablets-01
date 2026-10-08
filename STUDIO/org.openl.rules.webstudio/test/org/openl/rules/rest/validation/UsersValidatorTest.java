package org.openl.rules.rest.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.time.Duration;
import java.util.HashSet;
import java.util.Objects;
import java.util.stream.Stream;
import jakarta.validation.ConstraintValidatorContext;

import org.apache.commons.lang3.RandomStringUtils;
import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;
import org.hibernate.validator.constraintvalidation.HibernateConstraintViolationBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import org.openl.rules.rest.model.ChangePasswordModel;
import org.openl.rules.rest.model.InternalPasswordModel;
import org.openl.rules.rest.model.UserCreateModel;
import org.openl.rules.rest.model.UserEditModel;
import org.openl.rules.rest.model.UserInfoEditModel;
import org.openl.rules.rest.model.UserInfoModel;
import org.openl.rules.rest.model.UserProfileEditModel;
import org.openl.rules.security.SimpleUser;
import org.openl.rules.webstudio.service.UserManagementService;
import org.openl.studio.common.validation.AbstractConstraintValidatorTest;
import org.openl.studio.security.CurrentUserInfo;

@SpringJUnitConfig(classes = MockConfiguration.class)
class UsersValidatorTest extends AbstractConstraintValidatorTest {

    private static final String MUST_BE_LESS_THAN_25 = "Must be less than 25.";
    private static final String CANNOT_BE_EMPTY = "Cannot be empty.";
    // V7: messages of LocalPasswordPolicy
    private static final String PASSWORD_MIN_LENGTH = "The password must contain at least 12 characters.";
    private static final String PASSWORD_MAX_BYTES = "The password must not exceed 72 bytes in UTF-8.";
    // V7: message of a password that holds an unpaired surrogate
    private static final String PASSWORD_INVALID = "The password is not valid.";
    private static final String MUST_NOT_CONTAIN_FOLLOWING_CHARS = "The name cannot contain spaces and any of the following characters: / \\ : * ? \" < > | { } ~ ^ ; %";

    @Autowired
    private UserManagementService userManagementService;

    @Autowired
    private CurrentUserInfo currentUserInfo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // V7: credentials are generated per test instance, so no literal password appears in this class
    private final String currentPassword = RandomStringUtils.secure().nextAlphanumeric(16);
    private final String currentPasswordHash = RandomStringUtils.secure().nextAlphanumeric(16);
    private final String newPassword = RandomStringUtils.secure().nextAlphanumeric(16);
    private final String otherPassword = RandomStringUtils.secure().nextAlphanumeric(16);
    private final String otherPasswordHash = RandomStringUtils.secure().nextAlphanumeric(16);

    @AfterEach
    void reset_mocks() {
        reset(userManagementService, passwordEncoder, currentUserInfo);
    }

    @Test
    void testUserInfo_valid() {
        assertNull(validateAndGetResult(getValidUserInfoModel()));
    }

    @Test
    void testUserInfo_firstName_notValid() {
        var userInfoModel = getValidUserInfoModel();
        String wrongFirstName = RandomStringUtils.random(26, "John");
        userInfoModel.setFirstName(wrongFirstName);
        var bindingResult = validateAndGetResult(userInfoModel);
        assertFieldError("firstName", MUST_BE_LESS_THAN_25, wrongFirstName, bindingResult.getFieldError("firstName"));
    }

    @Test
    void testUserInfo_lastName_notValid() {
        var userInfoModel = getValidUserInfoModel();
        String wrongLastName = RandomStringUtils.random(26, "Smith");
        userInfoModel.setLastName(wrongLastName);
        var bindingResult = validateAndGetResult(userInfoModel);
        assertFieldError("lastName", MUST_BE_LESS_THAN_25, wrongLastName, bindingResult.getFieldError("lastName"));
    }

    @Test
    void testUserInfo_displayName_notValid() {
        var userInfoModel = getValidUserInfoModel();
        String wrongDisplayName = RandomStringUtils.random(65, "John Smith");
        userInfoModel.setDisplayName(wrongDisplayName);
        var bindingResult = validateAndGetResult(userInfoModel);
        assertFieldError("displayName",
                "Must be less than 64.",
                wrongDisplayName,
                bindingResult.getFieldError("displayName"));
    }

    @Test
    void testUserInfo_email_notValid() {
        var userInfoModel = getValidUserInfoModel();
        userInfoModel.setEmail("wrongEmail");
        var bindingResult = validateAndGetResult(userInfoModel);
        assertFieldError("email", "The email address is invalid.", "wrongEmail", bindingResult.getFieldError("email"));
    }

    @Test
    void testEditUserInfo_requiredFields() {
        var userInfoEditModel = getValidUserInfoEditModel();

        userInfoEditModel.setEmail("");
        var bindingResult = validateAndGetResult(userInfoEditModel);
        assertFieldError("email", CANNOT_BE_EMPTY, "", bindingResult.getFieldError("email"));

        userInfoEditModel.setEmail("jsmith@email").setDisplayName("");
        bindingResult = validateAndGetResult(userInfoEditModel);
        assertFieldError("displayName", CANNOT_BE_EMPTY, "", bindingResult.getFieldError("displayName"));
    }

    @Test
    void testEditRequests_firstAndLastNames_optional() {
        when(userManagementService.getUser(anyString())).thenReturn(null);

        assertOptionalNamesValid(getValidUserInfoEditModel());
        assertOptionalNamesValid(getValidUserEditModel());
        assertOptionalNamesValid(getValidUserCreateModel());
        assertOptionalNamesValid(getValidUserProfileEditModel().setChangePassword(new ChangePasswordModel()));
    }

    @Test
    void testEditUser_valid() {
        var userEditModel = getValidUserEditModel();

        assertValid(userEditModel);

        userEditModel.setPassword(null);
        assertValid(userEditModel);

        // V7: blank password on edit means "unchanged" and stays valid
        userEditModel.setPassword("");
        assertValid(userEditModel);
        userEditModel.setPassword(" ");
        assertValid(userEditModel);
    }

    // V7: admin edit route, boundary cases of LocalPasswordPolicy
    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("passwordPolicyCases")
    void testEditUser_password_policy(String label, String candidate, String expectedMessage) {
        var model = getValidUserEditModel().setPassword(candidate);
        assertPasswordPolicy(label, model, "password", expectedMessage, candidate);
    }

    @Test
    void testEditUser_requiredFields() {
        var userEditModel = getValidUserEditModel().setEmail("");
        var bindingResult = validateAndGetResult(userEditModel);
        assertFieldError("email", CANNOT_BE_EMPTY, "", bindingResult.getFieldError("email"));

        userEditModel.setEmail("jsmith@email").setDisplayName(" ");
        bindingResult = validateAndGetResult(userEditModel);
        assertFieldError("displayName", CANNOT_BE_EMPTY, " ", bindingResult.getFieldError("displayName"));
    }

    @Test
    void testCreateUser_valid() {
        when(userManagementService.getUser(anyString())).thenReturn(null);
        var userCreateModel = getValidUserCreateModel();

        assertValid(getValidUserCreateModel());

        // V7: a generated policy-compliant password
        userCreateModel.setInternalPassword(new InternalPasswordModel().setPassword(otherPassword));
        assertValid(userCreateModel);

        userCreateModel.setUsername("a1!@#$&()_-+='.,");
        assertValid(userCreateModel);

        userCreateModel.setUsername("фы漢語,汉语ęął");
        assertValid(userCreateModel);

        userCreateModel.setUsername("a");
        assertValid(userCreateModel);
    }

    @Test
    void testCreateUser_noGroups_valid() {
        var userCreateModel = getValidUserCreateModel();
        userCreateModel.setGroups(null);
        assertValid(userCreateModel);
    }

    @Test
    void testCreateUser_requiredFields() {
        when(userManagementService.getUser(anyString())).thenReturn(null);
        var userCreateModel = getValidUserCreateModel().setEmail("");
        var bindingResult = validateAndGetResult(userCreateModel);
        assertFieldError("email", CANNOT_BE_EMPTY, "", bindingResult.getFieldError("email"));

        userCreateModel.setEmail("jsmith@email").setDisplayName("");
        bindingResult = validateAndGetResult(userCreateModel);
        assertFieldError("displayName", CANNOT_BE_EMPTY, "", bindingResult.getFieldError("displayName"));
    }

    @Test
    void testCreateUser_password_notValid() {
        when(userManagementService.getUser(anyString())).thenReturn(null);
        var userCreateModel = getValidUserCreateModel();

        var wrongInternalPassword = new InternalPasswordModel().setPassword(null);
        userCreateModel.setInternalPassword(wrongInternalPassword);
        var bindingResult = validateAndGetResult(userCreateModel);
        assertFieldError("internalPassword",
                CANNOT_BE_EMPTY,
                wrongInternalPassword,
                bindingResult.getFieldError("internalPassword"));
    }

    // V7: create route, boundary cases of LocalPasswordPolicy
    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("passwordPolicyCases")
    void testCreateUser_password_policy(String label, String candidate, String expectedMessage) {
        when(userManagementService.getUser(anyString())).thenReturn(null);
        var internalPassword = new InternalPasswordModel().setPassword(candidate);
        var model = getValidUserCreateModel().setInternalPassword(internalPassword);
        assertPasswordPolicy(label, model, "internalPassword", expectedMessage, internalPassword);
    }

    // V7: a blank password is valid when internal users cannot be created
    @Test
    void testCreateUser_blankPasswordAllowedWhenInternalUsersDisabled() {
        // The Spring test context fixes canCreateInternalUsers to true, so the validator is exercised directly here.
        var validator = new InternalPasswordConstraintValidator();
        validator.canCreateInternalUsers = false;
        assertTrue(validator.isValid(new InternalPasswordModel().setPassword(null),
                mock(ConstraintValidatorContext.class)));
    }

    @Test
    void testCreateUser_username_notValid() {
        when(userManagementService.getUser(anyString())).thenReturn(null);
        var userCreateModel = getValidUserCreateModel();

        String wrongUsername = RandomStringUtils.random(26, "jsmith");
        userCreateModel.setUsername(wrongUsername);
        var bindingResult = validateAndGetResult(userCreateModel);
        assertFieldError("username", MUST_BE_LESS_THAN_25, wrongUsername, bindingResult.getFieldError("username"));

        userCreateModel.setUsername(null);
        bindingResult = validateAndGetResult(userCreateModel);
        assertFieldError("username", CANNOT_BE_EMPTY, null, bindingResult.getFieldError("username"));

        userCreateModel.setUsername("a..aa");
        bindingResult = validateAndGetResult(userCreateModel);
        assertFieldError("username", "The name cannot contain consecutive '.'.", "a..aa", bindingResult.getFieldError("username"));

        userCreateModel.setUsername(".aa");
        bindingResult = validateAndGetResult(userCreateModel);
        assertFieldError("username",
                "The name cannot start or end with '.'.",
                ".aa",
                bindingResult.getFieldError("username"));

        userCreateModel.setUsername("aa.");
        bindingResult = validateAndGetResult(userCreateModel);
        assertFieldError("username",
                "The name cannot start or end with '.'.",
                "aa.",
                bindingResult.getFieldError("username"));

        userCreateModel.setUsername("jsmith");
        when(userManagementService.existsByName(anyString())).thenReturn(Boolean.TRUE);
        bindingResult = validateAndGetResult(userCreateModel);
        assertFieldError("username",
                "A user with such username already exists.",
                "jsmith",
                bindingResult.getFieldError("username"));

    }

    @ParameterizedTest
    @ValueSource(strings = {
            " aa", "aa ", "a/", "a\\", "a:", "a*", "a?", "a\"", "a<", "a|", "a{", "a~", "a^", "a%", "a;", "a\u2028",
            "a\u2029", "a\t", "a\r", "a\n"})
    void testCreateUser_username_forbiddenCharacters(String username) {
        when(userManagementService.getUser(anyString())).thenReturn(null);
        var userCreateModel = getValidUserCreateModel();
        userCreateModel.setUsername(username);
        var bindingResult = validateAndGetResult(userCreateModel);
        assertFieldError("username", MUST_NOT_CONTAIN_FOLLOWING_CHARS, username,
                bindingResult.getFieldError("username"));
    }

    @Test
    void testEditUserProfile_valid() {
        var userProfileEditModel = getValidUserProfileEditModel();
        when(currentUserInfo.getUserName()).thenReturn("jsmith");
        // V7: generated current password and hash
        when(passwordEncoder.matches(currentPassword, currentPasswordHash)).thenReturn(true);
        var existedUser = new SimpleUser();
        existedUser.setPassword(currentPasswordHash);
        when(userManagementService.getUser(anyString())).thenReturn(existedUser);

        assertValid(userProfileEditModel);

        userProfileEditModel.setChangePassword(new ChangePasswordModel());
        assertValid(userProfileEditModel);
    }

    @Test
    void testEditUserProfile_password_notValid() {
        // V7: generated credentials; empty current, mismatch and wrong current password are reported in that order
        when(passwordEncoder.matches(currentPassword, currentPasswordHash)).thenReturn(true);
        when(currentUserInfo.getUserName()).thenReturn("jsmith");
        var existedUser = new SimpleUser();
        existedUser.setPassword(currentPasswordHash);
        var userProfileEditModel = getValidUserProfileEditModel();

        var changePasswordModel = new ChangePasswordModel().setNewPassword(newPassword);
        userProfileEditModel.setChangePassword(changePasswordModel);
        when(userManagementService.getUser(anyString())).thenReturn(existedUser);
        var bindingResult = validateAndGetResult(userProfileEditModel);
        assertFieldError("changePassword",
                "Enter your password.",
                changePasswordModel,
                bindingResult.getFieldError("changePassword"));

        changePasswordModel = new ChangePasswordModel().setNewPassword(newPassword)
                .setCurrentPassword(currentPassword)
                .setConfirmPassword(otherPassword);
        userProfileEditModel.setChangePassword(changePasswordModel);
        bindingResult = validateAndGetResult(userProfileEditModel);
        assertFieldError("changePassword",
                "The new password and confirmed password do not match.",
                changePasswordModel,
                bindingResult.getFieldError("changePassword"));

        when(passwordEncoder.matches(currentPassword, currentPasswordHash)).thenReturn(true);
        when(passwordEncoder.matches(otherPassword, otherPasswordHash)).thenReturn(true);
        changePasswordModel = new ChangePasswordModel().setNewPassword(newPassword)
                .setCurrentPassword(otherPassword)
                .setConfirmPassword(newPassword);
        userProfileEditModel.setChangePassword(changePasswordModel);
        bindingResult = validateAndGetResult(userProfileEditModel);
        assertFieldError("changePassword",
                "Incorrect current password.",
                changePasswordModel,
                bindingResult.getFieldError("changePassword"));
    }

    // V7: profile change route, boundary cases of LocalPasswordPolicy
    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("passwordPolicyCases")
    void testEditUserProfile_password_policy(String label, String candidate, String expectedMessage) {
        when(currentUserInfo.getUserName()).thenReturn("jsmith");
        var existedUser = new SimpleUser();
        existedUser.setPassword(currentPasswordHash);
        when(userManagementService.getUser(anyString())).thenReturn(existedUser);
        when(passwordEncoder.matches(currentPassword, currentPasswordHash)).thenReturn(true);
        var changePasswordModel = new ChangePasswordModel().setNewPassword(candidate)
                .setConfirmPassword(candidate)
                .setCurrentPassword(currentPassword);
        var model = getValidUserProfileEditModel().setChangePassword(changePasswordModel);
        assertPasswordPolicy(label, model, "changePassword", expectedMessage, changePasswordModel);
    }

    // V7: the policy applies only to a non-empty new password
    @Test
    void testEditUserProfile_emptyNewPassword_valid() {
        when(currentUserInfo.getUserName()).thenReturn("jsmith");
        var existedUser = new SimpleUser();
        existedUser.setPassword(currentPasswordHash);
        when(userManagementService.getUser(anyString())).thenReturn(existedUser);
        when(passwordEncoder.matches(currentPassword, currentPasswordHash)).thenReturn(true);
        var changePasswordModel = new ChangePasswordModel().setCurrentPassword(currentPassword)
                .setNewPassword("")
                .setConfirmPassword("");
        var model = getValidUserProfileEditModel().setChangePassword(changePasswordModel);
        assertValid(model);
    }

    // V7: guards the oversized-input shortcut, which rejects more than MAX_BYTES UTF-16 units without scanning them
    @Test
    void testPasswordPolicy_oversizedInput_rejectedWithoutScan() {
        // A generated 2 MB size fixture outside Latin-1, so counting its code points and encoding it are both linear
        var oversized = "\u20AC".repeat(1_000_000);

        var context = mock(HibernateConstraintValidatorContext.class);
        var builder = mock(HibernateConstraintViolationBuilder.class);
        stubViolationChain(context, builder);
        assertFalse(LocalPasswordPolicy.check(oversized, context));
        verify(context).unwrap(HibernateConstraintValidatorContext.class);
        verify(context).addMessageParameter("max", LocalPasswordPolicy.MAX_BYTES);
        verify(context).buildConstraintViolationWithTemplate("{" + LocalPasswordPolicy.MAX_BYTES_KEY + "}");
        verify(builder).addConstraintViolation();
        verifyNoMoreInteractions(context, builder);

        // Stub-only mocks record no invocations, so the loop measures the policy. Scanning and encoding the fixture
        // on every call takes tens of seconds; the shortcut takes well under 1 s.
        var stubContext = mock(HibernateConstraintValidatorContext.class, withSettings().stubOnly());
        stubViolationChain(stubContext, mock(HibernateConstraintViolationBuilder.class, withSettings().stubOnly()));
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
            for (int i = 0; i < 20_000; i++) {
                assertFalse(LocalPasswordPolicy.check(oversized, stubContext));
            }
        }, "an oversized password must be rejected without being scanned or encoded");
    }

    // V7: a password within both limits that holds unpaired surrogates gets exactly one violation, the invalid one
    @Test
    void testPasswordPolicy_unpairedSurrogate_singleInvalidViolation() {
        var malformed = "\uDC00".repeat(LocalPasswordPolicy.MIN_CHARACTERS);

        var context = mock(HibernateConstraintValidatorContext.class);
        var builder = mock(HibernateConstraintViolationBuilder.class);
        stubViolationChain(context, builder);
        assertFalse(LocalPasswordPolicy.check(malformed, context));
        verify(context).buildConstraintViolationWithTemplate("{" + LocalPasswordPolicy.INVALID_KEY + "}");
        verify(builder).addConstraintViolation();
        verifyNoMoreInteractions(context, builder);
    }

    @Test
    void testEditUserProfile_requiredFields() {
        var userProfileEditModel = getValidUserProfileEditModel()
                .setChangePassword(new ChangePasswordModel());

        userProfileEditModel.setEmail("");
        var bindingResult = validateAndGetResult(userProfileEditModel);
        assertFieldError("email", CANNOT_BE_EMPTY, "", bindingResult.getFieldError("email"));

        userProfileEditModel.setEmail("jsmith@email").setDisplayName(" ");
        bindingResult = validateAndGetResult(userProfileEditModel);
        assertFieldError("displayName", CANNOT_BE_EMPTY, " ", bindingResult.getFieldError("displayName"));
    }

    private UserCreateModel getValidUserCreateModel() {
        var groups = new HashSet<String>();
        groups.add("Administrators");
        return new UserCreateModel().setDisplayName("John Smith")
                .setFirstName("John")
                .setEmail("jsmith@email")
                .setLastName("Smith")
                // V7: a generated policy-compliant password
                .setInternalPassword(new InternalPasswordModel().setPassword(newPassword))
                .setGroups(groups)
                .setUsername("jsmith");
    }

    private UserEditModel getValidUserEditModel() {
        var groups = new HashSet<String>();
        groups.add("Administrators");
        return new UserEditModel().setDisplayName("John Smith")
                .setFirstName("John")
                .setEmail("jsmith@email")
                .setLastName("Smith")
                // V7: a generated policy-compliant password
                .setPassword(newPassword)
                .setGroups(groups);
    }

    private UserInfoModel getValidUserInfoModel() {
        return new UserInfoModel().setDisplayName("John Smith")
                .setFirstName("John")
                .setEmail("jsmith@email")
                .setLastName("Smith");
    }

    private UserInfoEditModel getValidUserInfoEditModel() {
        return new UserInfoEditModel().setDisplayName("John Smith")
                .setFirstName("John")
                .setEmail("jsmith@email")
                .setLastName("Smith");
    }

    private UserProfileEditModel getValidUserProfileEditModel() {
        // V7: generated policy-compliant passwords
        return new UserProfileEditModel().setChangePassword(
                        new ChangePasswordModel().setConfirmPassword(newPassword)
                                .setNewPassword(newPassword)
                                .setCurrentPassword(currentPassword))
                .setShowComplexResult(true)
                .setShowFormulas(true)
                .setShowRealNumbers(true)
                .setTestsFailuresOnly(true)
                .setTestsFailuresPerTest(20)
                .setTestsPerPage(20)
                .setShowHeader(true)
                .setDisplayName("John Smith")
                .setFirstName("John")
                .setEmail("jsmith@email")
                .setLastName("Smith");
    }

    // V7: asserts a password-bearing model is valid; a failure names only fields and codes, never a submitted value
    private void assertValid(Object model) {
        var bindingResult = validateAndGetResult(model);
        assertTrue(bindingResult == null,
                () -> "unexpected violations on " + Stream.concat(
                        bindingResult.getFieldErrors().stream().map(e -> e.getField() + "/" + e.getCode()),
                        bindingResult.getGlobalErrors().stream().map(e -> e.getObjectName() + "/" + e.getCode()))
                        .toList());
    }

    private void assertOptionalNamesValid(UserInfoModel userInfoModel) {
        userInfoModel.setFirstName("").setLastName(" ");
        assertValid(userInfoModel);
    }

    // V7: boundary cases of LocalPasswordPolicy (12 code points min, 72 UTF-8 bytes max)
    static Stream<Arguments> passwordPolicyCases() {
        var euro = "\u20AC"; // 3 UTF-8 bytes, 1 UTF-16 unit
        var emoji = Character.toString(0x1F600); // 4 UTF-8 bytes, 2 UTF-16 units
        var highSurrogate = "\uD83D"; // V7: the high half of U+1F600, unpaired where it is used alone
        var lowSurrogate = "\uDE00"; // V7: the low half of U+1F600, unpaired where it is used alone
        return Stream.of(
                Arguments.of("11 code points", RandomStringUtils.secure().nextAlphanumeric(11), PASSWORD_MIN_LENGTH),
                Arguments.of("12 code points", RandomStringUtils.secure().nextAlphanumeric(12), null),
                Arguments.of("72 ASCII bytes", RandomStringUtils.secure().nextAlphanumeric(72), null),
                Arguments.of("73 ASCII bytes", RandomStringUtils.secure().nextAlphanumeric(73), PASSWORD_MAX_BYTES),
                Arguments.of("24 x U+20AC (72 bytes)", euro.repeat(24), null),
                Arguments.of("24 x U+20AC + a (73 bytes)", euro.repeat(24) + "a", PASSWORD_MAX_BYTES),
                Arguments.of("18 x U+1F600 (72 bytes, 36 UTF-16 units)", emoji.repeat(18), null),
                Arguments.of("11 x U+1F600 (11 code points, 44 bytes)", emoji.repeat(11), PASSWORD_MIN_LENGTH),
                // V7: oversized input is rejected before any scan, and the bytes counted are the ones bcrypt receives
                Arguments.of("100000 ASCII characters", RandomStringUtils.secure().nextAlphanumeric(100_000),
                        PASSWORD_MAX_BYTES),
                Arguments.of("36 x U+1F600 (72 UTF-16 units, 144 bytes)", emoji.repeat(36), PASSWORD_MAX_BYTES),
                Arguments.of("12 x U+1F600 (12 code points, 48 bytes)", emoji.repeat(12), null),
                // V7: an unpaired surrogate makes a password invalid, since UTF-8 would hash it as '?'
                Arguments.of("11 ASCII + U+1F600 (well-formed pair, 12 code points)",
                        RandomStringUtils.secure().nextAlphanumeric(11) + emoji, null),
                Arguments.of("71 ASCII + lone high surrogate (72 UTF-16 units)",
                        RandomStringUtils.secure().nextAlphanumeric(71) + "\uD800", PASSWORD_INVALID),
                Arguments.of("12 lone high surrogates", "\uD800".repeat(12), PASSWORD_INVALID),
                Arguments.of("lone low surrogate inside 16 ASCII",
                        RandomStringUtils.secure().nextAlphanumeric(8) + lowSurrogate
                                + RandomStringUtils.secure().nextAlphanumeric(8),
                        PASSWORD_INVALID),
                Arguments.of("reversed pair (low, then high) after 12 ASCII",
                        RandomStringUtils.secure().nextAlphanumeric(12) + lowSurrogate + highSurrogate,
                        PASSWORD_INVALID),
                Arguments.of("trailing high surrogate after 12 ASCII",
                        RandomStringUtils.secure().nextAlphanumeric(12) + highSurrogate, PASSWORD_INVALID),
                // V7: the length violations take precedence over the malformed one; a lone surrogate counts as one
                // code point and, encoded as '?', as one byte
                Arguments.of("5 ASCII + lone low surrogate (too short before malformed)",
                        RandomStringUtils.secure().nextAlphanumeric(5) + lowSurrogate, PASSWORD_MIN_LENGTH),
                Arguments.of("24 x U+20AC + lone high surrogate (73 bytes)", euro.repeat(24) + highSurrogate,
                        PASSWORD_MAX_BYTES),
                Arguments.of("11 ASCII + lone surrogate (12 code points)",
                        RandomStringUtils.secure().nextAlphanumeric(11) + lowSurrogate, PASSWORD_INVALID),
                Arguments.of("73 lone high surrogates (oversized before malformed)", "\uD800".repeat(73),
                        PASSWORD_MAX_BYTES));
    }

    // V7: asserts the policy outcome without putting the submitted password into any failure message
    private void assertPasswordPolicy(String label,
                                      Object model,
                                      String field,
                                      String expectedMessage,
                                      Object expectedRejectedValue) {
        var bindingResult = validateAndGetResult(model);
        if (expectedMessage == null) {
            assertTrue(bindingResult == null,
                    () -> label + ": unexpected violations on " + bindingResult.getFieldErrors()
                            .stream()
                            .map(e -> e.getField() + "/" + e.getCode())
                            .toList());
            return;
        }
        assertNotNull(bindingResult, label + ": expected a violation");
        var fieldError = bindingResult.getFieldError(field);
        assertNotNull(fieldError, label + ": no error on " + field);
        assertTrue(Objects.equals(expectedRejectedValue, fieldError.getRejectedValue()),
                label + ": rejected value is not the submitted one");
        assertFieldError(field, expectedMessage, expectedRejectedValue, fieldError);
    }

    // V7: the Hibernate violation chain LocalPasswordPolicy calls, each step returning the next
    private static void stubViolationChain(HibernateConstraintValidatorContext context,
                                           HibernateConstraintViolationBuilder builder) {
        when(context.unwrap(HibernateConstraintValidatorContext.class)).thenReturn(context);
        when(context.addMessageParameter(anyString(), any())).thenReturn(context);
        when(context.buildConstraintViolationWithTemplate(anyString())).thenReturn(builder);
        when(builder.addConstraintViolation()).thenReturn(context);
    }
}

package org.openl.rules.rest.validation;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.Objects;
import java.util.stream.Stream;

import org.apache.commons.lang3.RandomStringUtils;
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
    private static final String MUST_NOT_CONTAIN_FOLLOWING_CHARS = "The name cannot contain spaces and any of the following characters: / \\ : * ? \" < > | { } ~ ^ ; %";

    @Autowired
    private UserManagementService userManagementService;

    @Autowired
    private CurrentUserInfo currentUserInfo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // V7: credentials generated per test instance (AAP 0.8.3); no literal password in this class
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

        assertNull(validateAndGetResult(userEditModel));

        userEditModel.setPassword(null);
        assertNull(validateAndGetResult(userEditModel));

        // V7: blank password on edit means "unchanged" and stays valid
        userEditModel.setPassword("");
        assertNull(validateAndGetResult(userEditModel));
        userEditModel.setPassword(" ");
        assertNull(validateAndGetResult(userEditModel));
    }

    @Test
    void testEditUser_password_notValid() {
        var userEditModel = getValidUserEditModel();
        String wrongPassword = RandomStringUtils.random(26, "pass");
        userEditModel.setPassword(wrongPassword);
        var bindingResult = validateAndGetResult(userEditModel);
        assertFieldError("password", MUST_BE_LESS_THAN_25, wrongPassword, bindingResult.getFieldError("password"));
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

        assertNull(validateAndGetResult(getValidUserCreateModel()));

        // V7: a generated policy-compliant password instead of a literal
        userCreateModel.setInternalPassword(new InternalPasswordModel().setPassword(otherPassword));
        assertNull(validateAndGetResult(userCreateModel));

        userCreateModel.setUsername("a1!@#$&()_-+='.,");
        assertNull(validateAndGetResult(userCreateModel));

        userCreateModel.setUsername("фы漢語,汉语ęął");
        assertNull(validateAndGetResult(userCreateModel));

        userCreateModel.setUsername("a");
        assertNull(validateAndGetResult(userCreateModel));
    }

    @Test
    void testCreateUser_noGroups_valid() {
        var userCreateModel = getValidUserCreateModel();
        userCreateModel.setGroups(null);
        assertNull(validateAndGetResult(userCreateModel));
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
        // V7: the 25-character maximum is replaced by the policy cases of testCreateUser_password_policy
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
        // V7: generated current password and hash instead of literals
        when(passwordEncoder.matches(currentPassword, currentPasswordHash)).thenReturn(true);
        var existedUser = new SimpleUser();
        existedUser.setPassword(currentPasswordHash);
        when(userManagementService.getUser(anyString())).thenReturn(existedUser);

        assertNull(validateAndGetResult(userProfileEditModel));

        userProfileEditModel.setChangePassword(new ChangePasswordModel());
        assertNull(validateAndGetResult(userProfileEditModel));
    }

    @Test
    void testEditUserProfile_password_notValid() {
        // V7: generated credentials instead of literals; the three steps and their messages are unchanged
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
        assertNull(validateAndGetResult(model));
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
                // V7: a generated policy-compliant password instead of a literal
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
                // V7: a generated password instead of a literal
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
        // V7: generated policy-compliant passwords instead of literals
        return new UserProfileEditModel().setChangePassword(
                        new ChangePasswordModel().setConfirmPassword(newPassword).setNewPassword(newPassword).setCurrentPassword(currentPassword))
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

    private void assertOptionalNamesValid(UserInfoModel userInfoModel) {
        userInfoModel.setFirstName("").setLastName(" ");
        assertNull(validateAndGetResult(userInfoModel));
    }

    // V7: boundary cases of LocalPasswordPolicy (12 code points min, 72 UTF-8 bytes max)
    static Stream<Arguments> passwordPolicyCases() {
        var euro = "\u20AC"; // 3 UTF-8 bytes, 1 UTF-16 unit
        var emoji = Character.toString(0x1F600); // 4 UTF-8 bytes, 2 UTF-16 units
        return Stream.of(
                Arguments.of("11 code points", RandomStringUtils.secure().nextAlphanumeric(11), PASSWORD_MIN_LENGTH),
                Arguments.of("12 code points", RandomStringUtils.secure().nextAlphanumeric(12), null),
                Arguments.of("72 ASCII bytes", RandomStringUtils.secure().nextAlphanumeric(72), null),
                Arguments.of("73 ASCII bytes", RandomStringUtils.secure().nextAlphanumeric(73), PASSWORD_MAX_BYTES),
                Arguments.of("24 x U+20AC (72 bytes)", euro.repeat(24), null),
                Arguments.of("24 x U+20AC + a (73 bytes)", euro.repeat(24) + "a", PASSWORD_MAX_BYTES),
                Arguments.of("18 x U+1F600 (72 bytes, 36 UTF-16 units)", emoji.repeat(18), null),
                Arguments.of("11 x U+1F600 (11 code points, 44 bytes)", emoji.repeat(11), PASSWORD_MIN_LENGTH));
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
}

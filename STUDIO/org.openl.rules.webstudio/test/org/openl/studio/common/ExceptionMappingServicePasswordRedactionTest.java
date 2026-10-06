package org.openl.studio.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.util.List;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.validation.BeanPropertyBindingResult;

import org.openl.rules.rest.model.ChangePasswordModel;
import org.openl.rules.rest.model.InternalPasswordModel;
import org.openl.rules.rest.model.UserCreateModel;
import org.openl.rules.rest.model.UserEditModel;
import org.openl.rules.rest.model.UserInfoModel;
import org.openl.rules.rest.model.UserProfileEditModel;
import org.openl.rules.rest.validation.LocalPasswordConstraint;
import org.openl.rules.rest.validation.MockConfiguration;
import org.openl.rules.security.SimpleUser;
import org.openl.rules.webstudio.service.UserManagementService;
import org.openl.studio.common.exception.ValidationException;
import org.openl.studio.common.model.FieldError;
import org.openl.studio.common.model.ValidationError;
import org.openl.studio.common.validation.BeanValidationProvider;
import org.openl.studio.security.CurrentUserInfo;

/**
 * V7: a rejected password, or a model carrying one, never reaches the serialized 400 body, while the field and message
 * of the error stay as they are. A local password policy violation carries its message key as its code, and every
 * other error keeps its code. Every password is generated per run, and no assertion message carries a password or a
 * serialized body.
 */
@SpringJUnitConfig(classes = MockConfiguration.class)
class ExceptionMappingServicePasswordRedactionTest {

    private static final String PASSWORD_MIN_LENGTH = "The password must contain at least 12 characters.";
    private static final String PASSWORD_MAX_BYTES = "The password must not exceed 72 bytes in UTF-8.";
    /** A local password policy violation carries its message key, as is, as the field error code. */
    private static final String PASSWORD_MIN_LENGTH_CODE = "openl.constraints.password.min-length.message";
    private static final String PASSWORD_MAX_BYTES_CODE = "openl.constraints.password.max-bytes.message";
    private static final String INVALID_EMAIL = "wrongEmail";

    /** Serializes as plain Jackson does, so a redacted value shows as {@code "rejectedValue":null}. */
    private static final ObjectMapper PLAIN_MAPPER = new ObjectMapper();

    /** Serializes with the default inclusion of the production REST mapper, so a redacted value is omitted. */
    private static final ObjectMapper PRODUCTION_INCLUSION_MAPPER = new ObjectMapper()
            .setDefaultPropertyInclusion(JsonInclude.Include.NON_EMPTY);

    @Autowired
    private BeanValidationProvider validationProvider;

    @Autowired
    @Qualifier("localValidatorFactoryBean")
    private Validator validator;

    @Autowired
    @Qualifier("validationMessageSource")
    private MessageSource validationMessageSource;

    @Autowired
    private UserManagementService userManagementService;

    @Autowired
    private CurrentUserInfo currentUserInfo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private final String currentPassword = RandomStringUtils.secure().nextAlphanumeric(16);
    private final String currentPasswordHash = RandomStringUtils.secure().nextAlphanumeric(16);

    private ExceptionMappingService exceptionMappingService;

    @BeforeEach
    void setUp() {
        exceptionMappingService = new ExceptionMappingService(validationMessageSource);
    }

    @AfterEach
    void resetMocks() {
        reset(userManagementService, passwordEncoder, currentUserInfo);
    }

    @Test
    void create_tooShortPassword_isNotEchoed() throws Exception {
        when(userManagementService.getUser(anyString())).thenReturn(null);
        var password = RandomStringUtils.secure().nextAlphanumeric(11);
        var model = validUserCreateModel().setInternalPassword(new InternalPasswordModel().setPassword(password));

        var fieldError = mapAndAssertRedacted(validateWithProvider(model), "internalPassword", List.of(password));

        assertEquals(PASSWORD_MIN_LENGTH_CODE, fieldError.code);
        assertEquals(PASSWORD_MIN_LENGTH, fieldError.message);
    }

    @Test
    void create_tooLongPassword_isNotEchoed() throws Exception {
        when(userManagementService.getUser(anyString())).thenReturn(null);
        var password = RandomStringUtils.secure().nextAlphanumeric(80);
        var model = validUserCreateModel().setInternalPassword(new InternalPasswordModel().setPassword(password));

        var fieldError = mapAndAssertRedacted(validateWithProvider(model), "internalPassword", List.of(password));

        assertEquals(PASSWORD_MAX_BYTES_CODE, fieldError.code);
        assertEquals(PASSWORD_MAX_BYTES, fieldError.message);
    }

    @Test
    void adminEdit_rejectedPassword_isNotEchoed() throws Exception {
        var password = RandomStringUtils.secure().nextAlphanumeric(80);
        var model = validUserEditModel().setPassword(password);

        var fieldError = mapAndAssertRedacted(validateWithProvider(model), "password", List.of(password));

        assertEquals(PASSWORD_MAX_BYTES_CODE, fieldError.code);
        assertEquals(PASSWORD_MAX_BYTES, fieldError.message);
    }

    @Test
    void profileChange_tooShortNewPassword_isNotEchoed() throws Exception {
        mockCurrentUser();
        when(passwordEncoder.matches(currentPassword, currentPasswordHash)).thenReturn(true);
        var newPassword = RandomStringUtils.secure().nextAlphanumeric(11);
        var model = validUserProfileEditModel(new ChangePasswordModel().setCurrentPassword(currentPassword)
                .setNewPassword(newPassword)
                .setConfirmPassword(newPassword));

        var fieldError = mapAndAssertRedacted(validateWithProvider(model),
                "changePassword",
                List.of(currentPassword, newPassword));

        assertEquals(PASSWORD_MIN_LENGTH_CODE, fieldError.code);
        assertEquals(PASSWORD_MIN_LENGTH, fieldError.message);
    }

    @Test
    void profileChange_emptyCurrentPassword_isNotEchoed() throws Exception {
        mockCurrentUser();
        var newPassword = RandomStringUtils.secure().nextAlphanumeric(16);
        var model = validUserProfileEditModel(new ChangePasswordModel().setNewPassword(newPassword)
                .setConfirmPassword(newPassword));

        var fieldError = mapAndAssertRedacted(validateWithProvider(model), "changePassword", List.of(newPassword));

        assertEquals("openl.error.ChangePasswordConstraint", fieldError.code);
        assertEquals("Enter your password.", fieldError.message);
    }

    @Test
    void profileChange_notMatchingPasswords_areNotEchoed() throws Exception {
        mockCurrentUser();
        when(passwordEncoder.matches(currentPassword, currentPasswordHash)).thenReturn(true);
        var newPassword = RandomStringUtils.secure().nextAlphanumeric(16);
        var confirmPassword = RandomStringUtils.secure().nextAlphanumeric(16);
        var model = validUserProfileEditModel(new ChangePasswordModel().setCurrentPassword(currentPassword)
                .setNewPassword(newPassword)
                .setConfirmPassword(confirmPassword));

        var fieldError = mapAndAssertRedacted(validateWithProvider(model),
                "changePassword",
                List.of(currentPassword, newPassword, confirmPassword));

        assertEquals("openl.error.ChangePasswordConstraint", fieldError.code);
        assertEquals("The new password and confirmed password do not match.", fieldError.message);
    }

    @Test
    void profileChange_wrongCurrentPassword_isNotEchoed() throws Exception {
        mockCurrentUser();
        var wrongCurrentPassword = RandomStringUtils.secure().nextAlphanumeric(16);
        var newPassword = RandomStringUtils.secure().nextAlphanumeric(16);
        var model = validUserProfileEditModel(new ChangePasswordModel().setCurrentPassword(wrongCurrentPassword)
                .setNewPassword(newPassword)
                .setConfirmPassword(newPassword));

        var fieldError = mapAndAssertRedacted(validateWithProvider(model),
                "changePassword",
                List.of(wrongCurrentPassword, newPassword));

        assertEquals("openl.error.ChangePasswordConstraint", fieldError.code);
        assertEquals("Incorrect current password.", fieldError.message);
    }

    @Test
    void localPasswordConstraint_bindingResult_isNotEchoed() throws Exception {
        var password = RandomStringUtils.secure().nextAlphanumeric(11);

        var fieldError = mapAndAssertRedacted(validateWithProvider(new LocalPasswordBean(password)),
                "password",
                List.of(password));

        assertEquals(PASSWORD_MIN_LENGTH_CODE, fieldError.code);
        assertEquals(PASSWORD_MIN_LENGTH, fieldError.message);
    }

    @Test
    void localPasswordConstraint_constraintViolations_isNotEchoed() throws Exception {
        var password = RandomStringUtils.secure().nextAlphanumeric(80);

        var fieldError = mapAndAssertRedacted(validateWithValidator(new LocalPasswordBean(password)),
                "password",
                List.of(password));

        assertEquals(PASSWORD_MAX_BYTES_CODE, fieldError.code);
        assertEquals(PASSWORD_MAX_BYTES, fieldError.message);
    }

    @Test
    void localPasswordConstraint_constraintViolations_tooShort_isNotEchoed() throws Exception {
        var password = RandomStringUtils.secure().nextAlphanumeric(11);

        var fieldError = mapAndAssertRedacted(validateWithValidator(new LocalPasswordBean(password)),
                "password",
                List.of(password));

        assertEquals(PASSWORD_MIN_LENGTH_CODE, fieldError.code);
        assertEquals(PASSWORD_MIN_LENGTH, fieldError.message);
    }

    @Test
    void nonPasswordField_bindingResult_keepsRejectedValue() throws Exception {
        var model = validUserEditModel().setPassword(null).setEmail(INVALID_EMAIL);

        var fieldError = assertRejectedValueKept(validateWithProvider(model), "email", INVALID_EMAIL);

        assertEquals("openl.error.Email", fieldError.code);
    }

    @Test
    void nonPasswordField_constraintViolations_keepsRejectedValue() throws Exception {
        var model = new UserInfoModel().setDisplayName("John Smith").setEmail(INVALID_EMAIL);

        var fieldError = assertRejectedValueKept(validateWithValidator(model), "email", INVALID_EMAIL);

        assertEquals("openl.error.{openl.constraints.user.email.format.message}", fieldError.code);
    }

    @Test
    void fieldErrorWithoutConstraintViolation_keepsItsCode() throws Exception {
        var bindingResult = new BeanPropertyBindingResult(new UserInfoModel().setEmail(INVALID_EMAIL), "user");
        bindingResult.rejectValue("email", "custom.email", "Custom message.");

        var fieldError = assertRejectedValueKept(new ValidationException(bindingResult), "email", INVALID_EMAIL);

        assertEquals("openl.error.custom.email", fieldError.code);
        assertEquals("Custom message.", fieldError.message);
    }

    /**
     * Maps the exception, then checks that no secret appears in either serialization and that the field carries no
     * rejected value. Secrets are checked first and only through boolean assertions with fixed messages.
     */
    private FieldError mapAndAssertRedacted(Exception ex,
                                            String field,
                                            List<String> secrets) throws JsonProcessingException {
        var error = assertInstanceOf(ValidationError.class, exceptionMappingService.processException(ex));
        var plainJson = PLAIN_MAPPER.writeValueAsString(error);
        var productionJson = PRODUCTION_INCLUSION_MAPPER.writeValueAsString(error);
        for (var secret : secrets) {
            assertFalse(plainJson.contains(secret), "a password is present in the plain serialization");
            assertFalse(productionJson.contains(secret), "a password is present in the production serialization");
        }

        var fieldError = findField(error, field);
        assertTrue(fieldError.getRejectedValue() == null, "the password field still carries a rejected value");

        var plainNode = findFieldNode(PLAIN_MAPPER.readTree(plainJson), field);
        assertTrue(plainNode.has("rejectedValue") && plainNode.get("rejectedValue").isNull(),
                "the plain serialization does not show a null rejected value");
        var productionNode = findFieldNode(PRODUCTION_INCLUSION_MAPPER.readTree(productionJson), field);
        assertFalse(productionNode.has("rejectedValue"),
                "the production serialization still has a rejected value key");
        assertEquals(field, productionNode.get("field").asText());
        return fieldError;
    }

    private FieldError assertRejectedValueKept(Exception ex,
                                               String field,
                                               String expectedRejectedValue) throws JsonProcessingException {
        var error = assertInstanceOf(ValidationError.class, exceptionMappingService.processException(ex));
        var fieldError = findField(error, field);
        assertEquals(expectedRejectedValue, fieldError.getRejectedValue());
        for (var mapper : List.of(PLAIN_MAPPER, PRODUCTION_INCLUSION_MAPPER)) {
            var node = findFieldNode(mapper.readTree(mapper.writeValueAsString(error)), field);
            assertEquals(expectedRejectedValue, node.path("rejectedValue").asText(null));
        }
        return fieldError;
    }

    private static FieldError findField(ValidationError error, String field) {
        assertEquals(1, error.getFields().size(), "exactly one field error is expected");
        var fieldError = error.getFields().getFirst();
        assertEquals(field, fieldError.getField());
        return fieldError;
    }

    private static JsonNode findFieldNode(JsonNode root, String field) {
        var fields = root.path("fields");
        assertTrue(fields.isArray() && fields.size() == 1, "exactly one serialized field error is expected");
        var node = fields.get(0);
        assertEquals(field, node.path("field").asText(null));
        return node;
    }

    private ValidationException validateWithProvider(Object bean) {
        try {
            validationProvider.validate(bean);
        } catch (ValidationException e) {
            return e;
        }
        throw new AssertionError("a validation error is expected");
    }

    private ConstraintViolationException validateWithValidator(Object bean) {
        var violations = validator.validate(bean);
        assertFalse(violations.isEmpty(), "a constraint violation is expected");
        return new ConstraintViolationException(violations);
    }

    private void mockCurrentUser() {
        when(currentUserInfo.getUserName()).thenReturn("jsmith");
        var existingUser = new SimpleUser();
        existingUser.setPassword(currentPasswordHash);
        when(userManagementService.getUser(anyString())).thenReturn(existingUser);
    }

    private static UserCreateModel validUserCreateModel() {
        return new UserCreateModel().setDisplayName("John Smith")
                .setFirstName("John")
                .setLastName("Smith")
                .setEmail("jsmith@email")
                .setUsername("jsmith");
    }

    private static UserEditModel validUserEditModel() {
        return new UserEditModel().setDisplayName("John Smith")
                .setFirstName("John")
                .setLastName("Smith")
                .setEmail("jsmith@email");
    }

    private static UserProfileEditModel validUserProfileEditModel(ChangePasswordModel changePassword) {
        return new UserProfileEditModel().setChangePassword(changePassword)
                .setDisplayName("John Smith")
                .setFirstName("John")
                .setLastName("Smith")
                .setEmail("jsmith@email");
    }

    /** A bean whose only constraint is the optional local password, as on the admin user edit form. */
    private static final class LocalPasswordBean {

        @LocalPasswordConstraint
        private final String password;

        private LocalPasswordBean(String password) {
            this.password = password;
        }

        public String getPassword() {
            return password;
        }
    }
}

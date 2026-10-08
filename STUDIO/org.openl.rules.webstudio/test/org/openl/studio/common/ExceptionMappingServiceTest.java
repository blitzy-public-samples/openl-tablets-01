package org.openl.studio.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Path;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.TypeMismatchException;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.core.MethodParameter;
import org.springframework.core.convert.ConversionFailedException;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
import org.springframework.validation.MapBindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import org.openl.studio.common.exception.AmbiguityException;
import org.openl.studio.common.exception.ConflictException;
import org.openl.studio.common.exception.NotFoundException;
import org.openl.studio.common.exception.ValidationException;
import org.openl.studio.common.model.AmbiguityError;
import org.openl.studio.common.model.BaseError;
import org.openl.studio.common.model.FieldError;
import org.openl.studio.common.model.ValidationError;

/**
 * V7: the error mapping that keeps rejected passwords out of 400 bodies answers every kind of exception with its error
 * model. REST, conversion, security, type mismatch and plain exceptions get their code and their message or status
 * reason. Binding results and constraint violations get their field and global errors, each sorted
 * case-insensitively, with codes and messages resolved from the message source. No value here is a credential.
 */
class ExceptionMappingServiceTest {

    private static final String BAD_REQUEST = "Bad Request";
    private static final String OBJECT_NAME = "project";

    private final StaticMessageSource messageSource = new StaticMessageSource();
    private final ExceptionMappingService service = new ExceptionMappingService(messageSource);

    @BeforeEach
    void setUp() {
        messageSource.addMessage("openl.error.range.message", Locale.US, "The value {0} is out of range.");
        messageSource.addMessage("openl.error.version.format.message", Locale.US, "Use a version such as 1.0.0.");
        messageSource.addMessage("openl.error.404.project.missing.message", Locale.US, "Project {0} is not found.");
        messageSource.addMessage("openl.error.409.project.ambiguous.message",
                Locale.US,
                "The project name {0} is ambiguous.");
    }

    @Test
    void defaultErrorCode_isTheStatusValueUnderTheErrorPrefix() {
        assertEquals("openl.error.404.default.message", service.buildDefaultErrorCode(HttpStatus.NOT_FOUND));
    }

    @Test
    void restException_withAKnownCode_getsItsMessageWithItsArguments() {
        var error = service.processException(new NotFoundException("project.missing.message", "Example"));

        assertSame(BaseError.class, error.getClass());
        assertEquals("openl.error.404.project.missing.message", error.code);
        assertEquals("Project Example is not found.", error.message);
    }

    @Test
    void restException_withAnUnknownCode_getsTheCodeAsItsMessage() {
        var error = service.processException(new ConflictException("lock.taken.message"));

        assertSame(BaseError.class, error.getClass());
        assertEquals("openl.error.409.lock.taken.message", error.code);
        assertEquals("openl.error.409.lock.taken.message", error.message);
    }

    @Test
    void restException_withoutACode_getsItsOwnMessage() {
        // A spy, because a subclass cannot override the non-null getErrorCode() with a nullable one
        var exception = spy(new ConflictException("lock.taken.message"));
        doReturn(null).when(exception).getErrorCode();
        doReturn("The project is locked.").when(exception).getMessage();

        var error = service.processException(exception);

        assertSame(BaseError.class, error.getClass());
        assertNull(error.code);
        assertEquals("The project is locked.", error.message);
    }

    @Test
    void ambiguityException_listsItsCandidatesBesideItsMessage() {
        var candidates = List.of("first", "second");

        var error = assertInstanceOf(AmbiguityError.class,
                service.processException(new AmbiguityException("project.ambiguous.message", candidates, "Example")));

        assertEquals("openl.error.409.project.ambiguous.message", error.code);
        assertEquals("The project name Example is ambiguous.", error.message);
        assertEquals(candidates, error.getCandidates());
    }

    @Test
    void conversionFailure_causedByARestException_isMappedAsThatException() {
        var failure = conversionFailure(new NotFoundException("project.missing.message", "Example"));

        var error = service.processException(failure);

        assertSame(BaseError.class, error.getClass());
        assertEquals("openl.error.404.project.missing.message", error.code);
        assertEquals("Project Example is not found.", error.message);
    }

    @Test
    void conversionFailure_withAnotherCause_keepsItsOwnMessage() {
        var failure = conversionFailure(new IllegalArgumentException("Not a project identifier"));

        var error = service.processException(failure);

        assertSame(BaseError.class, error.getClass());
        assertNull(error.code);
        assertEquals(failure.getMessage(), error.message);
        assertTrue(error.message.contains("Example"), "the conversion failure message names the converted value");
    }

    @Test
    void securityExceptions_areForbidden() {
        assertMessage("Forbidden", new java.nio.file.AccessDeniedException(null));
        assertMessage("/rules/project", new java.nio.file.AccessDeniedException("/rules/project"));
        assertMessage("Forbidden", new org.springframework.security.access.AccessDeniedException(" "));
        assertMessage("Access is denied",
                new org.springframework.security.access.AccessDeniedException("Access is denied"));
        assertMessage("Forbidden", new SecurityException());
        assertMessage("The sandbox denied the call", new SecurityException("The sandbox denied the call"));
    }

    @Test
    void plainException_keepsItsMessage_orGetsTheInternalServerErrorReason() {
        assertMessage("The disk is full", new IllegalStateException("The disk is full"));
        assertMessage("Internal Server Error", new IllegalStateException());
        assertMessage("Internal Server Error", new IllegalStateException(" "));
    }

    @Test
    void exceptionWithAResponseStatus_getsTheReasonOfThatStatus() {
        assertMessage("Service Unavailable", new UnavailableException());
    }

    @Test
    void methodArgumentTypeMismatch_namesTheParameter() throws NoSuchMethodException {
        var parameter = new MethodParameter(Integer.class.getMethod("parseInt", String.class), 0);
        var exception = new MethodArgumentTypeMismatchException("many",
                Integer.class,
                "count",
                parameter,
                new NumberFormatException("For input string: \"many\""));

        var error = assertInstanceOf(ValidationError.class, service.processException(exception));

        assertNull(error.code);
        assertEquals(BAD_REQUEST, error.message);
        assertTrue(error.getErrors().isEmpty(), "a type mismatch has no global error");
        assertEquals(1, error.getFields().size());
        assertField(error.getFields().getFirst(), "count", null, exception.getLocalizedMessage(), "many");
    }

    @Test
    void typeMismatch_namesTheProperty_orNoField() {
        var named = new TypeMismatchException("many", Integer.class);
        named.initPropertyName("count");
        var unnamed = new TypeMismatchException("many", Integer.class);

        var namedError = assertInstanceOf(ValidationError.class, service.processException(named));
        var unnamedError = assertInstanceOf(ValidationError.class, service.processException(unnamed));

        assertEquals(BAD_REQUEST, namedError.message);
        assertEquals(1, namedError.getFields().size());
        assertField(namedError.getFields().getFirst(), "count", null, named.getLocalizedMessage(), "many");
        assertEquals(1, unnamedError.getFields().size());
        assertField(unnamedError.getFields().getFirst(), null, null, unnamed.getLocalizedMessage(), "many");
    }

    @Test
    void methodArgumentNotValid_listsItsFieldErrorsSortedCaseInsensitively() throws NoSuchMethodException {
        var bindingResult = bindingResult();
        bindingResult.addError(fieldError("Version", "1.x", new String[]{"version.format.message"}, null));
        bindingResult.addError(fieldError("name", "", new String[]{"name.blank.message"}, null));
        var parameter = new MethodParameter(Integer.class.getMethod("parseInt", String.class), 0);

        var error = assertInstanceOf(ValidationError.class,
                service.processException(new MethodArgumentNotValidException(parameter, bindingResult)));

        assertNull(error.code);
        assertEquals(BAD_REQUEST, error.message);
        assertTrue(error.getErrors().isEmpty(), "no global error is reported");
        assertEquals(2, error.getFields().size());
        assertField(error.getFields().get(0),
                "name",
                "openl.error.name.blank.message",
                "openl.error.name.blank.message",
                "");
        assertField(error.getFields().get(1),
                "Version",
                "openl.error.version.format.message",
                "Use a version such as 1.0.0.",
                "1.x");
    }

    @Test
    void singleGlobalError_givesItsCodeAndTheMessageOfItsFirstKnownCode() {
        var bindingResult = bindingResult();
        bindingResult.addError(new ObjectError(OBJECT_NAME,
                new String[]{"range.project.message", "range.message"},
                new Object[]{7},
                "The value is out of range."));

        var error = assertInstanceOf(ValidationError.class, service.processException(validation(bindingResult)));

        assertEquals("openl.error.range.message", error.code);
        assertEquals("The value 7 is out of range.", error.message);
        assertTrue(error.getFields().isEmpty(), "no field error is reported");
        assertTrue(error.getErrors().isEmpty(), "the only global error is the error itself");
    }

    @Test
    void singleGlobalError_skipsAMissingCode() {
        var bindingResult = bindingResult();
        bindingResult.addError(new ObjectError(OBJECT_NAME,
                new String[]{null, "range.message"},
                new Object[]{3},
                null));

        var error = assertInstanceOf(ValidationError.class, service.processException(validation(bindingResult)));

        assertEquals("openl.error.range.message", error.code);
        assertEquals("The value 3 is out of range.", error.message);
    }

    @Test
    void singleGlobalError_withoutAKnownCodeOrDefaultMessage_getsItsFirstCodeAsItsMessage() {
        for (var defaultMessage : new String[]{null, " "}) {
            var bindingResult = bindingResult();
            bindingResult.addError(new ObjectError(OBJECT_NAME,
                    new String[]{"first.message", "last.message"},
                    null,
                    defaultMessage));

            var error = assertInstanceOf(ValidationError.class, service.processException(validation(bindingResult)));

            assertEquals("openl.error.last.message", error.code);
            assertEquals("openl.error.first.message", error.message);
        }
    }

    @Test
    void singleGlobalError_withoutAKnownCode_getsItsDefaultMessage() {
        var bindingResult = bindingResult();
        bindingResult.addError(new ObjectError(OBJECT_NAME,
                new String[]{"first.message"},
                null,
                "The project is not valid."));

        var error = assertInstanceOf(ValidationError.class, service.processException(validation(bindingResult)));

        assertEquals("openl.error.first.message", error.code);
        assertEquals("The project is not valid.", error.message);
    }

    @Test
    void singleGlobalError_withoutCodes_hasNoCodeAndGetsItsDefaultMessage() {
        var bindingResult = bindingResult();
        bindingResult.addError(new ObjectError(OBJECT_NAME, "The project is not valid."));

        var error = assertInstanceOf(ValidationError.class, service.processException(validation(bindingResult)));

        assertNull(error.code);
        assertEquals("The project is not valid.", error.message);
    }

    @Test
    void globalErrorBesideFieldErrors_isListedWithThem() {
        var bindingResult = bindingResult();
        bindingResult.addError(new ObjectError(OBJECT_NAME, new String[]{"range.message"}, new Object[]{3}, null));
        bindingResult.addError(fieldError("name", "", new String[]{"name.blank.message"}, "Enter a name."));

        var error = assertInstanceOf(ValidationError.class, service.processException(validation(bindingResult)));

        assertNull(error.code);
        assertEquals(BAD_REQUEST, error.message);
        assertEquals(1, error.getFields().size());
        assertField(error.getFields().getFirst(), "name", "openl.error.name.blank.message", "Enter a name.", "");
        assertEquals(1, error.getErrors().size());
        assertGlobalError(error.getErrors().getFirst(), "openl.error.range.message", "The value 3 is out of range.");
    }

    @Test
    void severalGlobalErrors_areSortedByCodeCaseInsensitively_underTheStatusOfTheException() {
        var bindingResult = bindingResult();
        bindingResult.addError(new ObjectError(OBJECT_NAME, new String[]{"Zeta.message"}, null, "Zeta failed."));
        bindingResult.addError(new ObjectError(OBJECT_NAME, new String[]{"alpha.message"}, null, "Alpha failed."));

        var error = assertInstanceOf(ValidationError.class,
                service.processException(new ConflictingValidationException(bindingResult)));

        assertNull(error.code);
        assertEquals("Conflict", error.message);
        assertTrue(error.getFields().isEmpty(), "no field error is reported");
        assertEquals(2, error.getErrors().size());
        assertGlobalError(error.getErrors().get(0), "openl.error.alpha.message", "Alpha failed.");
        assertGlobalError(error.getErrors().get(1), "openl.error.Zeta.message", "Zeta failed.");
    }

    @Test
    void emptyBindingResult_getsTheStatusReasonOnly() {
        var error = assertInstanceOf(ValidationError.class, service.processException(validation(bindingResult())));

        assertNull(error.code);
        assertEquals(BAD_REQUEST, error.message);
        assertTrue(error.getFields().isEmpty(), "no field error is reported");
        assertTrue(error.getErrors().isEmpty(), "no global error is reported");
    }

    @Test
    void constraintViolations_areSplitIntoSortedFieldAndGlobalErrors() {
        Set<ConstraintViolation<?>> violations = new LinkedHashSet<>();
        violations.add(violation("Version", "version.format.message", "Use a version such as 1.0.0.", "1.x"));
        violations.add(violation(null, "Zeta.message", "Zeta failed.", null));
        violations.add(violation("name", "name.blank.message", "Enter a name.", ""));
        violations.add(violation("", "alpha.message", "Alpha failed.", null));

        var error = assertInstanceOf(ValidationError.class,
                service.processException(new ConstraintViolationException(violations)));

        assertNull(error.code);
        assertEquals(BAD_REQUEST, error.message);
        assertEquals(2, error.getFields().size());
        assertField(error.getFields().get(0), "name", "openl.error.name.blank.message", "Enter a name.", "");
        assertField(error.getFields().get(1),
                "Version",
                "openl.error.version.format.message",
                "Use a version such as 1.0.0.",
                "1.x");
        assertEquals(2, error.getErrors().size());
        assertGlobalError(error.getErrors().get(0), "openl.error.alpha.message", "Alpha failed.");
        assertGlobalError(error.getErrors().get(1), "openl.error.Zeta.message", "Zeta failed.");
    }

    private void assertMessage(String expectedMessage, Exception exception) {
        var error = service.processException(exception);

        assertSame(BaseError.class, error.getClass());
        assertNull(error.code);
        assertEquals(expectedMessage, error.message);
    }

    private static void assertField(FieldError field,
                                    @Nullable String expectedField,
                                    @Nullable String expectedCode,
                                    @Nullable String expectedMessage,
                                    String expectedRejectedValue) {
        assertEquals(expectedField, field.getField());
        assertEquals(expectedCode, field.code);
        assertEquals(expectedMessage, field.message);
        assertEquals(expectedRejectedValue, field.getRejectedValue());
    }

    private static void assertGlobalError(BaseError error, String expectedCode, String expectedMessage) {
        assertSame(BaseError.class, error.getClass());
        assertEquals(expectedCode, error.code);
        assertEquals(expectedMessage, error.message);
    }

    private static ConversionFailedException conversionFailure(Throwable cause) {
        return new ConversionFailedException(TypeDescriptor.valueOf(String.class),
                TypeDescriptor.valueOf(Object.class),
                "Example",
                cause);
    }

    private static MapBindingResult bindingResult() {
        return new MapBindingResult(new HashMap<>(), OBJECT_NAME);
    }

    private static ValidationException validation(BindingResult bindingResult) {
        return new ValidationException(bindingResult);
    }

    private static org.springframework.validation.FieldError fieldError(String field,
                                                                        Object rejectedValue,
                                                                        String[] codes,
                                                                        @Nullable String defaultMessage) {
        return new org.springframework.validation.FieldError(OBJECT_NAME,
                field,
                rejectedValue,
                false,
                codes,
                null,
                defaultMessage);
    }

    private static ConstraintViolation<?> violation(@Nullable String propertyPath,
                                                    String messageTemplate,
                                                    String message,
                                                    @Nullable Object invalidValue) {
        ConstraintViolation<?> violation = mock(ConstraintViolation.class);
        if (propertyPath != null) {
            var path = mock(Path.class);
            when(path.toString()).thenReturn(propertyPath);
            when(violation.getPropertyPath()).thenReturn(path);
        }
        when(violation.getMessageTemplate()).thenReturn(messageTemplate);
        when(violation.getMessage()).thenReturn(message);
        when(violation.getInvalidValue()).thenReturn(invalidValue);
        return violation;
    }

    /** A plain exception whose status comes only from its annotation. */
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    private static final class UnavailableException extends RuntimeException {
    }

    /** A validation failure that answers with another status than its parent. */
    @ResponseStatus(HttpStatus.CONFLICT)
    private static final class ConflictingValidationException extends ValidationException {

        private ConflictingValidationException(BindingResult bindingResult) {
            super(bindingResult);
        }
    }
}

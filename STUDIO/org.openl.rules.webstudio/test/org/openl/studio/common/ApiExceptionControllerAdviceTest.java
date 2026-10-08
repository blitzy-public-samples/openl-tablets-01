package org.openl.studio.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

import java.io.Closeable;
import java.math.BigDecimal;
import java.nio.file.InvalidPathException;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validation;
import jakarta.validation.constraints.NotBlank;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeanInstantiationException;
import org.springframework.beans.TypeMismatchException;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.UnsatisfiedDependencyException;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.core.MethodParameter;
import org.springframework.core.convert.ConversionFailedException;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.MapBindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.util.WebUtils;

import org.openl.rules.webstudio.web.admin.RepositoryValidationException;
import org.openl.rules.webstudio.web.servlet.RulesUserSession;
import org.openl.studio.common.exception.AmbiguityException;
import org.openl.studio.common.exception.ForbiddenException;
import org.openl.studio.common.exception.RestRuntimeException;
import org.openl.studio.common.exception.ValidationException;
import org.openl.studio.common.model.AmbiguityError;
import org.openl.studio.common.model.BaseError;
import org.openl.studio.common.model.ValidationError;

class ApiExceptionControllerAdviceTest {

    @Test
    void invalidPath_isMappedToBadRequest() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());

        var response = advice.handleInvalidPath(
                new InvalidPathException("/AGENTS.md", "The path cannot be absolute."), request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("openl.error.400.default.message", error.code);
    }

    @Test
    void problemDetailUsesItsDetailInsteadOfItsRecordRepresentation() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Readable failure");

        var response = advice.handleExceptionInternal(
                new IllegalArgumentException(), problemDetail, new HttpHeaders(), HttpStatus.BAD_REQUEST, request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals("openl.error.400.default.message", error.code);
        assertEquals("Readable failure", error.message);
    }

    @Test
    void problemDetailWithoutDescriptionUsesStatusReason() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var problemDetail = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problemDetail.setDetail(" ");
        problemDetail.setTitle(" ");

        var response = advice.handleExceptionInternal(
                new IllegalArgumentException(), problemDetail, new HttpHeaders(), HttpStatus.BAD_REQUEST, request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals("Bad Request", error.message);
    }

    @Test
    void oversizedUploadUsesProblemDetailMessage() throws Exception {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());

        var response = advice.handleException(new MaxUploadSizeExceededException(1024), request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
        assertEquals("openl.error.413.default.message", error.code);
        assertEquals("Maximum upload size exceeded", error.message);
    }

    @Test
    void jettyPartLimitUsesPayloadTooLargeResponse() throws Exception {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var exception = new MultipartException("Failed to parse multipart servlet request",
                new IllegalStateException("Form with too many keys [4 > 3]"));

        var response = advice.handleMultipartException(exception, request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
        assertEquals("openl.error.413.default.message", error.code);
        assertEquals("Maximum upload size exceeded", error.message);
    }

    @Test
    void malformedMultipartUsesBadRequestResponse() throws Exception {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());

        var response = advice.handleMultipartException(
                new MultipartException("Failed to parse multipart servlet request"), request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("openl.error.400.default.message", error.code);
        assertEquals("Failed to parse multipart servlet request", error.message);
    }

    @Test
    void ambiguity_listsItsCandidatesBesideTheMessage() throws JsonProcessingException {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var candidates = List.of(Map.of("id", "a"), Map.of("id", "b"));

        var response = advice.handleAllRestRuntimeExceptions(ambiguity(candidates), request);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        var error = assertInstanceOf(AmbiguityError.class, response.getBody());
        assertEquals("openl.error.409.project.identifier.ambiguous.message", error.code);
        assertEquals("The project name 'hello' is ambiguous. Use a project identifier instead. Candidates: a, b.",
                error.message);
        assertEquals(candidates, error.getCandidates());
        // What a client reads: the candidates travel as data beside the code and the message.
        assertTrue(new ObjectMapper().writeValueAsString(error).contains("\"candidates\":[{\"id\":\"a\"},{\"id\":\"b\"}]"));
    }

    @Test
    void ambiguity_raisedWhileConvertingAPathVariable_listsItsCandidates() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var candidates = List.of(Map.of("id", "a"), Map.of("id", "b"));
        var failure = new ConversionFailedException(TypeDescriptor.valueOf(String.class),
                TypeDescriptor.valueOf(Object.class),
                "hello",
                ambiguity(candidates));

        var response = advice.handleConversionFailedException(failure, request);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        var error = assertInstanceOf(AmbiguityError.class, response.getBody());
        assertEquals(candidates, error.getCandidates());
    }

    // V1: a refused session bean answers with its refusal; every other bean-creation failure keeps its answer
    @Test
    void refusedSessionBean_answersTheRefusalWithoutBeanNames() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());

        var response = advice.handleBeanCreationException(refusedSessionBean(), request);

        assertRefusedWithoutBeanNames(response);
    }

    @Test
    void beanDependingOnARefusedSessionBean_answersTheRefusalWithoutBeanNames() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var failure = new UnsatisfiedDependencyException(null, "userWorkspace", "rulesUserSession", refusedSessionBean());

        var response = advice.handleBeanCreationException(failure, request);

        assertRefusedWithoutBeanNames(response);
    }

    @Test
    void beanCreationFailureWithoutARefusal_staysAnInternalError() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var failure = new BeanCreationException("rulesUserSession", "Instantiation failed",
                new IllegalStateException("Unexpected failure"));

        var response = advice.handleBeanCreationException(failure, request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("openl.error.500.default.message", error.code);
        assertEquals(failure.getMessage(), error.message);
    }

    @Test
    void beanCreationFailureWithACircularCauseChain_staysAnInternalError() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var inner = new IllegalStateException("Unexpected failure");
        var failure = new BeanCreationException("rulesUserSession", "Instantiation failed", inner);
        inner.initCause(failure);

        var response = advice.handleBeanCreationException(failure, request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("openl.error.500.default.message", error.code);
    }

    @Test
    void refusedSessionBean_raisedWhileConvertingAPathVariable_answersTheRefusalWithoutBeanNames() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var failure = new ConversionFailedException(TypeDescriptor.valueOf(String.class),
                TypeDescriptor.valueOf(Object.class),
                "hello",
                new UnsatisfiedDependencyException(null, "userWorkspace", "rulesUserSession", refusedSessionBean()));

        var response = advice.handleConversionFailedException(failure, request);

        assertRefusedWithoutBeanNames(response);
    }

    @Test
    void beanCreationFailureWithoutARefusal_raisedWhileConvertingAPathVariable_staysABadRequest() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var cause = new BeanCreationException("userWorkspace", "Instantiation failed",
                new IllegalStateException("Unexpected failure"));
        var failure = new ConversionFailedException(TypeDescriptor.valueOf(String.class),
                TypeDescriptor.valueOf(Object.class),
                "hello",
                cause);

        var response = advice.handleConversionFailedException(failure, request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("openl.error.400.default.message", error.code);
        assertEquals(cause.getMessage(), error.message);
    }

    @Test
    void unconvertiblePathVariable_staysABadRequest() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var failure = new ConversionFailedException(TypeDescriptor.valueOf(String.class),
                TypeDescriptor.valueOf(Integer.class),
                "hello",
                new NumberFormatException("For input string: \"hello\""));

        var response = advice.handleConversionFailedException(failure, request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("openl.error.400.default.message", error.code);
        assertEquals("For input string: \"hello\"", error.message);
    }

    @Test
    void invalidEnumValue_givesFriendlyMessage() {
        assertEquals("Invalid enum format for field 'color'", describeParseFailure("{\"color\":\"PURPLE\"}"));
    }

    @Test
    void wrongType_givesFriendlyMessage() {
        assertEquals("Invalid number format for field 'count'", describeParseFailure("{\"count\":\"abc\"}"));
    }

    @Test
    void unknownField_givesFriendlyMessage() {
        assertEquals("Unknown field 'extra'", describeParseFailure("{\"extra\":1}"));
    }

    @Test
    void malformedJson_givesGenericMessage() {
        assertEquals("Request body is malformed", describeParseFailure("{"));
    }

    // V1: every other answer of the advice the session refusal changed keeps its status, code and message
    @Test
    void validationFailure_answersBadRequestWithItsFieldErrors() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var bindingResult = new MapBindingResult(new HashMap<String, Object>(), "project");
        bindingResult.rejectValue("name", "400.cannot.be.empty.message");

        var response = advice.handleAllRestRuntimeExceptions(new ValidationException(bindingResult), request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        var error = assertInstanceOf(ValidationError.class, response.getBody());
        assertEquals("Bad Request", error.message);
        assertEquals(1, error.getFields().size());
        var field = error.getFields().getFirst();
        assertEquals("name", field.getField());
        assertEquals("openl.error.400.cannot.be.empty.message", field.code);
        assertEquals("Cannot be empty.", field.message);
    }

    @Test
    void validationFailureOfADeclaredStatus_answersThatStatus() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var bindingResult = new MapBindingResult(new HashMap<String, Object>(), "project");
        bindingResult.rejectValue("name", "400.cannot.be.empty.message");

        var response = advice.handleAllRestRuntimeExceptions(new ConflictingValuesException(bindingResult), request);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        var error = assertInstanceOf(ValidationError.class, response.getBody());
        assertEquals("Conflict", error.message);
        assertEquals("name", error.getFields().getFirst().getField());
        // Only an internal error is handed on to the error page.
        assertNull(request.getAttribute(WebUtils.ERROR_EXCEPTION_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST));
    }

    @Test
    void constraintViolations_answerBadRequestWithTheViolatedFields() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            var violations = factory.getValidator().validate(new NamedProject(" "));

            var response = advice.handleConstraintViolationException(new ConstraintViolationException(violations),
                    request);

            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            var error = assertInstanceOf(ValidationError.class, response.getBody());
            assertEquals("Bad Request", error.message);
            assertEquals(1, error.getFields().size());
            var field = error.getFields().getFirst();
            assertEquals("name", field.getField());
            assertEquals("Cannot be empty.", field.message);
        }
    }

    @Test
    void invalidRequestArgument_answersBadRequestWithItsGlobalError() throws Exception {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var bindingResult = new MapBindingResult(new HashMap<String, Object>(), "branch");
        bindingResult.reject("branch.name.empty.message");
        var parameter = new MethodParameter(String.class.getMethod("valueOf", Object.class), 0);

        var response = advice.handleException(new MethodArgumentNotValidException(parameter, bindingResult), request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        var error = assertInstanceOf(ValidationError.class, response.getBody());
        assertEquals("openl.error.branch.name.empty.message", error.code);
        assertEquals("The branch name cannot be empty.", error.message);
    }

    @Test
    void restFailure_answersItsStatusAndHandsTheFailureToTheErrorPage() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var failure = new RestRuntimeException("default.message");

        var response = advice.handleAllRestRuntimeExceptions(failure, request);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals("openl.error.500.default.message", error.code);
        assertEquals("openl.error.500.default.message", error.message);
        assertSame(failure, request.getAttribute(WebUtils.ERROR_EXCEPTION_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST));
    }

    @Test
    void restFailureReportingNoStatus_isAnInternalError() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var failure = spy(new RestRuntimeException("unexpected.message"));
        doReturn(null).when(failure).getHttpStatus();

        var response = advice.handleAllRestRuntimeExceptions(failure, request);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals("unexpected.message", error.code);
        assertEquals("unexpected.message", error.message);
        assertSame(failure, request.getAttribute(WebUtils.ERROR_EXCEPTION_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST));
    }

    @Test
    void securityFailures_areForbidden() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());

        var fileDenied = advice.handleSecurityErrors(new java.nio.file.AccessDeniedException("rules/Bank.xlsx"),
                request);
        var aclDenied = advice.handleSecurityErrors(new AccessDeniedException("Access is denied"), request);
        var sandboxDenied = advice.handleSecurityErrors(new SecurityException(), request);

        assertEquals(HttpStatus.FORBIDDEN, fileDenied.getStatusCode());
        assertEquals("rules/Bank.xlsx", assertInstanceOf(BaseError.class, fileDenied.getBody()).message);
        assertEquals(HttpStatus.FORBIDDEN, aclDenied.getStatusCode());
        assertEquals("Access is denied", assertInstanceOf(BaseError.class, aclDenied.getBody()).message);
        assertEquals(HttpStatus.FORBIDDEN, sandboxDenied.getStatusCode());
        assertEquals("Forbidden", assertInstanceOf(BaseError.class, sandboxDenied.getBody()).message);
    }

    @Test
    void failureOfADeclaredStatus_answersThatStatus() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());

        var response = advice.handleInternalErrors(new RepositoryValidationException("Repository name is not set."),
                request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals("openl.error.400.default.message", error.code);
        assertEquals("Repository name is not set.", error.message);
        assertNull(request.getAttribute(WebUtils.ERROR_EXCEPTION_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST));
    }

    @Test
    void failureWithoutAMessage_answersAnInternalErrorWithoutAMessage() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var failure = new IllegalStateException();

        var response = advice.handleInternalErrors(failure, request);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals("openl.error.500.default.message", error.code);
        assertNull(error.message);
        assertSame(failure, request.getAttribute(WebUtils.ERROR_EXCEPTION_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST));
    }

    @Test
    void failureWithABlankMessage_answersTheReasonPhrase() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());

        var response = advice.handleInternalErrors(new IllegalStateException(" "), request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("openl.error.500.default.message", error.code);
        assertEquals("Internal Server Error", error.message);
    }

    @Test
    void nonStandardStatusWithoutAMessage_isNamedByItsNumber() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var status = HttpStatusCode.valueOf(599);

        var response = advice.handleExceptionInternal(new IllegalStateException(), " ", new HttpHeaders(), status,
                request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(status, response.getStatusCode());
        assertEquals("openl.error.599.default.message", error.code);
        assertEquals("599", error.message);
    }

    @Test
    void problemDetailWithoutDetailUsesItsTitle() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var problemDetail = ProblemDetail.forStatus(HttpStatus.CONFLICT);
        problemDetail.setTitle("Conflicting change");

        var response = advice.handleExceptionInternal(
                new IllegalStateException(), problemDetail, new HttpHeaders(), HttpStatus.CONFLICT, request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertEquals("openl.error.409.default.message", error.code);
        assertEquals("Conflicting change", error.message);
    }

    @Test
    void jettyPartLimitBehindAnotherCause_usesPayloadTooLargeResponse() throws Exception {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var exception = new MultipartException("Failed to parse multipart servlet request",
                new IllegalArgumentException("Cannot read the parts",
                        new IllegalStateException("Form with too many keys [4 > 3]")));

        var response = advice.handleMultipartException(exception, request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
        assertEquals("openl.error.413.default.message", error.code);
        assertEquals("Maximum upload size exceeded", error.message);
    }

    @Test
    void otherIllegalStateBehindAMultipartFailure_usesBadRequestResponse() throws Exception {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());

        for (var cause : List.of(new IllegalStateException(), new IllegalStateException("Stream ended unexpectedly"))) {
            var response = advice.handleMultipartException(
                    new MultipartException("Failed to parse multipart servlet request", cause), request);

            var error = assertInstanceOf(BaseError.class, response.getBody());
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            assertEquals("openl.error.400.default.message", error.code);
            assertEquals("Failed to parse multipart servlet request", error.message);
        }
    }

    @Test
    void unconvertiblePathVariableWithoutACause_staysABadRequest() {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var failure = new ConversionFailedException(TypeDescriptor.valueOf(String.class),
                TypeDescriptor.valueOf(Integer.class),
                "hello",
                null);

        var response = advice.handleConversionFailedException(failure, request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("openl.error.400.default.message", error.code);
        assertEquals(failure.getMessage(), error.message);
    }

    @Test
    void typeMismatchOfAnUnconvertibleValue_answersTheConversionFailure() throws Exception {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var conversion = new ConversionFailedException(TypeDescriptor.valueOf(String.class),
                TypeDescriptor.valueOf(Integer.class),
                "hello",
                new NumberFormatException("For input string: \"hello\""));

        var response = advice.handleException(new TypeMismatchException("hello", Integer.class, conversion), request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("openl.error.400.default.message", error.code);
        assertEquals("For input string: \"hello\"", error.message);
    }

    @Test
    void typeMismatch_answersBadRequestNamingTheField() throws Exception {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var mismatch = new TypeMismatchException("hello", Integer.class);
        mismatch.initPropertyName("count");

        var response = advice.handleException(mismatch, request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        var error = assertInstanceOf(ValidationError.class, response.getBody());
        assertEquals("Bad Request", error.message);
        assertEquals(1, error.getFields().size());
        var field = error.getFields().getFirst();
        assertEquals("count", field.getField());
        assertEquals("hello", field.getRejectedValue());
    }

    @Test
    void unreadableJsonBody_answersBadRequestWithAFriendlyMessage() throws Exception {
        var advice = advice();
        var request = new ServletWebRequest(new MockHttpServletRequest());
        var failure = new HttpMessageNotReadableException("JSON parse error",
                parseFailure("{\"color\":\"PURPLE\"}"),
                new MockHttpInputMessage(new byte[0]));

        var response = advice.handleException(failure, request);

        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("openl.error.400.default.message", error.code);
        assertEquals("Invalid enum format for field 'color'", error.message);
    }

    @Test
    void valueOfTheWrongShape_namesTheField() {
        assertEquals("Invalid value for field 'count'", describeParseFailure("{\"count\":[1]}"));
    }

    @Test
    void bodyOfTheWrongShape_givesGenericMappingMessage() {
        assertEquals("Invalid request body", describeParseFailure("[]"));
    }

    @Test
    void nestedFields_areNamedWithTheirIndexes() {
        assertEquals("Invalid number format for field 'items[1]'", describeParseFailure("{\"items\":[1,\"x\"]}"));
        assertEquals("Invalid number format for field 'rows[0].count'",
                describeParseFailure("{\"rows\":[{\"count\":\"x\"}]}"));
    }

    @Test
    void referenceWithoutANameOrAnIndex_isLeftOutOfThePath() {
        var failure = new JsonMappingException((Closeable) null, "Cannot map the value");
        failure.prependPath(new JsonMappingException.Reference(Holder.class, "count"));
        failure.prependPath(new JsonMappingException.Reference(Holder.class));
        failure.prependPath(new JsonMappingException.Reference(Holder.class, "rows"));

        assertEquals("Invalid value for field 'rows.count'", ApiExceptionControllerAdvice.describeJsonError(failure));
    }

    @Test
    void mappingFailuresWithoutAPath_giveGenericMessages() {
        var unknownField = new UnrecognizedPropertyException((JsonParser) null,
                "Unrecognized field",
                null,
                Holder.class,
                "extra",
                List.of());

        assertEquals("Unknown field in request", ApiExceptionControllerAdvice.describeJsonError(unknownField));
        assertEquals("Invalid number format", describeInvalidFormat(Integer.class));
        assertEquals("Invalid request body",
                ApiExceptionControllerAdvice.describeJsonError(new PathlessMappingException()));
    }

    @Test
    void invalidFormat_namesTheTargetTypeInPlainWords() {
        assertEquals("Invalid date format", describeInvalidFormat(Date.class));
        assertEquals("Invalid date format", describeInvalidFormat(LocalDate.class));
        assertEquals("Invalid date format", describeInvalidFormat(OffsetDateTime.class));
        assertEquals("Invalid boolean format", describeInvalidFormat(Boolean.class));
        assertEquals("Invalid boolean format", describeInvalidFormat(boolean.class));
        assertEquals("Invalid number format", describeInvalidFormat(BigDecimal.class));
        assertEquals("Invalid number format", describeInvalidFormat(long.class));
        assertEquals("Invalid string format", describeInvalidFormat(String.class));
        assertEquals("Invalid string format", describeInvalidFormat(char.class));
        assertEquals("Invalid string format", describeInvalidFormat(Character.class));
        assertEquals("Invalid enum format", describeInvalidFormat(Color.class));
        assertEquals("Invalid value format", describeInvalidFormat(Object.class));
        assertEquals("Invalid value format", describeInvalidFormat(void.class));
        assertEquals("Invalid value format", describeInvalidFormat(null));
    }

    private static JsonProcessingException parseFailure(String json) {
        try {
            new ObjectMapper().readValue(json, Holder.class);
            throw new AssertionError("expected a parse failure for: " + json);
        } catch (JsonProcessingException e) {
            return e;
        }
    }

    private static String describeInvalidFormat(@Nullable Class<?> targetType) {
        return ApiExceptionControllerAdvice.describeJsonError(
                new InvalidFormatException((JsonParser) null, "Cannot deserialize the value", "x", targetType));
    }

    private static String describeParseFailure(String json) {
        try {
            new ObjectMapper().readValue(json, Holder.class);
            throw new AssertionError("expected a parse failure for: " + json);
        } catch (JsonProcessingException e) {
            return ApiExceptionControllerAdvice.describeJsonError(e);
        }
    }

    /**
     * The failure Spring raises when the session factory refuses a user id that is not a valid workspace folder name.
     */
    private static BeanCreationException refusedSessionBean() {
        var refusal = new ForbiddenException();
        refusal.initCause(new IllegalArgumentException("The user id is not a valid workspace folder name."));
        var instantiation = new BeanInstantiationException(RulesUserSession.class,
                "Factory method 'rulesUserSession' threw exception",
                refusal);
        return new BeanCreationException("org.openl.studio.config.ServiceApiConfig",
                "rulesUserSession",
                "Instantiation of supplied bean failed",
                instantiation);
    }

    private static void assertRefusedWithoutBeanNames(ResponseEntity<?> response) {
        var error = assertInstanceOf(BaseError.class, response.getBody());
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertEquals("openl.error.403.default.message", error.code);
        assertEquals("You do not have the required privileges to do that.", error.message);
        for (var internal : List.of("bean", "ServiceApiConfig", "RulesUserSession", "workspace")) {
            assertFalse(error.message.toLowerCase(Locale.ROOT).contains(internal.toLowerCase(Locale.ROOT)), internal);
        }
    }

    private static AmbiguityException ambiguity(List<?> candidates) {
        return new AmbiguityException("project.identifier.ambiguous.message", candidates, "hello", "a, b");
    }

    private static ApiExceptionControllerAdvice advice() {
        var messageSource = new ReloadableResourceBundleMessageSource();
        messageSource.setBasename("classpath:ValidationMessages");
        messageSource.setDefaultEncoding("UTF-8");
        return new ApiExceptionControllerAdvice(new ExceptionMappingService(messageSource));
    }

    private enum Color {
        RED, GREEN
    }

    private static final class Holder {
        public Color color;
        public int count;
        public List<Integer> items;
        public List<Holder> rows;
    }

    private record NamedProject(@NotBlank String name) {
    }

    @ResponseStatus(HttpStatus.CONFLICT)
    private static final class ConflictingValuesException extends ValidationException {
        private ConflictingValuesException(BindingResult bindingResult) {
            super(bindingResult);
        }
    }

    /**
     * A mapping failure that carries no path at all.
     */
    private static final class PathlessMappingException extends JsonMappingException {
        private PathlessMappingException() {
            super((Closeable) null, "Cannot map the value");
        }

        @Override
        public @Nullable List<Reference> getPath() {
            return null;
        }
    }
}

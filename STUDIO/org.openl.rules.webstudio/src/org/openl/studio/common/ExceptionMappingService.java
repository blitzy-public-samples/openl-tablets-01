package org.openl.studio.common;

import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Path;

import org.jspecify.annotations.Nullable;
import org.springframework.beans.TypeMismatchException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.convert.ConversionFailedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import org.openl.rules.rest.validation.LocalPasswordPolicy;
import org.openl.studio.common.exception.AmbiguityException;
import org.openl.studio.common.exception.RestRuntimeException;
import org.openl.studio.common.exception.ValidationException;
import org.openl.studio.common.model.AmbiguityError;
import org.openl.studio.common.model.BaseError;
import org.openl.studio.common.model.ValidationError;
import org.openl.util.StringUtils;

@Service
public class ExceptionMappingService {

    private static final String DEF_ERROR_PREFIX = "openl.error.";

    private final MessageSource messageSource;

    public ExceptionMappingService(@Qualifier("validationMessageSource") MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    public String buildDefaultErrorCode(HttpStatusCode status) {
        return buildErrorCode(status.value() + ".default.message");
    }

    public BaseError processException(Exception ex) {
        return switch (ex) {
            case ConversionFailedException error when error.getCause() instanceof RestRuntimeException rex ->
                    processRestRuntimeException(rex);
            case ValidationException error -> {
                var code = Optional.ofNullable(AnnotationUtils.findAnnotation(error.getClass(), ResponseStatus.class))
                        .map(ResponseStatus::code)
                        .orElse(HttpStatus.BAD_REQUEST);
                yield handleBindingResult(code, error.getBindingResult());
            }
            case ConstraintViolationException error ->
                    handleConstraintViolations(error.getConstraintViolations());
            case MethodArgumentNotValidException error ->
                    handleBindingResult(HttpStatus.BAD_REQUEST, error.getBindingResult());
            case RestRuntimeException error -> processRestRuntimeException(error);
            case TypeMismatchException error -> handleTypeMismatchException(error);
            case Exception error when isSecurityException(error) -> mapCommonException(HttpStatus.FORBIDDEN, error);
            default -> {
                var httpStatus = Optional.ofNullable(AnnotationUtils.findAnnotation(ex.getClass(), ResponseStatus.class))
                        .map(ResponseStatus::code)
                        .orElse(HttpStatus.INTERNAL_SERVER_ERROR);
                yield mapCommonException(httpStatus, ex);
            }
        };
    }

    private static boolean isSecurityException(Exception ex) {
        return ex instanceof java.nio.file.AccessDeniedException ||
                ex instanceof org.springframework.security.access.AccessDeniedException ||
                ex instanceof SecurityException;
    }

    private BaseError processRestRuntimeException(RestRuntimeException ex) {
        if (ex instanceof AmbiguityException ambiguity) {
            return new AmbiguityError(BaseError.builder()
                    .code(ambiguity.getErrorCode())
                    .message(resolveLocalMessage(ambiguity)), ambiguity.getCandidates());
        }
        var httpStatus = Optional.ofNullable(ex.getHttpStatus())
                .orElse(HttpStatus.INTERNAL_SERVER_ERROR);
        return mapCommonException(httpStatus, ex);
    }

    private ValidationError handleTypeMismatchException(TypeMismatchException ex) {
        return ValidationError.builder()
                .message(HttpStatus.BAD_REQUEST.getReasonPhrase())
                .addField(org.openl.studio.common.model.FieldError.builder()
                        .field(getFieldName(ex))
                        .message(ex.getLocalizedMessage())
                        .rejectedValue(ex.getValue())
                        .build())
                .build();
    }

    private static String getFieldName(TypeMismatchException ex) {
        if (ex instanceof MethodArgumentTypeMismatchException exception) {
            return exception.getName();
        }
        return ex.getPropertyName();
    }

    private ValidationError handleBindingResult(HttpStatusCode status, BindingResult bindingResult) {
        var builder = ValidationError.builder();
        if (bindingResult.getGlobalErrorCount() == 1 && !bindingResult.hasFieldErrors()) {
            builder.code(buildErrorCode(bindingResult.getGlobalError().getCode()))
                    .message(resolveLocalMessage(bindingResult.getGlobalError()));
        } else {
            builder.message(HttpStatus.resolve(status.value()).getReasonPhrase());
            if (bindingResult.hasFieldErrors()) {
                bindingResult.getFieldErrors()
                        .stream()
                        .sorted(Comparator.comparing(FieldError::getField, String.CASE_INSENSITIVE_ORDER))
                        .map(fieldError -> org.openl.studio.common.model.FieldError.builder()
                                // V7: a local password policy violation is answered with its message key as its code
                                .code(fieldErrorCode(messageTemplateOf(fieldError),
                                        buildErrorCode(fieldError.getCode())))
                                .field(fieldError.getField())
                                // V7: a rejected password, or a model carrying one, is never echoed back
                                .rejectedValue(rejectedValueOf(fieldError.getField(), fieldError.getRejectedValue()))
                                .message(resolveLocalMessage(fieldError))
                                .build())
                        // V7: each local password policy violation is reported once per response
                        .filter(passwordPolicyViolationReportedOnce())
                        .forEach(builder::addField);
            }
            if (bindingResult.hasGlobalErrors()) {
                bindingResult.getGlobalErrors()
                        .stream()
                        .sorted(Comparator.comparing(ObjectError::getCode, String.CASE_INSENSITIVE_ORDER))
                        .map(objErr -> BaseError.builder()
                                .code(buildErrorCode(objErr.getCode()))
                                .message(resolveLocalMessage(objErr))
                                .build())
                        .forEach(builder::addError);
            }
        }
        return builder.build();
    }

    private ValidationError handleConstraintViolations(Set<ConstraintViolation<?>> constraintViolations) {
        var builder = ValidationError.builder();

        builder.message(HttpStatus.BAD_REQUEST.getReasonPhrase());

        // Handle field errors
        constraintViolations.stream()
                .filter(violation -> isFieldError(violation.getPropertyPath()))
                .sorted(Comparator.comparing(violation -> violation.getPropertyPath().toString(), String.CASE_INSENSITIVE_ORDER))
                .map(violation -> org.openl.studio.common.model.FieldError.builder()
                        // V7: a local password policy violation is answered with its message key as its code
                        .code(fieldErrorCode(violation.getMessageTemplate(),
                                buildErrorCode(violation.getMessageTemplate())))
                        .field(violation.getPropertyPath().toString())
                        // V7: a rejected password, or a model carrying one, is never echoed back
                        .rejectedValue(rejectedValueOf(violation.getPropertyPath().toString(),
                                violation.getInvalidValue()))
                        .message(violation.getMessage())
                        .build())
                // V7: each local password policy violation is reported once per response
                .filter(passwordPolicyViolationReportedOnce())
                .forEach(builder::addField);

        // Handle global errors
        constraintViolations.stream()
                .filter(violation -> !isFieldError(violation.getPropertyPath()))
                .sorted(Comparator.comparing(ConstraintViolation::getMessageTemplate, String.CASE_INSENSITIVE_ORDER))
                .map(violation -> BaseError.builder()
                        .code(buildErrorCode(violation.getMessageTemplate()))
                        .message(violation.getMessage())
                        .build())
                .forEach(builder::addError);

        return builder.build();
    }

    // V7: a field whose name contains "password" gets no rejected value, so no password is echoed back
    private static @Nullable Object rejectedValueOf(@Nullable String field, @Nullable Object rejectedValue) {
        if (field != null && field.toLowerCase(Locale.ROOT).contains("password")) {
            return null;
        }
        return rejectedValue;
    }

    // V7: the three local password policy violations use their message key as the code; any other code is unchanged
    private static String fieldErrorCode(@Nullable String messageTemplate, String code) {
        if (("{" + LocalPasswordPolicy.MIN_LENGTH_KEY + "}").equals(messageTemplate)) {
            return LocalPasswordPolicy.MIN_LENGTH_KEY;
        }
        if (("{" + LocalPasswordPolicy.MAX_BYTES_KEY + "}").equals(messageTemplate)) {
            return LocalPasswordPolicy.MAX_BYTES_KEY;
        }
        if (("{" + LocalPasswordPolicy.INVALID_KEY + "}").equals(messageTemplate)) {
            return LocalPasswordPolicy.INVALID_KEY;
        }
        return code;
    }

    // V7: a policy violation describes the submitted value, so the create form's two copies of one value, password
    // and internalPassword, are reported once: a field error with a policy code is dropped when an earlier one of the
    // same response has the same code and message. Every other field error is kept, even when it repeats another.
    private static Predicate<org.openl.studio.common.model.FieldError> passwordPolicyViolationReportedOnce() {
        Set<List<String>> reported = new HashSet<>();
        return fieldError -> !isPasswordPolicyCode(fieldError.code)
                || reported.add(Arrays.asList(fieldError.code, fieldError.message));
    }

    // V7: whether a field error code is the message key of a local password policy violation
    private static boolean isPasswordPolicyCode(@Nullable String code) {
        return LocalPasswordPolicy.MIN_LENGTH_KEY.equals(code)
                || LocalPasswordPolicy.MAX_BYTES_KEY.equals(code)
                || LocalPasswordPolicy.INVALID_KEY.equals(code);
    }

    // V7: the message template of the constraint violation behind a field error, if a Bean Validation one made it
    private static @Nullable String messageTemplateOf(FieldError fieldError) {
        return fieldError.contains(ConstraintViolation.class)
                ? fieldError.unwrap(ConstraintViolation.class).getMessageTemplate()
                : null;
    }

    private boolean isFieldError(Path propertyPath) {
        return propertyPath != null && !propertyPath.toString().isEmpty();
    }

    private String resolveLocalMessage(ObjectError error) {
        if (error == null) {
            return null;
        }
        if (error.getCodes() != null) {
            for (String code : error.getCodes()) {
                if (code == null) {
                    continue;
                }
                try {
                    return messageSource.getMessage(buildErrorCode(code), error.getArguments(), Locale.US);
                } catch (NoSuchMessageException ignored) {
                    // no message for this code, so the next code is tried
                }
            }
            if (error.getDefaultMessage() == null || error.getDefaultMessage().isBlank()) {
                // if no default message just return first code
                return buildErrorCode(error.getCodes()[0]);
            }
        }
        return error.getDefaultMessage();
    }

    private String resolveLocalMessage(RestRuntimeException e) {
        if (e.getErrorCode() != null) {
            try {
                return messageSource.getMessage(e.getErrorCode(), e.getArgs(), Locale.US);
            } catch (NoSuchMessageException ignored) {
                return e.getErrorCode();
            }
        }
        return e.getMessage();
    }

    private BaseError mapCommonException(HttpStatus status, Exception e) {
        var builder = BaseError.builder();
        if (e instanceof RestRuntimeException restEx) {
            builder.code(restEx.getErrorCode()).message(resolveLocalMessage(restEx));
        } else {
            builder.message(Optional.ofNullable(e.getMessage())
                    .filter(StringUtils::isNotBlank)
                    .orElseGet(status::getReasonPhrase));
        }
        return builder.build();
    }

    private static String buildErrorCode(String errorSuffix) {
        if (errorSuffix == null) {
            return null;
        }
        return DEF_ERROR_PREFIX + errorSuffix;
    }
}

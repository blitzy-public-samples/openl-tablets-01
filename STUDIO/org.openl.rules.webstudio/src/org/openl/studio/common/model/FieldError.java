package org.openl.studio.common.model;

import io.swagger.v3.oas.annotations.Parameter;
import lombok.Getter;
import org.jspecify.annotations.Nullable;

import org.openl.studio.common.ApiExceptionControllerAdvice;

/**
 * Field Validation Error model for handling Binding Exceptions (validation) in OpenL Studio REST API
 *
 * @author Vladyslav Pikus
 * @see ApiExceptionControllerAdvice
 */
public final class FieldError extends BaseError {

    @Getter
    @Parameter(description = "Affected field of the validated object")
    private final String field;

    // V7: a password field's rejected value is redacted to null, so rejectedValue is nullable here and in the Builder
    @Getter
    @Parameter(description = "Rejected field value")
    private final @Nullable Object rejectedValue;

    private FieldError(Builder from) {
        super(from);
        this.field = from.field;
        this.rejectedValue = from.rejectedValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends BaseError.Builder {

        private String field;
        private @Nullable Object rejectedValue;

        private Builder() {
        }

        public Builder field(String field) {
            this.field = field;
            return this;
        }

        public Builder rejectedValue(@Nullable Object rejectedValue) {
            this.rejectedValue = rejectedValue;
            return this;
        }

        @Override
        public Builder code(String code) {
            super.code(code);
            return this;
        }

        @Override
        public Builder message(String message) {
            super.message(message);
            return this;
        }

        @Override
        public FieldError build() {
            return new FieldError(this);
        }
    }
}

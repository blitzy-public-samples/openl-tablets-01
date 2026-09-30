package org.openl.rules.rest.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import org.openl.util.StringUtils;

/**
 * V7: validates a local password that is optional on edit.
 * <p>
 * A blank value means that the password is left unchanged and is valid. Any other value must satisfy
 * {@link LocalPasswordPolicy}.
 */
public class LocalPasswordConstraintValidator implements ConstraintValidator<LocalPasswordConstraint, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (StringUtils.isBlank(value)) {
            return true;
        }
        context.disableDefaultConstraintViolation();
        return LocalPasswordPolicy.check(value, context);
    }

}

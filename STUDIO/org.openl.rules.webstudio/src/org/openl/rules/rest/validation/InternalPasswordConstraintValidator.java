package org.openl.rules.rest.validation;

import jakarta.annotation.Resource;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import org.openl.rules.rest.model.InternalPasswordModel;
import org.openl.util.StringUtils;

public class InternalPasswordConstraintValidator implements ConstraintValidator<InternalPasswordConstraint, InternalPasswordModel> {

    @Resource(name = "canCreateInternalUsers")
    protected boolean canCreateInternalUsers;

    @Override
    public void initialize(InternalPasswordConstraint constraintAnnotation) {
        // The constraint has no attributes to read.
    }

    @Override
    public boolean isValid(InternalPasswordModel value, ConstraintValidatorContext context) {
        context.disableDefaultConstraintViolation();
        if (StringUtils.isNotBlank(value.getPassword())) {
            // V7: a nonblank password needs at least 12 code points and at most 72 UTF-8 bytes.
            if (!LocalPasswordPolicy.check(value.getPassword(), context)) {
                return false;
            }
        } else if (canCreateInternalUsers) {
            context.buildConstraintViolationWithTemplate("{jakarta.validation.constraints.NotBlank.message}")
                    .addConstraintViolation();
            return false;
        }
        return true;
    }

}

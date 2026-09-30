package org.openl.rules.rest.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

/**
 * V7: applies the local password policy to an optional password, such as the one on the admin user edit form.
 * <p>
 * A blank value means that the password is left unchanged and is valid. Any other value must satisfy
 * {@code LocalPasswordPolicy}. The validator reports the policy-specific message, so the default message below is
 * only a fallback.
 */
@Documented
@Constraint(validatedBy = LocalPasswordConstraintValidator.class)
@Target({ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface LocalPasswordConstraint {

    String message() default "{openl.constraints.password.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

}

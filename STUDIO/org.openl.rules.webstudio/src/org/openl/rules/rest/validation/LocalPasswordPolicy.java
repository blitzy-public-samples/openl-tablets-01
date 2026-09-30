package org.openl.rules.rest.validation;

import java.nio.charset.StandardCharsets;
import jakarta.validation.ConstraintValidatorContext;

import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;

/**
 * V7: the local password policy for internal (local) users.
 * <p>
 * It applies on create, admin edit and profile change. The minimum is counted in Unicode code points and the maximum
 * in UTF-8 bytes, because bcrypt ignores input beyond 72 bytes. Existing password hashes are not re-validated.
 */
public final class LocalPasswordPolicy {

    public static final int MIN_CHARACTERS = 12;

    public static final int MAX_BYTES = 72;

    private LocalPasswordPolicy() {
        // Utility class.
    }

    /**
     * Checks a password against the policy and adds at most one violation to the context.
     *
     * @param password the password to check; never {@code null}, which every caller guarantees
     * @param context  the validator context that receives the violation
     * @return {@code true} if the password satisfies the policy
     */
    public static boolean check(String password, ConstraintValidatorContext context) {
        if (password.codePointCount(0, password.length()) < MIN_CHARACTERS) {
            context.unwrap(HibernateConstraintValidatorContext.class)
                    .addMessageParameter("min", MIN_CHARACTERS)
                    .buildConstraintViolationWithTemplate("{openl.constraints.password.min-length.message}")
                    .addConstraintViolation();
            return false;
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            context.unwrap(HibernateConstraintValidatorContext.class)
                    .addMessageParameter("max", MAX_BYTES)
                    .buildConstraintViolationWithTemplate("{openl.constraints.password.max-bytes.message}")
                    .addConstraintViolation();
            return false;
        }
        return true;
    }

}

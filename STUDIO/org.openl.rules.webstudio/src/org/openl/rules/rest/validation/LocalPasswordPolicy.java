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

    /** The message key of a password with fewer than {@link #MIN_CHARACTERS} code points, and its error code. */
    public static final String MIN_LENGTH_KEY = "openl.constraints.password.min-length.message";

    /** The message key of a password of more than {@link #MAX_BYTES} UTF-8 bytes, and its error code. */
    public static final String MAX_BYTES_KEY = "openl.constraints.password.max-bytes.message";

    private LocalPasswordPolicy() {
        // Utility class.
    }

    /**
     * Checks a password against the policy and adds at most one violation to the context. A password that violates
     * the minimum gets the minimum violation only. A password of more than {@link #MAX_BYTES} UTF-16 units is rejected
     * without being scanned or encoded, so the work done does not grow with the size of the input.
     *
     * @param password the password to check; never {@code null}, which every caller guarantees
     * @param context  the validator context that receives the violation
     * @return {@code true} if the password satisfies the policy
     */
    public static boolean check(String password, ConstraintValidatorContext context) {
        // UTF-8 takes at least one byte per UTF-16 unit: 1 to 3 for a unit outside a surrogate pair, 4 for a pair and
        // 1 for a lone surrogate, which String.getBytes encodes as '?'. A password of more than MAX_BYTES units
        // therefore exceeds the maximum, and its more than MAX_BYTES / 2 code points meet the minimum, which is not
        // above MAX_BYTES / 2. It is rejected at once, and only passwords of at most MAX_BYTES units are counted and
        // encoded.
        var oversized = password.length() > MAX_BYTES;
        if (!oversized && password.codePointCount(0, password.length()) < MIN_CHARACTERS) {
            context.unwrap(HibernateConstraintValidatorContext.class)
                    .addMessageParameter("min", MIN_CHARACTERS)
                    .buildConstraintViolationWithTemplate("{" + MIN_LENGTH_KEY + "}")
                    .addConstraintViolation();
            return false;
        }
        if (oversized || password.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            context.unwrap(HibernateConstraintValidatorContext.class)
                    .addMessageParameter("max", MAX_BYTES)
                    .buildConstraintViolationWithTemplate("{" + MAX_BYTES_KEY + "}")
                    .addConstraintViolation();
            return false;
        }
        return true;
    }

}

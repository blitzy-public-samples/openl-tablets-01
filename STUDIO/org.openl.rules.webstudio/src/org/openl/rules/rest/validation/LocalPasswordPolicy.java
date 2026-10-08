package org.openl.rules.rest.validation;

import java.nio.charset.StandardCharsets;
import jakarta.validation.ConstraintValidatorContext;

import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;

/**
 * V7: the local password policy for internal (local) users.
 * <p>
 * It applies on create, admin edit and profile change. The minimum is counted in Unicode code points and the maximum
 * in UTF-8 bytes, which enforces bcrypt's 72-byte input limit. Both limits measure the password as submitted: an
 * unpaired surrogate counts as one code point, and as the one byte {@code '?'} that {@code String.getBytes(UTF_8)}
 * and bcrypt encode it as. A password within both limits must also be well-formed UTF-16 text, a rule checked only
 * after the limits, so a length violation takes precedence over it. A password that holds an unpaired surrogate is
 * rejected because UTF-8 encoding would replace each such unit with {@code '?'}, so the value that is hashed would not
 * be the value that was checked. Existing password hashes are not re-validated.
 */
public final class LocalPasswordPolicy {

    public static final int MIN_CHARACTERS = 12;

    public static final int MAX_BYTES = 72;

    /** The message key of a password with fewer than {@link #MIN_CHARACTERS} code points, and its error code. */
    public static final String MIN_LENGTH_KEY = "openl.constraints.password.min-length.message";

    /** The message key of a password of more than {@link #MAX_BYTES} UTF-8 bytes, and its error code. */
    public static final String MAX_BYTES_KEY = "openl.constraints.password.max-bytes.message";

    // V7: a malformed password reuses the existing generic password message, so no message key is added
    /**
     * The message key of a password that is not well-formed UTF-16 text, because it holds an unpaired surrogate, and
     * its error code.
     */
    public static final String INVALID_KEY = "openl.constraints.password.default";

    private LocalPasswordPolicy() {
        // Utility class.
    }

    /**
     * Checks a password against the policy and adds at most one violation to the context, the first that applies in
     * this order:
     * <ol>
     * <li>more than {@link #MAX_BYTES} UTF-16 units: the maximum violation, without the password being counted,
     * encoded or scanned, so the work done does not grow with the size of the input;</li>
     * <li>fewer than {@link #MIN_CHARACTERS} code points: the minimum violation;</li>
     * <li>more than {@link #MAX_BYTES} UTF-8 bytes: the maximum violation;</li>
     * <li>an unpaired surrogate in a password that meets both limits: the {@link #INVALID_KEY} violation.</li>
     * </ol>
     *
     * @param password the password to check; never {@code null}, which every caller guarantees
     * @param context  the validator context that receives the violation
     * @return {@code true} if the password satisfies the policy
     */
    public static boolean check(String password, ConstraintValidatorContext context) {
        // String.getBytes(UTF_8) takes at least one byte per UTF-16 unit: 1 to 3 for a unit outside a surrogate pair,
        // 4 for a pair and 1 for an unpaired surrogate, which it encodes as '?'. A password of more than MAX_BYTES
        // units therefore exceeds the maximum, and its more than MAX_BYTES / 2 code points meet the minimum, which is
        // not above MAX_BYTES / 2, so the maximum violation is the one the full checks below would add. It is added at
        // once, and only passwords of at most MAX_BYTES units are counted, encoded and scanned.
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
        // V7: the length violations take precedence, so only a password within both limits is scanned here.
        // String.getBytes and bcrypt encode an unpaired surrogate as '?', so such a password would be hashed as
        // another value than the one checked. codePoints() yields a surrogate pair as one supplementary code point,
        // and an unpaired surrogate as its own value in the surrogate range.
        if (password.codePoints().anyMatch(cp -> cp >= Character.MIN_SURROGATE && cp <= Character.MAX_SURROGATE)) {
            context.buildConstraintViolationWithTemplate("{" + INVALID_KEY + "}").addConstraintViolation();
            return false;
        }
        return true;
    }

}

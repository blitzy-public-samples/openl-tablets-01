package org.openl.studio.security.pat.service;

import java.time.Instant;
import jakarta.validation.constraints.NotBlank;

import org.openl.studio.users.model.pat.CreatedPersonalAccessTokenResponse;

/**
 * Service for generating Personal Access Tokens (PATs).
 * <p>
 * This service handles the creation of new PATs with cryptographically secure
 * public IDs and secrets. The generated tokens are persisted in the database
 * with hashed secrets for security.
 * </p>
 *
 * @since 6.0.0
 */
public interface PatGeneratorService {

    /**
     * Generates a new Personal Access Token for the specified user.
     * <p>
     * The method creates a unique public ID and a cryptographically secure secret,
     * stores the token in the database with a hashed secret, and returns the complete
     * token value. The actual token secret is only returned once and cannot be retrieved later.
     * </p>
     * <p>
     * V8: every token created by this method expires. A missing expiration is replaced by the
     * configured default lifetime, and an expiration beyond the configured maximum lifetime is refused.
     * </p>
     *
     * @param loginName the login name of the user who owns the token (must not be blank)
     * @param name      a human-readable name for the token (must not be blank)
     * @param expiresAt the expiration instant of the token. When null, the token expires after the
     *                  configured default lifetime ({@code security.pat.default-expiration-days},
     *                  90 days by default). A value later than now plus
     *                  {@code security.pat.max-expiration-days} (365 days by default) is rejected.
     * @return the created token response containing the full token value (shown only once)
     * @throws IllegalArgumentException if expiresAt is in the past
     * @throws org.openl.studio.common.exception.BadRequestException if expiresAt exceeds the maximum
     *                  lifetime (HTTP 400, {@code openl.error.400.pat.expires-at.max.message})
     */
    CreatedPersonalAccessTokenResponse generateToken(@NotBlank String loginName,
                                                     @NotBlank String name,
                                                     Instant expiresAt);

}

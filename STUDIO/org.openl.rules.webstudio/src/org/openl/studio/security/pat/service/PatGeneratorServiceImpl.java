package org.openl.studio.security.pat.service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import jakarta.validation.constraints.NotBlank;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import org.openl.rules.security.standalone.persistence.PersonalAccessToken;
import org.openl.studio.common.exception.BadRequestException;
import org.openl.studio.security.pat.Base62Generator;
import org.openl.studio.security.pat.model.PatToken;
import org.openl.studio.users.model.pat.CreatedPersonalAccessTokenResponse;
import org.openl.studio.users.service.pat.PersonalAccessTokenService;

/**
 * Default implementation of {@link PatGeneratorService}.
 * <p>
 * This service generates cryptographically secure Personal Access Tokens with:
 * <ul>
 *   <li>16-character Base62 public ID</li>
 *   <li>32-character Base62 secret</li>
 *   <li>Hashed secret storage for security</li>
 * </ul>
 * </p>
 *
 * @since 6.0.0
 */
@Validated
public class PatGeneratorServiceImpl implements PatGeneratorService {

    private final PersonalAccessTokenService crudService;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;
    // V8: configured default and maximum PAT lifetime
    private final Duration defaultLifetime;
    private final Duration maxLifetime;

    /**
     * Constructs a new PatGeneratorServiceImpl.
     *
     * @param crudService     the PAT CRUD service for database operations
     * @param passwordEncoder the password encoder for hashing secrets
     * @param clock           the clock for generating timestamps
     * @param defaultLifetime the lifetime applied when a token is created without an expiration date
     *                        ({@code security.pat.default-expiration-days})
     * @param maxLifetime     the maximum lifetime a token may be created with
     *                        ({@code security.pat.max-expiration-days})
     * @throws IllegalArgumentException if a lifetime is null, zero or negative, or the default exceeds the maximum
     */
    public PatGeneratorServiceImpl(PersonalAccessTokenService crudService,
                                   PasswordEncoder passwordEncoder,
                                   Clock clock,
                                   Duration defaultLifetime,
                                   Duration maxLifetime) {
        this.crudService = crudService;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
        // V8: a misconfigured lifetime fails at startup instead of producing unbounded or already-expired tokens
        if (defaultLifetime == null || defaultLifetime.isZero() || defaultLifetime.isNegative()) {
            throw new IllegalArgumentException(
                    "security.pat.default-expiration-days must be a positive number of days");
        }
        if (maxLifetime == null || maxLifetime.isZero() || maxLifetime.isNegative()) {
            throw new IllegalArgumentException("security.pat.max-expiration-days must be a positive number of days");
        }
        if (defaultLifetime.compareTo(maxLifetime) > 0) {
            throw new IllegalArgumentException(
                    "security.pat.default-expiration-days must not exceed security.pat.max-expiration-days");
        }
        this.defaultLifetime = defaultLifetime;
        this.maxLifetime = maxLifetime;
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation generates a unique 16-character public ID and a 32-character secret,
     * handles collision detection for public IDs, and stores the token with a hashed secret.
     * </p>
     * <p>
     * V8: a token requested without an expiration date expires after the configured default lifetime, and an
     * expiration date later than now plus the configured maximum lifetime is rejected with a
     * {@link BadRequestException} before anything is generated or stored.
     * </p>
     */
    @Transactional
    @Override
    public CreatedPersonalAccessTokenResponse generateToken(@NotBlank String loginName,
                                                            @NotBlank String name,
                                                            Instant expiresAt) {
        Instant now = Instant.now(clock);

        if (expiresAt != null && expiresAt.isBefore(now)) {
            throw new IllegalArgumentException("expiresAt must be in the future");
        }

        // V8: a missing expiration gets the configured default lifetime
        Instant effectiveExpiresAt = expiresAt != null ? expiresAt : now.plus(defaultLifetime);
        // V8: reject an expiration beyond the configured maximum lifetime (exactly now + max is accepted)
        if (effectiveExpiresAt.isAfter(now.plus(maxLifetime))) {
            // V8: a plain string keeps MessageFormat from grouping digits ("1000 days", not "1,000 days")
            throw new BadRequestException("pat.expires-at.max.message",
                    new Object[]{String.valueOf(maxLifetime.toDays())});
        }

        // generate unique publicId (very low collision, but handle it)
        String publicId;
        do {
            publicId = Base62Generator.generate(PatToken.PUBLIC_ID_LENGTH);
        } while (crudService.existsByPublicId(publicId));

        // secret (high entropy)
        String secret = Base62Generator.generate(PatToken.SECRET_LENGTH);
        var secretHash = passwordEncoder.encode(secret);

        var token = new PersonalAccessToken();
        token.setPublicId(publicId);
        token.setSecretHash(secretHash);
        token.setLoginName(loginName);
        token.setName(name);
        token.setCreatedAt(now);
        token.setExpiresAt(effectiveExpiresAt); // V8: persist the effective expiry

        crudService.save(token);

        var pat = new PatToken(publicId, secret);

        return CreatedPersonalAccessTokenResponse.builder()
                .publicId(publicId)
                .name(name)
                .loginName(loginName)
                .token(pat.asTokenValue())
                .createdAt(now)
                .expiresAt(effectiveExpiresAt) // V8: return the effective expiry
                .build();
    }
}

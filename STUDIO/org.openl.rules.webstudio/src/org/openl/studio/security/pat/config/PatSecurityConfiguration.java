package org.openl.studio.security.pat.config;

import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.function.BiFunction;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.NumberUtils;

import org.openl.rules.security.standalone.dao.PersonalAccessTokenDao;
import org.openl.rules.security.standalone.dao.UserDao;
import org.openl.rules.webstudio.service.AdminUsers;
import org.openl.rules.webstudio.service.ExternalGroupService;
import org.openl.studio.security.GetUserPrivileges;
import org.openl.studio.security.pat.filter.PatAuthenticationFilter;
import org.openl.studio.security.pat.service.PatAuthService;
import org.openl.studio.security.pat.service.PatAuthServiceImpl;
import org.openl.studio.security.pat.service.PatGeneratorServiceImpl;
import org.openl.studio.security.pat.service.PatUserInfoUserDetailsServiceImpl;
import org.openl.studio.security.pat.service.PatValidationService;
import org.openl.studio.security.pat.service.PatValidationServiceImpl;
import org.openl.studio.users.service.pat.PersonalAccessTokenService;

/**
 * Spring Security configuration for Personal Access Token (PAT) authentication.
 * <p>
 * This configuration is active for every authenticated user mode (OAuth2, SAML, AD and multi),
 * that is, any mode except {@code single}. It configures all beans required for PAT
 * authentication including services and filters.
 * </p>
 * <p>
 * The PAT authentication flow:
 * <ol>
 *   <li>{@link PatAuthenticationFilter} extracts and parses PAT from Authorization header</li>
 *   <li>{@link PatValidationService} validates the token cryptographically</li>
 *   <li>{@link PatAuthService} converts valid token to Spring Security authentication</li>
 *   <li>{@link PatUserInfoUserDetailsServiceImpl} loads user details with external groups</li>
 * </ol>
 * </p>
 *
 * @since 6.0.0
 */
@Configuration
@ConditionalOnExpression("'${user.mode}' != 'single'")
public class PatSecurityConfiguration {

    /**
     * Creates the configuration and checks that both PAT lifetime properties hold a whole number of days.
     * <p>
     * Spring creates this configuration before it resolves the arguments of its bean methods, so a value that cannot
     * be bound to an {@code int} stops the startup here, with an error naming its property, instead of a type
     * conversion error on a {@code patGeneratorService} parameter. Whether each lifetime is positive, and whether the
     * default exceeds the maximum, is checked by {@link PatGeneratorServiceImpl}.
     * </p>
     *
     * @param defaultExpirationDays the raw value of {@code security.pat.default-expiration-days}
     * @param maxExpirationDays     the raw value of {@code security.pat.max-expiration-days}
     * @throws IllegalArgumentException if a value is empty, not a whole number, or outside the {@code int} range
     */
    public PatSecurityConfiguration(@Value("${security.pat.default-expiration-days}") String defaultExpirationDays,
                                    @Value("${security.pat.max-expiration-days}") String maxExpirationDays) {
        // V8: a lifetime that is not a whole number of days fails startup with its property named
        requireWholeDays("security.pat.default-expiration-days", defaultExpirationDays);
        requireWholeDays("security.pat.max-expiration-days", maxExpirationDays);
    }

    /**
     * Checks that a PAT lifetime value can be bound to an {@code int} number of days.
     * <p>
     * The value is parsed by Spring's default {@code String} to {@code int} conversion, the one that binds the
     * {@code int} parameters of {@code patGeneratorService}, so this check accepts every value that binding accepts
     * and rejects every value it rejects. The message names the property and never repeats the value.
     * </p>
     *
     * @param property the property name reported in the error
     * @param value    the raw property value
     * @throws IllegalArgumentException if the value cannot be parsed as an {@code int}
     */
    private static void requireWholeDays(String property, String value) {
        try {
            NumberUtils.parseNumber(value, Integer.class);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    property + " must be a positive whole number of days, at most " + Integer.MAX_VALUE, e);
        }
    }

    /**
     * Creates the PAT authentication service bean.
     *
     * @param validator          the token validation service
     * @param userDetailsService the PAT user details service loading external group privileges
     * @return configured PAT authentication service
     */
    @Bean
    public PatAuthServiceImpl patAuthService(PatValidationService validator,
                                             @Qualifier("patUserInfoUserDetailsService") UserDetailsService userDetailsService) {
        return new PatAuthServiceImpl(validator, userDetailsService);
    }

    /**
     * Creates the PAT generator service bean.
     *
     * @param crudService the PAT CRUD service
     * @param passwordEncoder the password encoder for hashing secrets
     * @param clock the clock for generating timestamps
     * @param defaultExpirationDays lifetime in days applied when a token is created without an expiration date
     *                              ({@code security.pat.default-expiration-days})
     * @param maxExpirationDays maximum lifetime in days accepted for a token's expiration date
     *                          ({@code security.pat.max-expiration-days})
     * @return configured PAT generator service
     */
    @Bean
    public PatGeneratorServiceImpl patGeneratorService(PersonalAccessTokenService crudService,
                                                       PasswordEncoder passwordEncoder,
                                                       Clock clock,
                                                       @Value("${security.pat.default-expiration-days}")
                                                       int defaultExpirationDays,
                                                       @Value("${security.pat.max-expiration-days}")
                                                       int maxExpirationDays) {
        // V8: tokens without expiresAt get the configured default lifetime; dates beyond the maximum are rejected
        return new PatGeneratorServiceImpl(crudService, passwordEncoder, clock,
                Duration.ofDays(defaultExpirationDays), Duration.ofDays(maxExpirationDays));
    }

    /**
     * Creates the PAT validation service bean.
     *
     * @param tokenDao the DAO for accessing stored tokens
     * @param passwordEncoder the password encoder for verifying secrets
     * @param clock the clock for checking expiration
     * @return configured PAT validation service
     */
    @Bean
    public PatValidationServiceImpl patValidationService(PersonalAccessTokenDao tokenDao,
                                                         PasswordEncoder passwordEncoder,
                                                         Clock clock) {
        return new PatValidationServiceImpl(tokenDao, passwordEncoder, clock);
    }

    /**
     * Creates the PAT-specific UserDetailsService bean.
     * <p>
     * This service loads user details with external group privileges, ensuring that
     * PAT-authenticated users have the same authorities as interactively-authenticated users.
     * When the privilege mapper is {@link GetUserPrivileges}, its
     * {@link GetUserPrivileges#withoutAdminMatchWarning() non-warning view} is used, because PAT requests
     * replay the groups stored at the last IdP login and are not IdP logins.
     * </p>
     *
     * @param userDao the user DAO
     * @param adminUsersInitializer the admin users initializer
     * @param privilegeMapper the privilege mapping function
     * @param externalGroupService the external group service
     * @return configured UserDetailsService for PAT authentication
     */
    @Bean
    public PatUserInfoUserDetailsServiceImpl patUserInfoUserDetailsService(@Qualifier("openlUserDao") UserDao userDao,
                                                                           @Qualifier("adminUsersInitializer") AdminUsers adminUsersInitializer,
                                                                           @Qualifier("privilegeMapper") BiFunction<String, Collection<? extends GrantedAuthority>, Collection<GrantedAuthority>> privilegeMapper,
                                                                           ExternalGroupService externalGroupService) {
        // V12: PAT requests replay stored groups, so they must not repeat the IdP ADMIN name-match WARN
        BiFunction<String, Collection<? extends GrantedAuthority>, Collection<GrantedAuthority>> patPrivilegeMapper =
                privilegeMapper instanceof GetUserPrivileges getUserPrivileges
                        ? getUserPrivileges.withoutAdminMatchWarning()
                        : privilegeMapper;
        return new PatUserInfoUserDetailsServiceImpl(userDao, adminUsersInitializer, patPrivilegeMapper,
                externalGroupService);
    }

    /**
     * Creates the PAT authentication filter bean.
     * <p>
     * This filter processes requests with "Authorization: Token &lt;pat&gt;" header
     * and should be placed before bearer token authentication in the security filter chain.
     * </p>
     *
     * @param patAuthService the PAT authentication service
     * @return configured PAT authentication filter
     */
    @Bean
    public PatAuthenticationFilter patAuthenticationFilter(PatAuthService patAuthService) {
        return new PatAuthenticationFilter(patAuthService);
    }

}

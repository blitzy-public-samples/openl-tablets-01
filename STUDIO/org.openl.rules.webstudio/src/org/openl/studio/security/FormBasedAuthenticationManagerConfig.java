package org.openl.studio.security;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;

/**
 * Makes the form login and the HTTP Basic authentication of the {@code ad} and {@code multi} modes authenticate
 * through the {@code authenticationManager} bean of {@link CommonAuthenticationConfig}.
 *
 * <p>The filter chains of {@link FormBasedAuthenticationConfig} are built with {@code HttpSecurity}, whose
 * authentication manager has the global authentication manager of Spring Security as its parent. Left alone, Spring
 * Security builds that global manager from the single {@code AuthenticationProvider} bean of the mode, the
 * {@code DaoAuthenticationProvider} of {@code multi} or the {@code ActiveDirectoryLdapAuthenticationProvider} of
 * {@code ad}, so form login and HTTP Basic would skip the {@code authenticationManager} bean: its security audit
 * trail (V11), its login lockout (V9) and the {@code AuthenticationHolder} that the Active Directory mapper reads.
 * This configurer makes the {@code authenticationManager} bean the parent of the global manager instead, and the
 * global manager then holds no provider of its own, so every attempt is authenticated, audited and counted once.
 *
 * <p>The parent is a plain delegate rather than the bean itself. The bean keeps the credentials of a successful
 * authentication for SAML single logout, and a {@code ProviderManager} given as a parent would pass that setting on
 * to the global manager. Behind the delegate, the global manager keeps its default and erases the credentials of
 * every successful form or HTTP Basic login, as it does without this configurer. The delegate also looks the bean
 * up only on the first attempt, so the global manager can be built before the bean exists.
 */
// V11: form login and HTTP Basic of the ad and multi modes reach the audited (and V9 lockout) authentication manager
@Configuration
@ConditionalOnExpression("'${user.mode}' == 'ad' || '${user.mode}' == 'multi'")
public class FormBasedAuthenticationManagerConfig {

    // Static, as Spring Security declares its own global configurers: the bean is needed early, while the security
    // configuration is still being built, and must not create this configuration class that early.
    @Bean
    public static GlobalAuthenticationConfigurerAdapter formBasedAuthenticationManagerConfigurer(
            @Qualifier("authenticationManager") ObjectProvider<AuthenticationManager> authenticationManager) {
        return new GlobalAuthenticationConfigurerAdapter() {
            @Override
            public void init(AuthenticationManagerBuilder auth) {
                // A parent marks the builder as configured, so Spring Security adds no provider bean of its own.
                auth.parentAuthenticationManager(
                        authentication -> authenticationManager.getObject().authenticate(authentication));
            }
        };
    }
}

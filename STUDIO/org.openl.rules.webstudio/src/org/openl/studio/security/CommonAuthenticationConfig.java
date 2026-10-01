package org.openl.studio.security;

import java.time.Clock;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import org.openl.studio.security.ad.OpenLAuthenticationProviderWrapper;

@Configuration
@ConditionalOnExpression("'${user.mode}' != 'single'")
public class CommonAuthenticationConfig {

    @Bean(initMethod = "afterPropertiesSet", destroyMethod = "destroy")
    public SecurityContextPersistenceFilter securityContextPersistenceFilter() {
        return new SecurityContextPersistenceFilter();
    }

    // V4: default Spring Security response headers for the hand-built SAML and OIDC chains
    @Bean(initMethod = "afterPropertiesSet")
    public HeaderWriterFilter securityHeadersFilter() {
        return new HeaderWriterFilter(List.of(
                new XContentTypeOptionsHeaderWriter(),
                new XXssProtectionHeaderWriter(),
                new CacheControlHeadersWriter(),
                new HstsHeaderWriter(),
                new XFrameOptionsHeaderWriter(XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY)));
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> authenticationProviders, Clock clock) {
        if (authenticationProviders.isEmpty()) {
            throw new IllegalStateException("No AuthenticationProvider is configured");
        }
        List<AuthenticationProvider> wrappedAuthProviders = authenticationProviders.stream()
                // V9: count failed logins of the local (multi) and Active Directory providers only
                .map(p -> new OpenLAuthenticationProviderWrapper(
                        p instanceof DaoAuthenticationProvider || p instanceof ActiveDirectoryLdapAuthenticationProvider
                                ? new LoginLockoutAuthenticationProvider(p, clock)
                                : p))
                .collect(Collectors.toList());
        ProviderManager manager = new ProviderManager(wrappedAuthProviders);
        // Needed for SAML. Without credentials it's not possible to make global single sign out
        manager.setEraseCredentialsAfterAuthentication(false);
        return manager;
    }

    @Bean(initMethod = "afterPropertiesSet", destroyMethod = "destroy")
    public ExceptionTranslationFilter webExceptionTranslationFilter(
            @Qualifier("httpSessionRequestCache") HttpSessionRequestCache httpSessionRequestCache) {
        return new ExceptionTranslationFilter(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED), httpSessionRequestCache);
    }

    @Bean
    public HttpSessionRequestCache httpSessionRequestCache() {
        HttpSessionRequestCache cache = new HttpSessionRequestCache();
        // Don't redirect to these pages after login
        cache.setRequestMatcher(RequestMatchers.not(RequestMatchers.matcher("/rest/**")));
        return cache;
    }

    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy(SessionRegistry sessionRegistry) {
        // V5: change the session ID first, then register the new ID in the SessionRegistry
        return new CompositeSessionAuthenticationStrategy(List.of(
                new ChangeSessionIdAuthenticationStrategy(),
                new RegisterSessionAuthenticationStrategy(sessionRegistry)));
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        var successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl("/");
        successHandler.setTargetUrlParameter("from");
        return successHandler;
    }

    @Bean
    public AuthorizationFilter filterSecurityInterceptor() {
        return new AuthorizationFilter(AuthenticatedAuthorizationManager.authenticated());
    }

}

package org.openl.studio.security;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.web.PathPatternRequestMatcherBuilderFactoryBean;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AndRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean(initMethod = "afterPropertiesSet", destroyMethod = "destroy")
    public FilterChainProxy filterChainProxy(List<SecurityFilterChain> securityFilterChains) {
        var filterChainProxy = new FilterChainProxy(securityFilterChains);
        // V4: every chain also writes its response-independent security headers before an early-committed body
        filterChainProxy.setFilterChainDecorator(new EagerSecurityHeadersChainDecorator());
        return filterChainProxy;
    }

    @Bean
    PathPatternRequestMatcherBuilderFactoryBean requestMatcherBuilder() {
        return new PathPatternRequestMatcherBuilderFactoryBean();
    }

    // Static resource patterns: no authentication, default security headers only
    @Bean
    @Order(0)
    public SecurityFilterChain staticResourcesFilterChain(HttpSecurity http) throws Exception {

        return http
                // V10: sys.json and http.json leave the public chain, so each mode's /rest/** chain authenticates them
                .securityMatcher(new AndRequestMatcher(
                        RequestMatchers.anyOf(
                                "/favicon.ico",
                                "/favicon.svg",
                                "/application.properties",
                                "/api-docs",
                                "/icons/**",
                                "/assets/**",
                                "/.well-known/**",
                                "/rest/public/**",
                                "/rest/settings",
                                "/rest/api-docs",
                                "/rest/openapi.json"),
                        RequestMatchers.not(RequestMatchers.anyOf(
                                "/rest/public/info/sys.json",
                                "/rest/public/info/http.json"))))
                // Disable every configurer and authentication except the default security headers.
                // V4: security headers stay enabled (HttpSecurity defaults) on the static chain.
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .securityContext(AbstractHttpConfigurer::disable)
                .anonymous(AbstractHttpConfigurer::disable)
                .exceptionHandling(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .servletApi(AbstractHttpConfigurer::disable)
                .build();
    }
}

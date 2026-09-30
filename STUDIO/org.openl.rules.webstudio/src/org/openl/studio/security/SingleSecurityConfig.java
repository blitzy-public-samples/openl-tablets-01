package org.openl.studio.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import org.openl.rules.security.Privileges;

@Slf4j
@Configuration
@ConditionalOnExpression("'${user.mode}' == 'single'")
public class SingleSecurityConfig {

    // V14: single mode has no login, so every visitor is an ADMIN; warn once when the configuration is created
    public SingleSecurityConfig() {
        log.warn("user.mode=single: OpenL Studio runs without authentication and grants ADMIN to every visitor; "
                + "use it only on an isolated workstation.");
    }

    @Bean
    public Boolean canCreateInternalUsers() {
        return Boolean.FALSE;
    }

    @Bean
    // Create security filter chain for /** pattern with filters
    public SecurityFilterChain defaultFilterChain(HttpSecurity http,
                                                  @Value("${security.single.username}") String singleUsername) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .anonymous(anon -> anon
                        .principal(singleUsername)
                        .authorities(Privileges.ADMIN.getAuthority()))
                .build();

    }

}

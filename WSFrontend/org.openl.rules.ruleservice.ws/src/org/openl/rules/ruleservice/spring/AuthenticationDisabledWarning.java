package org.openl.rules.ruleservice.spring;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import org.openl.util.StringUtils;

/**
 * V14: logs a warning at startup when Rule Services runs without authentication.
 * <p>
 * The default {@code ruleservice.authentication.enabled = false} is kept unchanged, so a default installation exposes
 * every endpoint, including {@code /admin/deploy} when the deployer is enabled, to anyone who can reach it. In that
 * state {@link JWTValidator} is not created and nothing else reports the missing protection. This component
 * complements {@link JWTValidator}: it exists in every configuration and warns exactly when that validator is absent.
 * <p>
 * It is picked up by the {@code org.openl.rules.ruleservice.spring} component scan and, being a non-lazy singleton,
 * is created while the context refreshes, so the warning appears once per application start. It deliberately carries
 * no {@code @ConditionalOnEnable}: it evaluates the property itself with the same semantics as that condition's
 * existence check, where a blank, absent or case-insensitive {@code false} value means disabled. The component only
 * logs; it changes no default, bean condition or request handling.
 */
@Component
@Slf4j
public class AuthenticationDisabledWarning {

    /**
     * Reads {@code ruleservice.authentication.enabled} and logs one WARN when authentication is disabled.
     *
     * @param env the application environment holding the Rule Services properties
     */
    @Autowired
    public AuthenticationDisabledWarning(Environment env) {
        if (isDisabled(env.getProperty("ruleservice.authentication.enabled"))) {
            // The message is fixed text: it never includes property values or credentials.
            log.warn(
                    "ruleservice.authentication.enabled=false: every Rule Services endpoint, including /admin/deploy when the deployer is enabled, is reachable without authentication.");
        }
    }

    /**
     * Tells whether a {@code ruleservice.authentication.enabled} value disables authentication.
     * <p>
     * Mirrors the existence check of {@code @ConditionalOnEnable}, which decides whether {@link JWTValidator} is
     * created, so the warning is logged exactly when the validator is absent.
     *
     * @param value the raw property value, {@code null} when the property is not defined
     * @return {@code true} for {@code null}, blank or case-insensitive {@code false}; {@code false} otherwise
     */
    static boolean isDisabled(String value) {
        return "false".equalsIgnoreCase(value) || StringUtils.isBlank(value);
    }
}

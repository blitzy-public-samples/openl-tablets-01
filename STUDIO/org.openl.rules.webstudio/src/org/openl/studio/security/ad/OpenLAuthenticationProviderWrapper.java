package org.openl.studio.security.ad;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import org.openl.studio.security.audit.SecurityAuditLog;

@RequiredArgsConstructor
public class OpenLAuthenticationProviderWrapper implements AuthenticationProvider {
    private final AuthenticationProvider delegate;

    @Override
    public Authentication authenticate(Authentication authentication) {
        if (!delegate.supports(authentication.getClass())) {
            return null;
        }

        try {
            AuthenticationHolder.setAuthentication(authentication);

            // V11: one audit line per attempt this provider handles; a lockout rejection is logged as a failure too
            try {
                var result = delegate.authenticate(authentication);
                if (result != null) {
                    SecurityAuditLog.authSuccess(authentication, result);
                }
                return result;
            } catch (AuthenticationException e) {
                SecurityAuditLog.authFailure(authentication);
                throw e;
            }
        } finally {
            AuthenticationHolder.clear();
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication != null && Authentication.class.isAssignableFrom(authentication);
    }
}

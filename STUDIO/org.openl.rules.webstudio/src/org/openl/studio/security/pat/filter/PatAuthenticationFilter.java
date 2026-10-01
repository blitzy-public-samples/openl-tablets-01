package org.openl.studio.security.pat.filter;

import java.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import org.openl.studio.security.audit.SecurityAuditLog;
import org.openl.studio.security.pat.model.PatAuthResolution;
import org.openl.studio.security.pat.model.PatToken;
import org.openl.studio.security.pat.service.PatAuthService;

/**
 * Authentication filter for Personal Access Tokens (PAT).
 * <p>
 * This filter processes requests with the "{@code HttpHeaders.AUTHORIZATION}: Token &lt;pat&gt;" header
 * for service-to-service authorization in every authenticated user mode (OAuth2, SAML, AD and multi).
 * </p>
 * <p>
 * The filter extracts the PAT token, validates it using {@link PatAuthService},
 * and sets the authentication in the {@link SecurityContext} if valid.
 * </p>
 * <p>
 * This filter should be placed before the credential authentication filter (bearer or basic)
 * in the security filter chain.
 * </p>
 */
public class PatAuthenticationFilter extends OncePerRequestFilter {

    private static final String PREFIX = "Token ";

    private final PatAuthService patAuthService;
    private final SecurityContextHolderStrategy securityContextHolderStrategy;

    /**
     * Constructs a new PatAuthenticationFilter with default SecurityContextHolderStrategy.
     *
     * @param patAuthService the PAT authentication service
     */
    public PatAuthenticationFilter(PatAuthService patAuthService) {
        this.patAuthService = patAuthService;
        this.securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    }

    /**
     * Package-private constructor for testing with custom SecurityContextHolderStrategy.
     *
     * @param patAuthService                the PAT authentication service
     * @param securityContextHolderStrategy the security context holder strategy
     */
    PatAuthenticationFilter(PatAuthService patAuthService, SecurityContextHolderStrategy securityContextHolderStrategy) {
        this.patAuthService = patAuthService;
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        var header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        var tokenValue = header.substring(PREFIX.length()).trim();

        PatToken patToken;
        try {
            patToken = PatToken.parse(tokenValue);
        } catch (IllegalArgumentException e) {
            // V11: audit the failed PAT attempt; no public ID exists for an unparsable token
            SecurityAuditLog.authFailure(request, null);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, HttpStatus.UNAUTHORIZED.getReasonPhrase());
            return;
        }

        PatAuthResolution resolution;
        try {
            resolution = patAuthService.resolveAuthentication(patToken);
        } catch (RuntimeException e) {
            // V11: audit a PAT whose resolution failed (e.g. its user was just deleted), then rethrow unchanged
            SecurityAuditLog.authFailure(request, patToken.publicId());
            throw e;
        }

        if (!resolution.valid()) {
            // V11: audit the rejected PAT; only the non-secret public ID is logged
            SecurityAuditLog.authFailure(request, patToken.publicId());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, HttpStatus.UNAUTHORIZED.getReasonPhrase());
            return;
        }

        var authResult = resolution.authentication();
        // V11: log every valid PAT authentication, even when the context already holds this user
        SecurityAuditLog.authSuccess(request, authResult.getName(), patToken.publicId());

        if (authenticationIsRequired(authResult.getName())) {
            var context = securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(authResult);
            securityContextHolderStrategy.setContext(context);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Checks if authentication should be set in the security context.
     * <p>
     * Authentication is required if:
     * <ul>
     *   <li>No authentication exists in the current context</li>
     *   <li>Existing authentication is not authenticated</li>
     *   <li>Existing authentication is anonymous</li>
     *   <li>Existing authentication is for a different user</li>
     * </ul>
     * </p>
     *
     * @param username the username from the PAT
     * @return true if authentication should be set, false otherwise
     */
    protected boolean authenticationIsRequired(String username) {
        var existingAuth = securityContextHolderStrategy.getContext().getAuthentication();

        if (existingAuth == null) {
            return true;
        }
        if (!existingAuth.isAuthenticated()) {
            return true;
        }
        if (existingAuth instanceof AnonymousAuthenticationToken) {
            return true;
        }
        return !username.equals(existingAuth.getName());
    }
}

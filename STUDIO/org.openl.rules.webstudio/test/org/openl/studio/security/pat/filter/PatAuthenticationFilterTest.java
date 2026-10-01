package org.openl.studio.security.pat.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.List;
import java.util.stream.Stream;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.openl.studio.security.pat.model.PatAuthResolution;
import org.openl.studio.security.pat.model.PatAuthenticationToken;
import org.openl.studio.security.pat.model.PatToken;
import org.openl.studio.security.pat.service.PatAuthService;

/**
 * Unit tests for {@link PatAuthenticationFilter}.
 * Tests PAT authentication filter logic using mocked dependencies.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PatAuthenticationFilterTest {

    // Valid test tokens matching PatToken format requirements (16 char publicId, 32 char secret)
    // V11: every credential in this test (token parts, anonymous key, password) is generated per run
    private static final String TEST_PUBLIC_ID = RandomStringUtils.secure().nextAlphanumeric(PatToken.PUBLIC_ID_LENGTH);
    private static final String TEST_SECRET = RandomStringUtils.secure().nextAlphanumeric(PatToken.SECRET_LENGTH);
    private static final String TEST_TOKEN_VALUE = new PatToken(TEST_PUBLIC_ID, TEST_SECRET).asTokenValue();
    private static final String ANONYMOUS_KEY = RandomStringUtils.secure().nextAlphanumeric(16);
    // V11: the audit logger name, as a literal, so these tests pin the name and compile without the audit class
    private static final String AUDIT_LOGGER = "org.openl.security.audit";

    @Mock
    private PatAuthService patAuthService;

    @Mock
    private SecurityContextHolderStrategy securityContextHolderStrategy;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private FilterChain filterChain;

    private PatAuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        filter = new PatAuthenticationFilter(patAuthService, securityContextHolderStrategy);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();

        // Default: no existing authentication
        when(securityContextHolderStrategy.getContext()).thenReturn(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);
        when(securityContextHolderStrategy.createEmptyContext()).thenReturn(securityContext);
    }

    @Test
    void testDoFilter_ValidToken() throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + TEST_TOKEN_VALUE);

        var userDetails = createUserDetails("jdoe", "ROLE_USER");
        var authentication = new PatAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        PatAuthResolution resolution = PatAuthResolution.valid(authentication);

        when(patAuthService.resolveAuthentication(any(PatToken.class))).thenReturn(resolution);

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(patAuthService, times(1)).resolveAuthentication(any(PatToken.class));
        verify(securityContextHolderStrategy, times(1)).createEmptyContext();
        verify(securityContext, times(1)).setAuthentication(authentication);
        verify(securityContextHolderStrategy, times(1)).setContext(securityContext);
        verify(filterChain, times(1)).doFilter(request, response);

        // Response should be successful (filter passed through)
        assertEquals(200, response.getStatus());
    }

    @Test
    void testDoFilter_NoAuthorizationHeader() throws ServletException, IOException {
        // Arrange - no Authorization header

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(patAuthService, never()).resolveAuthentication(any(PatToken.class));
        verify(securityContextHolderStrategy, never()).createEmptyContext();
        verify(filterChain, times(1)).doFilter(request, response);

        assertEquals(200, response.getStatus());
    }

    @Test
    void testDoFilter_AuthorizationHeaderWithoutTokenPrefix() throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + RandomStringUtils.secure().nextAlphanumeric(24));

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(patAuthService, never()).resolveAuthentication(any(PatToken.class));
        verify(securityContextHolderStrategy, never()).createEmptyContext();
        verify(filterChain, times(1)).doFilter(request, response);

        assertEquals(200, response.getStatus());
    }

    @Test
    void testDoFilter_InvalidTokenFormat() throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token invalid-token-format");

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(patAuthService, never()).resolveAuthentication(any(PatToken.class));
        verify(securityContextHolderStrategy, never()).createEmptyContext();
        verify(filterChain, never()).doFilter(request, response);

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertEquals("Unauthorized", response.getErrorMessage());
    }

    @Test
    void testDoFilter_ValidFormatButInvalidToken() throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + TEST_TOKEN_VALUE);

        PatAuthResolution resolution = PatAuthResolution.invalid();

        when(patAuthService.resolveAuthentication(any(PatToken.class))).thenReturn(resolution);

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(patAuthService, times(1)).resolveAuthentication(any(PatToken.class));
        verify(securityContextHolderStrategy, never()).createEmptyContext();
        verify(filterChain, never()).doFilter(request, response);

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertEquals("Unauthorized", response.getErrorMessage());
    }

    @Test
    void testDoFilter_RevokedToken() throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + TEST_TOKEN_VALUE);

        PatAuthResolution resolution = PatAuthResolution.invalid();

        when(patAuthService.resolveAuthentication(any(PatToken.class))).thenReturn(resolution);

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(patAuthService, times(1)).resolveAuthentication(any(PatToken.class));
        verify(securityContextHolderStrategy, never()).createEmptyContext();
        verify(filterChain, never()).doFilter(request, response);

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
    }

    @Test
    void testDoFilter_TokenWithWhitespace() throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token   " + TEST_TOKEN_VALUE + "   ");

        var userDetails = createUserDetails("jdoe", "ROLE_USER");
        var authentication = new PatAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        PatAuthResolution resolution = PatAuthResolution.valid(authentication);

        when(patAuthService.resolveAuthentication(any(PatToken.class))).thenReturn(resolution);

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(patAuthService, times(1)).resolveAuthentication(any(PatToken.class));
        verify(filterChain, times(1)).doFilter(request, response);

        assertEquals(200, response.getStatus());
    }

    @Test
    void testDoFilter_ExistingAuthenticationSameUser() throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + TEST_TOKEN_VALUE);

        // Existing authentication for jdoe
        var existingUserDetails = createUserDetails("jdoe", "ROLE_USER");
        var existingAuth = new PatAuthenticationToken(
                existingUserDetails,
                null,
                existingUserDetails.getAuthorities()
        );
        when(securityContext.getAuthentication()).thenReturn(existingAuth);

        // New PAT authentication also for jdoe
        var newUserDetails = createUserDetails("jdoe", "ROLE_USER");
        var newAuth = new PatAuthenticationToken(
                newUserDetails,
                null,
                newUserDetails.getAuthorities()
        );
        PatAuthResolution resolution = PatAuthResolution.valid(newAuth);

        when(patAuthService.resolveAuthentication(any(PatToken.class))).thenReturn(resolution);

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(patAuthService, times(1)).resolveAuthentication(any(PatToken.class));
        // Should NOT set authentication because same user is already authenticated
        verify(securityContextHolderStrategy, never()).createEmptyContext();
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain, times(1)).doFilter(request, response);

        assertEquals(200, response.getStatus());
    }

    @Test
    void testDoFilter_ExistingAuthenticationDifferentUser() throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + TEST_TOKEN_VALUE);

        // Existing authentication for jdoe
        var existingUserDetails = createUserDetails("jdoe", "ROLE_USER");
        var existingAuth = new PatAuthenticationToken(
                existingUserDetails,
                null,
                existingUserDetails.getAuthorities()
        );
        when(securityContext.getAuthentication()).thenReturn(existingAuth);

        // New PAT authentication for jsmith
        var newUserDetails = createUserDetails("jsmith", "ROLE_ADMIN");
        var newAuth = new PatAuthenticationToken(
                newUserDetails,
                null,
                newUserDetails.getAuthorities()
        );
        PatAuthResolution resolution = PatAuthResolution.valid(newAuth);

        when(patAuthService.resolveAuthentication(any(PatToken.class))).thenReturn(resolution);

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(patAuthService, times(1)).resolveAuthentication(any(PatToken.class));
        // Should set new authentication because different user
        verify(securityContextHolderStrategy, times(1)).createEmptyContext();
        verify(securityContext, times(1)).setAuthentication(newAuth);
        verify(securityContextHolderStrategy, times(1)).setContext(securityContext);
        verify(filterChain, times(1)).doFilter(request, response);

        assertEquals(200, response.getStatus());
    }

    @Test
    void testDoFilter_AnonymousAuthentication() throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + TEST_TOKEN_VALUE);

        // Existing anonymous authentication
        var anonymousAuth = new AnonymousAuthenticationToken(
                ANONYMOUS_KEY,
                "anonymousUser",
                java.util.List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))
        );
        when(securityContext.getAuthentication()).thenReturn(anonymousAuth);

        // New PAT authentication
        var newUserDetails = createUserDetails("jdoe", "ROLE_USER");
        var newAuth = new PatAuthenticationToken(
                newUserDetails,
                null,
                newUserDetails.getAuthorities()
        );
        PatAuthResolution resolution = PatAuthResolution.valid(newAuth);

        when(patAuthService.resolveAuthentication(any(PatToken.class))).thenReturn(resolution);

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(patAuthService, times(1)).resolveAuthentication(any(PatToken.class));
        // Should replace anonymous authentication with PAT authentication
        verify(securityContextHolderStrategy, times(1)).createEmptyContext();
        verify(securityContext, times(1)).setAuthentication(newAuth);
        verify(securityContextHolderStrategy, times(1)).setContext(securityContext);
        verify(filterChain, times(1)).doFilter(request, response);

        assertEquals(200, response.getStatus());
    }

    @Test
    void testDoFilter_UnauthenticatedExistingAuth() throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + TEST_TOKEN_VALUE);

        // Existing authentication but not authenticated
        Authentication existingAuth = mock(Authentication.class);
        when(existingAuth.isAuthenticated()).thenReturn(false);
        when(existingAuth.getName()).thenReturn("jdoe");
        when(securityContext.getAuthentication()).thenReturn(existingAuth);

        // New PAT authentication
        var newUserDetails = createUserDetails("jdoe", "ROLE_USER");
        var newAuth = new PatAuthenticationToken(
                newUserDetails,
                null,
                newUserDetails.getAuthorities()
        );
        PatAuthResolution resolution = PatAuthResolution.valid(newAuth);

        when(patAuthService.resolveAuthentication(any(PatToken.class))).thenReturn(resolution);

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(patAuthService, times(1)).resolveAuthentication(any(PatToken.class));
        // Should set authentication because existing auth is not authenticated
        verify(securityContextHolderStrategy, times(1)).createEmptyContext();
        verify(securityContext, times(1)).setAuthentication(newAuth);
        verify(securityContextHolderStrategy, times(1)).setContext(securityContext);
        verify(filterChain, times(1)).doFilter(request, response);

        assertEquals(200, response.getStatus());
    }

    @Test
    void testAuthenticationIsRequired_NoExistingAuth() {
        // Arrange
        when(securityContext.getAuthentication()).thenReturn(null);

        // Act
        var required = filter.authenticationIsRequired("jdoe");

        // Assert
        assertTrue(required, "Authentication should be required when no existing auth");
    }

    @Test
    void testAuthenticationIsRequired_UnauthenticatedExistingAuth() {
        // Arrange
        Authentication existingAuth = mock(Authentication.class);
        when(existingAuth.isAuthenticated()).thenReturn(false);
        when(securityContext.getAuthentication()).thenReturn(existingAuth);

        // Act
        var required = filter.authenticationIsRequired("jdoe");

        // Assert
        assertTrue(required, "Authentication should be required when existing auth is not authenticated");
    }

    @Test
    void testAuthenticationIsRequired_AnonymousAuth() {
        // Arrange
        var anonymousAuth = new AnonymousAuthenticationToken(
                ANONYMOUS_KEY,
                "anonymousUser",
                java.util.List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))
        );
        when(securityContext.getAuthentication()).thenReturn(anonymousAuth);

        // Act
        var required = filter.authenticationIsRequired("jdoe");

        // Assert
        assertTrue(required, "Authentication should be required when existing auth is anonymous");
    }

    @Test
    void testAuthenticationIsRequired_SameUser() {
        // Arrange
        var userDetails = createUserDetails("jdoe", "ROLE_USER");
        var existingAuth = new PatAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        when(securityContext.getAuthentication()).thenReturn(existingAuth);

        // Act
        var required = filter.authenticationIsRequired("jdoe");

        // Assert
        assertFalse(required, "Authentication should NOT be required when same user is already authenticated");
    }

    @Test
    void testAuthenticationIsRequired_DifferentUser() {
        // Arrange
        var userDetails = createUserDetails("jdoe", "ROLE_USER");
        var existingAuth = new PatAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        when(securityContext.getAuthentication()).thenReturn(existingAuth);

        // Act
        var required = filter.authenticationIsRequired("jsmith");

        // Assert
        assertTrue(required, "Authentication should be required when different user");
    }

    @Test
    void testDoFilter_ParsedTokenPassedCorrectly() throws ServletException, IOException {
        // Arrange - Test that token is parsed correctly and passed to service
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + TEST_TOKEN_VALUE);

        var tokenCaptor = ArgumentCaptor.forClass(PatToken.class);

        var userDetails = createUserDetails("jdoe", "ROLE_USER");
        var authentication = new PatAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        PatAuthResolution resolution = PatAuthResolution.valid(authentication);

        when(patAuthService.resolveAuthentication(any(PatToken.class))).thenReturn(resolution);

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert - Verify the token was parsed and passed with correct publicId and secret
        verify(patAuthService).resolveAuthentication(tokenCaptor.capture());

        var capturedToken = tokenCaptor.getValue();
        assertEquals(TEST_PUBLIC_ID, capturedToken.publicId());
        assertEquals(TEST_SECRET, capturedToken.secret());
    }

    // V11: a token whose resolution throws (its user deleted meanwhile, a database failure) still gets one audit line
    @Test
    @StdIo
    void testDoFilter_ResolutionThrows_AuditsFailureAndRethrows(StdErr err) throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + TEST_TOKEN_VALUE);
        var failure = new UsernameNotFoundException("gone");
        when(patAuthService.resolveAuthentication(any(PatToken.class))).thenThrow(failure);

        // Act
        var thrown = assertThrows(UsernameNotFoundException.class,
                () -> filter.doFilterInternal(request, response, filterChain));

        // Assert - the same exception propagates; the filter neither answers, continues nor changes the context
        assertSame(failure, thrown);
        verify(filterChain, never()).doFilter(any(), any());
        verify(securityContextHolderStrategy, never()).setContext(any());
        assertEquals(200, response.getStatus());
        assertNull(response.getErrorMessage());

        // Assert - exactly one failure line, with the public ID and never the secret or the token
        var marker = " " + AUDIT_LOGGER + " - ";
        var lines = err.capturedString().lines().filter(l -> l.contains(marker)).toList();
        assertEquals(1, lines.size(), () -> "Expected one audit line, got: " + String.join("\n", lines));
        var line = lines.getFirst();
        assertTrue(line.contains("event=auth.failure outcome=failure user=\"-\""), line);
        assertTrue(line.contains(" method=pat"), line);
        assertTrue(line.endsWith(" pat=" + TEST_PUBLIC_ID), line);
        var output = err.capturedString();
        assertFalse(output.contains(TEST_SECRET), "The token secret reached the log output.");
        assertFalse(output.contains(TEST_TOKEN_VALUE), "The token reached the log output.");
    }

    // V11: a valid token gets exactly one success line, carrying the public ID and never the token or its secret
    @Test
    @StdIo
    void testAudit_ValidToken_LogsOneSuccessLine(StdErr err) throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + TEST_TOKEN_VALUE);

        var userDetails = createUserDetails("jdoe", "ROLE_USER");
        var authentication = new PatAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        when(patAuthService.resolveAuthentication(any(PatToken.class)))
                .thenReturn(PatAuthResolution.valid(authentication));

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert - one success line with user, address, method and public ID, written to the audit logger
        var lines = auditLines(err);
        var successLines = lines.stream().filter(l -> l.contains("event=auth.success")).toList();
        assertEquals(1, successLines.size(), "exactly one auth.success line is expected");
        var line = successLines.getFirst();
        assertTrue(line.contains(AUDIT_LOGGER), "the line must be written to the audit logger");
        assertTrue(line.contains("outcome=success"), "the line must carry outcome=success");
        assertTrue(line.contains("user=\"jdoe\""), "the line must carry the authenticated user");
        assertTrue(line.contains("ip=" + request.getRemoteAddr()), "the line must carry the remote address");
        assertTrue(line.contains("method=pat"), "the line must carry method=pat");
        assertTrue(line.contains("pat=" + TEST_PUBLIC_ID), "the line must carry the public ID");
        assertTrue(lines.stream().noneMatch(l -> l.contains("event=auth.failure")),
                "no auth.failure line is expected");
        verify(filterChain, times(1)).doFilter(request, response);
        assertNoSecretCaptured(err);
    }

    // V11: an unparsable token gets exactly one failure line, without a public ID and without the token itself
    @Test
    @StdIo
    void testAudit_MalformedToken_LogsOneFailureLineWithoutPublicId(StdErr err) throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token invalid-token-format");

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert - the response is unchanged
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        verify(filterChain, never()).doFilter(request, response);

        // Assert - one failure line, with no user, no public ID and not the presented value
        var lines = auditLines(err);
        var failureLines = lines.stream().filter(l -> l.contains("event=auth.failure")).toList();
        assertEquals(1, failureLines.size(), "exactly one auth.failure line is expected");
        var line = failureLines.getFirst();
        assertTrue(line.contains(AUDIT_LOGGER), "the line must be written to the audit logger");
        assertTrue(line.contains("outcome=failure"), "the line must carry outcome=failure");
        assertTrue(line.contains("user=\"-\""), "the line must not name a user");
        assertTrue(line.contains("method=pat"), "the line must carry method=pat");
        assertFalse(line.contains(" pat="), "the line must not carry a public ID for an unparsable token");
        assertTrue(lines.stream().noneMatch(l -> l.contains("event=auth.success")),
                "no auth.success line is expected");
        assertTrue(Stream.of(err.capturedLines()).noneMatch(l -> l.contains("invalid-token-format")),
                "captured output must not contain the presented token value");
        assertNoSecretCaptured(err);
    }

    // V11: a parsed token that does not resolve gets exactly one failure line with its public ID
    @Test
    @StdIo
    void testAudit_InvalidResolution_LogsOneFailureLineWithPublicId(StdErr err) throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + TEST_TOKEN_VALUE);
        when(patAuthService.resolveAuthentication(any(PatToken.class))).thenReturn(PatAuthResolution.invalid());

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert - the response is unchanged
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        verify(filterChain, never()).doFilter(request, response);

        // Assert - one failure line with the public ID and no user
        var lines = auditLines(err);
        var failureLines = lines.stream().filter(l -> l.contains("event=auth.failure")).toList();
        assertEquals(1, failureLines.size(), "exactly one auth.failure line is expected");
        var line = failureLines.getFirst();
        assertTrue(line.contains(AUDIT_LOGGER), "the line must be written to the audit logger");
        assertTrue(line.contains("outcome=failure"), "the line must carry outcome=failure");
        assertTrue(line.contains("user=\"-\""), "the line must not name a user");
        assertTrue(line.contains("method=pat"), "the line must carry method=pat");
        assertTrue(line.contains("pat=" + TEST_PUBLIC_ID), "the line must carry the public ID");
        assertTrue(lines.stream().noneMatch(l -> l.contains("event=auth.success")),
                "no auth.success line is expected");
        assertNoSecretCaptured(err);
    }

    // V11: a valid token of the user already in the context is logged once, and the context is left as it is
    @Test
    @StdIo
    void testAudit_ValidTokenSameUserInContext_LogsSuccessWithoutReplacingContext(StdErr err)
            throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + TEST_TOKEN_VALUE);

        // Existing authentication for jdoe
        var existingUserDetails = createUserDetails("jdoe", "ROLE_USER");
        var existingAuth = new PatAuthenticationToken(
                existingUserDetails,
                null,
                existingUserDetails.getAuthorities()
        );
        when(securityContext.getAuthentication()).thenReturn(existingAuth);

        // New PAT authentication also for jdoe
        var newUserDetails = createUserDetails("jdoe", "ROLE_USER");
        var newAuth = new PatAuthenticationToken(
                newUserDetails,
                null,
                newUserDetails.getAuthorities()
        );
        when(patAuthService.resolveAuthentication(any(PatToken.class))).thenReturn(PatAuthResolution.valid(newAuth));

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert - the success is logged even though the context is not replaced
        var successLines = auditLines(err).stream().filter(l -> l.contains("event=auth.success")).toList();
        assertEquals(1, successLines.size(), "exactly one auth.success line is expected");
        var line = successLines.getFirst();
        assertTrue(line.contains("user=\"jdoe\""), "the line must carry the authenticated user");
        assertTrue(line.contains("pat=" + TEST_PUBLIC_ID), "the line must carry the public ID");

        // Assert - the context decision is unchanged
        verify(securityContextHolderStrategy, never()).createEmptyContext();
        verify(securityContextHolderStrategy, never()).setContext(any());
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain, times(1)).doFilter(request, response);
        assertEquals(200, response.getStatus());
        assertNoSecretCaptured(err);
    }

    // V11: a request without the Token prefix is not a PAT attempt, so it writes no audit line
    @Test
    @StdIo
    void testAudit_BearerHeader_LogsNothing(StdErr err) throws ServletException, IOException {
        // Arrange
        var bearerValue = RandomStringUtils.secure().nextAlphanumeric(24);
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + bearerValue);

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        assertTrue(auditLines(err).isEmpty(), "no audit line is expected for a request without a PAT");
        assertTrue(Stream.of(err.capturedLines()).noneMatch(l -> l.contains(bearerValue)),
                "captured output must not contain the bearer value");
        verify(patAuthService, never()).resolveAuthentication(any(PatToken.class));
        verify(filterChain, times(1)).doFilter(request, response);
        assertNoSecretCaptured(err);
    }

    /**
     * Helper method to create UserDetails with authorities.
     */
    private UserDetails createUserDetails(String username, String... authorities) {
        return new User(
                username,
                RandomStringUtils.secure().nextAlphanumeric(16), // V11: generated password (secret hygiene)
                Stream.of(authorities)
                        .map(SimpleGrantedAuthority::new)
                        .map(a -> (org.springframework.security.core.GrantedAuthority) a)
                        .toList()
        );
    }

    // V11: the captured audit lines, that is every captured line that carries an event pair
    private static List<String> auditLines(StdErr err) {
        return Stream.of(err.capturedLines()).filter(l -> l.contains("event=")).toList();
    }

    // V11: no captured line may contain the PAT or its secret; the message names the fields, never their values
    private static void assertNoSecretCaptured(StdErr err) {
        assertTrue(Stream.of(err.capturedLines())
                        .noneMatch(l -> l.contains(TEST_TOKEN_VALUE) || l.contains(TEST_SECRET)),
                "captured output must not contain the PAT or its secret");
    }
}

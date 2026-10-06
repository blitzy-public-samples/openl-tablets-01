package org.openl.studio.security.pat.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
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

    // V11: every UserDetails password createUserDetails generates in the current test, for assertNoSecretCaptured
    private final List<String> generatedPasswords = new ArrayList<>();

    @BeforeEach
    void setUp() {
        generatedPasswords.clear(); // V11: each test proves only the passwords it generated itself
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
        assertNoResolverCall(); // V11: a value-free zero-call check, so a failure never prints a token argument
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
        assertNoResolverCall(); // V11: a value-free zero-call check, so a failure never prints a token argument
        verify(securityContextHolderStrategy, never()).createEmptyContext();
        verify(filterChain, times(1)).doFilter(request, response);

        assertEquals(200, response.getStatus());
    }

    @Test
    void testDoFilter_InvalidTokenFormat() throws ServletException, IOException {
        // Arrange
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + unparsableTokenValue()); // V11: generated, not literal

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNoResolverCall(); // V11: a value-free zero-call check, so a failure never prints a token argument
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
        // V11: a boolean comparison, so a mismatch never prints either secret
        assertTrue(TEST_SECRET.equals(capturedToken.secret()), "the parsed token must carry the presented secret");
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

        // V11: every generated credential is excluded first, so no later failure can stop that check
        assertNoSecretCaptured(err);

        // Assert - the same exception propagates; the filter neither answers, continues nor changes the context
        assertTrue(failure == thrown, "the resolution failure must propagate unchanged"); // V11: formats neither
        verify(filterChain, never()).doFilter(any(), any());
        verify(securityContextHolderStrategy, never()).setContext(any());
        assertEquals(200, response.getStatus());
        assertNull(response.getErrorMessage());

        // Assert - exactly one failure line, with the public ID
        // V11: the failure messages are fixed and never quote a captured line
        var marker = " " + AUDIT_LOGGER + " - ";
        var lines = err.capturedString().lines().filter(l -> l.contains(marker)).toList();
        assertEquals(1, lines.size(), "exactly one audit line is expected");
        var line = lines.getFirst();
        assertTrue(line.contains("event=auth.failure outcome=failure user=\"-\""),
                "the line must carry event=auth.failure, outcome=failure and no user");
        assertTrue(line.contains(" method=pat"), "the line must carry method=pat");
        assertTrue(line.endsWith(" pat=" + TEST_PUBLIC_ID), "the line must end with the public ID");
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

        // V11: the token, its secret and the generated password are excluded first
        assertNoSecretCaptured(err);

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
    }

    // V11: an unparsable token gets exactly one failure line, without a public ID and without the token itself
    @Test
    @StdIo
    void testAudit_MalformedToken_LogsOneFailureLineWithoutPublicId(StdErr err) throws ServletException, IOException {
        // Arrange
        var presentedValue = unparsableTokenValue(); // V11: generated per run, never a literal credential payload
        request.addHeader(HttpHeaders.AUTHORIZATION, "Token " + presentedValue);

        // Act
        filter.doFilterInternal(request, response, filterChain);

        // V11: the presented value and every generated credential are excluded first
        assertTrue(Stream.of(err.capturedLines()).noneMatch(l -> l.contains(presentedValue)),
                "captured output must not contain the presented token value");
        assertNoSecretCaptured(err, presentedValue);

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

        // V11: the token and its secret are excluded first
        assertNoSecretCaptured(err);

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

        // V11: the token, its secret and both generated passwords are excluded first
        assertNoSecretCaptured(err);

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

        // V11: the bearer value and every generated credential are excluded first
        assertTrue(Stream.of(err.capturedLines()).noneMatch(l -> l.contains(bearerValue)),
                "captured output must not contain the bearer value");
        assertNoSecretCaptured(err, bearerValue);

        // Assert
        assertTrue(auditLines(err).isEmpty(), "no audit line is expected for a request without a PAT");
        assertNoResolverCall(); // V11: a value-free zero-call check, so a failure never prints a token argument
        verify(filterChain, times(1)).doFilter(request, response);
    }

    // V11: an unexpected resolver call fails the zero-call check with its count, never with the token it received
    @Test
    void testAssertNoResolverCall_UnexpectedCall_FailsWithoutTokenValues() {
        // Arrange - an unexpected call with a token generated for this test alone
        var publicId = RandomStringUtils.secure().nextAlphanumeric(PatToken.PUBLIC_ID_LENGTH);
        var secret = RandomStringUtils.secure().nextAlphanumeric(PatToken.SECRET_LENGTH);
        var token = new PatToken(publicId, secret);
        var tokenValue = token.asTokenValue();
        patAuthService.resolveAuthentication(token);

        // Act
        var error = assertThrows(AssertionError.class, this::assertNoResolverCall);

        // Assert - neither the message nor the printed failure carries a token part; no message quotes a value
        var message = String.valueOf(error.getMessage());
        var trace = new StringWriter();
        error.printStackTrace(new PrintWriter(trace, true));
        var printed = trace.toString();
        assertFalse(message.contains(secret), "the failure message must not contain the secret");
        assertFalse(message.contains(publicId), "the failure message must not contain the public ID");
        assertFalse(message.contains(tokenValue), "the failure message must not contain the token");
        assertFalse(printed.contains(secret), "the printed failure must not contain the secret");
        assertFalse(printed.contains(publicId), "the printed failure must not contain the public ID");
        assertFalse(printed.contains(tokenValue), "the printed failure must not contain the token");
        assertNull(error.getCause(), "the failure must not carry a cause");
        assertTrue(error.getSuppressed().length == 0, "the failure must not carry a suppressed error");

        // Assert - the failure still names the check and reports the one unexpected call
        assertTrue(message.contains("resolveAuthentication must not be called"), "the failure must name the check");
        assertTrue(message.contains("but was: <1>"), "the failure must report one unexpected call");
    }

    // V11: counts resolver calls from invocation metadata, so a failure never formats a token argument
    private void assertNoResolverCall() {
        var calls = mockingDetails(patAuthService).getInvocations().stream()
                .filter(invocation -> "resolveAuthentication".equals(invocation.getMethod().getName()))
                .count();
        assertEquals(0, calls, "resolveAuthentication must not be called");
    }

    /**
     * Helper method to create UserDetails with authorities.
     */
    private UserDetails createUserDetails(String username, String... authorities) {
        var password = RandomStringUtils.secure().nextAlphanumeric(16); // V11: generated password (secret hygiene)
        generatedPasswords.add(password); // V11: retained, so assertNoSecretCaptured proves it is never logged
        return new User(
                username,
                password,
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

    /**
     * Fails when the whole capture contains the PAT, its secret, the anonymous key, a password generated by
     * {@link #createUserDetails} or a value the test presented. The messages name the field, never the value.
     */
    // V11: assert that no generated or presented credential reaches captured output, without quoting its value
    private void assertNoSecretCaptured(StdErr err, String... presentedValues) {
        var output = err.capturedString();
        assertFalse(output.contains(TEST_TOKEN_VALUE), "captured output must not contain the PAT");
        assertFalse(output.contains(TEST_SECRET), "captured output must not contain the PAT secret");
        assertFalse(output.contains(ANONYMOUS_KEY), "captured output must not contain the anonymous key");
        assertTrue(generatedPasswords.stream().noneMatch(output::contains),
                "captured output must not contain a generated UserDetails password");
        assertTrue(Stream.of(presentedValues).noneMatch(output::contains),
                "captured output must not contain a value the test presented");
    }

    /**
     * A presented value, generated per run, that can never parse as a PAT: an alphanumeric value has no underscore,
     * so it cannot carry the {@link PatToken#PREFIX} that {@link PatToken#parse} requires.
     */
    // V11: an alphanumeric value cannot contain the required PAT prefix
    private static String unparsableTokenValue() {
        return RandomStringUtils.secure().nextAlphanumeric(24);
    }
}

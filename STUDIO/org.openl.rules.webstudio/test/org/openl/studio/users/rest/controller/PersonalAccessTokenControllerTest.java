package org.openl.studio.users.rest.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.openl.studio.common.exception.BadRequestException;
import org.openl.studio.common.exception.NotFoundException;
import org.openl.studio.security.CurrentUserInfo;
import org.openl.studio.security.audit.SecurityAuditLog;
import org.openl.studio.security.pat.model.PatToken;
import org.openl.studio.security.pat.service.PatGeneratorService;
import org.openl.studio.users.model.pat.CreatePersonalAccessTokenRequest;
import org.openl.studio.users.model.pat.CreatedPersonalAccessTokenResponse;
import org.openl.studio.users.model.pat.PersonalAccessTokenResponse;
import org.openl.studio.users.service.pat.PersonalAccessTokenService;

/**
 * Unit tests for {@link PersonalAccessTokenController}.
 * Tests the V11 audit lines of PAT creation and revocation, the duplicate-name rejection and the read endpoints using
 * mocked dependencies.
 *
 * <p>The unit-test classpath binds slf4j to slf4j-simple, which writes every line to the current
 * {@code System.err}; JUnit Pioneer's {@link StdIo} captures it per test. Every public ID, secret and token name used
 * here is generated at run time. Each token name has the shape of a token, because a name can itself be a credential,
 * and must never reach the output.
 */
@ExtendWith(MockitoExtension.class)
class PersonalAccessTokenControllerTest {

    private static final String LOGIN_NAME = "jdoe";
    private static final Instant CREATED_AT = Instant.parse("2025-01-01T12:00:00Z");

    @Mock
    private PersonalAccessTokenService crudService;

    @Mock
    private PatGeneratorService generatorService;

    @Mock
    private CurrentUserInfo currentUserInfo;

    private PersonalAccessTokenController controller;

    @BeforeEach
    void setUp() {
        controller = new PersonalAccessTokenController(crudService, generatorService, currentUserInfo);
        when(currentUserInfo.getUserName()).thenReturn(LOGIN_NAME);
    }

    @Test
    @StdIo
    void testCreateToken_AuditsTheGeneratedPublicIdOnly(StdErr err) {
        // Arrange
        var publicId = randomPublicId();
        var secret = RandomStringUtils.secure().nextAlphanumeric(PatToken.SECRET_LENGTH);
        var tokenValue = new PatToken(publicId, secret).asTokenValue();
        var tokenName = credentialLookingName();
        var created = CreatedPersonalAccessTokenResponse.builder()
                .publicId(publicId)
                .name(tokenName)
                .loginName(LOGIN_NAME)
                .token(tokenValue)
                .createdAt(CREATED_AT)
                .expiresAt(CREATED_AT.plus(Duration.ofDays(90)))
                .build();
        when(crudService.existsByLoginNameAndName(LOGIN_NAME, tokenName)).thenReturn(false);
        when(generatorService.generateToken(LOGIN_NAME, tokenName, null)).thenReturn(created);

        // Act
        var response = controller.createToken(new CreatePersonalAccessTokenRequest(tokenName, null));

        // Assert - the secret, the token and the token name first, so no later failure can stop that check
        var output = err.capturedString();
        assertFalse(output.contains(secret), "The token secret reached the log output.");
        assertFalse(output.contains(tokenValue), "The token reached the log output.");
        assertFalse(output.contains(tokenName), "The token name reached the log output.");
        // An identity check that never formats the response, whose token() is the full PAT
        assertTrue(created == response, "The generated response must be returned as it is");
        var line = singleAuditLine(err);
        assertTrue(line.contains("event=pat.create outcome=success "), "pat.create must carry outcome=success");
        assertTrue(line.endsWith(" pat=" + publicId), "pat.create must end with the generated public ID");
    }

    @Test
    @StdIo
    void testCreateToken_DuplicateName_ThrowsBadRequestWithoutGeneratingOrAuditing(StdErr err) {
        // Arrange
        var tokenName = credentialLookingName();
        var request = new CreatePersonalAccessTokenRequest(tokenName, null);
        when(crudService.existsByLoginNameAndName(LOGIN_NAME, tokenName)).thenReturn(true);

        // Act & Assert
        var ex = assertThrows(BadRequestException.class, () -> controller.createToken(request));

        // The token name first, so no later failure can stop that check
        var output = err.capturedString();
        assertFalse(output.contains(tokenName), "The token name reached the log output.");
        assertEquals("openl.error.400.pat.duplicate.name.message", ex.getErrorCode());
        verify(generatorService, never()).generateToken(any(), any(), any());
        assertTrue(auditLines(err).isEmpty(), "A duplicate name must write no audit line");
        assertFalse(output.contains("event=pat.create"), "A duplicate name must write no pat.create");
    }

    @Test
    @StdIo
    void testListTokens_ReturnsTheStoredTokensWithoutAuditLine(StdErr err) {
        // Arrange
        var firstName = credentialLookingName();
        var secondName = credentialLookingName();
        var stored = List.of(storedToken(randomPublicId(), firstName), storedToken(randomPublicId(), secondName));
        when(crudService.getTokensByUser(LOGIN_NAME)).thenReturn(stored);

        // Act
        var response = controller.listTokens();

        // Assert - the token names first, so no later failure can stop that check
        var output = err.capturedString();
        assertFalse(output.contains(firstName), "A token name reached the log output.");
        assertFalse(output.contains(secondName), "A token name reached the log output.");
        // An identity check that never formats the tokens, whose names have the shape of a credential
        assertTrue(stored == response, "The stored tokens must be returned as they are");
        assertTrue(auditLines(err).isEmpty(), "Listing tokens must write no audit line");
    }

    @Test
    @StdIo
    void testGetToken_KnownPublicId_ReturnsTheStoredTokenWithoutAuditLine(StdErr err) {
        // Arrange
        var publicId = randomPublicId();
        var tokenName = credentialLookingName();
        var stored = storedToken(publicId, tokenName);
        when(crudService.getTokenForUser(publicId, LOGIN_NAME)).thenReturn(stored);

        // Act
        var response = controller.getToken(publicId);

        // Assert - the token name first, so no later failure can stop that check
        assertFalse(err.capturedString().contains(tokenName), "The token name reached the log output.");
        // An identity check that never formats the token, whose name has the shape of a credential
        assertTrue(stored == response, "The stored token must be returned as it is");
        assertTrue(auditLines(err).isEmpty(), "Reading a token must write no audit line");
    }

    @Test
    @StdIo
    void testGetToken_UnknownPublicId_ThrowsNotFoundWithoutAuditLine(StdErr err) {
        // Arrange
        var pathValue = randomPublicId();
        when(crudService.getTokenForUser(pathValue, LOGIN_NAME)).thenReturn(null);

        // Act & Assert
        var ex = assertThrows(NotFoundException.class, () -> controller.getToken(pathValue));

        assertEquals("openl.error.404.pat.not.found.message", ex.getErrorCode());
        assertTrue(auditLines(err).isEmpty(), "An unknown public ID must write no audit line");
    }

    @Test
    @StdIo
    void testDeleteToken_AuditsTheStoredPublicIdNotThePathValue(StdErr err) {
        // Arrange - a case-insensitive collation matches a path value whose case differs from the stored ID
        var storedId = randomPublicId();
        var pathValue = StringUtils.swapCase(storedId);
        var tokenName = credentialLookingName();
        when(crudService.getTokenForUser(pathValue, LOGIN_NAME)).thenReturn(storedToken(storedId, tokenName));

        // Act
        controller.deleteToken(pathValue);

        // Assert - the stored token name first, so no later failure can stop that check
        assertFalse(err.capturedString().contains(tokenName), "The token name reached the log output.");
        // The deletion is unchanged, and the audit line names the token as pat.create did
        verify(crudService).deleteByPublicId(pathValue);
        var line = singleAuditLine(err);
        assertTrue(line.contains("event=pat.revoke outcome=success "), "pat.revoke must carry outcome=success");
        assertTrue(line.endsWith(" pat=" + storedId), "pat.revoke must end with the stored public ID");
        assertFalse(line.contains(pathValue), "pat.revoke must not carry the path value");
    }

    @Test
    @StdIo
    void testDeleteToken_UnknownPublicId_ThrowsNotFoundWithoutAuditLine(StdErr err) {
        // Arrange
        var pathValue = randomPublicId();
        when(crudService.getTokenForUser(pathValue, LOGIN_NAME)).thenReturn(null);

        // Act & Assert
        var ex = assertThrows(NotFoundException.class, () -> controller.deleteToken(pathValue));

        assertEquals("openl.error.404.pat.not.found.message", ex.getErrorCode());
        verify(crudService, never()).deleteByPublicId(anyString());
        assertTrue(auditLines(err).isEmpty(), "An unknown public ID must write no audit line");
        assertFalse(err.capturedString().contains("event=pat.revoke"), "An unknown public ID must write no pat.revoke");
    }

    /** A stored token as the CRUD service returns it, without any secret. */
    private static PersonalAccessTokenResponse storedToken(String publicId, String name) {
        return PersonalAccessTokenResponse.builder()
                .publicId(publicId)
                .name(name)
                .loginName(LOGIN_NAME)
                .createdAt(CREATED_AT)
                .expiresAt(CREATED_AT.plus(Duration.ofDays(90)))
                .build();
    }

    /** A Base62 public ID of letters only, so that swapping its case always yields a different value. */
    private static String randomPublicId() {
        return RandomStringUtils.secure().nextAlphabetic(PatToken.PUBLIC_ID_LENGTH);
    }

    /** A token name shaped like a token, with a generated public ID and secret of its own. */
    private static String credentialLookingName() {
        return new PatToken(randomPublicId(), RandomStringUtils.secure().nextAlphanumeric(PatToken.SECRET_LENGTH))
                .asTokenValue();
    }

    /** The captured lines written by the audit logger, in order. */
    private static List<String> auditLines(StdErr err) {
        var marker = " " + SecurityAuditLog.LOGGER_NAME + " - ";
        return err.capturedString().lines().filter(l -> l.contains(marker)).toList();
    }

    /** Asserts that exactly one audit line was written and returns it; the failure message never quotes a line. */
    private static String singleAuditLine(StdErr err) {
        var lines = auditLines(err);
        assertEquals(1, lines.size(), "Expected exactly one audit line");
        return lines.getFirst();
    }
}

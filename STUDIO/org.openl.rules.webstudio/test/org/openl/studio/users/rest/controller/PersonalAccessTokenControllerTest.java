package org.openl.studio.users.rest.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
 * Tests the V11 audit lines of PAT creation and revocation using mocked dependencies.
 *
 * <p>The unit-test classpath binds slf4j to slf4j-simple, which writes every line to the current
 * {@code System.err}; JUnit Pioneer's {@link StdIo} captures it per test. Every public ID and secret used here is
 * generated at run time.
 */
@ExtendWith(MockitoExtension.class)
class PersonalAccessTokenControllerTest {

    private static final String LOGIN_NAME = "jdoe";
    private static final String TOKEN_NAME = "My Token";
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
        var created = CreatedPersonalAccessTokenResponse.builder()
                .publicId(publicId)
                .name(TOKEN_NAME)
                .loginName(LOGIN_NAME)
                .token(tokenValue)
                .createdAt(CREATED_AT)
                .expiresAt(CREATED_AT.plus(Duration.ofDays(90)))
                .build();
        when(crudService.existsByLoginNameAndName(LOGIN_NAME, TOKEN_NAME)).thenReturn(false);
        when(generatorService.generateToken(LOGIN_NAME, TOKEN_NAME, null)).thenReturn(created);

        // Act
        var response = controller.createToken(new CreatePersonalAccessTokenRequest(TOKEN_NAME, null));

        // Assert - the secret and the token first, so no later failure can stop that check
        var output = err.capturedString();
        assertFalse(output.contains(secret), "The token secret reached the log output.");
        assertFalse(output.contains(tokenValue), "The token reached the log output.");
        // An identity check that never formats the response, whose token() is the full PAT
        assertTrue(created == response, "The generated response must be returned as it is");
        var line = singleAuditLine(err);
        assertTrue(line.contains("event=pat.create outcome=success "), "pat.create must carry outcome=success");
        assertTrue(line.endsWith(" pat=" + publicId), "pat.create must end with the generated public ID");
    }

    @Test
    @StdIo
    void testDeleteToken_AuditsTheStoredPublicIdNotThePathValue(StdErr err) {
        // Arrange - a case-insensitive collation matches a path value whose case differs from the stored ID
        var storedId = randomPublicId();
        var pathValue = StringUtils.swapCase(storedId);
        when(crudService.getTokenForUser(pathValue, LOGIN_NAME)).thenReturn(storedToken(storedId));

        // Act
        controller.deleteToken(pathValue);

        // Assert - the deletion is unchanged, and the audit line names the token as pat.create did
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
    private static PersonalAccessTokenResponse storedToken(String publicId) {
        return PersonalAccessTokenResponse.builder()
                .publicId(publicId)
                .name(TOKEN_NAME)
                .loginName(LOGIN_NAME)
                .createdAt(CREATED_AT)
                .expiresAt(CREATED_AT.plus(Duration.ofDays(90)))
                .build();
    }

    /** A Base62 public ID of letters only, so that swapping its case always yields a different value. */
    private static String randomPublicId() {
        return RandomStringUtils.secure().nextAlphabetic(PatToken.PUBLIC_ID_LENGTH);
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

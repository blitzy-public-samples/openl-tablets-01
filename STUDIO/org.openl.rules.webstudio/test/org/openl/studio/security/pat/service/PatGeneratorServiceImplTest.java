package org.openl.studio.security.pat.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.openl.rules.security.standalone.persistence.PersonalAccessToken;
import org.openl.studio.common.exception.BadRequestException;
import org.openl.studio.security.pat.model.PatToken;
import org.openl.studio.users.service.pat.PersonalAccessTokenService;

/**
 * Unit tests for {@link PatGeneratorServiceImpl}.
 * Tests token generation logic using mocked dependencies.
 */
@ExtendWith(MockitoExtension.class)
class PatGeneratorServiceImplTest {

    private static final Instant FIXED_TIME = Instant.parse("2025-01-01T12:00:00Z");

    @Mock
    private PersonalAccessTokenService crudService;

    private PasswordEncoder passwordEncoder;
    private PatGeneratorService generatorService;

    @BeforeEach
    void setUp() {
        // Use real BCrypt encoder for realistic password hashing
        passwordEncoder = new BCryptPasswordEncoder(10);

        // Use fixed clock for deterministic time-based testing
        Clock clock = Clock.fixed(FIXED_TIME, ZoneId.of("UTC"));

        // Create service with mocked CRUD service
        // V8: default and maximum lifetime
        generatorService = new PatGeneratorServiceImpl(crudService, passwordEncoder, clock,
                Duration.ofDays(90), Duration.ofDays(365));
    }

    @Test
    void testGenerateToken_WithoutExpiration() {
        // Arrange
        when(crudService.existsByPublicId(anyString())).thenReturn(false);

        // Act
        var response = generatorService.generateToken("jdoe", "My Token", null);

        // Assert
        assertNotNull(response);
        assertEquals("jdoe", response.loginName());
        assertEquals("My Token", response.name());
        assertEquals(FIXED_TIME, response.createdAt());
        assertEquals(FIXED_TIME.plus(Duration.ofDays(90)), response.expiresAt()); // V8: null expiry defaults to 90 days

        // Verify publicId format and length (16 chars, base62)
        assertNotNull(response.publicId());
        assertEquals(16, response.publicId().length());
        assertTrue(response.publicId().matches("^[0-9a-zA-Z]+$"));

        // Verify token format: openl_pat_<publicId>.<secret>
        assertNotNull(response.token());
        assertTrue(response.token().startsWith(PatToken.PREFIX));
        var parts = response.token().substring(PatToken.PREFIX.length()).split("\\.");
        assertEquals(2, parts.length, "Token should have publicId and secret parts");
        assertEquals(response.publicId(), parts[0], "Token publicId should match response publicId");
        assertEquals(32, parts[1].length(), "Secret should be 32 characters");

        // Verify service interactions
        verify(crudService, times(1)).existsByPublicId(anyString());
        verify(crudService, times(1)).save(any(PersonalAccessToken.class));

        // V8: the saved token carries the default expiry, too
        var tokenCaptor = ArgumentCaptor.forClass(PersonalAccessToken.class);
        verify(crudService).save(tokenCaptor.capture());
        assertEquals(FIXED_TIME.plus(Duration.ofDays(90)), tokenCaptor.getValue().getExpiresAt());
    }

    @Test
    void testGenerateToken_WithFutureExpiration() {
        // Arrange
        var futureExpiration = FIXED_TIME.plusSeconds(86400); // 1 day later
        when(crudService.existsByPublicId(anyString())).thenReturn(false);

        // Act
        var response = generatorService.generateToken("jdoe", "My Token", futureExpiration);

        // Assert
        assertNotNull(response);
        assertEquals("jdoe", response.loginName());
        assertEquals("My Token", response.name());
        assertEquals(FIXED_TIME, response.createdAt());
        assertEquals(futureExpiration, response.expiresAt());

        verify(crudService, times(1)).save(any(PersonalAccessToken.class));
    }

    @Test
    void testGenerateToken_WithPastExpiration_ThrowsException() {
        // Arrange
        var pastExpiration = FIXED_TIME.minusSeconds(3600); // 1 hour ago

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> generatorService.generateToken("jdoe", "My Token", pastExpiration));

        assertEquals("expiresAt must be in the future", exception.getMessage());

        // Verify no token was saved
        verify(crudService, never()).save(any(PersonalAccessToken.class));
    }

    @Test
    void testGenerateToken_WithExpirationAtCurrentTime_IsValid() {
        // Arrange
        // Implementation uses isBefore(), so expiring exactly at current time is valid
        var currentTime = FIXED_TIME;
        when(crudService.existsByPublicId(anyString())).thenReturn(false);

        // Act
        var response = generatorService.generateToken("jdoe", "My Token", currentTime);

        // Assert
        assertNotNull(response);
        assertEquals(currentTime, response.expiresAt());

        verify(crudService, times(1)).save(any(PersonalAccessToken.class));
    }

    @Test
    void testGenerateToken_HandlesPublicIdCollision() {
        // Arrange
        // Simulate collision on first attempt, then success
        when(crudService.existsByPublicId(anyString()))
                .thenReturn(true)   // First attempt: collision
                .thenReturn(true)   // Second attempt: collision
                .thenReturn(false); // Third attempt: success

        // Act
        var response = generatorService.generateToken("jdoe", "My Token", null);

        // Assert
        assertNotNull(response);
        assertEquals("jdoe", response.loginName());

        // Verify retry behavior - should check 3 times
        verify(crudService, times(3)).existsByPublicId(anyString());
        verify(crudService, times(1)).save(any(PersonalAccessToken.class));
    }

    @Test
    void testGenerateToken_SavedTokenHasHashedSecret() {
        // Arrange
        when(crudService.existsByPublicId(anyString())).thenReturn(false);
        var tokenCaptor = ArgumentCaptor.forClass(PersonalAccessToken.class);

        // Act
        var response = generatorService.generateToken("jdoe", "My Token", null);

        // Assert
        verify(crudService).save(tokenCaptor.capture());

        var savedToken = tokenCaptor.getValue();
        assertNotNull(savedToken.getSecretHash());

        // Verify secret is hashed (BCrypt hashes start with $2a$ or $2b$)
        assertTrue(savedToken.getSecretHash().startsWith("$2"), "Secret should be BCrypt hashed");

        // Verify raw secret from response is NOT the same as stored hash
        var rawSecret = response.token().substring(PatToken.PREFIX.length()).split("\\.")[1];
        assertNotEquals(rawSecret, savedToken.getSecretHash(), "Secret should be hashed before storage");

        // Verify BCrypt can validate the secret
        assertTrue(passwordEncoder.matches(rawSecret, savedToken.getSecretHash()),
                "Stored hash should match the raw secret");
    }

    @Test
    void testGenerateToken_SavedTokenHasCorrectFields() {
        // Arrange
        var futureExpiration = FIXED_TIME.plusSeconds(86400);
        when(crudService.existsByPublicId(anyString())).thenReturn(false);
        var tokenCaptor = ArgumentCaptor.forClass(PersonalAccessToken.class);

        // Act
        var response = generatorService.generateToken("jdoe", "My Token", futureExpiration);

        // Assert
        verify(crudService).save(tokenCaptor.capture());

        var savedToken = tokenCaptor.getValue();
        assertEquals(response.publicId(), savedToken.getPublicId());
        assertEquals("jdoe", savedToken.getLoginName());
        assertEquals("My Token", savedToken.getName());
        assertEquals(FIXED_TIME, savedToken.getCreatedAt());
        assertEquals(futureExpiration, savedToken.getExpiresAt());
        assertNotNull(savedToken.getSecretHash());
    }

    @Test
    void testGenerateToken_MultipleCalls_GenerateDifferentTokens() {
        // Arrange
        when(crudService.existsByPublicId(anyString())).thenReturn(false);

        // Act
        var response1 = generatorService.generateToken("jdoe", "Token 1", null);
        var response2 = generatorService.generateToken("jdoe", "Token 2", null);

        // Assert
        assertNotEquals(response1.publicId(), response2.publicId(), "PublicIds should be different");
        assertNotEquals(response1.token(), response2.token(), "Full tokens should be different");

        verify(crudService, times(2)).save(any(PersonalAccessToken.class));
    }

    @Test
    void testGenerateToken_ResponseContainsAllFields() {
        // Arrange
        var futureExpiration = FIXED_TIME.plusSeconds(86400);
        when(crudService.existsByPublicId(anyString())).thenReturn(false);

        // Act
        var response = generatorService.generateToken("jsmith", "Test Token", futureExpiration);

        // Assert - verify all fields are populated
        assertNotNull(response.publicId());
        assertNotNull(response.name());
        assertNotNull(response.loginName());
        assertNotNull(response.token());
        assertNotNull(response.createdAt());
        assertNotNull(response.expiresAt());

        assertEquals("jsmith", response.loginName());
        assertEquals("Test Token", response.name());
        assertEquals(FIXED_TIME, response.createdAt());
        assertEquals(futureExpiration, response.expiresAt());
    }

    @Test
    void testGenerateToken_TokenCanBeParsed() {
        // Arrange
        when(crudService.existsByPublicId(anyString())).thenReturn(false);

        // Act
        var response = generatorService.generateToken("jdoe", "My Token", null);

        // Assert - verify token can be parsed back to PatToken
        PatToken parsedToken = PatToken.parse(response.token());
        assertEquals(response.publicId(), parsedToken.publicId());
        assertNotNull(parsedToken.secret());
        assertEquals(32, parsedToken.secret().length());
    }

    @Test
    void testGenerateToken_VerifyPublicIdUniqueness() {
        // Arrange
        var publicIdCaptor = ArgumentCaptor.forClass(String.class);
        when(crudService.existsByPublicId(anyString())).thenReturn(false);

        // Act
        generatorService.generateToken("jdoe", "My Token", null);

        // Assert
        verify(crudService).existsByPublicId(publicIdCaptor.capture());
        var checkedPublicId = publicIdCaptor.getValue();

        // Verify the publicId checked for uniqueness matches what was saved
        verify(crudService).save(argThat(token ->
                token.getPublicId().equals(checkedPublicId)
        ));
    }

    @Test
    void testGenerateToken_DifferentUsers() {
        // Arrange
        when(crudService.existsByPublicId(anyString())).thenReturn(false);

        // Act
        var response1 = generatorService.generateToken("jdoe", "Token 1", null);
        var response2 = generatorService.generateToken("jsmith", "Token 2", null);

        // Assert
        assertEquals("jdoe", response1.loginName());
        assertEquals("jsmith", response2.loginName());
        assertNotEquals(response1.publicId(), response2.publicId());
        assertNotEquals(response1.token(), response2.token());

        verify(crudService, times(2)).save(any(PersonalAccessToken.class));
    }

    @Test
    void testGenerateToken_WithLongTokenName() {
        // Arrange
        var longName = "A".repeat(100); // Max length per schema
        when(crudService.existsByPublicId(anyString())).thenReturn(false);

        // Act
        var response = generatorService.generateToken("jdoe", longName, null);

        // Assert
        assertEquals(longName, response.name());

        verify(crudService).save(argThat(token ->
                token.getName().equals(longName)
        ));
    }

    @Test
    void testGenerateToken_PublicIdAndSecretAreBase62() {
        // Arrange
        when(crudService.existsByPublicId(anyString())).thenReturn(false);

        // Act
        var response = generatorService.generateToken("jdoe", "My Token", null);

        // Assert
        var fullToken = response.token();
        var tokenWithoutPrefix = fullToken.substring(PatToken.PREFIX.length());
        var parts = tokenWithoutPrefix.split("\\.");

        // Both publicId and secret should only contain base62 characters
        assertTrue(parts[0].matches("^[0-9a-zA-Z]+$"), "PublicId should be base62");
        assertTrue(parts[1].matches("^[0-9a-zA-Z]+$"), "Secret should be base62");

        // Verify they don't contain invalid characters
        assertFalse(parts[0].contains("-"), "PublicId should not contain hyphens");
        assertFalse(parts[0].contains("_"), "PublicId should not contain underscores");
        assertFalse(parts[1].contains("-"), "Secret should not contain hyphens");
        assertFalse(parts[1].contains("_"), "Secret should not contain underscores");
    }

    // V8: builds a service with custom lifetimes over the same fixed clock
    private PatGeneratorServiceImpl newService(Duration defaultLifetime, Duration maxLifetime) {
        return new PatGeneratorServiceImpl(crudService,
                passwordEncoder,
                Clock.fixed(FIXED_TIME, ZoneId.of("UTC")),
                defaultLifetime,
                maxLifetime);
    }

    // V8: an expiration exactly at now + maximum lifetime is accepted and stored as given
    @Test
    void testGenerateToken_AtMaximumExpiration_IsAccepted() {
        // Arrange
        var maxExpiration = FIXED_TIME.plus(Duration.ofDays(365));
        when(crudService.existsByPublicId(anyString())).thenReturn(false);
        var tokenCaptor = ArgumentCaptor.forClass(PersonalAccessToken.class);

        // Act
        var response = generatorService.generateToken("jdoe", "My Token", maxExpiration);

        // Assert
        assertEquals(maxExpiration, response.expiresAt());
        verify(crudService).save(tokenCaptor.capture());
        assertEquals(maxExpiration, tokenCaptor.getValue().getExpiresAt());
    }

    // V8: an expiration one second beyond now + maximum lifetime is rejected with 400 before anything is stored
    @Test
    void testGenerateToken_BeyondMaximumExpiration_ThrowsBadRequest() {
        // Arrange
        var tooLate = FIXED_TIME.plus(Duration.ofDays(365)).plusSeconds(1);

        // Act & Assert
        var ex = assertThrows(BadRequestException.class,
                () -> generatorService.generateToken("jdoe", "My Token", tooLate));

        assertEquals("openl.error.400.pat.expires-at.max.message", ex.getErrorCode());
        assertEquals("365", String.valueOf(ex.getArgs()[0]));
        verify(crudService, never()).existsByPublicId(anyString());
        verify(crudService, never()).save(any(PersonalAccessToken.class));
    }

    // V8: configured default and maximum lifetimes are honored
    @Test
    void testGenerateToken_CustomLifetimes_AreHonored() {
        // Arrange
        var service = newService(Duration.ofDays(7), Duration.ofDays(30));
        when(crudService.existsByPublicId(anyString())).thenReturn(false);
        var maxExpiration = FIXED_TIME.plus(Duration.ofDays(30));

        // Act
        var defaulted = service.generateToken("jdoe", "Token 1", null);
        var atMaximum = service.generateToken("jdoe", "Token 2", maxExpiration);
        var ex = assertThrows(BadRequestException.class,
                () -> service.generateToken("jdoe", "Token 3", maxExpiration.plusSeconds(1)));

        // Assert
        assertEquals(FIXED_TIME.plus(Duration.ofDays(7)), defaulted.expiresAt());
        assertEquals(maxExpiration, atMaximum.expiresAt());
        assertEquals("openl.error.400.pat.expires-at.max.message", ex.getErrorCode());
        assertEquals("30", String.valueOf(ex.getArgs()[0]));
        verify(crudService, times(2)).save(any(PersonalAccessToken.class));
    }

    // V8: a null, zero or negative lifetime, or a default above the maximum, fails at construction
    @Test
    void testConstructor_RejectsInvalidLifetimes() {
        var max = Duration.ofDays(365);
        var def = Duration.ofDays(90);

        assertThrows(IllegalArgumentException.class, () -> newService(null, max));
        assertThrows(IllegalArgumentException.class, () -> newService(Duration.ZERO, max));
        assertThrows(IllegalArgumentException.class, () -> newService(Duration.ofDays(-1), max));
        assertThrows(IllegalArgumentException.class, () -> newService(def, null));
        assertThrows(IllegalArgumentException.class, () -> newService(def, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> newService(def, Duration.ofDays(-1)));
        assertThrows(IllegalArgumentException.class, () -> newService(Duration.ofDays(31), Duration.ofDays(30)));

        // Equal default and maximum are a valid configuration
        assertNotNull(newService(Duration.ofDays(30), Duration.ofDays(30)));
    }
}

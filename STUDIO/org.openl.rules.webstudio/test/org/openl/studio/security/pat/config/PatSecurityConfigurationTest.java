package org.openl.studio.security.pat.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.List;
import java.util.function.BiFunction;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.SimpleTypeConverter;
import org.springframework.beans.TypeMismatchException;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.openl.rules.security.standalone.dao.PersonalAccessTokenDao;
import org.openl.rules.security.standalone.dao.UserDao;
import org.openl.rules.security.standalone.persistence.PersonalAccessToken;
import org.openl.rules.webstudio.service.AdminUsers;
import org.openl.rules.webstudio.service.ExternalGroupService;
import org.openl.studio.common.exception.BadRequestException;
import org.openl.studio.security.GetUserPrivileges;
import org.openl.studio.security.pat.filter.PatAuthenticationFilter;
import org.openl.studio.security.pat.service.PatAuthServiceImpl;
import org.openl.studio.security.pat.service.PatGeneratorServiceImpl;
import org.openl.studio.security.pat.service.PatUserInfoUserDetailsServiceImpl;
import org.openl.studio.security.pat.service.PatValidationServiceImpl;
import org.openl.studio.users.service.pat.PersonalAccessTokenService;

/**
 * Unit tests for {@link PatSecurityConfiguration}: V8 PAT lifetime properties that cannot be bound to an
 * {@code int} number of days stop the startup with an error naming the property, and never with a type conversion
 * error on a {@code patGeneratorService} parameter.
 * <p>
 * The configuration's own check accepts exactly the values Spring's {@code int} binding accepts. Whether a lifetime
 * is positive, and whether the default exceeds the maximum, stays with {@link PatGeneratorServiceImpl}. No token is
 * generated: the generator is only driven down its rejection path, which runs before anything is generated.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
class PatSecurityConfigurationTest {

    private static final String DEFAULT_KEY = "security.pat.default-expiration-days";
    private static final String MAX_KEY = "security.pat.max-expiration-days";
    private static final String NOT_WHOLE_DAYS = " must be a positive whole number of days, at most 2147483647";
    private static final Instant FIXED_TIME = Instant.parse("2025-01-01T12:00:00Z");

    @Mock
    private PersonalAccessTokenService crudService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private PersonalAccessTokenDao tokenDao;

    @Mock
    private UserDao userDao;

    @Mock
    private AdminUsers adminUsers;

    @Mock
    private BiFunction<String, Collection<? extends GrantedAuthority>, Collection<GrantedAuthority>> privilegeMapper;

    @Mock
    private ExternalGroupService externalGroupService;

    @ParameterizedTest
    @ValueSource(strings = {"90", "365", " 90 ", "+90", "0x5A"})
    void acceptsWholeNumbersOfDays(String value) {
        assertDoesNotThrow(() -> new PatSecurityConfiguration(value, "365"), DEFAULT_KEY);
        assertDoesNotThrow(() -> new PatSecurityConfiguration("90", value), MAX_KEY);
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc", "1.5", "", "9999999999"})
    void rejectsADefaultThatIsNotAWholeNumberOfDays(String value) {
        var e = assertThrows(IllegalArgumentException.class, () -> new PatSecurityConfiguration(value, "365"));

        // The exact message names the property and cannot contain the rejected value
        assertEquals(DEFAULT_KEY + NOT_WHOLE_DAYS, e.getMessage());
        assertInstanceOf(NumberFormatException.class, e.getCause());
    }

    @ParameterizedTest
    @ValueSource(strings = {"xyz", "1.5", "", "9999999999"})
    void rejectsAMaximumThatIsNotAWholeNumberOfDays(String value) {
        var e = assertThrows(IllegalArgumentException.class, () -> new PatSecurityConfiguration("90", value));

        assertEquals(MAX_KEY + NOT_WHOLE_DAYS, e.getMessage());
        assertInstanceOf(NumberFormatException.class, e.getCause());
    }

    @Test
    void reportsTheDefaultFirstWhenBothValuesAreInvalid() {
        var e = assertThrows(IllegalArgumentException.class, () -> new PatSecurityConfiguration("abc", "xyz"));

        assertEquals(DEFAULT_KEY + NOT_WHOLE_DAYS, e.getMessage());
    }

    @Test
    void rejectsAMissingValueNamingTheProperty() {
        var e = assertThrows(IllegalArgumentException.class, () -> new PatSecurityConfiguration("90", null));

        assertEquals(MAX_KEY + NOT_WHOLE_DAYS, e.getMessage());
        assertInstanceOf(IllegalArgumentException.class, e.getCause());
    }

    /**
     * The check must not tighten or loosen what starts today: a value passes it exactly when Spring's default
     * {@code String} to {@code int} conversion, which the bean factory applies to {@code @Value int} parameters when
     * no conversion service is configured, accepts it. Values such as {@code -1} or {@code 0} pass here and are
     * rejected by the generator.
     */
    @ParameterizedTest
    @ValueSource(strings = {"90", " 90 ", "\t90\n", "9 0", "+90", "-1", "0", "0x5A", "#5A", "2147483647", "abc",
            "1.5", "", " ", "9999999999", "2147483648", "90d", "1e2", "0x"})
    void acceptsExactlyTheValuesTheIntBindingAccepts(String value) {
        boolean bindsToInt = bindsToInt(value);

        assertEquals(bindsToInt, constructs(value, "365"), DEFAULT_KEY);
        assertEquals(bindsToInt, constructs("90", value), MAX_KEY);
    }

    @ParameterizedTest
    @CsvSource({
            "abc, 365, " + DEFAULT_KEY,
            "1.5, 365, " + DEFAULT_KEY,
            "'', 365, " + DEFAULT_KEY,
            "9999999999, 365, " + DEFAULT_KEY,
            "90, xyz, " + MAX_KEY})
    void startupWithAnUnparsableLifetimeFailsNamingItsProperty(String defaultDays, String maxDays, String key) {
        var e = assertThrows(BeanCreationException.class,
                () -> context("multi", defaultDays, maxDays, privilegeMapper));

        List<Throwable> chain = ExceptionUtils.getThrowableList(e);
        assertTrue(chain.stream().noneMatch(TypeMismatchException.class::isInstance),
                () -> "no int conversion of a patGeneratorService parameter may be attempted: " + chain);
        assertTrue(chain.stream()
                        .anyMatch(t -> t instanceof IllegalArgumentException
                                && (key + NOT_WHOLE_DAYS).equals(t.getMessage())),
                () -> "the startup failure must name " + key + ": " + chain);
    }

    @ParameterizedTest
    @CsvSource({
            "0, 365, " + DEFAULT_KEY + " must be a positive number of days",
            "-1, 365, " + DEFAULT_KEY + " must be a positive number of days",
            "90, -5, " + MAX_KEY + " must be a positive number of days",
            "61, 60, " + DEFAULT_KEY + " must not exceed " + MAX_KEY})
    void startupLeavesTheRangeChecksToTheGenerator(String defaultDays, String maxDays, String message) {
        var e = assertThrows(BeanCreationException.class,
                () -> context("multi", defaultDays, maxDays, privilegeMapper));

        List<Throwable> chain = ExceptionUtils.getThrowableList(e);
        assertTrue(chain.stream()
                        .anyMatch(t -> t instanceof IllegalArgumentException && message.equals(t.getMessage())),
                () -> "the generator must reject the configured lifetimes: " + chain);
    }

    @Test
    void validLifetimesReachTheGenerator() {
        try (var context = context("multi", " 30 ", "60", privilegeMapper)) {
            var generator = context.getBean(PatGeneratorServiceImpl.class);
            var tooLate = FIXED_TIME.plus(Duration.ofDays(60)).plusSeconds(1);

            var e = assertThrows(BadRequestException.class, () -> generator.generateToken("jdoe", "Token", tooLate));

            assertEquals("openl.error.400.pat.expires-at.max.message", e.getErrorCode());
            assertEquals("60", String.valueOf(e.getArgs()[0]));
            assertNotNull(context.getBean(PatAuthServiceImpl.class));
            assertNotNull(context.getBean(PatValidationServiceImpl.class));
            assertNotNull(context.getBean(PatUserInfoUserDetailsServiceImpl.class));
            assertNotNull(context.getBean(PatAuthenticationFilter.class));
        }
        verify(crudService, never()).existsByPublicId(anyString());
        verify(crudService, never()).save(any(PersonalAccessToken.class));
    }

    @Test
    void patUserDetailsUseTheNonWarningViewOfGetUserPrivileges() {
        var getUserPrivileges = mock(GetUserPrivileges.class);
        when(getUserPrivileges.withoutAdminMatchWarning()).thenReturn(privilegeMapper);

        try (var context = context("multi", "90", "365", getUserPrivileges)) {
            assertNotNull(context.getBean(PatUserInfoUserDetailsServiceImpl.class));
        }
        verify(getUserPrivileges).withoutAdminMatchWarning();
    }

    @Test
    void singleModeStartsWithUnparsableLifetimes() {
        try (var context = context("single", "abc", "xyz", privilegeMapper)) {
            assertTrue(context.getBeansOfType(PatSecurityConfiguration.class).isEmpty());
            assertTrue(context.getBeansOfType(PatGeneratorServiceImpl.class).isEmpty());
        }
    }

    private AnnotationConfigApplicationContext context(
            String mode,
            String defaultDays,
            String maxDays,
            BiFunction<String, Collection<? extends GrantedAuthority>, Collection<GrantedAuthority>> mapper) {
        var context = new AnnotationConfigApplicationContext();
        context.setEnvironment(new MockEnvironment().withProperty("user.mode", mode)
                .withProperty(DEFAULT_KEY, defaultDays)
                .withProperty(MAX_KEY, maxDays));
        context.registerBean(PersonalAccessTokenService.class, () -> crudService);
        context.registerBean(PasswordEncoder.class, () -> passwordEncoder);
        context.registerBean(Clock.class, () -> Clock.fixed(FIXED_TIME, ZoneOffset.UTC));
        context.registerBean(PersonalAccessTokenDao.class, () -> tokenDao);
        context.registerBean("openlUserDao", UserDao.class, () -> userDao);
        context.registerBean("adminUsersInitializer", AdminUsers.class, () -> adminUsers);
        context.registerBean("privilegeMapper", BiFunction.class, () -> mapper);
        context.registerBean(ExternalGroupService.class, () -> externalGroupService);
        context.register(PatSecurityConfiguration.class);
        context.refresh();
        return context;
    }

    private static boolean bindsToInt(String value) {
        try {
            new SimpleTypeConverter().convertIfNecessary(value, int.class);
            return true;
        } catch (TypeMismatchException e) {
            return false;
        }
    }

    private static boolean constructs(String defaultDays, String maxDays) {
        try {
            new PatSecurityConfiguration(defaultDays, maxDays);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}

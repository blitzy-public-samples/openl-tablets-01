package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * Unit tests for {@link FormBasedAuthenticationManagerConfig}: the global authentication manager that its configurer
 * builds holds no provider of its own, looks the {@code authenticationManager} bean up on the first attempt only and
 * reuses it, retries a lookup that failed, and erases the credentials that the bean keeps. The configurer exists only
 * in the {@code ad} and {@code multi} modes.
 * <p>
 * The passwords are generated per run.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
class FormBasedAuthenticationManagerConfigTest {

    private static final String USER = "form-user";

    @Mock
    private ObjectProvider<AuthenticationManager> authenticationManager;

    @Mock
    private AuthenticationManager bean;

    private final UsernamePasswordAuthenticationToken request = UsernamePasswordAuthenticationToken
            .unauthenticated(USER, RandomStringUtils.secure().nextAlphanumeric(16));

    @Test
    void buildingTheGlobalManagerLooksNothingUp() throws Exception {
        var builder = new AuthenticationManagerBuilder(ObjectPostProcessor.identity());

        FormBasedAuthenticationManagerConfig.formBasedAuthenticationManagerConfigurer(authenticationManager)
                .init(builder);
        AuthenticationManager global = builder.build();

        assertTrue(builder.isConfigured(), "the parent marks the builder as configured");
        var providerManager = assertInstanceOf(ProviderManager.class, global);
        assertTrue(providerManager.getProviders().isEmpty(), "the global manager holds no provider of its own");
        verifyNoInteractions(authenticationManager);
    }

    @Test
    void looksTheBeanUpOnceAndReusesItForEveryAttempt() throws Exception {
        var result = authenticated(RandomStringUtils.secure().nextAlphanumeric(16));
        when(authenticationManager.getObject()).thenReturn(bean);
        when(bean.authenticate(request)).thenReturn(result);
        AuthenticationManager global = buildGlobalManager();

        assertSame(result, global.authenticate(request));
        assertSame(result, global.authenticate(request));
        assertSame(result, global.authenticate(request));

        verify(authenticationManager, times(1)).getObject();
        verify(bean, times(3)).authenticate(request);
    }

    @Test
    void failedLookupIsRetriedOnTheNextAttempt() throws Exception {
        var result = authenticated(RandomStringUtils.secure().nextAlphanumeric(16));
        var missing = new NoSuchBeanDefinitionException("authenticationManager");
        when(authenticationManager.getObject()).thenThrow(missing).thenReturn(bean);
        when(bean.authenticate(request)).thenReturn(result);
        AuthenticationManager global = buildGlobalManager();

        assertSame(missing, assertThrows(NoSuchBeanDefinitionException.class, () -> global.authenticate(request)));
        verify(bean, never()).authenticate(any());

        assertSame(result, global.authenticate(request));
        assertSame(result, global.authenticate(request));

        verify(authenticationManager, times(2)).getObject();
        verify(bean, times(2)).authenticate(request);
    }

    @Test
    void rejectionByTheBeanReachesTheCallerAndKeepsTheBean() throws Exception {
        var result = authenticated(RandomStringUtils.secure().nextAlphanumeric(16));
        var rejection = new BadCredentialsException("Bad credentials");
        when(authenticationManager.getObject()).thenReturn(bean);
        when(bean.authenticate(request)).thenThrow(rejection).thenReturn(result);
        AuthenticationManager global = buildGlobalManager();

        assertSame(rejection, assertThrows(BadCredentialsException.class, () -> global.authenticate(request)));
        assertSame(result, global.authenticate(request));

        verify(authenticationManager, times(1)).getObject();
        verify(bean, times(2)).authenticate(request);
    }

    /**
     * The bean is a {@link ProviderManager} that keeps the credentials, as the {@code authenticationManager} bean
     * does for SAML single logout. The global manager still erases them, because its parent is a delegate and not
     * the bean, so the setting is not passed on.
     */
    @Test
    void globalManagerErasesTheCredentialsThatTheBeanKeeps() throws Exception {
        var credentials = RandomStringUtils.secure().nextAlphanumeric(16);
        var provider = mock(AuthenticationProvider.class);
        when(provider.supports(UsernamePasswordAuthenticationToken.class)).thenReturn(true);
        when(provider.authenticate(request)).thenAnswer(invocation -> authenticated(credentials));
        var keepingManager = new ProviderManager(provider);
        keepingManager.setEraseCredentialsAfterAuthentication(false);
        when(authenticationManager.getObject()).thenReturn(keepingManager);
        AuthenticationManager global = buildGlobalManager();

        assertEquals(credentials, keepingManager.authenticate(request).getCredentials(), "the bean keeps them");
        Authentication result = global.authenticate(request);

        assertNotNull(result);
        assertTrue(result.isAuthenticated());
        assertEquals(USER, result.getName());
        assertNull(result.getCredentials(), "the global manager erases them");
    }

    /**
     * In a Spring context the configurer resolves the {@code authenticationManager} bean through its qualified
     * {@link ObjectProvider}, and the global manager authenticates through that bean.
     */
    @ParameterizedTest
    @ValueSource(strings = {"ad", "multi"})
    void formBasedModesAuthenticateThroughTheAuthenticationManagerBean(String mode) throws Exception {
        var result = authenticated(RandomStringUtils.secure().nextAlphanumeric(16));
        when(bean.authenticate(request)).thenReturn(result);

        try (var context = context(mode)) {
            var builder = new AuthenticationManagerBuilder(ObjectPostProcessor.identity());
            context.getBean(GlobalAuthenticationConfigurerAdapter.class).init(builder);
            AuthenticationManager global = builder.build();

            assertSame(result, global.authenticate(request), "user.mode=" + mode);
        }
        verify(bean, times(1)).authenticate(request);
    }

    @ParameterizedTest
    @ValueSource(strings = {"single", "oauth2", "saml"})
    void otherModesDeclareNoConfigurer(String mode) {
        try (var context = context(mode)) {
            assertTrue(context.getBeansOfType(FormBasedAuthenticationManagerConfig.class).isEmpty(),
                    "user.mode=" + mode + ": configuration");
            assertTrue(context.getBeansOfType(GlobalAuthenticationConfigurerAdapter.class).isEmpty(),
                    "user.mode=" + mode + ": configurer");
        }
        verifyNoInteractions(bean);
    }

    private AnnotationConfigApplicationContext context(String mode) {
        var context = new AnnotationConfigApplicationContext();
        context.setEnvironment(new MockEnvironment().withProperty("user.mode", mode));
        context.registerBean("authenticationManager", AuthenticationManager.class, () -> bean);
        context.register(FormBasedAuthenticationManagerConfig.class);
        context.refresh();
        return context;
    }

    private AuthenticationManager buildGlobalManager() throws Exception {
        var builder = new AuthenticationManagerBuilder(ObjectPostProcessor.identity());
        FormBasedAuthenticationManagerConfig.formBasedAuthenticationManagerConfigurer(authenticationManager)
                .init(builder);
        return builder.build();
    }

    private static UsernamePasswordAuthenticationToken authenticated(String credentials) {
        return UsernamePasswordAuthenticationToken
                .authenticated(USER, credentials, AuthorityUtils.createAuthorityList("ROLE_USER"));
    }
}

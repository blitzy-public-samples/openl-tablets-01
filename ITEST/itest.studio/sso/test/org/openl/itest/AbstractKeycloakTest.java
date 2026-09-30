package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.adobe.testing.s3mock.testcontainers.S3MockContainer;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.apache.http.HttpStatus;

import org.openl.itest.core.JettyServer;

/**
 * Shared setup for integration tests that drive OpenL Studio against a Keycloak Identity Provider: the
 * realm-backed Keycloak container, the Studio server wired to an S3 design repository, and the
 * login-lifecycle assertions reused by the OAuth2 and SAML tests.
 *
 * @author Yury Molchan
 */
abstract class AbstractKeycloakTest {

    // V3: credentials generated once per JVM, replacing the realm's literal user passwords and client secret
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final List<String> REALM_USERS = List.of("admin",
            "user1",
            "guest",
            "epbds12973_deployer",
            "epbds12973_editor",
            "epbds12973_viewer",
            "epbds14584_manager",
            "epbds14584_contributor",
            "epbds14584_viewer",
            "epbds14670_manager",
            "epbds14670_contributor",
            "epbds14670_viewer",
            "epbds14670r_manager",
            "epbds14670r_contributor",
            "epbds14670r_viewer",
            "epbds15131_admin",
            "epbds15134_user",
            "epbds15621_user");
    private static final Map<String, String> PASSWORDS = generatePasswords();
    private static final String CLIENT_SECRET = randomValue();
    private static final String S3_ACCESS_KEY = randomValue();
    private static final String S3_SECRET_KEY = randomValue();

    protected final ObjectMapper mapper = new ObjectMapper();

    // V3: the realm file reads each credential from the container environment at import time
    @SuppressWarnings("resource")
    protected static KeycloakContainer keycloak() {
        var container = new KeycloakContainer("quay.io/keycloak/keycloak:latest")
                .withRealmImportFile("/openlstudio-realm.json");
        for (Map.Entry<String, String> entry : PASSWORDS.entrySet()) {
            container.withEnv("ITEST_PASSWORD_" + entry.getKey().toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]", "_"),
                    entry.getValue());
        }
        container.withEnv("ITEST_CLIENT_SECRET", CLIENT_SECRET);
        return container;
    }

    // V3: generated S3 mock keys instead of literals
    protected static JettyServer studio(S3MockContainer s3) {
        return JettyServer.get()
                .withInitParam("repository.production-s3.service-endpoint", s3.getHttpEndpoint())
                .withInitParam("repository.production-s3.access-key", S3_ACCESS_KEY)
                .withInitParam("repository.production-s3.secret-key", S3_SECRET_KEY);
    }

    // V3: 16 random alphanumerics, safe in the un-encoded token request form body
    protected static String randomValue() {
        StringBuilder builder = new StringBuilder(16);
        for (int i = 0; i < 16; i++) {
            builder.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return builder.toString();
    }

    // V3: the generated password of a realm user
    protected static String password(String user) {
        String password = PASSWORDS.get(user);
        if (password == null) {
            throw new IllegalArgumentException("No generated password for realm user " + user);
        }
        return password;
    }

    // V3: the generated secret of the openlstudio client
    protected static String clientSecret() {
        return CLIENT_SECRET;
    }

    // V3: every generated credential, for leak scans of captured output
    protected static Set<String> generatedSecrets() {
        Set<String> secrets = new LinkedHashSet<>(PASSWORDS.values());
        secrets.add(CLIENT_SECRET);
        secrets.add(S3_ACCESS_KEY);
        secrets.add(S3_SECRET_KEY);
        return Collections.unmodifiableSet(secrets);
    }

    // V3: one generated password per realm user, in realm order
    private static Map<String, String> generatePasswords() {
        Map<String, String> passwords = new LinkedHashMap<>();
        for (String user : REALM_USERS) {
            passwords.put(user, randomValue());
        }
        return Collections.unmodifiableMap(passwords);
    }

    /**
     * Asserts an unauthenticated client is challenged: the home page redirects to {@code loginEntry} and the
     * REST API answers 401.
     */
    protected void assertProtected(SsoBrowser browser, String loginEntry) throws Exception {
        var landing = browser.get("/");
        assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, landing.statusCode());
        assertTrue(landing.headers().firstValue("Location").orElseThrow().endsWith(loginEntry),
                "Expected a redirect to the login entry " + loginEntry + " but was: "
                        + landing.headers().firstValue("Location"));
        assertRestUnauthorized(browser);
    }

    /**
     * Asserts the session resolves to the {@code admin} user with the administrator authority.
     */
    protected void assertAdminSession(SsoBrowser browser) throws Exception {
        var profile = browser.get("/rest/users/profile");
        assertEquals(HttpStatus.SC_OK, profile.statusCode());
        var user = mapper.readTree(profile.body());
        assertEquals("admin", user.get("username").asText());
        assertTrue(user.get("administrator").asBoolean(), "admin must be mapped to an administrator");
    }

    /**
     * Asserts that the REST API rejects the current client as unauthenticated.
     */
    protected void assertRestUnauthorized(SsoBrowser browser) throws Exception {
        assertEquals(HttpStatus.SC_UNAUTHORIZED, browser.get("/rest/users/profile").statusCode());
    }
}

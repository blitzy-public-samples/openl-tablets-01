package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;

import com.adobe.testing.s3mock.testcontainers.S3MockContainer;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;

@DisabledIfSystemProperty(named = "noDocker", matches = ".*")
class OAuthTest extends AbstractKeycloakTest {

    private static final String CLIENT_ID = "openlstudio";
    // V3: randomness for the per-run unknown access token
    private static final SecureRandom TOKEN_RANDOM = new SecureRandom();

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(Integer.parseInt(System.getProperty("http.timeout.connect"))))
            .build();

    @Test
    void smoke() throws Exception {
        try (var keycloack = keycloak();
             var s3 = new S3MockContainer("latest")) {
            keycloack.start();
            s3.start();
            var authServerUrl = keycloack.getAuthServerUrl();
            var bearerTokens = retrieveBearerAccessTokens(authServerUrl);
            try (var httpClient = studio(s3).start()) {
                initStudio(httpClient, authServerUrl);

                httpClient.localEnv.putAll(bearerTokens);
                httpClient.test("test-resources-oauth2");

                // stop Keycloak to simulate the lag
                keycloack.stop();
                httpClient.test("test-resources-oauth2-lag");
            }
        }
    }

    @Test
    void smokePat() throws Exception {
        try (var keycloack = keycloak();
             var s3 = new S3MockContainer("latest")) {
            keycloack.start();
            s3.start();
            var authServerUrl = keycloack.getAuthServerUrl();
            var bearerTokens = retrieveBearerAccessTokens(authServerUrl);
            try (var httpClient = studio(s3).start()) {
                initStudio(httpClient, authServerUrl);

                httpClient.localEnv.putAll(bearerTokens);
                httpClient.test("test-resources-pat/000-setup");

                // Create PATs for users
                var adminPat = getPersonalAccessTokenForUser(httpClient,
                        bearerTokens.get("ADMIN_ACCESS_TOKEN"),
                        new CreatePersonalAccessTokenRequest("admin-pat", Date.from(Instant.now().plusSeconds(3600))));
                assertEquals("admin", adminPat.loginName());
                httpClient.localEnv.put("ADMIN_PAT", adminPat.token());
                httpClient.localEnv.put("ADMIN_PAT_PUBLIC_ID", adminPat.publicId());

                var user1Pat = getPersonalAccessTokenForUser(httpClient,
                        bearerTokens.get("USER1_ACCESS_TOKEN"),
                        new CreatePersonalAccessTokenRequest("user1-pat", Date.from(Instant.now().plusSeconds(3600))));
                assertEquals("user1", user1Pat.loginName());
                httpClient.localEnv.put("USER1_PAT", user1Pat.token());
                httpClient.localEnv.put("USER1_PAT_PUBLIC_ID", user1Pat.publicId());

                var user1Pat2 = getPersonalAccessTokenForUser(httpClient,
                        bearerTokens.get("USER1_ACCESS_TOKEN"),
                        new CreatePersonalAccessTokenRequest("user1-pat-second", Date.from(Instant.now().plusSeconds(3600))));
                assertEquals("user1", user1Pat2.loginName());
                httpClient.localEnv.put("USER1_PAT_2", user1Pat2.token());
                httpClient.localEnv.put("USER1_PAT_PUBLIC_ID_2", user1Pat2.publicId());

                var guestPat = getPersonalAccessTokenForUser(httpClient,
                        bearerTokens.get("GUEST_ACCESS_TOKEN"),
                        new CreatePersonalAccessTokenRequest("guest-pat", Date.from(Instant.now().plusSeconds(3600))));
                assertEquals("guest", guestPat.loginName());
                httpClient.localEnv.put("GUEST_PAT", guestPat.token());
                httpClient.localEnv.put("GUEST_PAT_PUBLIC_ID", guestPat.publicId());

                // Continue tests with PATs
                httpClient.test("test-resources-pat/100-pat-tests");
            }
        }
    }

    @Test
    void singleLogout() throws Exception {
        try (var keycloack = keycloak();
             var s3 = new S3MockContainer("latest")) {
            keycloack.start();
            s3.start();
            var authServerUrl = keycloack.getAuthServerUrl();
            try (var httpClient = studio(s3).start()) {
                initStudio(httpClient, authServerUrl);

                var browser = new SsoBrowser(httpClient.getBaseURL());

                // Unauthenticated access is challenged.
                assertProtected(browser, "/oauth2/authorization/webstudio");

                // Log in; the session resolves to admin.
                // V3: the realm password is generated at runtime
                browser.loginViaOAuth2("admin", password("admin"));
                assertAdminSession(browser);

                // SP-initiated logout redirects to the OIDC end-session endpoint with the id_token_hint.
                var logoutRedirect = browser.logoutViaOAuth2();
                assertTrue(logoutRedirect.startsWith(authServerUrl + "/realms/openlstudio/protocol/openid-connect/logout"),
                        "Unexpected logout redirect: " + logoutRedirect);
                assertTrue(logoutRedirect.contains("id_token_hint="),
                        "Logout must pass the id_token_hint: " + logoutRedirect);

                // Local session cleared; the IdP requires re-authentication.
                assertRestUnauthorized(browser);
                assertTrue(browser.oauth2ChallengesForLogin(),
                        "Keycloak must require re-authentication after logout");
            }
        }
    }

    private Map<String, String> retrieveBearerAccessTokens(String authServerUrl) throws URISyntaxException, IOException, InterruptedException {
        Map<String, String> tokens = new HashMap<>();
        // V3: realm passwords are generated at runtime
        tokens.put("ADMIN_ACCESS_TOKEN", getAccessTokenForUser(authServerUrl, "admin", password("admin")));
        tokens.put("USER1_ACCESS_TOKEN", getAccessTokenForUser(authServerUrl, "user1", password("user1")));
        tokens.put("GUEST_ACCESS_TOKEN", getAccessTokenForUser(authServerUrl, "guest", password("guest")));
        tokens.put("EPBDS12973_DEPLOYER_TOKEN", getAccessTokenForUser(authServerUrl, "epbds12973_deployer", password("epbds12973_deployer")));
        tokens.put("EPBDS12973_EDITOR_TOKEN", getAccessTokenForUser(authServerUrl, "epbds12973_editor", password("epbds12973_editor")));
        tokens.put("EPBDS12973_VIEWER_TOKEN", getAccessTokenForUser(authServerUrl, "epbds12973_viewer", password("epbds12973_viewer")));
        tokens.put("EPBDS14584_MANAGER_TOKEN", getAccessTokenForUser(authServerUrl, "epbds14584_manager", password("epbds14584_manager")));
        tokens.put("EPBDS14584_CONTRIBUTOR_TOKEN", getAccessTokenForUser(authServerUrl, "epbds14584_contributor", password("epbds14584_contributor")));
        tokens.put("EPBDS14584_VIEWER_TOKEN", getAccessTokenForUser(authServerUrl, "epbds14584_viewer", password("epbds14584_viewer")));
        tokens.put("EPBDS14670_MANAGER_TOKEN", getAccessTokenForUser(authServerUrl, "epbds14670_manager", password("epbds14670_manager")));
        tokens.put("EPBDS14670_CONTRIBUTOR_TOKEN", getAccessTokenForUser(authServerUrl, "epbds14670_contributor", password("epbds14670_contributor")));
        tokens.put("EPBDS14670_VIEWER_TOKEN", getAccessTokenForUser(authServerUrl, "epbds14670_viewer", password("epbds14670_viewer")));
        tokens.put("EPBDS14670R_MANAGER_TOKEN", getAccessTokenForUser(authServerUrl, "epbds14670r_manager", password("epbds14670r_manager")));
        tokens.put("EPBDS14670R_CONTRIBUTOR_TOKEN", getAccessTokenForUser(authServerUrl, "epbds14670r_contributor", password("epbds14670r_contributor")));
        tokens.put("EPBDS14670R_VIEWER_TOKEN", getAccessTokenForUser(authServerUrl, "epbds14670r_viewer", password("epbds14670r_viewer")));
        tokens.put("EPBDS15131_ADMIN_TOKEN", getAccessTokenForUser(authServerUrl, "epbds15131_admin", password("epbds15131_admin")));
        tokens.put("EPBDS15134_USER_TOKEN", getAccessTokenForUser(authServerUrl, "epbds15134_user", password("epbds15134_user")));
        tokens.put("EPBDS15621_USER_TOKEN", getAccessTokenForUser(authServerUrl, "epbds15621_user", password("epbds15621_user")));
        // V3: a per-run JWT-shaped token that no realm key signs
        tokens.put("UNKNOWN_ACCESS_TOKEN", unknownAccessToken());
        return tokens;
    }

    // V3: header, payload and random signature, each base64url-encoded without padding
    private static String unknownAccessToken() {
        var encoder = Base64.getUrlEncoder().withoutPadding();
        var header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        var payload = "{\"sub\":\"" + randomValue() + "\",\"jti\":\"" + randomValue() + "\",\"iat\":"
                + Instant.now().getEpochSecond() + "}";
        var signature = new byte[32];
        TOKEN_RANDOM.nextBytes(signature);
        return encoder.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString(signature);
    }

    private void initStudio(org.openl.itest.core.HttpClient httpClient, String authServerUrl) {
        var oauth2Config = (ObjectNode) httpClient.readTree("test-resources-oauth2/set-authentication-template.json");
        oauth2Config.put("issuerUri", authServerUrl + "/realms/openlstudio");
        // V3: generated client secret
        oauth2Config.put("clientSecret", clientSecret());
        oauth2Config.put("clientId", CLIENT_ID);
        httpClient.postForObject("/rest/admin/settings/authentication", oauth2Config);
    }

    private String getAccessTokenForUser(String authServerUrl, String username, String password) throws URISyntaxException, IOException, InterruptedException {
        var request = HttpRequest.newBuilder()
                .uri(new URI(authServerUrl + "/realms/openlstudio/protocol/openid-connect/token"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .timeout(Duration.ofMillis(Integer.parseInt(System.getProperty("http.timeout.read"))))
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=password&scope=openid profile email" +
                        "&client_id=" + CLIENT_ID +
                        // V3: generated client secret
                        "&client_secret=" + clientSecret() +
                        "&username=" + username +
                        "&password=" + password))
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == HttpStatus.SC_OK) {
            String responseBody = response.body();
            var responseNode = mapper.readTree(responseBody);
            return responseNode.get("access_token").asText();
        } else {
            throw new RuntimeException("Failed to get Access Token: " + response.statusCode() + " - " + response.body());
        }
    }

    private PersonalAccessTokenResponse getPersonalAccessTokenForUser(org.openl.itest.core.HttpClient httpClient, String bearerToken, CreatePersonalAccessTokenRequest tokenData) {
        var patResponse = httpClient.postForObject("/rest/users/personal-access-tokens",
                tokenData,
                PersonalAccessTokenResponse.class,
                HttpStatus.SC_CREATED,
                HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
        assertEquals(tokenData.name(), patResponse.name());
        assertTrue(patResponse.createdAt().before(tokenData.expiresAt()));
        assertEquals(tokenData.expiresAt(), patResponse.expiresAt());
        return patResponse;
    }

    public record PersonalAccessTokenResponse(
            String publicId,
            String name,
            String loginName,
            String token,
            @JsonDeserialize(using = UtcDateDeserializer.class)
            Date createdAt,
            @JsonDeserialize(using = UtcDateDeserializer.class)
            Date expiresAt) {
    }

    public record CreatePersonalAccessTokenRequest(
            String name,
            @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSZ")
            Date expiresAt) {
    }

    public static class UtcDateDeserializer extends JsonDeserializer<Date> {

        @Override
        public Date deserialize(JsonParser p, DeserializationContext ctxt)
                throws IOException {
            Instant instant = Instant.parse(p.getValueAsString());
            return Date.from(instant);
        }
    }

}

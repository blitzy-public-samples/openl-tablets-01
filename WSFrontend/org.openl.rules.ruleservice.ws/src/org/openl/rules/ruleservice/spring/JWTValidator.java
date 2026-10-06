package org.openl.rules.ruleservice.spring;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import jakarta.servlet.http.HttpServletRequest;

import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwt.consumer.ErrorCodeValidator;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import org.openl.rules.ruleservice.api.AuthorizationChecker;
import org.openl.spring.config.ConditionalOnEnable;
import org.openl.util.CollectionUtils;
import org.openl.util.StringUtils;

/**
 * Check JWT with JWK and validate following claims: exp, iss, aud.
 *
 * @author Yury Molchan
 */
@Component
@ConditionalOnEnable("ruleservice.authentication.enabled")
@Slf4j
public class JWTValidator implements AuthorizationChecker {

    private static final String BEARER = "Bearer ";
    private static final List<String> PUBLIC_ADMIN_PREFIXES =
            List.of("/admin/healthcheck/", "/admin/info/", "/admin/config/");
    // V2: the longest part of a JWT ID that is logged.
    private static final int MAX_LOGGED_JWT_ID_LENGTH = 128;


    private final JwtConsumer jwtConsumer;

    @Autowired
    public JWTValidator(Environment env) throws JoseException, IOException, URISyntaxException {
        var expectedIssuers = StringUtils.split(env.getProperty("ruleservice.authentication.iss"), ',');
        if (CollectionUtils.isEmpty(expectedIssuers)) {
            throw new IllegalArgumentException("The 'ruleservice.authentication.iss' property should contain an issuer id");
        }

        var jwkPropertyUrl = env.getProperty("ruleservice.authentication.jwks");
        if (StringUtils.isEmpty(jwkPropertyUrl)) {
            throw new IllegalArgumentException("The 'ruleservice.authentication.jwks' property should contain valid URL");
        }

        VerificationKeyResolver jwksResolver;
        if (jwkPropertyUrl.startsWith("https:")) {
            // This resolver do secure connection, correctly handles "cache-control" header, do caching of the keys,
            // and multi-thread safe.
            jwksResolver = new HttpsJwksVerificationKeyResolver(new HttpsJwks(jwkPropertyUrl));
        } else {
            try (var resource = new URI(jwkPropertyUrl).toURL().openStream()) {
                var json = new String(resource.readAllBytes(), StandardCharsets.UTF_8);
                var jwks = new JsonWebKeySet(json);
                jwksResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());
            }
        }

        this.jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setExpectedIssuer(env.getProperty("ruleservice.authentication.iss")) // whom the JWT needs to have been issued by
                .setExpectedAudience(StringUtils.split(env.getProperty("ruleservice.authentication.aud"), ',')) // to whom the JWT is intended for
                .setVerificationKeyResolver(jwksResolver) // verify the signature with the public key
                .setJwsAlgorithmConstraints(AlgorithmConstraints.DISALLOW_NONE) // allow all algorithms
                .build(); // create the JwtConsumer instance
    }

    @Override
    public boolean authorize(HttpServletRequest httpRequest) {
        var pathInfo = httpRequest.getPathInfo();
        // V2: only /admin/healthcheck/, info/ and config/ are public; other /admin/ paths, OpenAPI too, need a JWT.
        if (pathInfo.startsWith("/admin/")) {
            if (PUBLIC_ADMIN_PREFIXES.stream().anyMatch(pathInfo::startsWith)) {
                return true;
            }
        } else if (pathInfo.endsWith("openapi.json") || pathInfo.endsWith("openapi.yaml")) {
            // Service OpenAPI documents stay public.
            return true;
        }

        var credentials = httpRequest.getHeader("Authorization");
        if (credentials == null) {
            log.warn("Authorization header is not present.");
            return false;
        }
        if (!credentials.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            log.warn("Bearer token is not present.");
            return false;
        }

        try {
            //  Validate the JWT and process it to the Claims
            var jwtClaims = jwtConsumer.processToClaims(credentials.substring(BEARER.length()));
            // V2: the JWT ID is read at every log level, so the authorization outcome never depends on the level.
            var jwtId = jwtClaims.getJwtId();
            // V2: the JWT ID is issuer-chosen text, so it is logged escaped and capped, and formatted only at INFO.
            if (log.isInfoEnabled()) {
                log.info("Authorized for JWT ID={}", loggableJwtId(jwtId));
            }
        } catch (InvalidJwtException e) {
            // V2: only at WARN, log only the jose4j error codes; the exception text carries the token or its claims.
            if (log.isWarnEnabled()) {
                var errorCodes = e.getErrorDetails().stream().map(ErrorCodeValidator.Error::getErrorCode).toList();
                log.warn("JWT rejected, jose4j error codes {}.", errorCodes);
            }
            return false;
        } catch (Exception e) {
            // V2: log only the exception class; its message can quote the token or one of its claims.
            log.warn("JWT rejected, unexpected {}.", e.getClass().getName());
            return false;
        }

        return true;
    }

    // V2: renders a JWT ID as one capped log line by escaping control characters and Unicode line separators.
    private static @Nullable String loggableJwtId(@Nullable String jwtId) {
        if (jwtId == null) {
            return null;
        }
        int end = Math.min(jwtId.length(), MAX_LOGGED_JWT_ID_LENGTH);
        var loggable = new StringBuilder(end + 3);
        for (int i = 0; i < end; i++) {
            char c = jwtId.charAt(i);
            if (Character.isISOControl(c) || c == '\u2028' || c == '\u2029') {
                loggable.append(String.format("\\u%04x", (int) c));
            } else {
                loggable.append(c);
            }
        }
        if (end < jwtId.length()) {
            loggable.append("...");
        }
        return loggable.toString();
    }
}

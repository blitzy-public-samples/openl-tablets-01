package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;

/**
 * V4: the application's own {@code filterChainProxy} bean of {@link SecurityConfig} writes the default security
 * headers, cache headers included, on a static-chain response that the container commits early, as Jetty does with
 * the {@code /application.properties} body when it is streamed in 16 KiB writes.
 * <p>
 * The context holds only {@link SecurityConfig}, so the static chain is the only chain. The response is an
 * {@link EarlyCommitResponse}, which commits the way Jetty does and then ignores every header.
 * </p>
 */
@SpringJUnitConfig(SecurityConfigEarlyCommitHeadersTest.TestConfig.class)
@WebAppConfiguration
class SecurityConfigEarlyCommitHeadersTest {

    private static final String APP_PROPERTIES = "/application.properties";
    private static final byte[] LARGE_BODY = new byte[16 * 1024];
    private static final FilterChain LARGE_BODY_WRITER = (req, res) -> res.getOutputStream().write(LARGE_BODY);

    @Autowired
    @Qualifier("filterChainProxy")
    private Filter filterChainProxy;

    @Test
    void earlyCommittedStaticResponseKeepsTheSecurityHeaders() throws Exception {
        var response = new EarlyCommitResponse();

        filterChainProxy.doFilter(request(APP_PROPERTIES, false), response, LARGE_BODY_WRITER);

        assertTrue(response.isCommitted(), "the large write commits the response");
        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
        assertNull(response.getHeader("Strict-Transport-Security"), "HSTS on a plain HTTP request");
        assertSingle(response, "Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        assertSingle(response, "Pragma", "no-cache");
        assertSingle(response, "Expires", "0");
    }

    @Test
    void secureEarlyCommittedStaticResponseKeepsHsts() throws Exception {
        var response = new EarlyCommitResponse();

        filterChainProxy.doFilter(request(APP_PROPERTIES, true), response, LARGE_BODY_WRITER);

        assertTrue(response.isCommitted(), "the large write commits the response");
        assertSingle(response, "Strict-Transport-Security", "max-age=31536000 ; includeSubDomains");
        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
    }

    /** The static chain's own lazy filter still writes the cache headers on an ordinary response. */
    @Test
    void ordinaryStaticResponseGetsTheFullSetOnce() throws Exception {
        var response = new EarlyCommitResponse();
        FilterChain smallBody = (req, res) -> res.getOutputStream().write("<svg/>".getBytes(StandardCharsets.UTF_8));

        filterChainProxy.doFilter(request("/favicon.svg", false), response, smallBody);

        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
        assertSingle(response, "Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        assertSingle(response, "Pragma", "no-cache");
        assertSingle(response, "Expires", "0");
    }

    /** A request no chain of the context matches passes through without any header. */
    @Test
    void requestOutsideEveryChainPassesThrough() throws Exception {
        var response = new EarlyCommitResponse();

        filterChainProxy.doFilter(request("/rest/projects", true), response, LARGE_BODY_WRITER);

        assertEquals(LARGE_BODY.length, response.getContentAsByteArray().length, "body length");
        assertTrue(response.getHeaderNames().isEmpty(), () -> "headers: " + response.getHeaderNames());
    }

    private static MockHttpServletRequest request(String path, boolean secure) {
        var request = new MockHttpServletRequest("GET", path);
        request.setServletPath(path);
        request.setSecure(secure);
        return request;
    }

    private static void assertSingle(EarlyCommitResponse response, String name, String value) {
        assertEquals(List.of(value), response.getHeaders(name), name);
    }

    @Configuration
    @Import(SecurityConfig.class)
    static class TestConfig {
    }
}

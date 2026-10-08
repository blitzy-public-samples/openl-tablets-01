package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.util.List;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequestWrapper;
import jakarta.servlet.ServletResponseWrapper;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;

/**
 * V4: the security headers of a response that the servlet container commits before Spring Security's lazy header
 * writer notices it, as Jetty does with a body streamed in large writes.
 * <p>
 * Each test runs a real {@link FilterChainProxy} over one chain that holds a lazy {@link HeaderWriterFilter} with the
 * default writers of {@code HttpSecurity}, as every chain of the application does. The response is an
 * {@link EarlyCommitResponse}, which commits on a single write larger than Jetty's aggregation size and then ignores
 * every header.
 * </p>
 */
class EagerSecurityHeadersChainDecoratorTest {

    private static final String MATCHED = "/matched";
    private static final String HSTS = "Strict-Transport-Security";
    private static final String HSTS_VALUE = "max-age=31536000 ; includeSubDomains";
    private static final List<String> CACHE_HEADERS = List.of("Cache-Control", "Pragma", "Expires");

    /** One write of the size {@code InputStream.transferTo} uses, larger than Jetty's aggregation size. */
    private static final byte[] LARGE_BODY = new byte[16 * 1024];

    private static final FilterChain LARGE_BODY_WRITER = (req, res) -> res.getOutputStream().write(LARGE_BODY);

    /**
     * The premise of every other test: without the decorator, an early-committed response carries no security header
     * at all. This is the behavior of the static and file-download responses before the fix.
     */
    @Test
    void lazyChainAloneLosesEveryHeaderOnEarlyCommit() throws Exception {
        var response = new EarlyCommitResponse();

        proxy(false).doFilter(request(MATCHED, false), response, LARGE_BODY_WRITER);

        assertTrue(response.isCommitted(), "the large write commits the response");
        assertTrue(response.getHeaderNames().isEmpty(), () -> "headers: " + response.getHeaderNames());
    }

    /** The default set, cache headers included, goes out before the large write that commits the response. */
    @Test
    void earlyCommittedResponseKeepsTheFullDefaultSet() throws Exception {
        var response = new EarlyCommitResponse();

        proxy(true).doFilter(request(MATCHED, false), response, LARGE_BODY_WRITER);

        assertTrue(response.isCommitted(), "the large write commits the response");
        assertEquals(LARGE_BODY.length, response.getContentAsByteArray().length, "body length");
        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
        assertNull(response.getHeader(HSTS), "HSTS on a plain HTTP request");
        assertDefaultCacheHeaders(response);
    }

    @Test
    void secureEarlyCommittedResponseKeepsHsts() throws Exception {
        var response = new EarlyCommitResponse();

        proxy(true).doFilter(request(MATCHED, true), response, LARGE_BODY_WRITER);

        assertTrue(response.isCommitted(), "the large write commits the response");
        assertSingle(response, HSTS, HSTS_VALUE);
        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
        assertDefaultCacheHeaders(response);
    }

    /** A body written through the writer in one large write gets the same set. */
    @Test
    void earlyCommitThroughTheWriterKeepsTheFullDefaultSet() throws Exception {
        var response = new EarlyCommitResponse();
        var largeText = "x".repeat(LARGE_BODY.length);
        FilterChain largeTextWriter = (req, res) -> res.getWriter().write(largeText);

        proxy(true).doFilter(request(MATCHED, false), response, largeTextWriter);

        assertTrue(response.isCommitted(), "the large write commits the response");
        assertEquals(largeText, response.getContentAsString(), "body");
        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
        assertDefaultCacheHeaders(response);
    }

    /** A cache policy set before the large write stays alone: no {@code Pragma} or {@code Expires} joins it. */
    @Test
    void earlyCommittedResponseKeepsItsOwnCacheControl() throws Exception {
        var response = new EarlyCommitResponse();

        proxy(true).doFilter(request(MATCHED, false), response, largeBodyAfter("Cache-Control", "private, max-age=60"));

        assertTrue(response.isCommitted(), "the large write commits the response");
        assertSingle(response, "Cache-Control", "private, max-age=60");
        assertNull(response.getHeader("Pragma"), "Pragma");
        assertNull(response.getHeader("Expires"), "Expires");
        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
    }

    /**
     * An {@code Expires} header of the response's own, such as the one the container adds with a session cookie, also
     * keeps the default cache headers away.
     */
    @Test
    void earlyCommittedResponseWithItsOwnExpiresGetsNoDefaultCacheHeaders() throws Exception {
        var response = new EarlyCommitResponse();
        var expires = "Thu, 01 Jan 1970 00:00:00 GMT";

        proxy(true).doFilter(request(MATCHED, false), response, largeBodyAfter("Expires", expires));

        assertTrue(response.isCommitted(), "the large write commits the response");
        assertSingle(response, "Expires", expires);
        assertNull(response.getHeader("Cache-Control"), "Cache-Control");
        assertNull(response.getHeader("Pragma"), "Pragma");
        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
    }

    @Test
    void earlyCommittedNotModifiedResponseGetsNoCacheHeaders() throws Exception {
        var response = new EarlyCommitResponse();
        FilterChain notModified = (req, res) -> {
            ((HttpServletResponse) res).setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            res.getOutputStream().write(LARGE_BODY);
        };

        proxy(true).doFilter(request(MATCHED, false), response, notModified);

        assertTrue(response.isCommitted(), "the large write commits the response");
        CACHE_HEADERS.forEach(name -> assertNull(response.getHeader(name), name));
        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
    }

    /**
     * A reset clears the headers the first output wrote, so the large write after it writes the full set again, once,
     * even through the output stream taken before the reset.
     */
    @Test
    void resetBeforeTheEarlyCommitWritesTheFullSetAgain() throws Exception {
        var response = new EarlyCommitResponse();
        FilterChain resetThenLarge = (req, res) -> {
            var out = res.getOutputStream();
            out.write("partial".getBytes(StandardCharsets.UTF_8));
            assertSingle(response, "Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
            res.reset();
            assertTrue(response.getHeaderNames().isEmpty(), () -> "headers after reset: " + response.getHeaderNames());
            out.write(LARGE_BODY);
        };

        proxy(true).doFilter(request(MATCHED, false), response, resetThenLarge);

        assertTrue(response.isCommitted(), "the large write commits the response");
        assertEquals(LARGE_BODY.length, response.getContentAsByteArray().length, "body length");
        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
        assertDefaultCacheHeaders(response);
    }

    /** The chain's lazy filter still adds the cache headers, and the duplicate writers add nothing. */
    @Test
    void ordinaryResponseGetsTheFullSetOnce() throws Exception {
        var response = new EarlyCommitResponse();

        proxy(true).doFilter(request(MATCHED, true), response, smallBody());

        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
        assertSingle(response, HSTS, HSTS_VALUE);
        assertSingle(response, "Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        assertSingle(response, "Pragma", "no-cache");
        assertSingle(response, "Expires", "0");
    }

    /** A response that sets its own cache policy keeps it alone, as the pages with {@code no-store} do. */
    @Test
    void responseOwnCacheHeaderKeepsPrecedence() throws Exception {
        var response = new EarlyCommitResponse();
        FilterChain noStorePage = (req, res) -> {
            ((HttpServletResponse) res).setHeader("Cache-Control", "no-store");
            res.getOutputStream().write("<html></html>".getBytes(StandardCharsets.UTF_8));
        };

        proxy(true).doFilter(request(MATCHED, false), response, noStorePage);

        assertSingle(response, "Cache-Control", "no-store");
        assertNull(response.getHeader("Pragma"), "Pragma");
        assertNull(response.getHeader("Expires"), "Expires");
        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
    }

    /** A response reset after the eager write, as on an error, still gets the headers from the chain's own filter. */
    @Test
    void resetResponseGetsTheHeadersFromTheChain() throws Exception {
        var response = new EarlyCommitResponse();
        FilterChain failing = (req, res) -> {
            var http = (HttpServletResponse) res;
            http.reset();
            http.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        };

        proxy(true).doFilter(request(MATCHED, false), response, failing);

        assertEquals(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, response.getStatus(), "status");
        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-Frame-Options", "DENY");
        assertSingle(response, "X-XSS-Protection", "0");
        assertSingle(response, "Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
    }

    /** No chain matches, so the request passes through: the security headers belong to the chains only. */
    @Test
    void unmatchedRequestPassesThroughWithoutHeaders() throws Exception {
        var response = new EarlyCommitResponse();

        proxy(true).doFilter(request("/unmatched", true), response, smallBody());

        assertEquals("ok", response.getContentAsString(), "body");
        assertTrue(response.getHeaderNames().isEmpty(), () -> "headers: " + response.getHeaderNames());
    }

    @Test
    void noFiltersLeaveTheChainAsItIs() {
        var decorator = new EagerSecurityHeadersChainDecorator();
        FilterChain original = (req, res) -> {
        };

        assertSame(original, decorator.decorate(original), "decorate(original)");
        assertSame(original, decorator.decorate(original, List.of()), "decorate(original, no filters)");
    }

    /**
     * The eager filter runs first and then the chain's filters in their order, ending in the original chain, all with
     * the response that writes the default set before its first output.
     */
    @Test
    void decoratedChainRunsTheChainFiltersAndTheOriginalChain() throws Exception {
        var decorator = new EagerSecurityHeadersChainDecorator();
        var response = new MockHttpServletResponse();
        var calls = new StringBuilder();
        FilterChain original = (req, res) -> {
            assertInstanceOf(BeforeCommitHeadersResponse.class, res, "response of the original chain");
            calls.append("original;");
        };

        decorator.decorate(original, List.of(
                (req, res, chain) -> {
                    assertInstanceOf(BeforeCommitHeadersResponse.class, res, "response of the chain");
                    calls.append("first:")
                            .append(((HttpServletResponse) res).getHeader("X-Frame-Options"))
                            .append(';');
                    chain.doFilter(req, res);
                },
                (req, res, chain) -> {
                    calls.append("second;");
                    chain.doFilter(req, res);
                })).doFilter(request(MATCHED, false), response);

        assertEquals("first:DENY;second;original;", calls.toString(), "call order");
    }

    /** A request that is not HTTP is not wrapped, and the eager filter rejects it as every security filter does. */
    @Test
    void nonHttpRequestIsRejectedByTheEagerFilter() {
        var chain = new EagerSecurityHeadersChainDecorator().decorate((req, res) -> fail("original chain"),
                List.of((req, res, next) -> fail("chain filter")));
        var request = new ServletRequestWrapper(request(MATCHED, false));
        var response = new MockHttpServletResponse();

        var thrown = assertThrows(ServletException.class, () -> chain.doFilter(request, response));

        assertEquals("OncePerRequestFilter only supports HTTP requests", thrown.getMessage(), "message");
        assertTrue(response.getHeaderNames().isEmpty(), () -> "headers: " + response.getHeaderNames());
    }

    /** A response that is not HTTP is not wrapped either. */
    @Test
    void nonHttpResponseIsRejectedByTheEagerFilter() {
        var chain = new EagerSecurityHeadersChainDecorator().decorate((req, res) -> fail("original chain"),
                List.of((req, res, next) -> fail("chain filter")));
        var target = new MockHttpServletResponse();
        var response = new ServletResponseWrapper(target);

        var thrown = assertThrows(ServletException.class, () -> chain.doFilter(request(MATCHED, false), response));

        assertEquals("OncePerRequestFilter only supports HTTP requests", thrown.getMessage(), "message");
        assertTrue(target.getHeaderNames().isEmpty(), () -> "headers: " + target.getHeaderNames());
    }

    @Test
    void filterThatFailsToInitializeIsRejected() {
        var failure = new ServletException("init failed");
        var filter = new HeaderWriterFilter(List.of(new XContentTypeOptionsHeaderWriter())) {

            @Override
            protected void initFilterBean() throws ServletException {
                throw failure;
            }
        };

        var thrown = assertThrows(IllegalStateException.class, () -> new EagerSecurityHeadersChainDecorator(filter));

        assertSame(failure, thrown.getCause(), "cause");
    }

    private static FilterChainProxy proxy(boolean decorated) {
        var lazyHeaders = new HeaderWriterFilter(List.of(
                new XContentTypeOptionsHeaderWriter(),
                new XXssProtectionHeaderWriter(),
                new CacheControlHeadersWriter(),
                new HstsHeaderWriter(),
                new XFrameOptionsHeaderWriter(XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY)));
        var chain = new DefaultSecurityFilterChain(request -> MATCHED.equals(request.getRequestURI()), lazyHeaders);
        var proxy = new FilterChainProxy(chain);
        if (decorated) {
            proxy.setFilterChainDecorator(new EagerSecurityHeadersChainDecorator());
        }
        proxy.afterPropertiesSet();
        return proxy;
    }

    private static MockHttpServletRequest request(String uri, boolean secure) {
        var request = new MockHttpServletRequest("GET", uri);
        request.setServletPath(uri);
        request.setSecure(secure);
        return request;
    }

    private static FilterChain smallBody() {
        return (req, res) -> res.getOutputStream().write("ok".getBytes(StandardCharsets.UTF_8));
    }

    /** A body written in one large write after the response set the given header itself. */
    private static FilterChain largeBodyAfter(String name, String value) {
        return (req, res) -> {
            ((HttpServletResponse) res).setHeader(name, value);
            res.getOutputStream().write(LARGE_BODY);
        };
    }

    private static void assertDefaultCacheHeaders(MockHttpServletResponse response) {
        assertSingle(response, "Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        assertSingle(response, "Pragma", "no-cache");
        assertSingle(response, "Expires", "0");
    }

    private static void assertSingle(MockHttpServletResponse response, String name, String value) {
        assertEquals(List.of(value), response.getHeaders(name), name);
    }
}

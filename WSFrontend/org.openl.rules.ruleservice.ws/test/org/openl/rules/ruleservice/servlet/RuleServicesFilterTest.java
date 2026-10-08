package org.openl.rules.ruleservice.servlet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLConnection;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.util.ReflectionTestUtils;

import org.openl.rules.ruleservice.api.AccessDeniedHandler;
import org.openl.rules.ruleservice.api.AuthorizationChecker;
import org.openl.rules.ruleservice.core.RuleServiceRedeployLock;

/**
 * Covers the request processing of {@link RuleServicesFilter}: static content, the request ID, the authorization
 * checkers and their V2 gate, CORS, and the redeploy lock.
 * <p>
 * Each filter is initialized as the web application initializes it: from a servlet context that holds a
 * {@link SpringInitializer} whose Spring context supplies the checkers, the access denied handler and the properties.
 * No request carries a credential, because the checkers are stubs that only count their calls.
 */
class RuleServicesFilterTest {

    private static final String REQUEST_ID_HEADER = "X-Request-Id";
    private static final String ALLOWED_ORIGIN = "https://a.example";
    private static final String OTHER_ORIGIN = "https://c.example";
    private static final String ALLOW_ORIGIN_HEADER = "Access-Control-Allow-Origin";

    @Test
    void isAllowedPath() {
        assertFalse(RuleServicesFilter.isAllowedPath(""));
        assertFalse(RuleServicesFilter.isAllowedPath("file"));
        assertFalse(RuleServicesFilter.isAllowedPath("file.txt"));
        assertFalse(RuleServicesFilter.isAllowedPath("path/file.txt"));
        assertFalse(RuleServicesFilter.isAllowedPath("//file"));
        assertFalse(RuleServicesFilter.isAllowedPath(".file"));
        assertFalse(RuleServicesFilter.isAllowedPath("/.file"));
        assertFalse(RuleServicesFilter.isAllowedPath("/./file"));
        assertFalse(RuleServicesFilter.isAllowedPath("/../file"));
        assertFalse(RuleServicesFilter.isAllowedPath("/file..txt"));
        assertFalse(RuleServicesFilter.isAllowedPath("/%2E/file.txt"));
        assertFalse(RuleServicesFilter.isAllowedPath("/path%2Epath/file.txt"));
        assertFalse(RuleServicesFilter.isAllowedPath("/%2E%2E/file.txt"));
        assertFalse(RuleServicesFilter.isAllowedPath("%2File.txt"));
        assertFalse(RuleServicesFilter.isAllowedPath("/%44File.txt"));

        assertTrue(RuleServicesFilter.isAllowedPath("/file"));
        assertTrue(RuleServicesFilter.isAllowedPath("/file.txt"));
        assertTrue(RuleServicesFilter.isAllowedPath("/path/file.txt"));
        assertTrue(RuleServicesFilter.isAllowedPath("/path/file.txt.gz"));
        assertTrue(RuleServicesFilter.isAllowedPath("/path/path.ext/file.txt.gz"));
    }

    // V2: static content is served before any checker runs, so a denying checker never sees it.
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = "/")
    void rootPath_servesIndexPage(@Nullable String pathInfo) throws Exception {
        var checker = new CountingChecker(Decision.DENY, 0);
        var handler = new CountingHandler();
        var filter = filter(new MockEnvironment(), checker, handler);
        var chain = new RecordingChain();
        var body = new CapturingOutputStream();
        var response = response(body);

        filter.doFilter(request("GET", pathInfo, "/"), response, chain);

        verify(response).setStatus(HttpServletResponse.SC_OK);
        verify(response).setContentType("text/html");
        assertArrayEquals(staticResource("/index.html"), body.bytes.toByteArray());
        assertEquals(0, checker.calls);
        assertEquals(0, handler.calls);
        assertEquals(0, chain.calls);
    }

    @Test
    void staticResource_isServed() throws Exception {
        var checker = new CountingChecker(Decision.DENY, 0);
        var filter = filter(new MockEnvironment(), checker, new CountingHandler());
        var chain = new RecordingChain();
        var body = new CapturingOutputStream();
        var response = response(body);

        filter.doFilter(request("GET", "/favicon.svg", "/favicon.svg"), response, chain);

        verify(response).setStatus(HttpServletResponse.SC_OK);
        verify(response).setContentType("image/svg+xml");
        assertArrayEquals(staticResource("/favicon.svg"), body.bytes.toByteArray());
        assertEquals(0, checker.calls);
        assertEquals(0, chain.calls);
    }

    @Test
    void missingStaticResource_reachesChain() throws Exception {
        var checker = new CountingChecker(Decision.ALLOW, 0);
        var filter = filter(new MockEnvironment(), checker, new CountingHandler());
        var chain = new RecordingChain();
        var response = response();

        filter.doFilter(request("GET", "/simple/ping", "/simple/ping"), response, chain);

        verify(response, never()).getOutputStream();
        assertEquals(1, checker.calls);
        assertEquals(1, chain.calls);
    }

    @ParameterizedTest
    @CsvSource({"POST, /index.html", "HEAD, /favicon.svg", "GET, /a/../index.html"})
    void nonGetOrTraversalPath_isNotServedStatically(String method, String pathInfo) throws Exception {
        var checker = new CountingChecker(Decision.DENY, 0);
        var handler = new CountingHandler();
        var filter = filter(new MockEnvironment(), checker, handler);
        var chain = new RecordingChain();
        var response = response();

        filter.doFilter(request(method, pathInfo, pathInfo), response, chain);

        verify(response, never()).getOutputStream();
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        assertEquals(1, checker.calls);
        assertEquals(1, handler.calls);
        assertEquals(0, chain.calls);
    }

    @Test
    void requestWithoutCharset_getsUtf8() throws Exception {
        var filter = filter(new MockEnvironment(), new CountingHandler());
        var request = request("POST", "/simple/ping", "/simple/ping");

        filter.doFilter(request, response(), new RecordingChain());

        assertEquals("UTF-8", request.getCharacterEncoding());
    }

    @Test
    void requestWithCharset_keepsIt() throws Exception {
        var filter = filter(new MockEnvironment(), new CountingHandler());
        var request = request("POST", "/simple/ping", "/simple/ping");
        request.setCharacterEncoding("ISO-8859-1");

        filter.doFilter(request, response(), new RecordingChain());

        assertEquals("ISO-8859-1", request.getCharacterEncoding());
    }

    @Test
    void requestId_isEchoed() throws Exception {
        var filter = filter(new MockEnvironment().withProperty("log.request-id.header", REQUEST_ID_HEADER),
                new CountingHandler());
        var request = request("POST", "/simple/ping", "/simple/ping");
        var requestId = UUID.randomUUID().toString();
        request.addHeader(REQUEST_ID_HEADER, requestId);
        var response = response();
        var chain = new RecordingChain();

        filter.doFilter(request, response, chain);

        verify(response).setHeader(REQUEST_ID_HEADER, requestId);
        assertEquals(1, chain.calls);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "  "})
    void absentOrBlankRequestId_isGenerated(@Nullable String sent) throws Exception {
        var filter = filter(new MockEnvironment().withProperty("log.request-id.header", REQUEST_ID_HEADER),
                new CountingHandler());
        var request = request("POST", "/simple/ping", "/simple/ping");
        if (sent != null) {
            request.addHeader(REQUEST_ID_HEADER, sent);
        }
        var response = response();
        var chain = new RecordingChain();

        filter.doFilter(request, response, chain);

        var generated = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(eq(REQUEST_ID_HEADER), generated.capture());
        assertDoesNotThrow(() -> UUID.fromString(generated.getValue()));
        assertEquals(1, chain.calls);
    }

    @Test
    void withoutRequestIdProperty_noRequestIdIsSet() throws Exception {
        var filter = filter(new MockEnvironment(), new CountingHandler());
        var response = response();
        var chain = new RecordingChain();

        filter.doFilter(request("POST", "/simple/ping", "/simple/ping"), response, chain);

        verify(response, never()).setHeader(any(), any());
        assertEquals(1, chain.calls);
    }

    @Test
    void withoutCheckers_everyRequestReachesChain() throws Exception {
        var handler = new CountingHandler();
        var filter = filter(new MockEnvironment(), handler);
        var chain = new RecordingChain();

        filter.doFilter(request("POST", "/admin/deploy", "/admin/deploy"), response(), chain);

        assertEquals(0, handler.calls);
        assertEquals(1, chain.calls);
    }

    // V2: a public admin prefix reached by a request URI without dot segments skips every checker.
    @ParameterizedTest
    @CsvSource({"/admin/healthcheck/readiness, /admin/healthcheck/readiness",
            "/admin/info/sys.json, /webservice/admin/info/sys.json",
            "/admin/config/application.properties, /admin/config/application.properties"})
    void publicAdminPathOfNormalizedUri_skipsCheckers(String pathInfo, String requestUri) throws Exception {
        var checker = new CountingChecker(Decision.DENY, 0);
        var handler = new CountingHandler();
        var filter = filter(new MockEnvironment(), checker, handler);
        var chain = new RecordingChain();

        filter.doFilter(request("GET", pathInfo, requestUri), response(), chain);

        assertEquals(0, checker.calls);
        assertEquals(0, handler.calls);
        assertEquals(1, chain.calls);
    }

    // V2: CXF routes inside /admin by the URI as sent, so a dot-segment URI resolving to a public prefix is checked.
    @ParameterizedTest
    @CsvSource({"/admin/info/a, /admin/deploy/x/../../info/a",
            "/admin/info/sys.json, /webservice/admin/deploy/../info/sys.json",
            "/admin/healthcheck/readiness, /admin/deploy/%2e%2e/healthcheck/readiness",
            "/admin/config/application.properties, /admin/deploy/..;x/config/application.properties"})
    void publicAdminPathOfDotSegmentUri_isChecked(String pathInfo, String requestUri) throws Exception {
        var checker = new CountingChecker(Decision.DENY, 0);
        var handler = new CountingHandler();
        var filter = filter(new MockEnvironment(), checker, handler);
        var chain = new RecordingChain();
        var response = response();

        filter.doFilter(request("POST", pathInfo, requestUri), response, chain);

        assertEquals(1, checker.calls);
        assertEquals(1, handler.calls);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        assertEquals(0, chain.calls);
    }

    @Test
    void dotSegmentUriAllowedByChecker_reachesChain() throws Exception {
        var checker = new CountingChecker(Decision.ALLOW, 0);
        var handler = new CountingHandler();
        var filter = filter(new MockEnvironment(), checker, handler);
        var chain = new RecordingChain();

        filter.doFilter(request("POST", "/admin/info/a", "/admin/deploy/x/../../info/a"), response(), chain);

        assertEquals(1, checker.calls);
        assertEquals(0, handler.calls);
        assertEquals(1, chain.calls);
    }

    @Test
    void requestDeniedByEveryChecker_isHandled() throws Exception {
        var first = new CountingChecker(Decision.DENY, 1);
        var second = new CountingChecker(Decision.DENY, 2);
        var handler = new CountingHandler();
        var filter = filter(new MockEnvironment(), second, first, handler);
        var chain = new RecordingChain();
        var response = response();

        filter.doFilter(request("POST", "/admin/deploy", "/admin/deploy"), response, chain);

        assertEquals(1, first.calls);
        assertEquals(1, second.calls);
        assertEquals(1, handler.calls);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        assertEquals(0, chain.calls);
    }

    @Test
    void requestAllowedByLaterChecker_reachesChain() throws Exception {
        var first = new CountingChecker(Decision.DENY, 1);
        var second = new CountingChecker(Decision.ALLOW, 2);
        var third = new CountingChecker(Decision.ALLOW, 3);
        var handler = new CountingHandler();
        var filter = filter(new MockEnvironment(), third, second, first, handler);
        var chain = new RecordingChain();

        filter.doFilter(request("POST", "/admin/deploy", "/admin/deploy"), response(), chain);

        assertEquals(1, first.calls);
        assertEquals(1, second.calls);
        assertEquals(0, third.calls);
        assertEquals(0, handler.calls);
        assertEquals(1, chain.calls);
    }

    @Test
    void throwingChecker_deniesAndStopsTheCheck() throws Exception {
        var first = new CountingChecker(Decision.THROW, 1);
        var second = new CountingChecker(Decision.ALLOW, 2);
        var handler = new CountingHandler();
        var filter = filter(new MockEnvironment(), second, first, handler);
        var chain = new RecordingChain();
        var response = response();

        filter.doFilter(request("POST", "/admin/deploy", "/admin/deploy"), response, chain);

        assertEquals(1, first.calls);
        assertEquals(0, second.calls);
        assertEquals(1, handler.calls);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        assertEquals(0, chain.calls);
    }

    @ParameterizedTest
    @ValueSource(strings = {ALLOWED_ORIGIN, "HTTPS://B.EXAMPLE"})
    void listedOrigin_getsCorsHeaders(String origin) throws Exception {
        var filter = filter(cors(ALLOWED_ORIGIN + ",https://b.example"), new CountingHandler());
        var request = request("POST", "/simple/ping", "/simple/ping");
        request.addHeader("Origin", origin);
        var response = response();
        var chain = new RecordingChain();

        filter.doFilter(request, response, chain);

        verify(response).addHeader(ALLOW_ORIGIN_HEADER, origin);
        verify(response).addHeader("Access-Control-Max-Age", "7200");
        verify(response).addHeader("Access-Control-Allow-Methods", "GET,POST");
        verify(response).addHeader("Access-Control-Allow-Headers", "Content-Type");
        verify(response, never()).setStatus(anyInt());
        assertEquals(1, chain.calls);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = OTHER_ORIGIN)
    void unlistedOrMissingOrigin_getsNoCorsHeaders(@Nullable String origin) throws Exception {
        var filter = filter(cors(ALLOWED_ORIGIN + ",https://b.example"), new CountingHandler());
        var request = request("POST", "/simple/ping", "/simple/ping");
        if (origin != null) {
            request.addHeader("Origin", origin);
        }
        var response = response();
        var chain = new RecordingChain();

        filter.doFilter(request, response, chain);

        verify(response, never()).addHeader(any(), any());
        assertEquals(1, chain.calls);
    }

    @Test
    void anyOrigin_getsCorsHeaders() throws Exception {
        var filter = filter(cors("*"), new CountingHandler());
        var request = request("POST", "/simple/ping", "/simple/ping");
        request.addHeader("Origin", OTHER_ORIGIN);
        var response = response();

        filter.doFilter(request, response, new RecordingChain());

        verify(response).addHeader(ALLOW_ORIGIN_HEADER, OTHER_ORIGIN);
    }

    @Test
    void withoutOriginsProperty_getsNoCorsHeaders() throws Exception {
        var filter = filter(new MockEnvironment(), new CountingHandler());
        var request = request("POST", "/simple/ping", "/simple/ping");
        request.addHeader("Origin", ALLOWED_ORIGIN);
        var response = response();

        filter.doFilter(request, response, new RecordingChain());

        verify(response, never()).addHeader(any(), any());
    }

    @Test
    void preflightFromListedOrigin_isAcceptedWithoutChain() throws Exception {
        var filter = filter(cors(ALLOWED_ORIGIN), new CountingHandler());
        var request = request("OPTIONS", "/simple/ping", "/simple/ping");
        request.addHeader("Origin", ALLOWED_ORIGIN);
        var response = response();
        var chain = new RecordingChain();

        filter.doFilter(request, response, chain);

        verify(response).setStatus(HttpServletResponse.SC_ACCEPTED);
        verify(response).addHeader(ALLOW_ORIGIN_HEADER, ALLOWED_ORIGIN);
        assertEquals(0, chain.calls);
    }

    @Test
    void preflightFromUnlistedOrigin_reachesChain() throws Exception {
        var filter = filter(cors(ALLOWED_ORIGIN), new CountingHandler());
        var request = request("OPTIONS", "/simple/ping", "/simple/ping");
        request.addHeader("Origin", OTHER_ORIGIN);
        var response = response();
        var chain = new RecordingChain();

        filter.doFilter(request, response, chain);

        verify(response, never()).setStatus(anyInt());
        assertEquals(1, chain.calls);
    }

    @Test
    void adminPath_bypassesRedeployLock() throws Exception {
        var filter = filter(new MockEnvironment(), new CountingHandler());
        var chain = new RecordingChain();

        filter.doFilter(request("GET", "/admin/services", "/admin/services"), response(), chain);

        assertEquals(1, chain.calls);
        assertEquals(0, chain.readHolds);
    }

    @Test
    void servicePath_holdsRedeployReadLockWhileChained() throws Exception {
        var filter = filter(new MockEnvironment(), new CountingHandler());
        var chain = new RecordingChain();

        filter.doFilter(request("POST", "/simple/ping", "/simple/ping"), response(), chain);

        assertEquals(1, chain.calls);
        assertEquals(1, chain.readHolds);
        assertEquals(0, readHolds());
    }

    @Test
    void destroy_releasesState() throws Exception {
        var filter = filter(new MockEnvironment(), new CountingChecker(Decision.ALLOW, 0), new CountingHandler());

        filter.destroy();

        assertNull(ReflectionTestUtils.getField(filter, "authorizationCheckers"));
        assertNull(ReflectionTestUtils.getField(filter, "accessDeniedHandler"));
        assertNull(ReflectionTestUtils.getField(filter, "mimeMap"));
        assertNull(ReflectionTestUtils.getField(filter, "xForwardedFilter"));
    }

    /**
     * Initializes a filter as the web application does: its servlet context holds a {@link SpringInitializer} whose
     * Spring context has the given environment and beans, and its filter configuration carries the init parameter of
     * the {@code @WebFilter} declaration. The servlet context reads MIME types from the JDK file name map, because the
     * mock's own lookup needs {@code spring-web}, which this module does not have.
     */
    private static RuleServicesFilter filter(MockEnvironment env, Object... beans) throws ServletException {
        try (var context = new ClassPathXmlApplicationContext()) {
            context.setEnvironment(env);
            context.refresh();
            for (int i = 0; i < beans.length; i++) {
                context.getBeanFactory().registerSingleton("bean" + i, beans[i]);
            }
            var initializer = new SpringInitializer();
            ReflectionTestUtils.setField(initializer, "applicationContext", context);
            var servletContext = new MockServletContext() {
                @Override
                public @Nullable String getMimeType(String filePath) {
                    return URLConnection.getFileNameMap().getContentTypeFor(filePath);
                }
            };
            servletContext.setAttribute(SpringInitializer.class.getName(), initializer);
            var filterConfig = new MockFilterConfig(servletContext);
            filterConfig.addInitParameter("xForwardedPrefixStrategy", "PREPEND");
            var filter = new RuleServicesFilter();
            filter.init(filterConfig);
            return filter;
        }
    }

    private static MockEnvironment cors(String allowedOrigins) {
        return new MockEnvironment().withProperty("cors.allowed.origins", allowedOrigins)
                .withProperty("cors.allowed.methods", "GET,POST")
                .withProperty("cors.allowed.headers", "Content-Type")
                .withProperty("cors.preflight.maxage", "7200");
    }

    /**
     * Builds a request whose path info is the servlet-resolved form of the request URI as sent.
     */
    private static MockHttpServletRequest request(String method, @Nullable String pathInfo, String requestUri) {
        var request = new MockHttpServletRequest(method, requestUri);
        request.setPathInfo(pathInfo);
        return request;
    }

    /**
     * A response mock, because the Spring mock response needs {@code spring-web}, which this module does not have.
     */
    private static HttpServletResponse response() {
        return mock(HttpServletResponse.class);
    }

    private static HttpServletResponse response(CapturingOutputStream body) throws IOException {
        var response = response();
        when(response.getOutputStream()).thenReturn(body);
        return response;
    }

    private static byte[] staticResource(String path) throws IOException {
        try (var stream = RuleServicesFilter.class.getClassLoader().getResourceAsStream("static" + path)) {
            return Objects.requireNonNull(stream, path).readAllBytes();
        }
    }

    /**
     * The read holds of the redeploy lock held by the calling thread.
     */
    private static int readHolds() {
        var lock = ReflectionTestUtils.getField(RuleServiceRedeployLock.getInstance(), "reentrantReadWriteLock");
        return ((ReentrantReadWriteLock) Objects.requireNonNull(lock)).getReadHoldCount();
    }

    private enum Decision {
        ALLOW,
        DENY,
        THROW
    }

    /**
     * An ordered checker stub that counts its calls and answers with a fixed decision.
     */
    private static final class CountingChecker implements AuthorizationChecker, Ordered {
        private final Decision decision;
        private final int order;
        private int calls;

        CountingChecker(Decision decision, int order) {
            this.decision = decision;
            this.order = order;
        }

        @Override
        public boolean authorize(HttpServletRequest request) {
            calls++;
            if (decision == Decision.THROW) {
                throw new IllegalStateException("Checker failure");
            }
            return decision == Decision.ALLOW;
        }

        @Override
        public int getOrder() {
            return order;
        }
    }

    /**
     * An access denied handler stub that counts its calls and answers 401.
     */
    private static final class CountingHandler implements AccessDeniedHandler {
        private int calls;

        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response) {
            calls++;
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    /**
     * A filter chain that counts its calls and records the redeploy read holds of the calling thread.
     */
    private static final class RecordingChain implements FilterChain {
        private int calls;
        private int readHolds = -1;

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) {
            calls++;
            readHolds = readHolds();
        }
    }

    /**
     * A blocking servlet output stream that keeps what is written to it.
     */
    private static final class CapturingOutputStream extends ServletOutputStream {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setWriteListener(WriteListener writeListener) {
            throw new IllegalStateException("Non-blocking output is not supported");
        }

        @Override
        public void write(int b) {
            bytes.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) {
            bytes.write(b, off, len);
        }
    }
}

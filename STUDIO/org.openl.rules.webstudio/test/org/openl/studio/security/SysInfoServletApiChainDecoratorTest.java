package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestWrapper;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;

/**
 * V10: {@link SysInfoServletApiChainDecorator} serves {@code sys.json} and {@code http.json} with the request beneath
 * the servlet-API wrapper, so the servlet sees neither the principal nor the remote user of the authentication, and
 * leaves every other request as the security filters passed it on.
 */
class SysInfoServletApiChainDecoratorTest {

    private static final String USER = "sysinfo-user";
    private static final String OTHER = "/rest/users/profile";

    private final Authentication authentication = UsernamePasswordAuthenticationToken
            .authenticated(USER, null, List.of(new SimpleGrantedAuthority("USER")));

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void httpJsonGetsTheRequestBeneathTheServletApiWrapper() throws Exception {
        var container = request(SysInfoServletApiChainDecorator.HTTP_JSON);
        var wrapper = servletApiWrapper(container);
        assertNotNull(wrapper.getUserPrincipal(), "premise: the wrapper exposes the principal");
        assertEquals(USER, wrapper.getRemoteUser(), "premise: the wrapper exposes the remote user");

        var served = serve(wrapper);

        assertSame(container, served, "request the servlet gets");
        assertNull(((HttpServletRequest) served).getUserPrincipal(), "principal the servlet sees");
        assertNull(((HttpServletRequest) served).getRemoteUser(), "remote user the servlet sees");
    }

    @Test
    void sysJsonGetsTheRequestBeneathTheServletApiWrapper() throws Exception {
        var container = request(SysInfoServletApiChainDecorator.SYS_JSON);

        assertSame(container, serve(servletApiWrapper(container)), "request the servlet gets");
    }

    /** Wrappers beneath the servlet-API wrapper, such as the header writer's, stay in place. */
    @Test
    void wrapperBeneathTheServletApiWrapperIsKept() throws Exception {
        var inner = new HttpServletRequestWrapper(request(SysInfoServletApiChainDecorator.HTTP_JSON));

        assertSame(inner, serve(servletApiWrapper(inner)), "request the servlet gets");
    }

    @Test
    void servletApiWrapperBeneathAnotherWrapperIsFound() throws Exception {
        var container = request(SysInfoServletApiChainDecorator.HTTP_JSON);
        var outer = new HttpServletRequestWrapper(servletApiWrapper(container));
        assertNotNull(outer.getUserPrincipal(), "premise: the outer wrapper exposes the principal");

        var served = serve(outer);

        assertSame(container, served, "request the servlet gets");
        assertNull(((HttpServletRequest) served).getUserPrincipal(), "principal the servlet sees");
    }

    /** With two servlet-API wrappers, the request beneath the innermost one is served, so neither remains. */
    @Test
    void requestBeneathTheInnermostServletApiWrapperIsServed() throws Exception {
        var container = request(SysInfoServletApiChainDecorator.HTTP_JSON);
        var doublyWrapped = servletApiWrapper(new HttpServletRequestWrapper(servletApiWrapper(container)));

        var served = serve(doublyWrapped);

        assertSame(container, served, "request the servlet gets");
        assertNull(((HttpServletRequest) served).getRemoteUser(), "remote user the servlet sees");
    }

    @Test
    void endpointRequestWithoutServletApiWrapperIsUnchanged() throws Exception {
        var plain = request(SysInfoServletApiChainDecorator.HTTP_JSON);
        var wrapped = new HttpServletRequestWrapper(request(SysInfoServletApiChainDecorator.SYS_JSON));

        assertSame(plain, serve(plain), "request without any wrapper");
        assertSame(wrapped, serve(wrapped), "request with another wrapper only");
    }

    @Test
    void otherRequestKeepsTheServletApiWrapper() throws Exception {
        var wrapper = servletApiWrapper(request(OTHER));

        var served = serve(wrapper);

        assertSame(wrapper, served, "request the servlet gets");
        assertEquals(USER, ((HttpServletRequest) served).getRemoteUser(), "remote user the servlet sees");
    }

    @Test
    void lookalikePathKeepsTheServletApiWrapper() throws Exception {
        var wrapper = servletApiWrapper(request(SysInfoServletApiChainDecorator.HTTP_JSON + "x"));

        assertSame(wrapper, serve(wrapper), "request the servlet gets");
    }

    @Test
    void requestThatIsNotHttpIsUnchanged() throws Exception {
        var notHttp = new ServletRequestWrapper(servletApiWrapper(request(SysInfoServletApiChainDecorator.HTTP_JSON)));

        assertSame(notHttp, serve(notHttp), "request the servlet gets");
    }

    /** The delegate decorates the same filters, and the response goes on as the filters passed it. */
    @Test
    void delegateDecoratesTheFiltersAroundTheOriginalChain() throws Exception {
        var recording = new RecordingDecorator();
        var calls = new ArrayList<String>();
        Filter first = (req, res, chain) -> {
            calls.add("first");
            chain.doFilter(req, res);
        };
        Filter second = (req, res, chain) -> {
            calls.add("second");
            chain.doFilter(req, res);
        };
        var response = new MockHttpServletResponse();
        var received = new ServletResponse[1];
        FilterChain original = (req, res) -> {
            calls.add("original");
            received[0] = res;
        };

        new SysInfoServletApiChainDecorator(recording).decorate(original, List.of(first, second))
                .doFilter(request(OTHER), response);

        assertEquals(List.of(first, second), recording.filters, "filters the delegate decorates");
        assertEquals(List.of("first", "second", "original"), calls, "call order");
        assertSame(response, received[0], "response of the original chain");
    }

    /** Without filters no wrapper can exist, so the delegate decorates the original chain itself. */
    @Test
    void noFiltersLeaveTheOriginalChainToTheDelegate() {
        var recording = new RecordingDecorator();
        var decorator = new SysInfoServletApiChainDecorator(recording);
        FilterChain original = (req, res) -> {
        };

        assertSame(original, decorator.decorate(original), "decorate(original)");
        assertSame(original, recording.original, "chain the delegate gets from decorate(original)");
        assertSame(original, decorator.decorate(original, List.of()), "decorate(original, no filters)");
        assertSame(original, recording.original, "chain the delegate gets with no filters");
    }

    /**
     * The decorator in a real {@link FilterChainProxy} whose chain holds Spring Security's servlet-API filter: the
     * endpoints are served without the authentication, any other request with it.
     */
    @Test
    void proxyWithTheServletApiFilterHidesTheAuthenticationFromTheEndpointsOnly() throws Exception {
        var servletApi = new SecurityContextHolderAwareRequestFilter();
        servletApi.afterPropertiesSet();
        var proxy = new FilterChainProxy(new DefaultSecurityFilterChain(request -> true, servletApi));
        proxy.setFilterChainDecorator(new SysInfoServletApiChainDecorator(new EagerSecurityHeadersChainDecorator()));
        proxy.afterPropertiesSet();

        for (String endpoint : List.of(SysInfoServletApiChainDecorator.SYS_JSON,
                SysInfoServletApiChainDecorator.HTTP_JSON)) {
            var seen = proxyServe(proxy, endpoint);
            assertNull(seen.getUserPrincipal(), endpoint + ": principal the servlet sees");
            assertNull(seen.getRemoteUser(), endpoint + ": remote user the servlet sees");
        }
        var other = proxyServe(proxy, OTHER);
        assertNotNull(other.getUserPrincipal(), OTHER + ": principal the servlet sees");
        assertEquals(USER, other.getRemoteUser(), OTHER + ": remote user the servlet sees");
    }

    /**
     * Runs the request through the proxy with {@link #authentication} in the security context and returns the
     * principal and remote user the servlet saw, read while the request was being served.
     */
    private HttpServletRequest proxyServe(FilterChainProxy proxy, String uri) throws Exception {
        var seen = new MockHttpServletRequest();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        proxy.doFilter(request(uri), new MockHttpServletResponse(), (req, res) -> {
            var http = (HttpServletRequest) req;
            seen.setUserPrincipal(http.getUserPrincipal());
            seen.setRemoteUser(http.getRemoteUser());
        });
        return seen;
    }

    /**
     * Serves the request through the decorator, around Spring Security's virtual filter chain with one pass-through
     * filter, and returns what the servlet got.
     */
    private static ServletRequest serve(ServletRequest request) throws Exception {
        var served = new ServletRequest[1];
        FilterChain servlet = (req, res) -> served[0] = req;
        Filter passThrough = (req, res, chain) -> chain.doFilter(req, res);
        new SysInfoServletApiChainDecorator(new FilterChainProxy.VirtualFilterChainDecorator())
                .decorate(servlet, List.of(passThrough))
                .doFilter(request, new MockHttpServletResponse());
        assertNotNull(served[0], "the servlet is reached");
        return served[0];
    }

    /** The servlet-API wrapper over the given request, with {@link #authentication} in its security context. */
    private SecurityContextHolderAwareRequestWrapper servletApiWrapper(HttpServletRequest request) {
        var strategy = mock(SecurityContextHolderStrategy.class);
        when(strategy.getContext()).thenReturn(new SecurityContextImpl(authentication));
        var wrapper = new SecurityContextHolderAwareRequestWrapper(request, "ROLE_");
        wrapper.setSecurityContextHolderStrategy(strategy);
        return wrapper;
    }

    private static MockHttpServletRequest request(String uri) {
        var request = new MockHttpServletRequest("GET", uri);
        request.setServletPath(uri);
        return request;
    }

    /** Records what it is asked to decorate and decorates it as Spring Security's virtual filter chain does. */
    private static final class RecordingDecorator implements FilterChainProxy.FilterChainDecorator {

        private final FilterChainProxy.VirtualFilterChainDecorator virtual =
                new FilterChainProxy.VirtualFilterChainDecorator();
        private @Nullable FilterChain original;
        private @Nullable List<Filter> filters;

        @Override
        public FilterChain decorate(FilterChain original, List<Filter> filters) {
            this.original = original;
            this.filters = filters;
            return filters.isEmpty() ? original : virtual.decorate(original, filters);
        }
    }
}

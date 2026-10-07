package org.openl.studio.security;

import java.util.List;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestWrapper;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.CollectionUtils;

/**
 * V10: serves {@code /rest/public/info/sys.json} and {@code /rest/public/info/http.json} with the servlet-API view of
 * the request they had on the static chain, now that they require authentication.
 * <p>
 * Until V10 both endpoints ran on the static chain of {@link SecurityConfig}, which disables the servlet-API
 * integration, so {@code getUserPrincipal()} and {@code getRemoteUser()} answered from the servlet container and gave
 * {@code null} in OpenL Studio. V10 leaves them to each mode's {@code /rest/**} chain, which authenticates them. In
 * the {@code multi} and {@code ad} modes that chain is built by {@code HttpSecurity} with the servlet-API integration
 * on, whose {@link SecurityContextHolderAwareRequestWrapper} answers {@code getUserPrincipal()} with the whole
 * {@code Authentication}: its principal with the stored password hash, its authorities and its details.
 * {@code http.json} serializes that principal, so it would hand the caller's credential material to anyone who can
 * read the response.
 * </p>
 * <p>
 * This decorator hands the rest of the servlet filter chain, the {@code DispatcherServlet} included, the request
 * beneath the innermost {@link SecurityContextHolderAwareRequestWrapper} for those two endpoints, which is the request
 * the static chain passed on before V10. Authentication and authorization have already run by then, so the endpoints
 * still answer {@code 401} without an authentication and {@code 200} with one, and their responses keep the shape
 * they had before V10. Every other request, and a request without the wrapper, as on the SAML and OAuth2 chains, goes
 * on unchanged. The decorated chain itself comes from the delegate, which this class leaves to decorate the security
 * filters as it does on its own.
 * </p>
 */
public final class SysInfoServletApiChainDecorator implements FilterChainProxy.FilterChainDecorator {

    /** The system information endpoint, which the static chain's matcher excludes. */
    static final String SYS_JSON = "/rest/public/info/sys.json";

    /** The request information endpoint, which the static chain's matcher excludes. */
    static final String HTTP_JSON = "/rest/public/info/http.json";

    private final FilterChainProxy.FilterChainDecorator delegate;
    private final RequestMatcher endpoints = RequestMatchers.anyOf(SYS_JSON, HTTP_JSON);

    /**
     * Creates the decorator around the one that decorates the security filters.
     *
     * @param delegate the decorator that builds the chain of the security filters
     */
    public SysInfoServletApiChainDecorator(FilterChainProxy.FilterChainDecorator delegate) {
        this.delegate = delegate;
    }

    /**
     * Lets the delegate decorate the security filters, ending in an original chain that serves the two endpoints with
     * the request beneath the servlet-API wrapper.
     *
     * @param original the rest of the servlet filter chain, after the security filter chain
     * @param filters the filters of the matched security filter chain; none when no chain matched
     * @return the chain the delegate decorates; with no filters, the delegate gets the original chain as it is,
     *         because no filter can have wrapped the request
     */
    @Override
    public FilterChain decorate(FilterChain original, List<Filter> filters) {
        if (CollectionUtils.isEmpty(filters)) {
            return delegate.decorate(original, filters);
        }
        FilterChain servedWithoutServletApi = (request, response) -> {
            if (request instanceof HttpServletRequest httpRequest && endpoints.matches(httpRequest)) {
                original.doFilter(beneathServletApiWrapper(request), response);
            } else {
                original.doFilter(request, response);
            }
        };
        return delegate.decorate(servedWithoutServletApi, filters);
    }

    /**
     * Returns the request beneath the innermost {@link SecurityContextHolderAwareRequestWrapper} of the given
     * request's wrapper chain, or the request itself when the chain holds no such wrapper. The innermost one is taken
     * so that no servlet-API wrapper is left between the servlet and the container's request.
     */
    private static ServletRequest beneathServletApiWrapper(ServletRequest request) {
        ServletRequest beneath = request;
        ServletRequest current = request;
        while (current instanceof ServletRequestWrapper wrapper) {
            current = wrapper.getRequest();
            if (wrapper instanceof SecurityContextHolderAwareRequestWrapper) {
                beneath = current;
            }
        }
        return beneath;
    }
}

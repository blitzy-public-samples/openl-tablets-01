package org.openl.studio.security;

import java.util.ArrayList;
import java.util.List;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.util.CollectionUtils;

/**
 * V4: makes the matched security filter chain write the default security headers no later than the first output of
 * the response, so that a response the servlet container commits early still carries all of them.
 * <p>
 * The {@code HeaderWriterFilter} of every chain writes its headers lazily, when it notices that the response is about
 * to be committed: once the body written so far reaches the response buffer size, once it reaches the declared
 * {@code Content-Length}, or on a flush, an error or a redirect. Jetty commits a response earlier than that whenever
 * a single write is larger than its aggregation size, so a body streamed in large writes without a
 * {@code Content-Length}, such as a project file download, would go out before the chain's filter adds any header.
 * </p>
 * <p>
 * This decorator therefore does two things for whichever chain matches the request:
 * </p>
 * <ul>
 * <li>It puts one more {@link HeaderWriterFilter} in front of the chain's filters. That filter writes eagerly, before
 * the rest of the chain, and holds only the writers whose output never depends on the response:
 * {@code X-Content-Type-Options: nosniff}, {@code X-XSS-Protection: 0}, {@code Strict-Transport-Security} (on secure
 * requests only) and {@code X-Frame-Options: DENY}.</li>
 * <li>It hands the chain a {@link BeforeCommitHeadersResponse}, which writes the full default set, the
 * {@code Cache-Control}, {@code Pragma} and {@code Expires} headers included, just before the first output of the
 * response reaches the container. The cache headers wait until then because they give way to a cache policy the
 * response sets itself, which it does before its output; written before the chain, they would always find no policy
 * yet.</li>
 * </ul>
 * <p>
 * The chains' own lazy filters are kept unchanged: they still write the full set before an error or a redirect, and
 * at the end of the chain on a response that has had no output, a reset one included. Every Spring Security writer
 * either adds a header only when it is missing or, for {@code X-Frame-Options}, sets it in place of any earlier
 * value, and the cache writer backs off when the response already has a cache header, so no header is ever written
 * twice and a response's own cache policy keeps precedence.
 * </p>
 * <p>
 * A request that no chain matches, or whose chain holds no filter, passes through unchanged: the security headers
 * belong to the security filter chains only. That also covers {@link #decorate(FilterChain)}, which decorates with
 * no filters.
 * </p>
 */
public final class EagerSecurityHeadersChainDecorator implements FilterChainProxy.FilterChainDecorator {

    /**
     * The name of the eager filter. It gives the filter its own "already filtered" request attribute, apart from the
     * one that every unnamed {@link HeaderWriterFilter} of the chains shares, so neither filter skips the other.
     */
    static final String FILTER_NAME = EagerSecurityHeadersChainDecorator.class.getName();

    private final FilterChainProxy.FilterChainDecorator delegate = new FilterChainProxy.VirtualFilterChainDecorator();
    private final HeaderWriterFilter headerWriterFilter;

    /** Creates the decorator with the four response-independent writers of the default header set. */
    public EagerSecurityHeadersChainDecorator() {
        this(new HeaderWriterFilter(SecurityHeaderWriters.responseIndependent()));
    }

    /**
     * Makes the given filter the eager header filter: it writes before the chain, under its own name, and is
     * initialized like a filter bean.
     *
     * @param filter the header filter with the response-independent writers
     * @throws IllegalStateException when the filter fails to initialize
     */
    EagerSecurityHeadersChainDecorator(HeaderWriterFilter filter) {
        filter.setShouldWriteHeadersEagerly(true);
        filter.setBeanName(FILTER_NAME);
        try {
            filter.afterPropertiesSet();
        } catch (ServletException e) {
            throw new IllegalStateException("Cannot initialize the security headers filter", e);
        }
        this.headerWriterFilter = filter;
    }

    /**
     * Runs the eager header filter, then the given filters of the matched chain, then the original chain, all with a
     * response that writes the default headers before its first output.
     *
     * @param original the rest of the servlet filter chain, after the security filter chain
     * @param filters the filters of the matched security filter chain; none when no chain matched
     * @return the original chain when there is no filter, otherwise the decorated chain
     */
    @Override
    public FilterChain decorate(FilterChain original, List<Filter> filters) {
        if (CollectionUtils.isEmpty(filters)) {
            return original;
        }
        var withHeaders = new ArrayList<Filter>(filters.size() + 1);
        withHeaders.add(headerWriterFilter);
        withHeaders.addAll(filters);
        var chain = delegate.decorate(original, withHeaders);
        // V4: the full default set, cache headers included, also goes out before the first output of the response.
        // A request that is not HTTP is left to the eager filter, which rejects it as every security filter does.
        return (request, response) -> {
            if (request instanceof HttpServletRequest httpRequest
                    && response instanceof HttpServletResponse httpResponse) {
                chain.doFilter(request, new BeforeCommitHeadersResponse(httpRequest, httpResponse));
            } else {
                chain.doFilter(request, response);
            }
        };
    }
}

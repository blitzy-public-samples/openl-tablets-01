package org.openl.studio.security;

import java.util.ArrayList;
import java.util.List;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;

import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.util.CollectionUtils;

/**
 * V4: writes the security headers that do not depend on the response before the matched security filter chain runs,
 * so that a response the servlet container commits early still carries them.
 * <p>
 * The {@code HeaderWriterFilter} of every chain writes its headers lazily, when it notices that the response is about
 * to be committed: once the body written so far reaches the response buffer size, once it reaches the declared
 * {@code Content-Length}, or on a flush, an error or a redirect. Jetty commits a response earlier than that whenever
 * a single write is larger than its aggregation size, so a body streamed in large writes without a
 * {@code Content-Length}, such as a project file download, goes out before the chain's filter adds any header.
 * </p>
 * <p>
 * This decorator therefore puts one more {@link HeaderWriterFilter} in front of the filters of whichever chain
 * matches the request. It writes eagerly, before the rest of the chain, and holds only the writers whose output
 * never depends on the response: {@code X-Content-Type-Options: nosniff}, {@code X-XSS-Protection: 0},
 * {@code Strict-Transport-Security} (on secure requests only) and {@code X-Frame-Options: DENY}. It holds no
 * {@code CacheControlHeadersWriter}, because the cache headers must give way to the cache headers a response sets
 * itself, which are known only once the response is written. So the chains' own lazy filters are kept unchanged:
 * they still write the cache headers or back off, and they write the four headers again after a response is reset.
 * Their writers of the four headers add nothing to a response that already has them, because every Spring Security
 * writer checks the header first, so no header is ever written twice.
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
        this(new HeaderWriterFilter(List.of(
                new XContentTypeOptionsHeaderWriter(),
                new XXssProtectionHeaderWriter(),
                new HstsHeaderWriter(),
                new XFrameOptionsHeaderWriter(XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY))));
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
     * Runs the eager header filter, then the given filters of the matched chain, then the original chain.
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
        return delegate.decorate(original, withHeaders);
    }
}

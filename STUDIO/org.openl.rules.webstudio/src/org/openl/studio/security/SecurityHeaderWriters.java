package org.openl.studio.security;

import java.util.List;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;

/**
 * V4: defines the default security header writers of {@code HttpSecurity} once, for the header filter of the
 * hand-built chains, the eager header filter and the before-commit response, so that all three write the same set.
 * <p>
 * The writers, in the order Spring Security's {@code HeadersConfigurer} installs them, write
 * {@code X-Content-Type-Options: nosniff}, {@code X-XSS-Protection: 0},
 * {@code Cache-Control: no-cache, no-store, max-age=0, must-revalidate} with {@code Pragma: no-cache} and
 * {@code Expires: 0}, {@code Strict-Transport-Security} (on secure requests only) and {@code X-Frame-Options: DENY}.
 * No {@code Content-Security-Policy} is written.
 * </p>
 */
final class SecurityHeaderWriters {

    private SecurityHeaderWriters() {
        // Utility class, no instantiation
    }

    /**
     * Creates the default header writers, in the order the chains' header filter runs them.
     *
     * @return an unmodifiable list of new writers
     */
    static List<HeaderWriter> defaults() {
        return List.of(
                new XContentTypeOptionsHeaderWriter(),
                new XXssProtectionHeaderWriter(),
                new CacheControlHeadersWriter(),
                new HstsHeaderWriter(),
                new XFrameOptionsHeaderWriter(XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY));
    }

    /**
     * Creates the default header writers whose output never depends on the response, in the same order: every one but
     * the cache writer. The cache writer is left out because it gives way to a cache policy the response sets itself,
     * so what it writes depends on what the response has set by the time it runs.
     *
     * @return an unmodifiable list of new writers
     */
    static List<HeaderWriter> responseIndependent() {
        return defaults().stream()
                .filter(writer -> !(writer instanceof CacheControlHeadersWriter))
                .toList();
    }
}

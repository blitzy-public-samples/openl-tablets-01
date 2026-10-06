package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;

/**
 * V4: {@link SecurityHeaderWriters} is the one definition of the default security header writers that the chains'
 * header filter, the eager header filter and the before-commit response share.
 * <p>
 * The writers run on a mock request and response, and each test pins every header they write, so a writer that is
 * added, removed or configured differently fails here.
 * </p>
 */
class SecurityHeaderWritersTest {

    private static final String HSTS = "Strict-Transport-Security";

    /** The headers every default writer but HSTS writes on a response that sets no header of its own. */
    private static final Map<String, String> PLAIN_HEADERS = Map.of(
            "X-Content-Type-Options", "nosniff",
            "X-XSS-Protection", "0",
            "Cache-Control", "no-cache, no-store, max-age=0, must-revalidate",
            "Pragma", "no-cache",
            "Expires", "0",
            "X-Frame-Options", "DENY");

    /** The headers of the response-independent writers on a plain request: no cache header. */
    private static final Map<String, String> RESPONSE_INDEPENDENT_PLAIN_HEADERS = Map.of(
            "X-Content-Type-Options", "nosniff",
            "X-XSS-Protection", "0",
            "X-Frame-Options", "DENY");

    // V4: the writers and the order of Spring Security's HeadersConfigurer, which every other chain uses
    @Test
    void defaultsAreTheWritersOfHttpSecurityInTheirOrder() {
        assertEquals(List.of(XContentTypeOptionsHeaderWriter.class,
                XXssProtectionHeaderWriter.class,
                CacheControlHeadersWriter.class,
                HstsHeaderWriter.class,
                XFrameOptionsHeaderWriter.class), typesOf(SecurityHeaderWriters.defaults()));
    }

    // V4: the eager filter holds the default set without the cache writer, and nothing else
    @Test
    void responseIndependentIsTheDefaultSetWithoutTheCacheWriter() {
        var withoutCache = typesOf(SecurityHeaderWriters.defaults()).stream()
                .filter(type -> type != CacheControlHeadersWriter.class)
                .toList();

        assertEquals(List.of(XContentTypeOptionsHeaderWriter.class,
                XXssProtectionHeaderWriter.class,
                HstsHeaderWriter.class,
                XFrameOptionsHeaderWriter.class), typesOf(SecurityHeaderWriters.responseIndependent()));
        assertEquals(withoutCache, typesOf(SecurityHeaderWriters.responseIndependent()));
    }

    // V4: a caller cannot change the shared definition through the list it receives
    @Test
    void theListsAreUnmodifiable() {
        var defaults = SecurityHeaderWriters.defaults();
        var responseIndependent = SecurityHeaderWriters.responseIndependent();
        var writer = new XContentTypeOptionsHeaderWriter();

        assertThrows(UnsupportedOperationException.class, () -> defaults.add(writer));
        assertThrows(UnsupportedOperationException.class, () -> responseIndependent.add(writer));
    }

    // V4: every call creates its own writers, so no caller shares a writer instance with another
    @Test
    void eachCallCreatesNewWriters() {
        var first = SecurityHeaderWriters.defaults();
        var second = SecurityHeaderWriters.defaults();
        var responseIndependent = SecurityHeaderWriters.responseIndependent();
        var otherResponseIndependent = SecurityHeaderWriters.responseIndependent();

        for (int i = 0; i < first.size(); i++) {
            assertNotSame(first.get(i), second.get(i), "defaults writer " + i);
        }
        for (int i = 0; i < responseIndependent.size(); i++) {
            assertNotSame(responseIndependent.get(i), otherResponseIndependent.get(i), "response-independent " + i);
            for (var writer : first) {
                assertNotSame(writer, responseIndependent.get(i), "response-independent " + i + " in defaults");
            }
        }
    }

    // V4: a plain-HTTP response carries the default headers, without HSTS and without a Content-Security-Policy
    @Test
    void defaultsWriteTheDefaultHeadersOnAPlainRequest() {
        assertHeaders(PLAIN_HEADERS, write(SecurityHeaderWriters.defaults(), false));
    }

    // V4: HSTS is written on secure requests only
    @Test
    void defaultsAlsoWriteStrictTransportSecurityOnASecureRequest() {
        var expected = new HashMap<>(PLAIN_HEADERS);
        expected.put(HSTS, "max-age=31536000 ; includeSubDomains");

        assertHeaders(expected, write(SecurityHeaderWriters.defaults(), true));
    }

    // V4: the response-independent writers write no cache header, so a response's own cache policy keeps precedence
    @Test
    void responseIndependentWritesNoCacheHeader() {
        assertHeaders(RESPONSE_INDEPENDENT_PLAIN_HEADERS, write(SecurityHeaderWriters.responseIndependent(), false));

        var expected = new HashMap<>(RESPONSE_INDEPENDENT_PLAIN_HEADERS);
        expected.put(HSTS, "max-age=31536000 ; includeSubDomains");
        assertHeaders(expected, write(SecurityHeaderWriters.responseIndependent(), true));
    }

    private static List<Class<?>> typesOf(List<HeaderWriter> writers) {
        return writers.stream().<Class<?>>map(Object::getClass).toList();
    }

    private static MockHttpServletResponse write(List<HeaderWriter> writers, boolean secure) {
        var request = new MockHttpServletRequest();
        request.setSecure(secure);
        var response = new MockHttpServletResponse();
        for (var writer : writers) {
            writer.writeHeaders(request, response);
        }
        return response;
    }

    /** Asserts that the response has exactly the expected headers, each with exactly its expected value. */
    private static void assertHeaders(Map<String, String> expected, MockHttpServletResponse response) {
        assertEquals(expected.keySet(), Set.copyOf(response.getHeaderNames()), "the header names");
        expected.forEach((name, value) -> assertEquals(List.of(value), response.getHeaders(name), name));
    }
}

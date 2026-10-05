package org.openl.rules.webstudio.web.servlet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;

import org.openl.spring.env.DefaultPropertySource;

class AppPropertiesServletTest {

    private final AppPropertiesServlet servlet = new AppPropertiesServlet();
    private final MockServletContext servletContext = new MockServletContext();

    @Test
    void writesTheDefaultPropertiesAsPlainText() throws Exception {
        var response = new MockHttpServletResponse();

        servlet.service(request(), response);

        assertEquals(200, response.getStatus());
        assertTrue(response.getContentType().startsWith("text/plain"), response.getContentType());
        assertTrue(response.getContentAsString().contains("This file was generated"),
                response.getContentAsString());
    }

    @Test
    void answersWithAnErrorWhenTheResponseStreamIsGone() throws Exception {
        var response = mock(HttpServletResponse.class);
        when(response.getOutputStream()).thenThrow(new IOException("Connection closed"));

        servlet.service(request(), response);

        verify(response).reset();
        verify(response).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }

    // V4: the body goes out in one write with its length declared, and is the unchanged default properties output
    @Test
    void declaresTheLengthOfTheUnchangedBody() throws Exception {
        var expected = new ByteArrayOutputStream();
        DefaultPropertySource.transferAllOpenLDefaultProperties(expected);
        var response = new MockHttpServletResponse();

        servlet.service(request(), response);

        assertArrayEquals(expected.toByteArray(), response.getContentAsByteArray(), "body");
        assertEquals(expected.size(), response.getContentLength(), "Content-Length");
        assertEquals(String.valueOf(expected.size()), response.getHeader("Content-Length"), "Content-Length header");
        assertEquals("text/plain;charset=UTF-8", response.getContentType(), "Content-Type");
    }

    /**
     * V4: behind a lazy {@link HeaderWriterFilter}, the security and cache headers reach a response that commits the
     * way Jetty does. Streamed in 16 KiB writes without a length, the body committed the response before the filter
     * wrote any header.
     */
    @Test
    void securityHeadersReachAResponseThatCommitsEarly() throws Exception {
        var headers = new HeaderWriterFilter(List.of(
                new XContentTypeOptionsHeaderWriter(),
                new XXssProtectionHeaderWriter(),
                new CacheControlHeadersWriter(),
                new HstsHeaderWriter(),
                new XFrameOptionsHeaderWriter(XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY)));
        var response = new EarlyCommitResponse();

        headers.doFilter(request(), response, servlet::service);

        assertTrue(response.isCommitted(), "the body write commits the response");
        assertEquals(List.of("nosniff"), response.getHeaders("X-Content-Type-Options"), "X-Content-Type-Options");
        assertEquals(List.of("0"), response.getHeaders("X-XSS-Protection"), "X-XSS-Protection");
        assertEquals(List.of("DENY"), response.getHeaders("X-Frame-Options"), "X-Frame-Options");
        assertEquals(List.of("no-cache, no-store, max-age=0, must-revalidate"),
                response.getHeaders("Cache-Control"),
                "Cache-Control");
        assertEquals(List.of("no-cache"), response.getHeaders("Pragma"), "Pragma");
        assertEquals(List.of("0"), response.getHeaders("Expires"), "Expires");
    }

    // V4: a write that fails once the response has gone out leaves the response as it is
    @Test
    void keepsACommittedResponseWhenTheWriteFails() throws Exception {
        var out = mock(ServletOutputStream.class);
        doThrow(new IOException("Broken pipe")).when(out).write(any(byte[].class), anyInt(), anyInt());
        var response = mock(HttpServletResponse.class);
        when(response.getOutputStream()).thenReturn(out);
        when(response.isCommitted()).thenReturn(true);

        servlet.service(request(), response);

        verify(response, never()).reset();
        verify(response, never()).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }

    private MockHttpServletRequest request() {
        return new MockHttpServletRequest(servletContext, "GET", "/application.properties");
    }

    /**
     * A mock response that commits the way Jetty does: a single write larger than Jetty's default output aggregation
     * size commits it before its default output buffer fills. Once committed, it ignores every header.
     */
    private static final class EarlyCommitResponse extends MockHttpServletResponse {

        private static final int AGGREGATION_SIZE = 8192;
        private static final int BUFFER_SIZE = 32768;

        private @Nullable ServletOutputStream outputStream;

        EarlyCommitResponse() {
            setBufferSize(BUFFER_SIZE);
        }

        @Override
        public ServletOutputStream getOutputStream() {
            if (outputStream == null) {
                var target = super.getOutputStream();
                outputStream = new ServletOutputStream() {

                    @Override
                    public boolean isReady() {
                        return true;
                    }

                    @Override
                    public void setWriteListener(WriteListener writeListener) {
                        throw new UnsupportedOperationException("Blocking writes only");
                    }

                    @Override
                    public void write(int b) throws IOException {
                        target.write(b);
                    }

                    @Override
                    public void write(byte[] b, int off, int len) throws IOException {
                        if (len > AGGREGATION_SIZE) {
                            setCommitted(true);
                        }
                        target.write(b, off, len);
                    }
                };
            }
            return outputStream;
        }

        @Override
        public void setHeader(String name, @Nullable String value) {
            if (!isCommitted()) {
                super.setHeader(name, value);
            }
        }

        @Override
        public void addHeader(String name, @Nullable String value) {
            if (!isCommitted()) {
                super.addHeader(name, value);
            }
        }
    }
}

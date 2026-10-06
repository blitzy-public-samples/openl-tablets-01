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
import jakarta.servlet.Filter;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;

import org.openl.spring.env.DefaultPropertySource;
import org.openl.studio.security.EagerSecurityHeadersChainDecorator;

class AppPropertiesServletTest {

    private final AppPropertiesServlet servlet = new AppPropertiesServlet();
    private final MockServletContext servletContext = new MockServletContext();

    @Test
    void writesTheDefaultPropertiesAsPlainText() throws Exception {
        var response = new MockHttpServletResponse();

        servlet.service(request(), response);

        assertEquals(200, response.getStatus());
        assertTrue(response.getContentType().startsWith("text/plain"), response.getContentType());
        // V4: a fixed failure message, so a failure never prints the response body
        assertTrue(response.getContentAsString().contains("This file was generated"),
                "the body lacks the generated-file marker");
    }

    @Test
    void answersWithAnErrorWhenTheResponseStreamIsGone() throws Exception {
        var response = mock(HttpServletResponse.class);
        when(response.getOutputStream()).thenThrow(new IOException("Connection closed"));

        servlet.service(request(), response);

        verify(response).reset();
        verify(response).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }

    /**
     * V4: streamed through the security filter chain decorator that every Studio request passes, the unchanged default
     * properties commit the response the way Jetty does, and the default security and cache headers are on it once
     * each before they do. The pass-through filter stands for a matched chain that holds no header writer of its own.
     */
    @Test
    void securityHeadersReachTheStreamedBodyBeforeItCommits() throws Exception {
        var expected = new ByteArrayOutputStream();
        DefaultPropertySource.transferAllOpenLDefaultProperties(expected);
        Filter passThrough = (req, res, chain) -> chain.doFilter(req, res);
        var chain = new EagerSecurityHeadersChainDecorator().decorate(servlet::service, List.of(passThrough));
        var response = new EarlyCommitResponse();

        chain.doFilter(request(), response);

        assertTrue(response.isCommitted(), "the streamed body commits the response");
        assertEquals(List.of("nosniff"), response.getHeaders("X-Content-Type-Options"), "X-Content-Type-Options");
        assertEquals(List.of("0"), response.getHeaders("X-XSS-Protection"), "X-XSS-Protection");
        assertEquals(List.of("DENY"), response.getHeaders("X-Frame-Options"), "X-Frame-Options");
        assertEquals(List.of("no-cache, no-store, max-age=0, must-revalidate"),
                response.getHeaders("Cache-Control"),
                "Cache-Control");
        assertEquals(List.of("no-cache"), response.getHeaders("Pragma"), "Pragma");
        assertEquals(List.of("0"), response.getHeaders("Expires"), "Expires");
        assertEquals(List.of(),
                response.getHeaders("Strict-Transport-Security"),
                "Strict-Transport-Security on a plain request");
        assertArrayEquals(expected.toByteArray(),
                response.getContentAsByteArray(),
                "the body differs from the default properties output");
        assertEquals("text/plain;charset=UTF-8", response.getContentType(), "Content-Type");
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

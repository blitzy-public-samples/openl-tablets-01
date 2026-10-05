package org.openl.studio.security;

import java.io.IOException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;

import org.jspecify.annotations.Nullable;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * V4: a mock response that commits the way Jetty does, for the tests of the security headers on early-committed
 * responses.
 * <p>
 * Its buffer size is Jetty's default output buffer size, which Spring Security's commit tracker compares the written
 * length with. A single write larger than Jetty's default output aggregation size commits it at once, before the
 * buffer fills. Like a servlet container, it ignores every header set once it is committed.
 * </p>
 */
final class EarlyCommitResponse extends MockHttpServletResponse {

    /** Jetty's default output aggregation size. A larger single write commits the response at once. */
    static final int AGGREGATION_SIZE = 8192;

    /** Jetty's default output buffer size. */
    static final int BUFFER_SIZE = 32768;

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

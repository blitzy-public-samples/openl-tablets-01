package org.openl.studio.security;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;

import org.jspecify.annotations.Nullable;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * V4: a mock response that commits the way Jetty does, for the tests of the security headers on early-committed
 * responses.
 * <p>
 * Its buffer size is Jetty's default output buffer size, which Spring Security's commit tracker compares the written
 * length with. A single write to its output stream or its writer that is larger than the aggregation size, by default
 * Jetty's, commits it at once, before the buffer fills; an aggregation size of {@code 0} commits it on its first byte
 * or character. A flush or a close commits it too. Like a servlet container, it ignores every header set once it is
 * committed.
 * </p>
 */
final class EarlyCommitResponse extends MockHttpServletResponse {

    /** Jetty's default output aggregation size. A larger single write commits the response at once. */
    static final int AGGREGATION_SIZE = 8192;

    /** Jetty's default output buffer size. */
    static final int BUFFER_SIZE = 32768;

    private final int aggregationSize;
    private @Nullable ServletOutputStream outputStream;
    private @Nullable PrintWriter writer;

    EarlyCommitResponse() {
        this(AGGREGATION_SIZE);
    }

    /**
     * Creates a response that commits on a single write larger than the given size.
     *
     * @param aggregationSize the largest single write, in bytes or characters, that does not commit the response
     */
    EarlyCommitResponse(int aggregationSize) {
        this.aggregationSize = aggregationSize;
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
                    commitIfLarger(1);
                    target.write(b);
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    commitIfLarger(len);
                    target.write(b, off, len);
                }

                @Override
                public void flush() throws IOException {
                    target.flush();
                }

                @Override
                public void close() throws IOException {
                    target.close();
                    setCommitted(true);
                }
            };
        }
        return outputStream;
    }

    /** Returns a writer that commits like the output stream; every print, format and append ends in its write. */
    @Override
    public PrintWriter getWriter() throws UnsupportedEncodingException {
        if (writer == null) {
            var target = super.getWriter();
            writer = new PrintWriter(new Writer() {

                @Override
                public void write(char[] cbuf, int off, int len) {
                    commitIfLarger(len);
                    target.write(cbuf, off, len);
                }

                @Override
                public void flush() {
                    target.flush();
                }

                @Override
                public void close() {
                    target.close();
                }
            });
        }
        return writer;
    }

    private void commitIfLarger(int length) {
        if (length > aggregationSize) {
            setCommitted(true);
        }
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

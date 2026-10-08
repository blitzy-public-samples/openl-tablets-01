package org.openl.studio.security;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Locale;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import org.jspecify.annotations.Nullable;
import org.springframework.security.web.header.HeaderWriter;

/**
 * V4: a response that writes the default security headers just before its first output reaches the servlet
 * container, so that they go out even when the container commits the response on that output.
 * <p>
 * Spring Security's {@code HeaderWriterFilter} writes its headers once it notices that the response is about to be
 * committed. Jetty commits a response before that whenever a single write is larger than its aggregation size, which
 * is how a body streamed in large writes without a {@code Content-Length}, such as a project file download, goes
 * out. This response does not wait: any write, print, append, flush or close on its output stream or its writer, a
 * {@code checkError} on its writer, and {@link #flushBuffer()} first write the full default set, with the writers and
 * in the order of the chains' own header filter: {@code X-Content-Type-Options: nosniff}, {@code X-XSS-Protection: 0},
 * {@code Cache-Control: no-cache, no-store, max-age=0, must-revalidate} with {@code Pragma: no-cache} and
 * {@code Expires: 0}, {@code Strict-Transport-Security} (on secure requests only) and {@code X-Frame-Options: DENY}.
 * </p>
 * <p>
 * Every writer but the {@code X-Frame-Options} one adds only a header the response does not have yet, and the cache
 * writer adds nothing to a response that already has a {@code Cache-Control}, {@code Pragma} or {@code Expires}
 * header of its own, such as the {@code Expires} Jetty adds with a new session cookie, or that answers
 * {@code 304 Not Modified}. So the headers and the cache policy a response sets before its first output keep
 * precedence; {@code X-Frame-Options} is always set to {@code DENY}, as the chain's header filter sets it. No header
 * is written twice, neither here nor by the chain's header filter afterwards. The headers are written once, and not at
 * all on a response that is already committed, which takes no more headers. A {@link #reset()} clears the headers, so
 * the next output writes them again. {@code sendError} and {@code sendRedirect} are left as they are: the chain's
 * header filter writes the full set before either of them.
 * </p>
 * <p>
 * Every call of {@link #getOutputStream()} or {@link #getWriter()} returns a new view of the container's stream or
 * writer, and each view hands every call to the container's own method, so the container's character encoding and
 * formatting stay in effect.
 * </p>
 */
final class BeforeCommitHeadersResponse extends HttpServletResponseWrapper {

    /** The default header writers of {@code HttpSecurity}, in the order the chains' header filter runs them. */
    private static final List<HeaderWriter> DEFAULT_HEADER_WRITERS = SecurityHeaderWriters.defaults();

    private final HttpServletRequest request;
    private boolean headersWritten;

    /**
     * Wraps the response of a request.
     *
     * @param request the request the response answers, which tells whether it is secure
     * @param response the response that receives the headers and the output
     */
    BeforeCommitHeadersResponse(HttpServletRequest request, HttpServletResponse response) {
        super(response);
        this.request = request;
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        return new HeadersFirstOutputStream(super.getOutputStream());
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        return new HeadersFirstWriter(super.getWriter());
    }

    @Override
    public void flushBuffer() throws IOException {
        writeHeaders();
        super.flushBuffer();
    }

    /** Resets the response, which clears its headers, so that its next output writes them again. */
    @Override
    public void reset() {
        super.reset();
        headersWritten = false;
    }

    /** Writes the default headers the response lacks, before its first output, unless it is already committed. */
    private void writeHeaders() {
        if (headersWritten) {
            return;
        }
        headersWritten = true;
        if (isCommitted()) {
            return;
        }
        var response = (HttpServletResponse) getResponse();
        for (var writer : DEFAULT_HEADER_WRITERS) {
            writer.writeHeaders(request, response);
        }
    }

    /** The container's output stream, with the headers written before anything reaches it. */
    private final class HeadersFirstOutputStream extends ServletOutputStream {

        private final ServletOutputStream delegate;

        HeadersFirstOutputStream(ServletOutputStream delegate) {
            this.delegate = delegate;
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setWriteListener(WriteListener writeListener) {
            delegate.setWriteListener(writeListener);
        }

        @Override
        public void write(int b) throws IOException {
            writeHeaders();
            delegate.write(b);
        }

        @Override
        public void write(byte[] b) throws IOException {
            writeHeaders();
            delegate.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            writeHeaders();
            delegate.write(b, off, len);
        }

        @Override
        public void print(@Nullable String s) throws IOException {
            writeHeaders();
            delegate.print(s);
        }

        @Override
        public void print(boolean b) throws IOException {
            writeHeaders();
            delegate.print(b);
        }

        @Override
        public void print(char c) throws IOException {
            writeHeaders();
            delegate.print(c);
        }

        @Override
        public void print(int i) throws IOException {
            writeHeaders();
            delegate.print(i);
        }

        @Override
        public void print(long l) throws IOException {
            writeHeaders();
            delegate.print(l);
        }

        @Override
        public void print(float f) throws IOException {
            writeHeaders();
            delegate.print(f);
        }

        @Override
        public void print(double d) throws IOException {
            writeHeaders();
            delegate.print(d);
        }

        @Override
        public void println() throws IOException {
            writeHeaders();
            delegate.println();
        }

        @Override
        public void println(@Nullable String s) throws IOException {
            writeHeaders();
            delegate.println(s);
        }

        @Override
        public void println(boolean b) throws IOException {
            writeHeaders();
            delegate.println(b);
        }

        @Override
        public void println(char c) throws IOException {
            writeHeaders();
            delegate.println(c);
        }

        @Override
        public void println(int i) throws IOException {
            writeHeaders();
            delegate.println(i);
        }

        @Override
        public void println(long l) throws IOException {
            writeHeaders();
            delegate.println(l);
        }

        @Override
        public void println(float f) throws IOException {
            writeHeaders();
            delegate.println(f);
        }

        @Override
        public void println(double d) throws IOException {
            writeHeaders();
            delegate.println(d);
        }

        @Override
        public void flush() throws IOException {
            writeHeaders();
            delegate.flush();
        }

        @Override
        public void close() throws IOException {
            writeHeaders();
            delegate.close();
        }
    }

    /** The container's writer, with the headers written before anything reaches it. */
    private final class HeadersFirstWriter extends PrintWriter {

        private final PrintWriter delegate;

        HeadersFirstWriter(PrintWriter delegate) {
            super(delegate);
            this.delegate = delegate;
        }

        @Override
        public void write(int c) {
            writeHeaders();
            delegate.write(c);
        }

        @Override
        public void write(char[] buf, int off, int len) {
            writeHeaders();
            delegate.write(buf, off, len);
        }

        @Override
        public void write(char[] buf) {
            writeHeaders();
            delegate.write(buf);
        }

        @Override
        public void write(String s, int off, int len) {
            writeHeaders();
            delegate.write(s, off, len);
        }

        @Override
        public void write(String s) {
            writeHeaders();
            delegate.write(s);
        }

        @Override
        public void print(boolean b) {
            writeHeaders();
            delegate.print(b);
        }

        @Override
        public void print(char c) {
            writeHeaders();
            delegate.print(c);
        }

        @Override
        public void print(int i) {
            writeHeaders();
            delegate.print(i);
        }

        @Override
        public void print(long l) {
            writeHeaders();
            delegate.print(l);
        }

        @Override
        public void print(float f) {
            writeHeaders();
            delegate.print(f);
        }

        @Override
        public void print(double d) {
            writeHeaders();
            delegate.print(d);
        }

        @Override
        public void print(char[] s) {
            writeHeaders();
            delegate.print(s);
        }

        @Override
        public void print(@Nullable String s) {
            writeHeaders();
            delegate.print(s);
        }

        @Override
        public void print(@Nullable Object obj) {
            writeHeaders();
            delegate.print(obj);
        }

        @Override
        public void println() {
            writeHeaders();
            delegate.println();
        }

        @Override
        public void println(boolean x) {
            writeHeaders();
            delegate.println(x);
        }

        @Override
        public void println(char x) {
            writeHeaders();
            delegate.println(x);
        }

        @Override
        public void println(int x) {
            writeHeaders();
            delegate.println(x);
        }

        @Override
        public void println(long x) {
            writeHeaders();
            delegate.println(x);
        }

        @Override
        public void println(float x) {
            writeHeaders();
            delegate.println(x);
        }

        @Override
        public void println(double x) {
            writeHeaders();
            delegate.println(x);
        }

        @Override
        public void println(char[] x) {
            writeHeaders();
            delegate.println(x);
        }

        @Override
        public void println(@Nullable String x) {
            writeHeaders();
            delegate.println(x);
        }

        @Override
        public void println(@Nullable Object x) {
            writeHeaders();
            delegate.println(x);
        }

        @Override
        public PrintWriter printf(String format, @Nullable Object... args) {
            writeHeaders();
            delegate.printf(format, args);
            return this;
        }

        @Override
        public PrintWriter printf(@Nullable Locale l, String format, @Nullable Object... args) {
            writeHeaders();
            delegate.printf(l, format, args);
            return this;
        }

        @Override
        public PrintWriter format(String format, @Nullable Object... args) {
            writeHeaders();
            delegate.format(format, args);
            return this;
        }

        @Override
        public PrintWriter format(@Nullable Locale l, String format, @Nullable Object... args) {
            writeHeaders();
            delegate.format(l, format, args);
            return this;
        }

        @Override
        public PrintWriter append(@Nullable CharSequence csq) {
            writeHeaders();
            delegate.append(csq);
            return this;
        }

        @Override
        public PrintWriter append(@Nullable CharSequence csq, int start, int end) {
            writeHeaders();
            delegate.append(csq, start, end);
            return this;
        }

        @Override
        public PrintWriter append(char c) {
            writeHeaders();
            delegate.append(c);
            return this;
        }

        @Override
        public void flush() {
            writeHeaders();
            delegate.flush();
        }

        @Override
        public void close() {
            writeHeaders();
            delegate.close();
        }

        @Override
        public boolean checkError() {
            writeHeaders();
            return delegate.checkError();
        }
    }
}

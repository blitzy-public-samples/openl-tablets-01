package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * V4: {@link BeforeCommitHeadersResponse} writes the default security headers before the first output of the response
 * reaches the container, through every method of its output stream and of its writer.
 * <p>
 * The output tests write to an {@link EarlyCommitResponse} that commits on its first byte or character, or on a flush
 * or a close, and then ignores every header, so every header it holds was written before any output reached it. They
 * also compare its body with the body the same call produces on a plain mock response. The delegation tests use
 * Mockito mocks of the container's stream and writer to show that every call reaches the container's own method of
 * the same name, with the same arguments, and nothing else does.
 * </p>
 */
class BeforeCommitHeadersResponseTest {

    private static final String HSTS = "Strict-Transport-Security";
    private static final byte[] BYTES = "bytes".getBytes(StandardCharsets.US_ASCII);
    private static final char[] CHARS = "chars".toCharArray();

    /** One call on an output stream or a writer. */
    @FunctionalInterface
    interface Call<T> {
        void on(T output) throws IOException;
    }

    static Stream<Arguments> streamCalls() {
        return Stream.of(
                streamCall("write(int)", out -> out.write('w')),
                streamCall("write(byte[])", out -> out.write(BYTES)),
                streamCall("write(byte[], int, int)", out -> out.write(BYTES, 1, 3)),
                streamCall("print(String)", out -> out.print("text")),
                streamCall("print(null)", out -> out.print((String) null)),
                streamCall("print(boolean)", out -> out.print(true)),
                streamCall("print(char)", out -> out.print('c')),
                streamCall("print(int)", out -> out.print(42)),
                streamCall("print(long)", out -> out.print(42L)),
                streamCall("print(float)", out -> out.print(1.5f)),
                streamCall("print(double)", out -> out.print(2.5d)),
                streamCall("println()", ServletOutputStream::println),
                streamCall("println(String)", out -> out.println("text")),
                streamCall("println(boolean)", out -> out.println(false)),
                streamCall("println(char)", out -> out.println('c')),
                streamCall("println(int)", out -> out.println(7)),
                streamCall("println(long)", out -> out.println(7L)),
                streamCall("println(float)", out -> out.println(0.5f)),
                streamCall("println(double)", out -> out.println(0.25d)),
                streamCall("flush()", ServletOutputStream::flush),
                streamCall("close()", ServletOutputStream::close));
    }

    static Stream<Arguments> writerCalls() {
        return Stream.of(
                writerCall("write(int)", writer -> writer.write('w')),
                writerCall("write(char[], int, int)", writer -> writer.write(CHARS, 1, 3)),
                writerCall("write(char[])", writer -> writer.write(CHARS)),
                writerCall("write(String, int, int)", writer -> writer.write("string", 2, 3)),
                writerCall("write(String)", writer -> writer.write("string")),
                writerCall("print(boolean)", writer -> writer.print(true)),
                writerCall("print(char)", writer -> writer.print('c')),
                writerCall("print(int)", writer -> writer.print(42)),
                writerCall("print(long)", writer -> writer.print(42L)),
                writerCall("print(float)", writer -> writer.print(1.5f)),
                writerCall("print(double)", writer -> writer.print(2.5d)),
                writerCall("print(char[])", writer -> writer.print(CHARS)),
                writerCall("print(String)", writer -> writer.print("text")),
                writerCall("print(null String)", writer -> writer.print((String) null)),
                writerCall("print(Object)", writer -> writer.print(List.of(1, 2))),
                writerCall("println()", PrintWriter::println),
                writerCall("println(boolean)", writer -> writer.println(false)),
                writerCall("println(char)", writer -> writer.println('c')),
                writerCall("println(int)", writer -> writer.println(7)),
                writerCall("println(long)", writer -> writer.println(7L)),
                writerCall("println(float)", writer -> writer.println(0.5f)),
                writerCall("println(double)", writer -> writer.println(0.25d)),
                writerCall("println(char[])", writer -> writer.println(CHARS)),
                writerCall("println(String)", writer -> writer.println("text")),
                writerCall("println(Object)", writer -> writer.println(List.of(3))),
                writerCall("printf(String, Object...)", writer -> writer.printf("%s-%d", "a", 1)),
                writerCall("printf(Locale, String, Object...)", writer -> writer.printf(Locale.GERMANY, "%.2f", 1.5d)),
                writerCall("format(String, Object...)", writer -> writer.format("%s-%d", "b", 2)),
                writerCall("format(Locale, String, Object...)", writer -> writer.format(Locale.GERMANY, "%.1f", 2.5d)),
                writerCall("append(CharSequence)", writer -> writer.append("sequence")),
                writerCall("append(CharSequence, int, int)", writer -> writer.append("sequence", 2, 5)),
                writerCall("append(char)", writer -> writer.append('a')),
                writerCall("flush()", PrintWriter::flush),
                writerCall("close()", PrintWriter::close),
                writerCall("checkError()", PrintWriter::checkError));
    }

    @ParameterizedTest
    @MethodSource("streamCalls")
    void streamCallWritesTheHeadersBeforeItsOutput(Call<ServletOutputStream> call) throws IOException {
        var plain = new MockHttpServletResponse();
        call.on(plain.getOutputStream());
        var target = new EarlyCommitResponse(0);

        call.on(new BeforeCommitHeadersResponse(request(false), target).getOutputStream());

        assertTrue(target.isCommitted(), "the call commits the response");
        assertDefaultHeaders(target);
        assertNull(target.getHeader(HSTS), "HSTS on a plain HTTP request");
        assertArrayEquals(plain.getContentAsByteArray(), target.getContentAsByteArray(), "body");
    }

    @ParameterizedTest
    @MethodSource("writerCalls")
    void writerCallWritesTheHeadersBeforeItsOutput(Call<PrintWriter> call) throws IOException {
        var plain = new MockHttpServletResponse();
        call.on(plain.getWriter());
        var target = new EarlyCommitResponse(0);

        call.on(new BeforeCommitHeadersResponse(request(false), target).getWriter());

        assertTrue(target.isCommitted(), "the call commits the response");
        assertDefaultHeaders(target);
        assertNull(target.getHeader(HSTS), "HSTS on a plain HTTP request");
        assertEquals(plain.getContentAsString(), target.getContentAsString(), "body");
    }

    @Test
    void flushBufferWritesTheHeadersBeforeItCommits() throws IOException {
        var target = new EarlyCommitResponse();

        new BeforeCommitHeadersResponse(request(false), target).flushBuffer();

        assertTrue(target.isCommitted(), "flushBuffer commits the response");
        assertDefaultHeaders(target);
    }

    @Test
    void secureRequestAlsoGetsHsts() throws IOException {
        var target = new EarlyCommitResponse(0);

        new BeforeCommitHeadersResponse(request(true), target).getOutputStream().write(BYTES);

        assertTrue(target.isCommitted(), "the write commits the response");
        assertSingle(target, HSTS, "max-age=31536000 ; includeSubDomains");
        assertDefaultHeaders(target);
    }

    /**
     * Headers and a cache policy the response sets before its output keep precedence over the defaults, except
     * {@code X-Frame-Options}, which is always {@code DENY}, as the chains' header filter sets it.
     */
    @Test
    void headersTheResponseSetsBeforeItsOutputKeepPrecedence() throws IOException {
        var target = new EarlyCommitResponse(0);
        var response = new BeforeCommitHeadersResponse(request(false), target);
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("X-XSS-Protection", "1; mode=block");
        response.setHeader("X-Frame-Options", "SAMEORIGIN");

        response.getWriter().print("page");

        assertTrue(target.isCommitted(), "the print commits the response");
        assertSingle(target, "Cache-Control", "no-store");
        assertNull(target.getHeader("Pragma"), "Pragma");
        assertNull(target.getHeader("Expires"), "Expires");
        assertSingle(target, "X-XSS-Protection", "1; mode=block");
        assertSingle(target, "X-Frame-Options", "DENY");
        assertSingle(target, "X-Content-Type-Options", "nosniff");
        assertEquals("page", target.getContentAsString(), "body");
    }

    /**
     * A reset clears the headers, so the next output writes them again, once, even through the output stream taken
     * before the reset.
     */
    @Test
    void resetMakesTheNextOutputWriteTheHeadersAgain() throws IOException {
        var target = new EarlyCommitResponse();
        var response = new BeforeCommitHeadersResponse(request(false), target);
        var out = response.getOutputStream();
        out.write(BYTES);
        assertDefaultHeaders(target);

        response.reset();
        assertTrue(target.getHeaderNames().isEmpty(), () -> "headers after reset: " + target.getHeaderNames());
        var large = new byte[EarlyCommitResponse.AGGREGATION_SIZE + 1];
        out.write(large);

        assertTrue(target.isCommitted(), "the large write commits the response");
        assertDefaultHeaders(target);
        assertArrayEquals(large, target.getContentAsByteArray(), "body after reset");
    }

    @Test
    void resetOfACommittedResponseFails() throws IOException {
        var target = new EarlyCommitResponse(0);
        var response = new BeforeCommitHeadersResponse(request(false), target);
        response.getOutputStream().write(BYTES);

        assertThrows(IllegalStateException.class, response::reset);
        assertDefaultHeaders(target);
    }

    /** A committed response takes no headers, so none is even looked at, and output still reaches it. */
    @Test
    void alreadyCommittedResponseGetsNoHeaders() throws IOException {
        var target = mock(HttpServletResponse.class);
        var container = mock(ServletOutputStream.class);
        when(target.isCommitted()).thenReturn(true);
        when(target.getOutputStream()).thenReturn(container);
        var out = new BeforeCommitHeadersResponse(request(false), target).getOutputStream();

        out.write('a');
        out.write('b');

        verify(target).getOutputStream();
        verify(target).isCommitted();
        verifyNoMoreInteractions(target);
        verify(container).write('a');
        verify(container).write('b');
        verifyNoMoreInteractions(container);
    }

    /** The headers are settled by the first output: later output does not look at the response again. */
    @Test
    void headersAreWrittenOnlyOnTheFirstOutput() throws IOException {
        var target = mock(HttpServletResponse.class);
        when(target.getOutputStream()).thenReturn(mock(ServletOutputStream.class));
        when(target.getWriter()).thenReturn(mock(PrintWriter.class));
        var response = new BeforeCommitHeadersResponse(request(false), target);

        response.getOutputStream().write(BYTES);
        response.getOutputStream().write(BYTES);
        response.getWriter().print("text");
        response.flushBuffer();

        verify(target).isCommitted();
        verify(target).addHeader("X-Content-Type-Options", "nosniff");
        verify(target).addHeader("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        verify(target).setHeader("X-Frame-Options", "DENY");
        verify(target).flushBuffer();
    }

    @Test
    void everyCallReturnsANewViewOfTheContainerOutput() throws IOException {
        var response = new BeforeCommitHeadersResponse(request(false), new MockHttpServletResponse());

        assertNotSame(response.getOutputStream(), response.getOutputStream(), "output stream");
        assertNotSame(response.getWriter(), response.getWriter(), "writer");
    }

    @Test
    void streamHandsEveryCallToTheContainerStream() throws IOException {
        var target = mock(HttpServletResponse.class);
        var container = mock(ServletOutputStream.class);
        var listener = mock(WriteListener.class);
        when(target.getOutputStream()).thenReturn(container);
        when(container.isReady()).thenReturn(true);
        var out = new BeforeCommitHeadersResponse(request(false), target).getOutputStream();

        assertTrue(out.isReady(), "isReady");
        out.setWriteListener(listener);
        out.write(1);
        out.write(BYTES);
        out.write(BYTES, 1, 2);
        out.print("s");
        out.print(true);
        out.print('c');
        out.print(1);
        out.print(2L);
        out.print(3f);
        out.print(4d);
        out.println();
        out.println("s");
        out.println(true);
        out.println('c');
        out.println(1);
        out.println(2L);
        out.println(3f);
        out.println(4d);
        out.flush();
        out.close();

        verify(container).isReady();
        verify(container).setWriteListener(listener);
        verify(container).write(1);
        verify(container).write(BYTES);
        verify(container).write(BYTES, 1, 2);
        verify(container).print("s");
        verify(container).print(true);
        verify(container).print('c');
        verify(container).print(1);
        verify(container).print(2L);
        verify(container).print(3f);
        verify(container).print(4d);
        verify(container).println();
        verify(container).println("s");
        verify(container).println(true);
        verify(container).println('c');
        verify(container).println(1);
        verify(container).println(2L);
        verify(container).println(3f);
        verify(container).println(4d);
        verify(container).flush();
        verify(container).close();
        verifyNoMoreInteractions(container);
    }

    @Test
    void writerHandsEveryCallToTheContainerWriter() throws IOException {
        var target = mock(HttpServletResponse.class);
        var container = mock(PrintWriter.class);
        when(target.getWriter()).thenReturn(container);
        when(container.checkError()).thenReturn(true);
        var writer = new BeforeCommitHeadersResponse(request(false), target).getWriter();
        Object object = List.of(1);

        writer.write(1);
        writer.write(CHARS, 1, 2);
        writer.write(CHARS);
        writer.write("s", 0, 1);
        writer.write("s");
        writer.print(true);
        writer.print('c');
        writer.print(1);
        writer.print(2L);
        writer.print(3f);
        writer.print(4d);
        writer.print(CHARS);
        writer.print("s");
        writer.print(object);
        writer.println();
        writer.println(true);
        writer.println('c');
        writer.println(1);
        writer.println(2L);
        writer.println(3f);
        writer.println(4d);
        writer.println(CHARS);
        writer.println("s");
        writer.println(object);
        assertSame(writer, writer.printf("%s", "a"), "printf");
        assertSame(writer, writer.printf(Locale.ROOT, "%s", "b"), "printf with a locale");
        assertSame(writer, writer.format("%s", "c"), "format");
        assertSame(writer, writer.format(Locale.ROOT, "%s", "d"), "format with a locale");
        assertSame(writer, writer.append("csq"), "append");
        assertSame(writer, writer.append("csq", 1, 2), "append of a subsequence");
        assertSame(writer, writer.append('e'), "append of a char");
        writer.flush();
        assertTrue(writer.checkError(), "checkError");
        writer.close();

        verify(container).write(1);
        verify(container).write(CHARS, 1, 2);
        verify(container).write(CHARS);
        verify(container).write("s", 0, 1);
        verify(container).write("s");
        verify(container).print(true);
        verify(container).print('c');
        verify(container).print(1);
        verify(container).print(2L);
        verify(container).print(3f);
        verify(container).print(4d);
        verify(container).print(CHARS);
        verify(container).print("s");
        verify(container).print(object);
        verify(container).println();
        verify(container).println(true);
        verify(container).println('c');
        verify(container).println(1);
        verify(container).println(2L);
        verify(container).println(3f);
        verify(container).println(4d);
        verify(container).println(CHARS);
        verify(container).println("s");
        verify(container).println(object);
        verify(container).printf("%s", "a");
        verify(container).printf(Locale.ROOT, "%s", "b");
        verify(container).format("%s", "c");
        verify(container).format(Locale.ROOT, "%s", "d");
        verify(container).append("csq");
        verify(container).append("csq", 1, 2);
        verify(container).append('e');
        verify(container).flush();
        verify(container).checkError();
        verify(container).close();
        verifyNoMoreInteractions(container);
    }

    private static Arguments streamCall(String name, Call<ServletOutputStream> call) {
        return arguments(named(name, call));
    }

    private static Arguments writerCall(String name, Call<PrintWriter> call) {
        return arguments(named(name, call));
    }

    private static MockHttpServletRequest request(boolean secure) {
        var request = new MockHttpServletRequest("GET", "/files");
        request.setSecure(secure);
        return request;
    }

    /** Asserts every default header but HSTS, each exactly once. */
    private static void assertDefaultHeaders(MockHttpServletResponse response) {
        assertSingle(response, "X-Content-Type-Options", "nosniff");
        assertSingle(response, "X-XSS-Protection", "0");
        assertSingle(response, "Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        assertSingle(response, "Pragma", "no-cache");
        assertSingle(response, "Expires", "0");
        assertSingle(response, "X-Frame-Options", "DENY");
    }

    private static void assertSingle(MockHttpServletResponse response, String name, String value) {
        assertEquals(List.of(value), response.getHeaders(name), name);
    }
}

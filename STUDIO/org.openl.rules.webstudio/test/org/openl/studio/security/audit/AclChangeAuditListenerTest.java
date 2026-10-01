package org.openl.studio.security.audit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.times;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Pattern;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import org.openl.security.acl.AclChangeListener;

/**
 * Unit tests for {@link AclChangeAuditListener} (V11: one acl.change audit line per ACL transaction).
 *
 * <p>The listener is driven through the {@link AclChangeListener} contract only, exactly as the ACL persistence
 * boundary calls it. The unit-test classpath binds slf4j to slf4j-simple, which writes every line to the current
 * {@code System.err}; JUnit Pioneer's {@link StdIo} captures it per test. Every credential and session identifier
 * placed in the security context or the request is generated at run time, and each test that places one asserts
 * that it never reaches the captured output.
 */
class AclChangeAuditListenerTest {

    /** The pairs of an {@code acl.change} line, in the fixed order the audit log writes them. */
    private static final List<String> ACL_CHANGE_KEYS = List.of("event",
            "outcome",
            "user",
            "ip",
            "changes",
            "kinds",
            "objectTypes");

    /** One {@code key=value} pair of an audit message; a quoted value may contain spaces. */
    private static final Pattern PAIR = Pattern.compile("(\\w+)=(\"[^\"]*\"|\\S*)");

    /** The fixed message the listener writes on its own logger when the audit line cannot be written. */
    private static final String LISTENER_WRITE_FAILED = "Failed to write the ACL change audit event (";

    private static final String USER_NAME = "jdoe";

    /** A documentation address (RFC 5737), never a real client. */
    private static final String REQUEST_ADDRESS = "203.0.113.5";

    private final AclChangeListener listener = new AclChangeAuditListener();

    @AfterEach
    void cleanUp() {
        RequestContextHolder.resetRequestAttributes();
        SecurityContextHolder.clearContext();
    }

    @Test
    void isComponentScannedAsTheAclChangeListener() {
        assertTrue(AclChangeAuditListener.class.isAnnotationPresent(Component.class),
                "The listener must be found by the component scan of org.openl.studio.");
    }

    @Test
    @StdIo
    void writesOneInfoLineWithTheUserAddressAndCodeDefinedNames(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        authenticateInContext(password);
        bindRequest(sessionId);

        listener.aclChanged(AclChangeListener.SUCCESS,
                2,
                sortedSet("updateAcl", "createAcl"),
                sortedSet("ProjectArtifact"));

        assertNoLeak(err, password, sessionId);
        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=acl.change"), "The line must carry event=acl.change");
        assertTrue(line.contains("outcome=success"), "The line must carry outcome=success");
        assertTrue(line.contains("user=\"" + USER_NAME + "\""), "The line must carry the user of the context");
        assertTrue(line.contains("ip=" + REQUEST_ADDRESS), "The line must carry the request address");
        assertTrue(line.endsWith(" changes=2 kinds=createAcl,updateAcl objectTypes=ProjectArtifact"),
                "The line must end with the count, the sorted kinds and the object type");
        assertTrue(ACL_CHANGE_KEYS.equals(keys(line)), "The line must carry exactly the pairs " + ACL_CHANGE_KEYS);
    }

    @Test
    @StdIo
    void writesOneLinePerNotification(StdErr err) {
        var password = password();
        authenticateInContext(password);

        listener.aclChanged(AclChangeListener.SUCCESS, 1, sortedSet("createAcl"), sortedSet("Root"));
        listener.aclChanged(AclChangeListener.SUCCESS,
                3,
                sortedSet("deleteAcl", "updateAcl"),
                sortedSet("ProjectArtifact", "RepositoryObjectIdentity"));

        assertNoLeak(err, password);
        var lines = auditLines(err);
        assertEquals(2, lines.size(), "Expected two audit lines");
        assertEquals(2, lines.stream().filter(l -> l.contains("event=acl.change")).count());
        assertTrue(lines.get(0).endsWith(" changes=1 kinds=createAcl objectTypes=Root"),
                "The first line must end with the counts and names of the first notification");
        assertTrue(lines.get(1)
                .endsWith(" changes=3 kinds=deleteAcl,updateAcl objectTypes=ProjectArtifact,RepositoryObjectIdentity"),
                "The second line must end with the counts and names of the second notification");
    }

    @Test
    @StdIo
    void writesTheSystemUserAndNoAddressWithoutAuthenticationOrRequest(StdErr err) {
        // A grant made at start-up runs with neither an authentication nor a bound request.
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();

        listener.aclChanged(AclChangeListener.SUCCESS, 1, sortedSet("createAcl"), sortedSet("Root"));

        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=acl.change outcome=success user=\"system\" ip=- changes=1"),
                "The line must name the system user and no address");
        assertTrue(ACL_CHANGE_KEYS.equals(keys(line)), "The line must carry exactly the pairs " + ACL_CHANGE_KEYS);
    }

    @Test
    @StdIo
    void writesAWarnLineForAFailedTransaction(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        authenticateInContext(password);
        bindRequest(sessionId);

        listener.aclChanged(AclChangeListener.FAILURE, 4, sortedSet("deleteAcl"), sortedSet("ProjectArtifact"));

        assertNoLeak(err, password, sessionId);
        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=acl.change outcome=failure user=\"" + USER_NAME + "\""),
                "The line must carry outcome=failure and the user of the context");
        assertTrue(line.endsWith(" changes=4 kinds=deleteAcl objectTypes=ProjectArtifact"),
                "The line must end with the count, the kind and the object type");
        assertTrue(ACL_CHANGE_KEYS.equals(keys(line)), "The line must carry exactly the pairs " + ACL_CHANGE_KEYS);
    }

    @Test
    @StdIo
    void writesOnlyTheCodeDefinedSidNamesAndNoOtherPair(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        authenticateInContext(password);
        bindRequest(sessionId);

        listener.aclChanged(AclChangeListener.SUCCESS,
                5,
                sortedSet("deleteSid", "updateSid"),
                sortedSet("sid", "Root", "RepositoryObjectIdentity"));

        assertNoLeak(err, password, sessionId);
        var line = singleAuditLine(err);
        assertTrue(line.contains(" kinds=deleteSid,updateSid"), "The line must carry the sorted SID kinds");
        assertTrue(line.contains(" objectTypes=RepositoryObjectIdentity,Root,sid"),
                "The line must carry the sorted object types");
        assertFalse(line.contains("method="), "The line must not carry a method pair");
        assertFalse(line.contains("pat="), "The line must not carry a pat pair");
        assertTrue(ACL_CHANGE_KEYS.equals(keys(line)), "The line must carry exactly the pairs " + ACL_CHANGE_KEYS);
    }

    @Test
    @StdIo
    void neverThrowsAndWritesOneLinePerCallForInputOutsideTheContract(StdErr err) {
        assertDoesNotThrow(() -> listener.aclChanged(AclChangeListener.SUCCESS, -1, null, null));
        assertDoesNotThrow(() -> listener.aclChanged(null, 0, null, null));
        assertDoesNotThrow(() -> listener.aclChanged(AclChangeListener.SUCCESS,
                0,
                Collections.emptySortedSet(),
                Collections.emptySortedSet()));

        var lines = auditLines(err);
        assertEquals(3, lines.size(), "Expected three audit lines");
        // A missing value is written as '-', and an outcome other than success is written at WARN.
        assertTrue(lines.get(0).endsWith(" changes=-1 kinds=- objectTypes=-"),
                "The first line must write the negative count and the missing sets");
        assertLevel(lines.get(0), "INFO");
        assertTrue(lines.get(1).contains("event=acl.change outcome=- "), "The second line must write outcome=-");
        assertTrue(lines.get(1).endsWith(" changes=0 kinds=- objectTypes=-"),
                "The second line must write the zero count and the missing sets");
        assertLevel(lines.get(1), "WARN");
        assertTrue(lines.get(2).endsWith(" changes=0 kinds=- objectTypes=-"),
                "The third line must write the zero count and the empty sets as missing");
        for (var line : lines) {
            assertTrue(ACL_CHANGE_KEYS.equals(keys(line)), "Each line must carry exactly the pairs " + ACL_CHANGE_KEYS);
        }
    }

    @Test
    @StdIo
    void swallowsAFailingAuditWriteAndReportsItWithAFixedMessage(StdErr err) {
        var message = randomValue(24);
        var kinds = sortedSet("updateAcl");
        var objectTypes = sortedSet("ProjectArtifact");
        try (MockedStatic<SecurityAuditLog> audit = Mockito.mockStatic(SecurityAuditLog.class)) {
            audit.when(() -> SecurityAuditLog.aclChange(any(), anyInt(), any(), any()))
                    .thenThrow(new IllegalStateException(message));

            var threw = callThrows(() -> listener.aclChanged(AclChangeListener.SUCCESS, 1, kinds, objectTypes));

            // The exception message is a generated sentinel: it must never reach the output.
            assertNoLeak(err, message);
            assertFalse(threw, "A failing audit write must be swallowed");
            audit.verify(() -> SecurityAuditLog.aclChange(AclChangeListener.SUCCESS, 1, kinds, objectTypes),
                    times(1));
        }

        var marker = " " + AclChangeAuditListener.class.getName() + " - ";
        var warnings = err.capturedString()
                .lines()
                .filter(l -> l.contains("WARN" + marker))
                .filter(l -> l.contains(marker + LISTENER_WRITE_FAILED))
                .toList();
        assertEquals(1, warnings.size(), "Expected exactly one listener warning with the fixed message");
    }

    @Test
    @StdIo
    void keepsWritingAfterAFailedAuditWrite(StdErr err) {
        var message = randomValue(24);
        boolean threw;
        try (MockedStatic<SecurityAuditLog> audit = Mockito.mockStatic(SecurityAuditLog.class)) {
            audit.when(() -> SecurityAuditLog.aclChange(any(), anyInt(), any(), any()))
                    .thenThrow(new IllegalStateException(message));
            threw = callThrows(() -> listener.aclChanged(AclChangeListener.SUCCESS,
                    1,
                    sortedSet("createAcl"),
                    sortedSet("Root")));
        }

        // The listener is stateless: the next notification is written as usual.
        listener.aclChanged(AclChangeListener.SUCCESS, 2, sortedSet("createAcl"), sortedSet("Root"));

        // The exception message is a generated sentinel: it must never reach the output.
        assertNoLeak(err, message);
        assertFalse(threw, "A failing audit write must be swallowed");
        var line = singleAuditLine(err);
        assertTrue(line.endsWith(" changes=2 kinds=createAcl objectTypes=Root"),
                "The next notification must be written with its own counts and names");
    }

    // ---------------------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------------------

    /** The captured lines written by the audit logger, in order. */
    private static List<String> auditLines(StdErr err) {
        var marker = " " + SecurityAuditLog.LOGGER_NAME + " - ";
        return err.capturedString().lines().filter(l -> l.contains(marker)).toList();
    }

    /** Asserts that exactly one audit line was written, and returns it. The message never quotes a line. */
    private static String singleAuditLine(StdErr err) {
        var lines = auditLines(err);
        assertEquals(1, lines.size(), "Expected exactly one audit line");
        return lines.getFirst();
    }

    /** The keys of the {@code key=value} pairs in the message part of a line, in order. */
    private static List<String> keys(String line) {
        var message = line.substring(line.indexOf(" - ") + 3);
        var keys = new ArrayList<String>();
        var pair = PAIR.matcher(message);
        while (pair.find()) {
            keys.add(pair.group(1));
        }
        return keys;
    }

    private static void assertLevel(String line, String level) {
        assertTrue(line.contains(level + " " + SecurityAuditLog.LOGGER_NAME + " - "),
                () -> "Expected the audit line at level " + level);
    }

    /** Asserts that none of the values occurs anywhere in the captured output. */
    private static void assertNoLeak(StdErr err, String... secrets) {
        var output = err.capturedString();
        for (var secret : secrets) {
            assertFalse(output.contains(secret), "A generated secret reached the log output.");
        }
    }

    /**
     * Runs the call and answers whether it threw. Unlike {@code assertDoesNotThrow}, an assertion on the answer
     * never formats the exception, whose message here is a generated sentinel.
     */
    private static boolean callThrows(Runnable call) {
        try {
            call.run();
            return false;
        } catch (RuntimeException e) {
            return true;
        }
    }

    /** Puts an authenticated user name and password authentication of {@code jdoe} into the security context. */
    private static void authenticateInContext(String password) {
        SecurityContextHolder.getContext()
                .setAuthentication(UsernamePasswordAuthenticationToken.authenticated(USER_NAME, password, List.of()));
    }

    /** Binds a request from {@link #REQUEST_ADDRESS} with a session of the given identifier to the thread. */
    private static void bindRequest(String sessionId) {
        var request = new MockHttpServletRequest();
        request.setRemoteAddr(REQUEST_ADDRESS);
        request.setSession(new MockHttpSession(null, sessionId));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    /** An unmodifiable sorted set, as the ACL persistence boundary passes it. */
    private static SortedSet<String> sortedSet(String... values) {
        return Collections.unmodifiableSortedSet(new TreeSet<>(List.of(values)));
    }

    private static String password() {
        return randomValue(16);
    }

    private static String randomValue(int length) {
        return RandomStringUtils.secure().nextAlphanumeric(length);
    }
}

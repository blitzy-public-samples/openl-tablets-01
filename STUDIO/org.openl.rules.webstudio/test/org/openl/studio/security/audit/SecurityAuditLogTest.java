package org.openl.studio.security.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Pattern;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.WritesStdIo;
import org.slf4j.LoggerFactory;
import org.slf4j.simple.SimpleLogger;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Unit tests for {@link SecurityAuditLog} (V11: security audit trail on logger org.openl.security.audit).
 *
 * <p>The unit-test classpath binds slf4j to slf4j-simple, which writes every line to the current
 * {@code System.err}; JUnit Pioneer's {@link StdIo} captures it per test. Every credential used here is generated
 * at run time, and each test that hands one to the audit log asserts that it never reaches the captured output.
 */
class SecurityAuditLogTest {

    /**
     * One complete audit line as slf4j-simple prints it: an optional prefix (thread name), the level, the logger
     * name, then the fixed {@code event outcome user ip} pairs followed by the optional pairs of the event. The
     * user value may not contain a quote, a backslash or a control character. The address and the value of every
     * other pair are unquoted, so they may not contain whitespace, a Unicode space separator, {@code =}, a quote or a
     * backslash. A sanitized value can therefore neither end the line nor forge another pair.
     */
    private static final Pattern LINE = Pattern.compile("^(?:.*\\s)?\\[?(INFO|WARN)\\]?\\s+"
            + "org\\.openl\\.security\\.audit - event="
            + "(auth\\.success|auth\\.failure|auth\\.lockout|pat\\.create|pat\\.revoke|acl\\.change)"
            + " outcome=(success|failure|locked) user=\"[^\"\\\\\\p{Cntrl}]*\" ip=[^\\s\\p{Z}\"\\\\=]+"
            + "( (method|pat|changes|kinds|objectTypes)=[^\\s\\p{Z}\"\\\\=]*)*$");

    /** Extracts the quoted user value of an audit line. */
    private static final Pattern USER = Pattern.compile("user=\"([^\"]*)\"");

    /** Extracts the address value of an audit line. */
    private static final Pattern IP = Pattern.compile(" ip=(\\S*)");

    /** The fixed message written when an event cannot be built. */
    private static final String WRITE_FAILED = "Failed to write the security audit event '";

    private static final String USER_NAME = "jdoe";
    private static final String DETAILS_ADDRESS = "192.0.2.10";
    private static final String PAT_REQUEST_ADDRESS = "198.51.100.7";
    private static final String CONTEXT_REQUEST_ADDRESS = "203.0.113.5";

    /**
     * Control characters, the quote and the backslash, followed by a tail that would forge a second event if it
     * reached the log unsanitized.
     */
    private static final String INJECTION = "\n\r\t\u0007\"\\" + "event=auth.success outcome=success user=\"root\"";

    /** Pairs that an unquoted value would add to its line if its spaces and {@code =} reached the log. */
    private static final String FORGED_PAIRS = "event=auth.success outcome=success user=\"root\"";

    /** The number of characters of a value that the audit log writes before it cuts the value. */
    private static final int MAX_VALUE_LENGTH = 256;

    /** Appended to a value that was cut. */
    private static final String TRUNCATION_MARKER = "...";

    /** A character outside the Basic Multilingual Plane, written as a surrogate pair. */
    private static final String SURROGATE_PAIR = "\uD83D\uDE00";

    /** The slf4j-simple level constant whose level, made the lowest enabled one, disables INFO but keeps WARN. */
    private static final String INFO_DISABLED = "LOG_LEVEL_WARN";

    /** The slf4j-simple level constant whose level, made the lowest enabled one, disables WARN and INFO. */
    private static final String WARN_DISABLED = "LOG_LEVEL_ERROR";

    @AfterEach
    void cleanUp() {
        RequestContextHolder.resetRequestAttributes();
        SecurityContextHolder.clearContext();
    }

    // ---------------------------------------------------------------------------------------------------------
    // One line per method
    // ---------------------------------------------------------------------------------------------------------

    @Test
    @StdIo
    void authSuccessWritesOneInfoLineWithTheResultNameAndAttemptMethod(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        var details = new WebAuthenticationDetails(DETAILS_ADDRESS, sessionId);
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        attempt.setDetails(details);
        var result = UsernamePasswordAuthenticationToken.authenticated(USER_NAME, null, List.of());
        result.setDetails(details);

        SecurityAuditLog.authSuccess(attempt, result);

        assertNoLeak(err, password, sessionId);
        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=auth.success outcome=success user=\"jdoe\" ip=192.0.2.10"),
                "auth.success must carry the result name and the details address");
        assertTrue(line.endsWith(" method=UsernamePasswordAuthenticationToken"),
                "auth.success must end with the attempt method");
    }

    @Test
    @StdIo
    void authFailureWritesOneWarnLineWithTheAttemptedUserName(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        attempt.setDetails(new WebAuthenticationDetails(DETAILS_ADDRESS, sessionId));

        SecurityAuditLog.authFailure(attempt);

        assertNoLeak(err, password, sessionId);
        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=auth.failure outcome=failure user=\"jdoe\" ip=192.0.2.10"),
                "auth.failure must carry the attempted user name and the details address");
        assertTrue(line.endsWith(" method=UsernamePasswordAuthenticationToken"),
                "auth.failure must end with the attempt method");
    }

    @Test
    @StdIo
    void lockoutWritesOneWarnLineWithTheLockedOutcome(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        attempt.setDetails(new WebAuthenticationDetails(DETAILS_ADDRESS, sessionId));

        SecurityAuditLog.lockout(attempt);

        assertNoLeak(err, password, sessionId);
        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=auth.lockout outcome=locked user=\"jdoe\" ip=192.0.2.10"),
                "auth.lockout must carry outcome=locked, the user name and the details address");
        assertTrue(line.endsWith(" method=UsernamePasswordAuthenticationToken"),
                "auth.lockout must end with the attempt method");
    }

    @Test
    @StdIo
    void patAuthSuccessWritesThePublicIdButNeverTheToken(StdErr err) {
        var publicId = randomValue(16);
        var secret = randomValue(32);
        var token = pat(publicId, secret);
        var request = patRequest(token);

        SecurityAuditLog.authSuccess(request, USER_NAME, publicId);

        assertNoLeak(err, secret, token);
        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=auth.success outcome=success user=\"jdoe\" ip=198.51.100.7"),
                "PAT auth.success must carry the user and the request address");
        assertTrue(line.endsWith(" method=pat pat=" + publicId), "PAT auth.success must end with the public ID");
    }

    @Test
    @StdIo
    void patAuthFailureWritesAnAnonymousWarnLineWithThePublicId(StdErr err) {
        var publicId = randomValue(16);
        var secret = randomValue(32);
        var token = pat(publicId, secret);

        SecurityAuditLog.authFailure(patRequest(token), publicId);

        assertNoLeak(err, secret, token);
        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=auth.failure outcome=failure user=\"-\" ip=198.51.100.7"),
                "PAT auth.failure must name no user and carry the request address");
        assertTrue(line.endsWith(" method=pat pat=" + publicId), "PAT auth.failure must end with the public ID");
    }

    @Test
    @StdIo
    void patAuthFailureOmitsThePublicIdOfATokenThatDidNotParse(StdErr err) {
        var token = pat(randomValue(16), randomValue(32)) + randomValue(8);

        SecurityAuditLog.authFailure(patRequest(token), null);

        assertNoLeak(err, token);
        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=auth.failure outcome=failure user=\"-\" ip=198.51.100.7"),
                "PAT auth.failure must name no user and carry the request address");
        assertTrue(line.endsWith(" method=pat"), "PAT auth.failure must end with method=pat");
        assertFalse(line.contains("pat="), "PAT auth.failure of an unparsed token must not carry a pat pair");
    }

    @Test
    @StdIo
    void patCreateWritesTheCurrentUserAndRequestAddress(StdErr err) {
        var password = password();
        var publicId = randomValue(16);
        var secret = randomValue(32);
        authenticateInContext(password);
        bindRequest(CONTEXT_REQUEST_ADDRESS, pat(publicId, secret));

        SecurityAuditLog.patCreate(publicId);

        assertNoLeak(err, password, secret, pat(publicId, secret));
        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=pat.create outcome=success user=\"jdoe\" ip=203.0.113.5"),
                "pat.create must carry the context user and the request address");
        assertTrue(line.contains(" pat=" + publicId), "pat.create must carry the public ID");
        assertNoMethodOtherThanPat(line);
    }

    @Test
    @StdIo
    void patRevokeWritesTheCurrentUserAndRequestAddress(StdErr err) {
        var password = password();
        var publicId = randomValue(16);
        var secret = randomValue(32);
        authenticateInContext(password);
        bindRequest(CONTEXT_REQUEST_ADDRESS, pat(publicId, secret));

        SecurityAuditLog.patRevoke(publicId);

        assertNoLeak(err, password, secret, pat(publicId, secret));
        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=pat.revoke outcome=success user=\"jdoe\" ip=203.0.113.5"),
                "pat.revoke must carry the context user and the request address");
        assertTrue(line.contains(" pat=" + publicId), "pat.revoke must carry the public ID");
        assertNoMethodOtherThanPat(line);
    }

    @Test
    @StdIo
    void patLifecycleLinesNeverCarryTheTokenName(StdErr err) {
        var password = password();
        var publicId = randomValue(16);
        // The token name is free text that could itself be a credential, so it is generated like one.
        var tokenName = randomValue(32);
        authenticateInContext(password);
        // The bound request carries the name as the creation request does, in its body, and as a parameter.
        var request = new MockHttpServletRequest();
        request.setRemoteAddr(CONTEXT_REQUEST_ADDRESS);
        request.setContentType("application/json");
        request.setContent(("{\"name\":\"" + tokenName + "\"}").getBytes(StandardCharsets.UTF_8));
        request.setParameter("name", tokenName);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        SecurityAuditLog.patCreate(publicId);
        SecurityAuditLog.patRevoke(publicId);

        assertNoLeak(err, password, tokenName);
        var lines = auditLines(err);
        assertEquals(2, lines.size(), "Expected one audit line per token lifecycle event");
        for (var line : lines) {
            assertTrue(LINE.matcher(line).matches(), "The audit line does not have the audit line format");
        }
        var create = " - event=pat.create outcome=success user=\"jdoe\" ip=203.0.113.5 pat=" + publicId;
        var revoke = " - event=pat.revoke outcome=success user=\"jdoe\" ip=203.0.113.5 pat=" + publicId;
        assertTrue(lines.get(0).endsWith(create), "pat.create must carry the user, address and public ID only");
        assertTrue(lines.get(1).endsWith(revoke), "pat.revoke must carry the user, address and public ID only");
    }

    @Test
    @StdIo
    void aclChangeWritesCountsAndCodeDefinedNamesOnly(StdErr err) {
        var password = password();
        authenticateInContext(password);
        bindRequest(CONTEXT_REQUEST_ADDRESS, null);

        SecurityAuditLog.aclChange("success",
                3,
                new TreeSet<>(List.of("updateAcl", "createAcl")),
                new TreeSet<>(List.of("Root", "ProjectArtifact")));

        assertNoLeak(err, password);
        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=acl.change outcome=success user=\"jdoe\" ip=203.0.113.5"),
                "acl.change must carry the context user and the request address");
        assertTrue(line.endsWith(" changes=3 kinds=createAcl,updateAcl objectTypes=ProjectArtifact,Root"),
                "acl.change must end with the count and the sorted names");
        assertFalse(line.contains("method="), "acl.change must not carry a method pair");
        assertFalse(line.contains("pat="), "acl.change must not carry a pat pair");
    }

    @Test
    @StdIo
    void aclChangeThatDidNotCommitIsWrittenAtWarn(StdErr err) {
        var password = password();
        authenticateInContext(password);

        SecurityAuditLog.aclChange("failure", 1, new TreeSet<>(List.of("deleteAcl")), new TreeSet<>(List.of("Root")));

        assertNoLeak(err, password);
        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=acl.change outcome=failure user=\"jdoe\""),
                "acl.change must carry outcome=failure and the context user");
        assertTrue(line.endsWith(" changes=1 kinds=deleteAcl objectTypes=Root"),
                "acl.change must end with the count and the names");
    }

    @Test
    @StdIo
    void aclChangeWithoutAuthenticationIsAttributedToSystem(StdErr err) {
        SecurityAuditLog.aclChange("success", 2, new TreeSet<>(List.of("createAcl")), new TreeSet<>(List.of("Root")));

        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=acl.change outcome=success user=\"system\" ip=- changes=2"),
                "acl.change without an authentication must name the system user and no address");
    }

    @Test
    @StdIo
    void aclChangeWritesEmptySetsAsMissingValues(StdErr err) {
        SecurityAuditLog.aclChange("success", 0, new TreeSet<>(), new TreeSet<>());

        var line = singleAuditLine(err);
        assertTrue(line.endsWith(" changes=0 kinds=- objectTypes=-"), "Empty sets must be written as missing values");
    }

    @Test
    @StdIo
    void aclChangeWithAnUnknownOutcomeIsWrittenAtWarn(StdErr err) {
        SecurityAuditLog.aclChange("rolled-back",
                1,
                new TreeSet<>(List.of("updateSid")),
                new TreeSet<>(List.of("sid")));

        var lines = auditLines(err);
        assertEquals(1, lines.size(), "Expected exactly one audit line");
        var line = lines.getFirst();
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=acl.change outcome=rolled-back user=\"system\""),
                "acl.change must carry the unknown outcome and the system user");
        assertTrue(line.endsWith(" changes=1 kinds=updateSid objectTypes=sid"),
                "acl.change must end with the count and the names");
    }

    // ---------------------------------------------------------------------------------------------------------
    // Sanitizing (log injection)
    // ---------------------------------------------------------------------------------------------------------

    @Test
    @StdIo
    void userNameCannotBreakTheLineOrForgeAnEvent(StdErr err) {
        var password = password();
        var prefix = randomValue(12);

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken.unauthenticated(prefix + INJECTION, password));

        assertNoLeak(err, password);
        var user = userOfTheOnlyEventLine(err);
        assertSanitized(user);
        assertTrue(user.startsWith(prefix), "The user value must keep the start of the name");
    }

    @Test
    @StdIo
    void addressCannotBreakTheLineOrForgeAnEvent(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        attempt.setDetails(new WebAuthenticationDetails(DETAILS_ADDRESS + "\nevent=x\r\t\u0007\"\\", sessionId));

        SecurityAuditLog.authFailure(attempt);

        assertNoLeak(err, password, sessionId);
        var line = theOnlyEventLine(err);
        assertTrue(LINE.matcher(line).matches(), "The event line does not have the audit line format");
        var ip = IP.matcher(line);
        assertTrue(ip.find(), "The event line carries no ip pair");
        assertSanitized(ip.group(1));
        assertTrue(ip.group(1).startsWith(DETAILS_ADDRESS), "The address value must keep the start of the address");
    }

    @Test
    @StdIo
    void patUserNameAndAddressCannotBreakTheLine(StdErr err) {
        var publicId = randomValue(16);
        var secret = randomValue(32);
        var prefix = randomValue(12);
        var request = patRequest(pat(publicId, secret));
        request.setRemoteAddr(PAT_REQUEST_ADDRESS + "\r\nevent=x");

        SecurityAuditLog.authSuccess(request, prefix + INJECTION, publicId);

        assertNoLeak(err, secret, pat(publicId, secret));
        var user = userOfTheOnlyEventLine(err);
        assertSanitized(user);
        assertTrue(user.startsWith(prefix), "The user value must keep the start of the name");
    }

    @Test
    @StdIo
    void unicodeLineSeparatorsAreReplaced(StdErr err) {
        var password = password();
        var prefix = randomValue(12);

        SecurityAuditLog.lockout(UsernamePasswordAuthenticationToken
                .unauthenticated(prefix + "\u2028event=x\u2029event=y", password));

        assertNoLeak(err, password);
        var user = userOfTheOnlyEventLine(err);
        assertFalse(user.contains("\u2028"), "The user value must not hold the line separator U+2028");
        assertFalse(user.contains("\u2029"), "The user value must not hold the paragraph separator U+2029");
        assertTrue(user.startsWith(prefix), "The user value must keep the start of the name");
    }

    @Test
    @StdIo
    void aclChangeNamesAndOutcomeAreSanitized(StdErr err) {
        SecurityAuditLog.aclChange("success",
                1,
                new TreeSet<>(List.of("create\nAcl")),
                new TreeSet<>(List.of("Ro\"ot", "Pro\\ject")));

        var line = singleAuditLine(err);
        assertTrue(line.endsWith(" changes=1 kinds=create_Acl objectTypes=Pro_ject,Ro_ot"),
                "The kinds and object types must be sanitized");
    }

    @Test
    @StdIo
    void addressWithSpacesCannotForgePairs(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        attempt.setDetails(new WebAuthenticationDetails(DETAILS_ADDRESS + " " + FORGED_PAIRS, sessionId));

        SecurityAuditLog.authFailure(attempt);

        assertNoLeak(err, password, sessionId);
        var line = singleAuditLine(err);
        assertNoForgedPair(line);
        assertOneToken(ipOf(line), DETAILS_ADDRESS);
    }

    @Test
    @StdIo
    void addressWithUnicodeSpacesCannotForgePairs(StdErr err) {
        var publicId = randomValue(16);
        var secret = randomValue(32);
        var request = patRequest(pat(publicId, secret));
        request.setRemoteAddr(PAT_REQUEST_ADDRESS + "\u00A0" + FORGED_PAIRS.replace(' ', '\u2003') + "\u202Fx=y");

        SecurityAuditLog.authFailure(request, publicId);

        assertNoLeak(err, secret, pat(publicId, secret));
        var line = singleAuditLine(err);
        assertNoForgedPair(line);
        assertOneToken(ipOf(line), PAT_REQUEST_ADDRESS);
        assertTrue(line.endsWith(" method=pat pat=" + publicId), "PAT auth.failure must end with the public ID");
    }

    @Test
    @StdIo
    void publicIdWithSpacesAndEqualsSignsIsWrittenAsOneToken(StdErr err) {
        var publicId = randomValue(16);
        var secret = randomValue(32);

        SecurityAuditLog.authFailure(patRequest(pat(publicId, secret)), publicId + " " + FORGED_PAIRS);

        assertNoLeak(err, secret, pat(publicId, secret));
        var line = singleAuditLine(err);
        assertNoForgedPair(line);
        assertTrue(line.endsWith(" method=pat pat=" + publicId + "_event_auth.success_outcome_success_user__root_"),
                "The public ID must be written as one sanitized token");
    }

    @Test
    @StdIo
    void aclOutcomeAndNamesWithSpacesAndEqualsSignsAreWrittenAsOneTokenEach(StdErr err) {
        SecurityAuditLog.aclChange("rolled back outcome=success",
                1,
                new TreeSet<>(List.of("create Acl=x")),
                new TreeSet<>(List.of("Root\u00A0type=y", "Sid\u2003z")));

        var lines = auditLines(err);
        assertEquals(1, lines.size(), "Expected exactly one audit line");
        var line = lines.getFirst();
        assertLevel(line, "WARN");
        assertNoForgedPair(line);
        assertTrue(line.contains("event=acl.change outcome=rolled_back_outcome_success user=\"system\" ip=- "),
                "The outcome must be written as one sanitized token");
        assertTrue(line.endsWith(" changes=1 kinds=create_Acl_x objectTypes=Root_type_y,Sid_z"),
                "The kinds and object types must be written as one sanitized token each");
    }

    // ---------------------------------------------------------------------------------------------------------
    // Value length limit
    // ---------------------------------------------------------------------------------------------------------

    @Test
    @StdIo
    void longUserNameIsCutAtTheLimitAndMarked(StdErr err) {
        var password = password();
        var name = randomValue(100_000);

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken.unauthenticated(name, password));

        assertNoLeak(err, password);
        var line = singleAuditLine(err);
        var user = userOfTheOnlyEventLine(err);
        assertEquals(MAX_VALUE_LENGTH + TRUNCATION_MARKER.length(),
                user.length(),
                "The cut user value must hold the limit and the marker");
        assertTrue((name.substring(0, MAX_VALUE_LENGTH) + TRUNCATION_MARKER).equals(user),
                "The user value must be cut at the limit and marked");
        assertTrue(line.length() < 1024, () -> "Line of " + line.length() + " characters");
    }

    @Test
    @StdIo
    void userNameOfExactlyTheLimitIsKeptWhole(StdErr err) {
        var password = password();
        var name = randomValue(MAX_VALUE_LENGTH);

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken.unauthenticated(name, password));

        assertNoLeak(err, password);
        assertTrue(name.equals(userOfTheOnlyEventLine(err)), "A user name of exactly the limit must be kept whole");
    }

    @Test
    @StdIo
    void longAddressIsSanitizedAndCutAtTheLimit(StdErr err) {
        var publicId = randomValue(16);
        var secret = randomValue(32);
        var request = patRequest(pat(publicId, secret));
        var address = PAT_REQUEST_ADDRESS + (" " + FORGED_PAIRS).repeat(2_000);
        request.setRemoteAddr(address);

        SecurityAuditLog.authFailure(request, publicId);

        assertNoLeak(err, secret, pat(publicId, secret));
        var line = singleAuditLine(err);
        assertNoForgedPair(line);
        var expected = address.substring(0, MAX_VALUE_LENGTH).replaceAll("[ =\"]", "_") + TRUNCATION_MARKER;
        assertTrue(expected.equals(ipOf(line)), "The address must be sanitized, cut at the limit and marked");
        assertTrue(line.endsWith(" method=pat pat=" + publicId), "PAT auth.failure must end with the public ID");
        assertTrue(line.length() < 1024, () -> "Line of " + line.length() + " characters");
    }

    @Test
    @StdIo
    void cutNeverSplitsASurrogatePair(StdErr err) {
        var password = password();
        var prefix = randomValue(MAX_VALUE_LENGTH - 1);

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken
                .unauthenticated(prefix + SURROGATE_PAIR + randomValue(100), password));

        assertNoLeak(err, password);
        var user = userOfTheOnlyEventLine(err);
        assertTrue((prefix + TRUNCATION_MARKER).equals(user), "The cut must end before the surrogate pair");
        assertTrue(user.chars().noneMatch(c -> Character.isSurrogate((char) c)),
                "The cut user value must not hold a surrogate");
    }

    @Test
    @StdIo
    void surrogatePairThatEndsAtTheLimitIsKeptWhole(StdErr err) {
        var password = password();
        var prefix = randomValue(MAX_VALUE_LENGTH - SURROGATE_PAIR.length());

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken
                .unauthenticated(prefix + SURROGATE_PAIR + randomValue(100), password));

        assertNoLeak(err, password);
        assertTrue((prefix + SURROGATE_PAIR + TRUNCATION_MARKER).equals(userOfTheOnlyEventLine(err)),
                "A surrogate pair that ends at the limit must be kept whole");
    }

    // ---------------------------------------------------------------------------------------------------------
    // Source address fallback order
    // ---------------------------------------------------------------------------------------------------------

    @Test
    @StdIo
    void webDetailsAddressWinsOverTheBoundRequest(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        attempt.setDetails(new WebAuthenticationDetails(DETAILS_ADDRESS, sessionId));
        bindRequest(CONTEXT_REQUEST_ADDRESS, null);

        SecurityAuditLog.authFailure(attempt);

        assertNoLeak(err, password, sessionId);
        assertTrue(DETAILS_ADDRESS.equals(ipOf(singleAuditLine(err))),
                "The details address must win over the bound request");
    }

    @Test
    @StdIo
    void boundRequestAddressIsUsedWithoutDetails(StdErr err) {
        var password = password();
        bindRequest(CONTEXT_REQUEST_ADDRESS, null);

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password));

        assertNoLeak(err, password);
        assertTrue(CONTEXT_REQUEST_ADDRESS.equals(ipOf(singleAuditLine(err))),
                "The bound request address must be used without details");
    }

    @Test
    @StdIo
    void boundRequestAddressIsUsedForDetailsOfAnotherType(StdErr err) {
        var password = password();
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        attempt.setDetails("not-web-details");
        bindRequest(CONTEXT_REQUEST_ADDRESS, null);

        SecurityAuditLog.authFailure(attempt);

        assertNoLeak(err, password);
        assertTrue(CONTEXT_REQUEST_ADDRESS.equals(ipOf(singleAuditLine(err))),
                "The bound request address must be used for details of another type");
    }

    @Test
    @StdIo
    void missingAddressIsWrittenAsDash(StdErr err) {
        var password = password();

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password));

        assertNoLeak(err, password);
        assertTrue("-".equals(ipOf(singleAuditLine(err))), "A missing address must be written as '-'");
    }

    @Test
    @StdIo
    void resultDetailsAddressIsUsedWhenTheAttemptHasNone(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        var result = UsernamePasswordAuthenticationToken.authenticated(USER_NAME, null, List.of());
        result.setDetails(new WebAuthenticationDetails(DETAILS_ADDRESS, sessionId));
        bindRequest(CONTEXT_REQUEST_ADDRESS, null);

        SecurityAuditLog.authSuccess(UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password), result);

        assertNoLeak(err, password, sessionId);
        assertTrue(DETAILS_ADDRESS.equals(ipOf(singleAuditLine(err))),
                "The result details address must be used when the attempt has none");
    }

    @Test
    @StdIo
    void contextAuthenticationDetailsAddressIsUsedForTokenLifecycle(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        var publicId = randomValue(16);
        var authentication = authenticateInContext(password);
        authentication.setDetails(new WebAuthenticationDetails(DETAILS_ADDRESS, sessionId));
        bindRequest(CONTEXT_REQUEST_ADDRESS, null);

        SecurityAuditLog.patRevoke(publicId);

        assertNoLeak(err, password, sessionId);
        assertTrue(DETAILS_ADDRESS.equals(ipOf(singleAuditLine(err))),
                "The details address of the context authentication must be used for token lifecycle events");
    }

    // ---------------------------------------------------------------------------------------------------------
    // User field of credential-bearing attempts
    // ---------------------------------------------------------------------------------------------------------

    @Test
    @StdIo
    void failedBearerAttemptIsNeverNamed(StdErr err) {
        var bearer = randomValue(40);

        SecurityAuditLog.authFailure(new BearerTokenAuthenticationToken(bearer));

        assertNoLeak(err, bearer);
        var line = singleAuditLine(err);
        assertTrue(line.contains(" user=\"-\" "), "A failed bearer attempt must name no user");
        assertTrue(line.endsWith(" method=BearerTokenAuthenticationToken"),
                "A failed bearer attempt must end with its method");
    }

    @Test
    @StdIo
    void failedAttemptOfAnotherTypeIsNeverNamed(StdErr err) {
        var principal = randomValue(40);
        var credential = randomValue(40);

        SecurityAuditLog.authFailure(new TestingAuthenticationToken(principal, credential));

        assertNoLeak(err, principal, credential);
        var line = singleAuditLine(err);
        assertTrue(line.contains(" user=\"-\" "), "A failed attempt of another type must name no user");
    }

    @Test
    @StdIo
    void lockoutOfAnotherTypeIsNeverNamed(StdErr err) {
        var bearer = randomValue(40);

        SecurityAuditLog.lockout(new BearerTokenAuthenticationToken(bearer));

        assertNoLeak(err, bearer);
        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=auth.lockout outcome=locked user=\"-\" "),
                "A lockout of another type must name no user");
    }

    @Test
    @StdIo
    void successfulBearerAttemptIsNamedAfterItsResult(StdErr err) {
        var bearer = randomValue(40);
        var result = UsernamePasswordAuthenticationToken.authenticated(USER_NAME, null, List.of());

        SecurityAuditLog.authSuccess(new BearerTokenAuthenticationToken(bearer), result);

        assertNoLeak(err, bearer);
        var line = singleAuditLine(err);
        assertTrue(line.contains("event=auth.success outcome=success user=\"jdoe\" "),
                "A successful bearer attempt must be named after its result");
        assertTrue(line.endsWith(" method=BearerTokenAuthenticationToken"),
                "A successful bearer attempt must end with its method");
    }

    @Test
    @StdIo
    void userDetailsPrincipalIsNamedByItsUserName(StdErr err) {
        var storedHash = randomValue(40);
        var password = password();
        var principal = User.withUsername(USER_NAME).password(storedHash).authorities(List.of()).build();

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken.unauthenticated(principal, password));

        assertNoLeak(err, storedHash, password);
        var line = singleAuditLine(err);
        assertTrue(line.contains(" user=\"jdoe\" "), "A UserDetails principal must be named by its user name");
    }

    @Test
    @StdIo
    void anonymousContextIsNamedByItsPrincipal(StdErr err) {
        var key = randomValue(40);
        var anonymous = new AnonymousAuthenticationToken(key,
                "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        SecurityContextHolder.getContext().setAuthentication(anonymous);

        SecurityAuditLog.aclChange("success", 1, new TreeSet<>(List.of("createAcl")), new TreeSet<>(List.of("Root")));

        assertNoLeak(err, key);
        var line = singleAuditLine(err);
        assertTrue(line.contains(" user=\"anonymousUser\" "), "An anonymous context must be named by its principal");
    }

    // ---------------------------------------------------------------------------------------------------------
    // Missing values and failures while building a line
    // ---------------------------------------------------------------------------------------------------------

    @Test
    @StdIo
    void nullArgumentsNeverFailAndWriteAtMostOneLinePerCall(StdErr err) {
        var password = password();
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);

        // Each call checks the password right after it runs, before it counts the lines it added.
        assertAtMostOneLine(err, () -> SecurityAuditLog.authSuccess((Authentication) null, null), password);
        assertAtMostOneLine(err, () -> SecurityAuditLog.authSuccess(attempt, null), password);
        assertAtMostOneLine(err, () -> SecurityAuditLog.authFailure((Authentication) null), password);
        assertAtMostOneLine(err, () -> SecurityAuditLog.lockout(null), password);
        assertAtMostOneLine(err, () -> SecurityAuditLog.authSuccess((HttpServletRequest) null, null, null), password);
        assertAtMostOneLine(err, () -> SecurityAuditLog.authFailure((HttpServletRequest) null, null), password);
        assertAtMostOneLine(err, () -> SecurityAuditLog.patCreate(null), password);
        assertAtMostOneLine(err, () -> SecurityAuditLog.patRevoke(null), password);
        assertAtMostOneLine(err, () -> SecurityAuditLog.aclChange(null, 0, null, null), password);
        assertAtMostOneLine(err,
                () -> SecurityAuditLog.aclChange("success", 0, new TreeSet<>(), new TreeSet<>()),
                password);
    }

    @Test
    @StdIo
    void emptyValuesAreWrittenAsDash(StdErr err) {
        var publicId = randomValue(16);
        var secret = randomValue(32);
        var request = patRequest(pat(publicId, secret));
        request.setRemoteAddr("");

        SecurityAuditLog.authSuccess(request, "", "");

        assertNoLeak(err, secret, pat(publicId, secret));
        var line = singleAuditLine(err);
        assertTrue(line.endsWith("event=auth.success outcome=success user=\"-\" ip=- method=pat pat=-"),
                "Empty values must be written as '-'");
    }

    @Test
    @StdIo
    void tokenLifecycleWithoutAuthenticationNamesNobody(StdErr err) {
        var publicId = randomValue(16);

        SecurityAuditLog.patCreate(publicId);

        var line = singleAuditLine(err);
        assertTrue(line.contains("event=pat.create outcome=success user=\"-\" ip=- pat=" + publicId),
                "pat.create without an authentication must name nobody and no address");
    }

    @Test
    @StdIo
    void failureWhileWritingAProviderSuccessIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var result = mock(Authentication.class);
        when(result.getName()).thenThrow(new IllegalStateException(secret));

        var threw = callThrows(() -> SecurityAuditLog.authSuccess(new BearerTokenAuthenticationToken(secret), result));

        assertWriteFailed(err, "auth.success", secret, threw);
    }

    @Test
    @StdIo
    void failureWhileWritingARejectedAttemptIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var attempt = mock(Authentication.class);
        when(attempt.getDetails()).thenThrow(new IllegalStateException(secret));

        var threw = callThrows(() -> SecurityAuditLog.authFailure(attempt));
        assertWriteFailed(err, "auth.failure", secret, threw);
    }

    @Test
    @StdIo
    void failureWhileWritingALockoutIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var attempt = mock(Authentication.class);
        when(attempt.getDetails()).thenThrow(new IllegalStateException(secret));

        var threw = callThrows(() -> SecurityAuditLog.lockout(attempt));
        assertWriteFailed(err, "auth.lockout", secret, threw);
    }

    @Test
    @StdIo
    void failureWhileWritingAPatSuccessIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenThrow(new IllegalStateException(secret));

        var threw = callThrows(() -> SecurityAuditLog.authSuccess(request, USER_NAME, randomValue(16)));
        assertWriteFailed(err, "auth.success", secret, threw);
    }

    @Test
    @StdIo
    void failureWhileWritingAPatFailureIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenThrow(new IllegalStateException(secret));

        var threw = callThrows(() -> SecurityAuditLog.authFailure(request, randomValue(16)));
        assertWriteFailed(err, "auth.failure", secret, threw);
    }

    @Test
    @StdIo
    void failureWhileWritingATokenLifecycleEventIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var authentication = mock(Authentication.class);
        when(authentication.getName()).thenThrow(new IllegalStateException(secret));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        var threw = callThrows(() -> SecurityAuditLog.patCreate(randomValue(16)));
        assertWriteFailed(err, "pat.create", secret, threw);
    }

    @Test
    @StdIo
    void failureWhileWritingAnAclChangeIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var authentication = mock(Authentication.class);
        when(authentication.getName()).thenThrow(new IllegalStateException(secret));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        var threw = callThrows(() -> SecurityAuditLog.aclChange("success", 1, null, null));
        assertWriteFailed(err, "acl.change", secret, threw);
    }

    @Test
    @WritesStdIo
    void everyEventNeverThrowsWhileTheLoggingBackendFails() {
        var password = password();
        var publicId = randomValue(16);
        var secret = randomValue(32);
        authenticateInContext(password);
        bindRequest(CONTEXT_REQUEST_ADDRESS, null);
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        var result = UsernamePasswordAuthenticationToken.authenticated(USER_NAME, password, List.of());
        var request = patRequest(pat(publicId, secret));
        var kinds = new TreeSet<>(List.of("createAcl"));
        var objectTypes = new TreeSet<>(List.of("Root"));
        var events = new LinkedHashMap<String, Runnable>();
        events.put("authSuccess(Authentication, Authentication)", () -> SecurityAuditLog.authSuccess(attempt, result));
        events.put("authFailure(Authentication)", () -> SecurityAuditLog.authFailure(attempt));
        events.put("lockout", () -> SecurityAuditLog.lockout(attempt));
        events.put("authSuccess(HttpServletRequest, String, String)",
                () -> SecurityAuditLog.authSuccess(request, USER_NAME, publicId));
        events.put("authFailure(HttpServletRequest, String)", () -> SecurityAuditLog.authFailure(request, publicId));
        events.put("patCreate", () -> SecurityAuditLog.patCreate(publicId));
        events.put("patRevoke", () -> SecurityAuditLog.patRevoke(publicId));
        events.put("aclChange success", () -> SecurityAuditLog.aclChange("success", 1, kinds, objectTypes));
        events.put("aclChange failure", () -> SecurityAuditLog.aclChange("failure", 1, kinds, objectTypes));
        var sink = new FailingSink(randomValue(24));
        assertSinkFails(sink);

        events.forEach((name, event) -> {
            var before = sink.writes;
            assertFalse(throwsWhileStdErrFails(sink, event),
                    () -> name + " must not throw while the logging backend fails");
            // The line of the event fails first, then the fixed report of that failure fails as well.
            assertTrue(sink.writes - before >= 2,
                    () -> name + " must hand its line and the report of its failure to the failing backend");
        });
        var handed = sink.refused.toString(StandardCharsets.UTF_8);
        for (var value : List.of(password, secret, pat(publicId, secret), sink.message)) {
            assertFalse(handed.contains(value), "A generated secret was handed to the logging backend.");
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    // Disabled levels: an event whose level is disabled inspects no principal, request, address or detail and
    // writes no line
    // ---------------------------------------------------------------------------------------------------------

    @Test
    @StdIo
    void infoEventsReadAndWriteNothingWhileInfoIsDisabled(StdErr err) throws Exception {
        var attempt = mock(Authentication.class);
        var result = mock(Authentication.class);
        var request = mock(HttpServletRequest.class);
        var context = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(context);
        var bound = mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(bound));
        SortedSet<String> kinds = mock();
        SortedSet<String> objectTypes = mock();

        atLevel(INFO_DISABLED, () -> {
            var logger = LoggerFactory.getLogger(SecurityAuditLog.LOGGER_NAME);
            assertTrue(!logger.isInfoEnabled() && logger.isWarnEnabled(), "Only INFO must be disabled");
            SecurityAuditLog.authSuccess(attempt, result);
            SecurityAuditLog.authSuccess(request, USER_NAME, randomValue(16));
            SecurityAuditLog.patCreate(randomValue(16));
            SecurityAuditLog.patRevoke(randomValue(16));
            SecurityAuditLog.aclChange("success", 1, kinds, objectTypes);
        });

        verifyNoInteractions(attempt, result, request, context, bound, kinds, objectTypes);
        assertTrue(auditLines(err).isEmpty(), "An event whose level is disabled must write nothing");
    }

    @Test
    @StdIo
    void warnEventsReadAndWriteNothingWhileWarnIsDisabled(StdErr err) throws Exception {
        var failed = mock(Authentication.class);
        var locked = mock(Authentication.class);
        var request = mock(HttpServletRequest.class);
        var context = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(context);
        var bound = mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(bound));
        SortedSet<String> kinds = mock();
        SortedSet<String> objectTypes = mock();

        atLevel(WARN_DISABLED, () -> {
            assertFalse(LoggerFactory.getLogger(SecurityAuditLog.LOGGER_NAME).isWarnEnabled(), "WARN must be disabled");
            SecurityAuditLog.authFailure(failed);
            SecurityAuditLog.lockout(locked);
            SecurityAuditLog.authFailure(request, randomValue(16));
            SecurityAuditLog.aclChange("failure", 1, kinds, objectTypes);
            SecurityAuditLog.aclChange(null, 1, kinds, objectTypes);
        });

        verifyNoInteractions(failed, locked, request, context, bound, kinds, objectTypes);
        assertTrue(auditLines(err).isEmpty(), "An event whose level is disabled must write nothing");
    }

    @Test
    @StdIo
    void warnEventsAreWrittenUnchangedWhileOnlyInfoIsDisabled(StdErr err) throws Exception {
        var password = password();
        var publicId = randomValue(16);
        var secret = randomValue(32);
        authenticateInContext(password);

        var root = new TreeSet<>(List.of("Root"));

        atLevel(INFO_DISABLED, () -> {
            SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password));
            SecurityAuditLog.lockout(UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password));
            SecurityAuditLog.authFailure(patRequest(pat(publicId, secret)), publicId);
            SecurityAuditLog.aclChange("success", 1, new TreeSet<>(List.of("createAcl")), root);
            SecurityAuditLog.aclChange("failure", 1, new TreeSet<>(List.of("deleteAcl")), root);
        });

        assertNoLeak(err, password, secret, pat(publicId, secret));
        var lines = auditLines(err);
        assertEquals(4, lines.size(), "Expected the four WARN events and no committed ACL change");
        for (var line : lines) {
            assertTrue(LINE.matcher(line).matches(), "The audit line does not have the audit line format");
            assertLevel(line, "WARN");
        }
        var method = " method=UsernamePasswordAuthenticationToken";
        assertTrue(lines.get(0).endsWith("event=auth.failure outcome=failure user=\"jdoe\" ip=-" + method),
                "auth.failure must be written unchanged");
        assertTrue(lines.get(1).endsWith("event=auth.lockout outcome=locked user=\"jdoe\" ip=-" + method),
                "auth.lockout must be written unchanged");
        assertTrue(lines.get(2)
                .endsWith("event=auth.failure outcome=failure user=\"-\" ip=198.51.100.7 method=pat pat=" + publicId),
                "PAT auth.failure must be written unchanged");
        assertTrue(lines.get(3)
                .endsWith("event=acl.change outcome=failure user=\"jdoe\" ip=- changes=1 kinds=deleteAcl"
                        + " objectTypes=Root"),
                "acl.change that did not commit must be written unchanged");
    }

    // ---------------------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------------------

    /** The captured lines written by the audit logger, in order. */
    private static List<String> auditLines(StdErr err) {
        var marker = " " + SecurityAuditLog.LOGGER_NAME + " - ";
        return err.capturedString().lines().filter(l -> l.contains(marker)).toList();
    }

    /**
     * Asserts that exactly one audit line was written and that it has the audit line format. Like every assertion
     * here, its failure message is fixed and never quotes captured output, which could hold a leaked secret.
     */
    private static String singleAuditLine(StdErr err) {
        var lines = auditLines(err);
        assertEquals(1, lines.size(), "Expected exactly one audit line");
        var line = lines.getFirst();
        assertTrue(LINE.matcher(line).matches(), "The audit line does not have the audit line format");
        return line;
    }

    /** The only captured line that carries an {@code event=} pair, however the value tried to split it. */
    private static String theOnlyEventLine(StdErr err) {
        var lines = err.capturedString().lines().filter(l -> l.contains("event=")).toList();
        assertEquals(1, lines.size(), "Expected exactly one captured line with an event pair");
        return lines.getFirst();
    }

    /** The user value of the only event line, which must have the audit line format. */
    private static String userOfTheOnlyEventLine(StdErr err) {
        var line = theOnlyEventLine(err);
        assertTrue(LINE.matcher(line).matches(), "The event line does not have the audit line format");
        var user = USER.matcher(line);
        assertTrue(user.find(), "The event line carries no quoted user value");
        return user.group(1);
    }

    private static String ipOf(String line) {
        var ip = IP.matcher(line);
        assertTrue(ip.find(), "The audit line carries no ip pair");
        return ip.group(1);
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

    /** Asserts that a sanitized value holds no control character, quote, backslash or line separator. */
    private static void assertSanitized(String value) {
        assertFalse(value.chars().anyMatch(Character::isISOControl), "A sanitized value holds a control character");
        for (var unsafe : List.of("\"", "\\", "\u2028", "\u2029")) {
            assertFalse(value.contains(unsafe), "A sanitized value holds a quote, a backslash or a line separator");
        }
    }

    /** Asserts that each of the fixed pairs occurs exactly once in the line, so no value added a forged one. */
    private static void assertNoForgedPair(String line) {
        for (var key : List.of("event=", " outcome=", " user=", " ip=")) {
            assertEquals(1,
                    Pattern.compile(Pattern.quote(key)).matcher(line).results().count(),
                    () -> "Expected the fixed pair '" + key.strip() + "' exactly once");
        }
    }

    /**
     * Asserts that an unquoted value starts with the given text and holds no whitespace, space character,
     * {@code =}, quote, backslash or control character, so it is one token that cannot add a pair.
     */
    private static void assertOneToken(String value, String prefix) {
        assertTrue(value.startsWith(prefix), "The value must keep its expected prefix");
        assertSanitized(value);
        assertTrue(value.chars()
                .noneMatch(c -> Character.isWhitespace(c) || Character.isSpaceChar(c) || c == '='),
                "The value must be one token without whitespace, a space character or '='");
    }

    /** A token lifecycle line carries no method pair other than {@code method=pat}. */
    private static void assertNoMethodOtherThanPat(String line) {
        var method = Pattern.compile(" method=(\\S*)").matcher(line);
        while (method.find()) {
            assertTrue("pat".equals(method.group(1)), "A token lifecycle line may carry only method=pat");
        }
    }

    /**
     * Runs the call, checks that none of the secrets reached the output, then asserts that the call did not throw
     * and added at most one audit line. Like {@link #callThrows}, it never formats an exception the call throws.
     */
    private static void assertAtMostOneLine(StdErr err, Runnable call, String... secrets) {
        var before = auditLines(err).size();
        var threw = callThrows(call);
        assertNoLeak(err, secrets);
        assertFalse(threw, "Writing an event with missing values must never throw");
        var added = auditLines(err).size() - before;
        assertTrue(added <= 1, () -> "Expected at most one audit line, got " + added);
    }

    /**
     * Asserts that a failure while building the event was swallowed and reported with the fixed WARN message,
     * which never quotes the cause. The secret, the message of that cause, is checked first.
     */
    private static void assertWriteFailed(StdErr err, String event, String secret, boolean threw) {
        assertNoLeak(err, secret);
        assertFalse(threw, () -> "A failure while writing " + event + " must be swallowed");
        var lines = auditLines(err);
        assertEquals(1, lines.size(), () -> "Expected exactly one audit line for " + event);
        var line = lines.getFirst();
        assertLevel(line, "WARN");
        assertTrue(line.endsWith(" - " + WRITE_FAILED + event + "' (IllegalStateException)."),
                () -> "Expected the fixed write-failure message for " + event);
    }

    /**
     * Runs the call and answers whether it threw. Unlike {@code assertDoesNotThrow}, an assertion on the answer
     * never formats the exception, whose message here is a generated secret.
     */
    private static boolean callThrows(Runnable call) {
        try {
            call.run();
            return false;
        } catch (RuntimeException e) {
            return true;
        }
    }

    /**
     * Runs the call while {@code System.err}, where slf4j-simple writes every line, is a fresh stream over the sink,
     * then restores it, and answers as {@link #callThrows} does. A fresh stream per call keeps the encoder state that
     * a refused write leaves behind from reaching the next call.
     */
    private static boolean throwsWhileStdErrFails(FailingSink sink, Runnable call) {
        var original = System.err;
        System.setErr(new PrintStream(sink, true, StandardCharsets.UTF_8));
        try {
            return callThrows(call);
        } finally {
            System.setErr(original);
        }
    }

    /**
     * Asserts that a line logged directly to the audit logger throws over the sink, so a test that runs an event
     * there really meets a failing logging backend.
     */
    private static void assertSinkFails(FailingSink sink) {
        var before = sink.writes;
        var threw = throwsWhileStdErrFails(sink,
                () -> LoggerFactory.getLogger(SecurityAuditLog.LOGGER_NAME).warn("Probe of the failing sink."));
        assertTrue(threw && sink.writes > before, "A line logged directly must throw while the sink fails");
    }

    /**
     * Runs the calls while the audit logger's lowest enabled level is the given one, then restores the level it had.
     * slf4j-simple, the unit-test binding, fixes the level of a logger when it creates the logger and has no API to
     * change it, so the current level of the logger is set directly.
     *
     * @param lowestEnabled the name of the slf4j-simple level constant, {@link #INFO_DISABLED} or
     *                      {@link #WARN_DISABLED}
     */
    private static void atLevel(String lowestEnabled, Runnable calls) throws ReflectiveOperationException {
        var logger = LoggerFactory.getLogger(SecurityAuditLog.LOGGER_NAME);
        assertTrue(logger instanceof SimpleLogger, "The unit tests must bind slf4j to slf4j-simple");
        var current = SimpleLogger.class.getDeclaredField("currentLogLevel");
        var lowest = SimpleLogger.class.getDeclaredField(lowestEnabled);
        current.setAccessible(true);
        lowest.setAccessible(true);
        var original = current.getInt(logger);
        current.setInt(logger, lowest.getInt(null));
        try {
            calls.run();
        } finally {
            current.setInt(logger, original);
        }
    }

    /** Puts an authenticated user name and password authentication of {@code jdoe} into the security context. */
    private static UsernamePasswordAuthenticationToken authenticateInContext(String password) {
        var authentication = UsernamePasswordAuthenticationToken.authenticated(USER_NAME, password, List.of());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return authentication;
    }

    /** Binds a request with the given remote address, and optionally a token header, to the current thread. */
    private static void bindRequest(String remoteAddress, String patOrNull) {
        var request = new MockHttpServletRequest();
        request.setRemoteAddr(remoteAddress);
        if (patOrNull != null) {
            request.addHeader("Authorization", "Token " + patOrNull);
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    /** A request as the token filter receives it, from the documentation address {@code 198.51.100.7}. */
    private static MockHttpServletRequest patRequest(String token) {
        var request = new MockHttpServletRequest();
        request.setRemoteAddr(PAT_REQUEST_ADDRESS);
        request.addHeader("Authorization", "Token " + token);
        return request;
    }

    /** A personal access token in its wire format, {@code openl_pat_<publicId>.<secret>}. */
    private static String pat(String publicId, String secret) {
        return "openl_pat_" + publicId + "." + secret;
    }

    private static String password() {
        return randomValue(16);
    }

    private static String randomValue(int length) {
        return RandomStringUtils.secure().nextAlphanumeric(length);
    }

    /**
     * The output of a logging backend that does not ignore its failures, as a log4j appender with
     * {@code ignoreExceptions=false}: every write throws, with a generated message. It counts the writes and keeps
     * their bytes, so a test can assert that it was reached and that no generated secret was handed to it.
     */
    private static final class FailingSink extends OutputStream {

        private final String message;
        private final ByteArrayOutputStream refused = new ByteArrayOutputStream();
        private int writes;

        private FailingSink(String message) {
            this.message = message;
        }

        @Override
        public void write(int b) {
            refused.write(b);
            throw refuse();
        }

        @Override
        public void write(byte[] b, int off, int len) {
            refused.write(b, off, len);
            throw refuse();
        }

        /** Counts one refused write and returns the exception that refuses it. */
        private IllegalStateException refuse() {
            writes++;
            return new IllegalStateException(message);
        }
    }
}

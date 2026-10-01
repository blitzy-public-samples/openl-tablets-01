package org.openl.studio.security.audit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.TreeSet;
import java.util.regex.Pattern;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
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

        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=auth.success outcome=success user=\"jdoe\" ip=192.0.2.10"), line);
        assertTrue(line.endsWith(" method=UsernamePasswordAuthenticationToken"), line);
        assertNoLeak(err, password, sessionId);
    }

    @Test
    @StdIo
    void authFailureWritesOneWarnLineWithTheAttemptedUserName(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        attempt.setDetails(new WebAuthenticationDetails(DETAILS_ADDRESS, sessionId));

        SecurityAuditLog.authFailure(attempt);

        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=auth.failure outcome=failure user=\"jdoe\" ip=192.0.2.10"), line);
        assertTrue(line.endsWith(" method=UsernamePasswordAuthenticationToken"), line);
        assertNoLeak(err, password, sessionId);
    }

    @Test
    @StdIo
    void lockoutWritesOneWarnLineWithTheLockedOutcome(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        attempt.setDetails(new WebAuthenticationDetails(DETAILS_ADDRESS, sessionId));

        SecurityAuditLog.lockout(attempt);

        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=auth.lockout outcome=locked user=\"jdoe\" ip=192.0.2.10"), line);
        assertTrue(line.endsWith(" method=UsernamePasswordAuthenticationToken"), line);
        assertNoLeak(err, password, sessionId);
    }

    @Test
    @StdIo
    void patAuthSuccessWritesThePublicIdButNeverTheToken(StdErr err) {
        var publicId = randomValue(16);
        var secret = randomValue(32);
        var token = pat(publicId, secret);
        var request = patRequest(token);

        SecurityAuditLog.authSuccess(request, USER_NAME, publicId);

        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=auth.success outcome=success user=\"jdoe\" ip=198.51.100.7"), line);
        assertTrue(line.endsWith(" method=pat pat=" + publicId), line);
        assertNoLeak(err, secret, token);
    }

    @Test
    @StdIo
    void patAuthFailureWritesAnAnonymousWarnLineWithThePublicId(StdErr err) {
        var publicId = randomValue(16);
        var secret = randomValue(32);
        var token = pat(publicId, secret);

        SecurityAuditLog.authFailure(patRequest(token), publicId);

        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=auth.failure outcome=failure user=\"-\" ip=198.51.100.7"), line);
        assertTrue(line.endsWith(" method=pat pat=" + publicId), line);
        assertNoLeak(err, secret, token);
    }

    @Test
    @StdIo
    void patAuthFailureOmitsThePublicIdOfATokenThatDidNotParse(StdErr err) {
        var token = pat(randomValue(16), randomValue(32)) + randomValue(8);

        SecurityAuditLog.authFailure(patRequest(token), null);

        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=auth.failure outcome=failure user=\"-\" ip=198.51.100.7"), line);
        assertTrue(line.endsWith(" method=pat"), line);
        assertFalse(line.contains("pat="), line);
        assertNoLeak(err, token);
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

        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=pat.create outcome=success user=\"jdoe\" ip=203.0.113.5"), line);
        assertTrue(line.contains(" pat=" + publicId), line);
        assertNoMethodOtherThanPat(line);
        assertNoLeak(err, password, secret, pat(publicId, secret));
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

        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=pat.revoke outcome=success user=\"jdoe\" ip=203.0.113.5"), line);
        assertTrue(line.contains(" pat=" + publicId), line);
        assertNoMethodOtherThanPat(line);
        assertNoLeak(err, password, secret, pat(publicId, secret));
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

        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=acl.change outcome=success user=\"jdoe\" ip=203.0.113.5"), line);
        assertTrue(line.endsWith(" changes=3 kinds=createAcl,updateAcl objectTypes=ProjectArtifact,Root"), line);
        assertFalse(line.contains("method="), line);
        assertFalse(line.contains("pat="), line);
        assertNoLeak(err, password);
    }

    @Test
    @StdIo
    void aclChangeThatDidNotCommitIsWrittenAtWarn(StdErr err) {
        var password = password();
        authenticateInContext(password);

        SecurityAuditLog.aclChange("failure", 1, new TreeSet<>(List.of("deleteAcl")), new TreeSet<>(List.of("Root")));

        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=acl.change outcome=failure user=\"jdoe\""), line);
        assertTrue(line.endsWith(" changes=1 kinds=deleteAcl objectTypes=Root"), line);
        assertNoLeak(err, password);
    }

    @Test
    @StdIo
    void aclChangeWithoutAuthenticationIsAttributedToSystem(StdErr err) {
        SecurityAuditLog.aclChange("success", 2, new TreeSet<>(List.of("createAcl")), new TreeSet<>(List.of("Root")));

        var line = singleAuditLine(err);
        assertLevel(line, "INFO");
        assertTrue(line.contains("event=acl.change outcome=success user=\"system\" ip=- changes=2"), line);
    }

    @Test
    @StdIo
    void aclChangeWritesEmptySetsAsMissingValues(StdErr err) {
        SecurityAuditLog.aclChange("success", 0, new TreeSet<>(), new TreeSet<>());

        var line = singleAuditLine(err);
        assertTrue(line.endsWith(" changes=0 kinds=- objectTypes=-"), line);
    }

    @Test
    @StdIo
    void aclChangeWithAnUnknownOutcomeIsWrittenAtWarn(StdErr err) {
        SecurityAuditLog.aclChange("rolled-back",
                1,
                new TreeSet<>(List.of("updateSid")),
                new TreeSet<>(List.of("sid")));

        var lines = auditLines(err);
        assertEquals(1, lines.size(), String.join("\n", lines));
        var line = lines.getFirst();
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=acl.change outcome=rolled-back user=\"system\""), line);
        assertTrue(line.endsWith(" changes=1 kinds=updateSid objectTypes=sid"), line);
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

        var user = userOfTheOnlyEventLine(err);
        assertSanitized(user);
        assertTrue(user.startsWith(prefix), user);
        assertNoLeak(err, password);
    }

    @Test
    @StdIo
    void addressCannotBreakTheLineOrForgeAnEvent(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        attempt.setDetails(new WebAuthenticationDetails(DETAILS_ADDRESS + "\nevent=x\r\t\u0007\"\\", sessionId));

        SecurityAuditLog.authFailure(attempt);

        var line = theOnlyEventLine(err);
        assertTrue(LINE.matcher(line).matches(), line);
        var ip = IP.matcher(line);
        assertTrue(ip.find(), line);
        assertSanitized(ip.group(1));
        assertTrue(ip.group(1).startsWith(DETAILS_ADDRESS), line);
        assertNoLeak(err, password, sessionId);
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

        var user = userOfTheOnlyEventLine(err);
        assertSanitized(user);
        assertTrue(user.startsWith(prefix), user);
        assertNoLeak(err, secret, pat(publicId, secret));
    }

    @Test
    @StdIo
    void unicodeLineSeparatorsAreReplaced(StdErr err) {
        var password = password();
        var prefix = randomValue(12);

        SecurityAuditLog.lockout(UsernamePasswordAuthenticationToken
                .unauthenticated(prefix + "\u2028event=x\u2029event=y", password));

        var user = userOfTheOnlyEventLine(err);
        assertFalse(user.contains("\u2028"), user);
        assertFalse(user.contains("\u2029"), user);
        assertTrue(user.startsWith(prefix), user);
        assertNoLeak(err, password);
    }

    @Test
    @StdIo
    void aclChangeNamesAndOutcomeAreSanitized(StdErr err) {
        SecurityAuditLog.aclChange("success",
                1,
                new TreeSet<>(List.of("create\nAcl")),
                new TreeSet<>(List.of("Ro\"ot", "Pro\\ject")));

        var line = singleAuditLine(err);
        assertTrue(line.endsWith(" changes=1 kinds=create_Acl objectTypes=Pro_ject,Ro_ot"), line);
    }

    @Test
    @StdIo
    void addressWithSpacesCannotForgePairs(StdErr err) {
        var password = password();
        var sessionId = randomValue(40);
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        attempt.setDetails(new WebAuthenticationDetails(DETAILS_ADDRESS + " " + FORGED_PAIRS, sessionId));

        SecurityAuditLog.authFailure(attempt);

        var line = singleAuditLine(err);
        assertNoForgedPair(line);
        assertOneToken(ipOf(line), DETAILS_ADDRESS);
        assertNoLeak(err, password, sessionId);
    }

    @Test
    @StdIo
    void addressWithUnicodeSpacesCannotForgePairs(StdErr err) {
        var publicId = randomValue(16);
        var secret = randomValue(32);
        var request = patRequest(pat(publicId, secret));
        request.setRemoteAddr(PAT_REQUEST_ADDRESS + "\u00A0" + FORGED_PAIRS.replace(' ', '\u2003') + "\u202Fx=y");

        SecurityAuditLog.authFailure(request, publicId);

        var line = singleAuditLine(err);
        assertNoForgedPair(line);
        assertOneToken(ipOf(line), PAT_REQUEST_ADDRESS);
        assertTrue(line.endsWith(" method=pat pat=" + publicId), line);
        assertNoLeak(err, secret, pat(publicId, secret));
    }

    @Test
    @StdIo
    void publicIdWithSpacesAndEqualsSignsIsWrittenAsOneToken(StdErr err) {
        var publicId = randomValue(16);
        var secret = randomValue(32);

        SecurityAuditLog.authFailure(patRequest(pat(publicId, secret)), publicId + " " + FORGED_PAIRS);

        var line = singleAuditLine(err);
        assertNoForgedPair(line);
        assertTrue(line.endsWith(" method=pat pat=" + publicId + "_event_auth.success_outcome_success_user__root_"),
                line);
        assertNoLeak(err, secret, pat(publicId, secret));
    }

    @Test
    @StdIo
    void aclOutcomeAndNamesWithSpacesAndEqualsSignsAreWrittenAsOneTokenEach(StdErr err) {
        SecurityAuditLog.aclChange("rolled back outcome=success",
                1,
                new TreeSet<>(List.of("create Acl=x")),
                new TreeSet<>(List.of("Root\u00A0type=y", "Sid\u2003z")));

        var lines = auditLines(err);
        assertEquals(1, lines.size(), String.join("\n", lines));
        var line = lines.getFirst();
        assertLevel(line, "WARN");
        assertNoForgedPair(line);
        assertTrue(line.contains("event=acl.change outcome=rolled_back_outcome_success user=\"system\" ip=- "), line);
        assertTrue(line.endsWith(" changes=1 kinds=create_Acl_x objectTypes=Root_type_y,Sid_z"), line);
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

        var line = singleAuditLine(err);
        var user = userOfTheOnlyEventLine(err);
        assertEquals(MAX_VALUE_LENGTH + TRUNCATION_MARKER.length(), user.length(), user);
        assertEquals(name.substring(0, MAX_VALUE_LENGTH) + TRUNCATION_MARKER, user);
        assertTrue(line.length() < 1024, () -> "Line of " + line.length() + " characters");
        assertNoLeak(err, password);
    }

    @Test
    @StdIo
    void userNameOfExactlyTheLimitIsKeptWhole(StdErr err) {
        var password = password();
        var name = randomValue(MAX_VALUE_LENGTH);

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken.unauthenticated(name, password));

        assertEquals(name, userOfTheOnlyEventLine(err));
        assertNoLeak(err, password);
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

        var line = singleAuditLine(err);
        assertNoForgedPair(line);
        var expected = address.substring(0, MAX_VALUE_LENGTH).replaceAll("[ =\"]", "_") + TRUNCATION_MARKER;
        assertEquals(expected, ipOf(line));
        assertTrue(line.endsWith(" method=pat pat=" + publicId), line);
        assertTrue(line.length() < 1024, () -> "Line of " + line.length() + " characters");
        assertNoLeak(err, secret, pat(publicId, secret));
    }

    @Test
    @StdIo
    void cutNeverSplitsASurrogatePair(StdErr err) {
        var password = password();
        var prefix = randomValue(MAX_VALUE_LENGTH - 1);

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken
                .unauthenticated(prefix + SURROGATE_PAIR + randomValue(100), password));

        var user = userOfTheOnlyEventLine(err);
        assertEquals(prefix + TRUNCATION_MARKER, user);
        assertTrue(user.chars().noneMatch(c -> Character.isSurrogate((char) c)), user);
        assertNoLeak(err, password);
    }

    @Test
    @StdIo
    void surrogatePairThatEndsAtTheLimitIsKeptWhole(StdErr err) {
        var password = password();
        var prefix = randomValue(MAX_VALUE_LENGTH - SURROGATE_PAIR.length());

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken
                .unauthenticated(prefix + SURROGATE_PAIR + randomValue(100), password));

        assertEquals(prefix + SURROGATE_PAIR + TRUNCATION_MARKER, userOfTheOnlyEventLine(err));
        assertNoLeak(err, password);
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

        assertEquals(DETAILS_ADDRESS, ipOf(singleAuditLine(err)));
        assertNoLeak(err, password, sessionId);
    }

    @Test
    @StdIo
    void boundRequestAddressIsUsedWithoutDetails(StdErr err) {
        var password = password();
        bindRequest(CONTEXT_REQUEST_ADDRESS, null);

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password));

        assertEquals(CONTEXT_REQUEST_ADDRESS, ipOf(singleAuditLine(err)));
        assertNoLeak(err, password);
    }

    @Test
    @StdIo
    void boundRequestAddressIsUsedForDetailsOfAnotherType(StdErr err) {
        var password = password();
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);
        attempt.setDetails("not-web-details");
        bindRequest(CONTEXT_REQUEST_ADDRESS, null);

        SecurityAuditLog.authFailure(attempt);

        assertEquals(CONTEXT_REQUEST_ADDRESS, ipOf(singleAuditLine(err)));
        assertNoLeak(err, password);
    }

    @Test
    @StdIo
    void missingAddressIsWrittenAsDash(StdErr err) {
        var password = password();

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password));

        assertEquals("-", ipOf(singleAuditLine(err)));
        assertNoLeak(err, password);
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

        assertEquals(DETAILS_ADDRESS, ipOf(singleAuditLine(err)));
        assertNoLeak(err, password, sessionId);
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

        assertEquals(DETAILS_ADDRESS, ipOf(singleAuditLine(err)));
        assertNoLeak(err, password, sessionId);
    }

    // ---------------------------------------------------------------------------------------------------------
    // User field of credential-bearing attempts
    // ---------------------------------------------------------------------------------------------------------

    @Test
    @StdIo
    void failedBearerAttemptIsNeverNamed(StdErr err) {
        var bearer = randomValue(40);

        SecurityAuditLog.authFailure(new BearerTokenAuthenticationToken(bearer));

        var line = singleAuditLine(err);
        assertTrue(line.contains(" user=\"-\" "), line);
        assertTrue(line.endsWith(" method=BearerTokenAuthenticationToken"), line);
        assertNoLeak(err, bearer);
    }

    @Test
    @StdIo
    void failedAttemptOfAnotherTypeIsNeverNamed(StdErr err) {
        var principal = randomValue(40);
        var credential = randomValue(40);

        SecurityAuditLog.authFailure(new TestingAuthenticationToken(principal, credential));

        var line = singleAuditLine(err);
        assertTrue(line.contains(" user=\"-\" "), line);
        assertNoLeak(err, principal, credential);
    }

    @Test
    @StdIo
    void lockoutOfAnotherTypeIsNeverNamed(StdErr err) {
        var bearer = randomValue(40);

        SecurityAuditLog.lockout(new BearerTokenAuthenticationToken(bearer));

        var line = singleAuditLine(err);
        assertLevel(line, "WARN");
        assertTrue(line.contains("event=auth.lockout outcome=locked user=\"-\" "), line);
        assertNoLeak(err, bearer);
    }

    @Test
    @StdIo
    void successfulBearerAttemptIsNamedAfterItsResult(StdErr err) {
        var bearer = randomValue(40);
        var result = UsernamePasswordAuthenticationToken.authenticated(USER_NAME, null, List.of());

        SecurityAuditLog.authSuccess(new BearerTokenAuthenticationToken(bearer), result);

        var line = singleAuditLine(err);
        assertTrue(line.contains("event=auth.success outcome=success user=\"jdoe\" "), line);
        assertTrue(line.endsWith(" method=BearerTokenAuthenticationToken"), line);
        assertNoLeak(err, bearer);
    }

    @Test
    @StdIo
    void userDetailsPrincipalIsNamedByItsUserName(StdErr err) {
        var storedHash = randomValue(40);
        var password = password();
        var principal = User.withUsername(USER_NAME).password(storedHash).authorities(List.of()).build();

        SecurityAuditLog.authFailure(UsernamePasswordAuthenticationToken.unauthenticated(principal, password));

        var line = singleAuditLine(err);
        assertTrue(line.contains(" user=\"jdoe\" "), line);
        assertNoLeak(err, storedHash, password);
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

        var line = singleAuditLine(err);
        assertTrue(line.contains(" user=\"anonymousUser\" "), line);
        assertNoLeak(err, key);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Missing values and failures while building a line
    // ---------------------------------------------------------------------------------------------------------

    @Test
    @StdIo
    void nullArgumentsNeverFailAndWriteAtMostOneLinePerCall(StdErr err) {
        var password = password();
        var attempt = UsernamePasswordAuthenticationToken.unauthenticated(USER_NAME, password);

        assertAtMostOneLine(err, () -> SecurityAuditLog.authSuccess((Authentication) null, null));
        assertAtMostOneLine(err, () -> SecurityAuditLog.authSuccess(attempt, null));
        assertAtMostOneLine(err, () -> SecurityAuditLog.authFailure((Authentication) null));
        assertAtMostOneLine(err, () -> SecurityAuditLog.lockout(null));
        assertAtMostOneLine(err, () -> SecurityAuditLog.authSuccess((HttpServletRequest) null, null, null));
        assertAtMostOneLine(err, () -> SecurityAuditLog.authFailure((HttpServletRequest) null, null));
        assertAtMostOneLine(err, () -> SecurityAuditLog.patCreate(null));
        assertAtMostOneLine(err, () -> SecurityAuditLog.patRevoke(null));
        assertAtMostOneLine(err, () -> SecurityAuditLog.aclChange(null, 0, null, null));
        assertAtMostOneLine(err, () -> SecurityAuditLog.aclChange("success", 0, new TreeSet<>(), new TreeSet<>()));
        assertNoLeak(err, password);
    }

    @Test
    @StdIo
    void emptyValuesAreWrittenAsDash(StdErr err) {
        var publicId = randomValue(16);
        var secret = randomValue(32);
        var request = patRequest(pat(publicId, secret));
        request.setRemoteAddr("");

        SecurityAuditLog.authSuccess(request, "", "");

        var line = singleAuditLine(err);
        assertTrue(line.endsWith("event=auth.success outcome=success user=\"-\" ip=- method=pat pat=-"), line);
        assertNoLeak(err, secret, pat(publicId, secret));
    }

    @Test
    @StdIo
    void tokenLifecycleWithoutAuthenticationNamesNobody(StdErr err) {
        var publicId = randomValue(16);

        SecurityAuditLog.patCreate(publicId);

        var line = singleAuditLine(err);
        assertTrue(line.contains("event=pat.create outcome=success user=\"-\" ip=- pat=" + publicId), line);
    }

    @Test
    @StdIo
    void failureWhileWritingAProviderSuccessIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var result = mock(Authentication.class);
        when(result.getName()).thenThrow(new IllegalStateException(secret));

        assertDoesNotThrow(() -> SecurityAuditLog.authSuccess(new BearerTokenAuthenticationToken(secret), result));

        assertWriteFailed(err, "auth.success", secret);
    }

    @Test
    @StdIo
    void failureWhileWritingARejectedAttemptIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var attempt = mock(Authentication.class);
        when(attempt.getDetails()).thenThrow(new IllegalStateException(secret));

        assertDoesNotThrow(() -> SecurityAuditLog.authFailure(attempt));
        assertWriteFailed(err, "auth.failure", secret);
    }

    @Test
    @StdIo
    void failureWhileWritingALockoutIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var attempt = mock(Authentication.class);
        when(attempt.getDetails()).thenThrow(new IllegalStateException(secret));

        assertDoesNotThrow(() -> SecurityAuditLog.lockout(attempt));
        assertWriteFailed(err, "auth.lockout", secret);
    }

    @Test
    @StdIo
    void failureWhileWritingAPatSuccessIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenThrow(new IllegalStateException(secret));

        assertDoesNotThrow(() -> SecurityAuditLog.authSuccess(request, USER_NAME, randomValue(16)));
        assertWriteFailed(err, "auth.success", secret);
    }

    @Test
    @StdIo
    void failureWhileWritingAPatFailureIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenThrow(new IllegalStateException(secret));

        assertDoesNotThrow(() -> SecurityAuditLog.authFailure(request, randomValue(16)));
        assertWriteFailed(err, "auth.failure", secret);
    }

    @Test
    @StdIo
    void failureWhileWritingATokenLifecycleEventIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var authentication = mock(Authentication.class);
        when(authentication.getName()).thenThrow(new IllegalStateException(secret));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        assertDoesNotThrow(() -> SecurityAuditLog.patCreate(randomValue(16)));
        assertWriteFailed(err, "pat.create", secret);
    }

    @Test
    @StdIo
    void failureWhileWritingAnAclChangeIsSwallowedWithoutItsMessage(StdErr err) {
        var secret = randomValue(40);
        var authentication = mock(Authentication.class);
        when(authentication.getName()).thenThrow(new IllegalStateException(secret));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        assertDoesNotThrow(() -> SecurityAuditLog.aclChange("success", 1, null, null));
        assertWriteFailed(err, "acl.change", secret);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------------------

    /** The captured lines written by the audit logger, in order. */
    private static List<String> auditLines(StdErr err) {
        var marker = " " + SecurityAuditLog.LOGGER_NAME + " - ";
        return err.capturedString().lines().filter(l -> l.contains(marker)).toList();
    }

    /** Asserts that exactly one audit line was written and that it has the audit line format. */
    private static String singleAuditLine(StdErr err) {
        var lines = auditLines(err);
        assertEquals(1, lines.size(), () -> "Expected one audit line, got: " + String.join("\n", lines));
        var line = lines.getFirst();
        assertTrue(LINE.matcher(line).matches(), () -> "Not an audit line: " + line);
        return line;
    }

    /** The only captured line that carries an {@code event=} pair, however the value tried to split it. */
    private static String theOnlyEventLine(StdErr err) {
        var lines = err.capturedString().lines().filter(l -> l.contains("event=")).toList();
        assertEquals(1, lines.size(), () -> "Expected one event line, got: " + String.join("\n", lines));
        return lines.getFirst();
    }

    /** The user value of the only event line, which must have the audit line format. */
    private static String userOfTheOnlyEventLine(StdErr err) {
        var line = theOnlyEventLine(err);
        assertTrue(LINE.matcher(line).matches(), () -> "Not an audit line: " + line);
        var user = USER.matcher(line);
        assertTrue(user.find(), line);
        return user.group(1);
    }

    private static String ipOf(String line) {
        var ip = IP.matcher(line);
        assertTrue(ip.find(), line);
        return ip.group(1);
    }

    private static void assertLevel(String line, String level) {
        assertTrue(line.contains(level + " " + SecurityAuditLog.LOGGER_NAME + " - "),
                () -> "Expected level " + level + ": " + line);
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
        assertFalse(value.chars().anyMatch(Character::isISOControl), value);
        for (var unsafe : List.of("\"", "\\", "\u2028", "\u2029")) {
            assertFalse(value.contains(unsafe), value);
        }
    }

    /** Asserts that each of the fixed pairs occurs exactly once in the line, so no value added a forged one. */
    private static void assertNoForgedPair(String line) {
        for (var key : List.of("event=", " outcome=", " user=", " ip=")) {
            assertEquals(1, Pattern.compile(Pattern.quote(key)).matcher(line).results().count(), line);
        }
    }

    /**
     * Asserts that an unquoted value starts with the given text and holds no whitespace, space character,
     * {@code =}, quote, backslash or control character, so it is one token that cannot add a pair.
     */
    private static void assertOneToken(String value, String prefix) {
        assertTrue(value.startsWith(prefix), value);
        assertSanitized(value);
        assertTrue(value.chars()
                .noneMatch(c -> Character.isWhitespace(c) || Character.isSpaceChar(c) || c == '='), value);
    }

    /** A token lifecycle line carries no method pair other than {@code method=pat}. */
    private static void assertNoMethodOtherThanPat(String line) {
        var method = Pattern.compile(" method=(\\S*)").matcher(line);
        while (method.find()) {
            assertEquals("pat", method.group(1), line);
        }
    }

    /** Runs the call, which must not throw, and asserts that it added at most one audit line. */
    private static void assertAtMostOneLine(StdErr err, Executable call) {
        var before = auditLines(err).size();
        assertDoesNotThrow(call);
        var added = auditLines(err).size() - before;
        assertTrue(added <= 1, () -> "Expected at most one audit line, got " + added);
    }

    /** Asserts the fixed WARN message for an event that could not be built, which never quotes the cause. */
    private static void assertWriteFailed(StdErr err, String event, String secret) {
        var lines = auditLines(err);
        assertEquals(1, lines.size(), () -> String.join("\n", lines));
        var line = lines.getFirst();
        assertLevel(line, "WARN");
        assertTrue(line.endsWith(" - " + WRITE_FAILED + event + "' (IllegalStateException)."), line);
        assertNoLeak(err, secret);
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
}

package org.openl.studio.security.audit;

import java.util.SortedSet;
import jakarta.servlet.http.HttpServletRequest;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Writes the security audit trail (V11): one line per authentication attempt, login lockout, personal
 * access token creation or revocation, and committed ACL change.
 *
 * <p>Every line goes to the logger {@value #LOGGER_NAME} as space-separated {@code key=value} pairs in a
 * fixed order: {@code event}, {@code outcome}, {@code user}, {@code ip}, then the pairs of the event. Only the
 * user value is quoted, and a missing value is written as {@code -}. For example:
 *
 * <pre>
 * event=auth.failure outcome=failure user="alice" ip=127.0.0.1 method=UsernamePasswordAuthenticationToken
 * event=pat.revoke outcome=success user="alice" ip=127.0.0.1 pat=${PAT_PUBLIC_ID}
 * event=acl.change outcome=success user="system" ip=- changes=2 kinds=createAcl,updateAcl objectTypes=Root
 * </pre>
 *
 * <p>Successful authentications, token lifecycle events and committed ACL changes are written at INFO.
 * Failed authentications, lockouts and ACL changes whose transaction did not commit are written at WARN. When the
 * level an event is written at is disabled, nothing of the event is read and no line is built.
 *
 * <p>A line carries nothing but user names, the public identifiers of personal access tokens, counts,
 * code-defined names (events, authentication token classes, ACL mutators and object types), addresses and
 * outcomes. Passwords, credentials, bearer tokens, token secrets, token names, SIDs and ACL object identifiers
 * are never logged. The name of a failed authentication attempt is logged only for a user name and password
 * attempt, because the name of any other attempt, such as a bearer, SAML or token attempt, can be the credential
 * itself. Every value is sanitized, so a crafted user name or address can neither break the line nor forge another
 * event or pair: the quoted user value keeps no control character, quote, backslash or line separator, and an
 * unquoted value, such as the address, additionally keeps no whitespace, Unicode space or {@code =}. A value
 * longer than 256 characters is cut there and marked with {@code ...}, so a single request cannot write an
 * unbounded line.
 *
 * <p>The {@code ip} value is the remote address the servlet container reports for the connection. Behind a reverse
 * proxy it is the proxy's address, unless the container itself is configured to take the client address from a
 * forwarded header, as Tomcat's {@code RemoteIpValve} or Jetty's {@code ForwardedRequestCustomizer} do. The
 * {@code ForwardedHeaderFilter} declared in {@code web.xml} rewrites only the scheme, host, port and context prefix
 * of a request, never its remote address.
 *
 * <p>Writing an event never fails its caller: a problem while building a line is reported with a fixed
 * message and swallowed, so auditing cannot break a login, a token request or an ACL transaction. The class is
 * stateless and thread-safe.
 */
public final class SecurityAuditLog {

    /** The name of the logger every audit line is written to. */
    public static final String LOGGER_NAME = "org.openl.security.audit";

    private static final Logger LOG = LoggerFactory.getLogger(LOGGER_NAME);

    private static final String AUTH_SUCCESS = "auth.success";
    private static final String AUTH_FAILURE = "auth.failure";
    private static final String AUTH_LOCKOUT = "auth.lockout";
    private static final String PAT_CREATE = "pat.create";
    private static final String PAT_REVOKE = "pat.revoke";
    private static final String ACL_CHANGE = "acl.change";

    private static final String SUCCESS = "success";
    private static final String FAILURE = "failure";
    private static final String LOCKED = "locked";

    /** The method written for an authentication by a personal access token. */
    private static final String PAT_METHOD = "pat";

    /** The user of an ACL change made without an authentication, such as a grant made at start-up. */
    private static final String SYSTEM_USER = "system";

    /** Written in place of a value that is missing or empty. */
    private static final String NONE = "-";

    /** Written in place of every character that could break a line or its quoting. */
    private static final char REPLACEMENT = '_';

    /**
     * The characters, besides the ISO control characters, that {@link #clean(String)} replaces: the quote and
     * the backslash, which would break the quoting of a value, and the Unicode line and paragraph separators,
     * which some log viewers render as a line break.
     */
    private static final String UNSAFE_CHARACTERS = "\"" + "\\" + "\u2028" + "\u2029";

    /** The number of characters of a value that is written; a longer value is cut there and marked. */
    private static final int MAX_VALUE_LENGTH = 256;

    /** Appended to a value that was cut at {@link #MAX_VALUE_LENGTH} characters. */
    private static final String TRUNCATION_MARKER = "...";

    private SecurityAuditLog() {
    }

    /**
     * Records a successful authentication through the authentication manager.
     *
     * @param attempt the authentication that was presented; only its class name and remote address are read
     * @param result  the authenticated result; only its name and remote address are read
     */
    public static void authSuccess(@Nullable Authentication attempt, @Nullable Authentication result) {
        try {
            if (!enabled(false)) {
                return;
            }
            var user = result == null ? null : result.getName();
            var line = line(AUTH_SUCCESS, SUCCESS, user, address(attempt, result));
            write(false, pair(line, "method", method(attempt)).toString());
        } catch (RuntimeException e) {
            writeFailed(AUTH_SUCCESS, e);
        }
    }

    /**
     * Records a failed authentication through the authentication manager.
     *
     * @param attempt the authentication that was rejected; its name is read only for a user name and password
     *                attempt
     */
    public static void authFailure(@Nullable Authentication attempt) {
        rejectedAttempt(AUTH_FAILURE, FAILURE, attempt);
    }

    /**
     * Records that an account has just been locked after repeated failed logins.
     *
     * @param attempt the failed authentication that engaged the lock; its name is read only for a user name and
     *                password attempt
     */
    public static void lockout(@Nullable Authentication attempt) {
        rejectedAttempt(AUTH_LOCKOUT, LOCKED, attempt);
    }

    /**
     * Records a successful authentication by a personal access token.
     *
     * @param request  the request that presented the token
     * @param user     the user the token belongs to
     * @param publicId the public identifier of the token, never the token itself
     */
    public static void authSuccess(@Nullable HttpServletRequest request,
                                   @Nullable String user,
                                   @Nullable String publicId) {
        try {
            if (!enabled(false)) {
                return;
            }
            var line = line(AUTH_SUCCESS, SUCCESS, user, remoteAddress(request));
            write(false, pair(pair(line, "method", PAT_METHOD), "pat", publicId).toString());
        } catch (RuntimeException e) {
            writeFailed(AUTH_SUCCESS, e);
        }
    }

    /**
     * Records a rejected personal access token. The user is always written as {@code -}.
     *
     * @param request        the request that presented the token
     * @param publicIdOrNull the public identifier of a token that parsed but was not accepted, or {@code null}
     *                       when the token could not be parsed
     */
    public static void authFailure(@Nullable HttpServletRequest request, @Nullable String publicIdOrNull) {
        try {
            if (!enabled(true)) {
                return;
            }
            var line = pair(line(AUTH_FAILURE, FAILURE, null, remoteAddress(request)), "method", PAT_METHOD);
            if (publicIdOrNull != null) {
                pair(line, "pat", publicIdOrNull);
            }
            write(true, line.toString());
        } catch (RuntimeException e) {
            writeFailed(AUTH_FAILURE, e);
        }
    }

    /**
     * Records the creation of a personal access token by the current user.
     *
     * @param publicId the public identifier of the new token, never the token itself
     */
    public static void patCreate(@Nullable String publicId) {
        tokenLifecycle(PAT_CREATE, publicId);
    }

    /**
     * Records the revocation of a personal access token by the current user.
     *
     * @param publicId the public identifier of the revoked token
     */
    public static void patRevoke(@Nullable String publicId) {
        tokenLifecycle(PAT_REVOKE, publicId);
    }

    /**
     * Records one completed ACL change: every mutation of one transaction, or one mutation made outside a
     * transaction. The user is the current user, or {@code system} when there is no authentication.
     *
     * @param outcome     {@code success} when the change was committed; any other value is written at WARN
     * @param changes     the number of mutations
     * @param kinds       the names of the mutators that ran
     * @param objectTypes the simple class names of the object identity types involved, never the identifiers
     */
    public static void aclChange(@Nullable String outcome,
                                 int changes,
                                 @Nullable SortedSet<String> kinds,
                                 @Nullable SortedSet<String> objectTypes) {
        try {
            var warn = !SUCCESS.equals(outcome);
            if (!enabled(warn)) {
                return;
            }
            var authentication = SecurityContextHolder.getContext().getAuthentication();
            var line = line(ACL_CHANGE, outcome, userOf(authentication, SYSTEM_USER), address(authentication))
                    .append(" changes=").append(changes)
                    .append(" kinds=").append(join(kinds))
                    .append(" objectTypes=").append(join(objectTypes));
            write(warn, line.toString());
        } catch (RuntimeException e) {
            writeFailed(ACL_CHANGE, e);
        }
    }

    /** Writes a failed or locked authentication attempt. */
    private static void rejectedAttempt(String event, String outcome, @Nullable Authentication attempt) {
        try {
            if (!enabled(true)) {
                return;
            }
            // Only a user name and password attempt is named: the name of any other attempt, such as a bearer,
            // SAML or token attempt, can be the credential itself.
            var user = attempt instanceof UsernamePasswordAuthenticationToken ? attempt.getName() : null;
            var line = line(event, outcome, user, address(attempt));
            write(true, pair(line, "method", method(attempt)).toString());
        } catch (RuntimeException e) {
            writeFailed(event, e);
        }
    }

    /** Writes the creation or revocation of a personal access token by the current user. */
    private static void tokenLifecycle(String event, @Nullable String publicId) {
        try {
            if (!enabled(false)) {
                return;
            }
            var authentication = SecurityContextHolder.getContext().getAuthentication();
            var line = line(event, SUCCESS, userOf(authentication, NONE), address(authentication));
            write(false, pair(line, "pat", publicId).toString());
        } catch (RuntimeException e) {
            writeFailed(event, e);
        }
    }

    /** Starts a line with the pairs every event carries, each value sanitized. */
    private static StringBuilder line(String event,
                                      @Nullable String outcome,
                                      @Nullable String user,
                                      @Nullable String ip) {
        // V11: only the user value is quoted; the outcome and the address are unquoted, so they are kept one token.
        return new StringBuilder(160).append("event=")
                .append(event)
                .append(" outcome=")
                .append(cleanToken(outcome))
                .append(" user=\"")
                .append(clean(user))
                .append("\" ip=")
                .append(cleanToken(ip));
    }

    /** Appends one sanitized {@code key=value} pair, whose unquoted value is kept one token. */
    private static StringBuilder pair(StringBuilder line, String key, @Nullable String value) {
        return line.append(' ').append(key).append('=').append(cleanToken(value));
    }

    /** The simple class name of an authentication attempt, which is code-defined and never a credential. */
    private static @Nullable String method(@Nullable Authentication attempt) {
        return attempt == null ? null : attempt.getClass().getSimpleName();
    }

    /** The name of the current authentication, or the given value when there is none. */
    private static @Nullable String userOf(@Nullable Authentication authentication, String whenAbsent) {
        return authentication == null ? whenAbsent : authentication.getName();
    }

    /** The remote address of an authentication, as {@link #address(Authentication, Authentication)} finds it. */
    private static @Nullable String address(@Nullable Authentication authentication) {
        return address(authentication, null);
    }

    /**
     * The remote address from the details of the first authentication, then from those of the second, then that
     * of the request bound to the current thread, which {@code RequestContextListener} populates for every
     * request.
     *
     * @return the address, or {@code null} when none is known
     */
    private static @Nullable String address(@Nullable Authentication first, @Nullable Authentication second) {
        var address = detailsAddress(first);
        if (address == null) {
            address = detailsAddress(second);
        }
        if (address == null
                && RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            address = attributes.getRequest().getRemoteAddr();
        }
        return address;
    }

    /** The remote address recorded in the web details of an authentication; nothing else of them is read. */
    private static @Nullable String detailsAddress(@Nullable Authentication authentication) {
        return authentication != null && authentication.getDetails() instanceof WebAuthenticationDetails details
                ? details.getRemoteAddress()
                : null;
    }

    private static @Nullable String remoteAddress(@Nullable HttpServletRequest request) {
        return request == null ? null : request.getRemoteAddr();
    }

    /** Joins the sanitized elements of a set with commas, in the set's own order, as one unquoted token. */
    private static String join(@Nullable SortedSet<String> values) {
        if (values == null || values.isEmpty()) {
            return NONE;
        }
        var joined = new StringBuilder();
        for (var value : values) {
            if (!joined.isEmpty()) {
                joined.append(',');
            }
            joined.append(cleanToken(value));
        }
        return joined.toString();
    }

    /**
     * Makes the quoted user value safe for one audit line: every ISO control character (including CR, LF and TAB),
     * the Unicode line and paragraph separators, the quote and the backslash are replaced with {@code _}. Spaces
     * and {@code =} are kept, because they cannot leave the quotes. A long value is cut as
     * {@link #sanitize(String, boolean)} describes.
     *
     * @return the sanitized value, or {@code -} when the value is {@code null} or empty
     */
    private static String clean(@Nullable String value) {
        return sanitize(value, false);
    }

    /**
     * Makes an unquoted value, such as the outcome, the address or the value of a detail pair, safe for one audit
     * line: besides the characters {@link #clean(String)} replaces, every whitespace or space character and every
     * {@code =} is replaced with {@code _}, so the value stays one token and cannot add a pair to the line. A long
     * value is cut as {@link #sanitize(String, boolean)} describes.
     *
     * @return the sanitized value, or {@code -} when the value is {@code null} or empty
     */
    private static String cleanToken(@Nullable String value) {
        return sanitize(value, true);
    }

    /**
     * Sanitizes a value as {@link #clean(String)} does, or as {@link #cleanToken(String)} does for a token. A value
     * longer than {@link #MAX_VALUE_LENGTH} characters is cut there, one character earlier when the cut would split
     * a surrogate pair, and {@link #TRUNCATION_MARKER} is appended.
     */
    private static String sanitize(@Nullable String value, boolean token) {
        if (value == null || value.isEmpty()) {
            return NONE;
        }
        // V11: the cut keeps a value that a request supplies, such as a user name, from making a line unbounded.
        var cut = value.length() > MAX_VALUE_LENGTH;
        var kept = cut ? MAX_VALUE_LENGTH : value.length();
        if (cut && Character.isHighSurrogate(value.charAt(kept - 1))) {
            kept--;
        }
        var cleaned = new StringBuilder(kept + (cut ? TRUNCATION_MARKER.length() : 0));
        for (var i = 0; i < kept; i++) {
            var c = value.charAt(i);
            cleaned.append(isUnsafe(c, token) ? REPLACEMENT : c);
        }
        if (cut) {
            cleaned.append(TRUNCATION_MARKER);
        }
        return cleaned.toString();
    }

    /** Whether a character must be replaced in a quoted value, or, when {@code token} is set, in an unquoted one. */
    private static boolean isUnsafe(char c, boolean token) {
        return Character.isISOControl(c)
                || UNSAFE_CHARACTERS.indexOf(c) >= 0
                || (token && (Character.isWhitespace(c) || Character.isSpaceChar(c) || c == '='));
    }

    /**
     * Whether the level an event is written at, WARN or INFO, is enabled. Each event checks it before it reads any
     * value or builds its line.
     */
    private static boolean enabled(boolean warn) {
        return warn ? LOG.isWarnEnabled() : LOG.isInfoEnabled();
    }

    /** Writes one finished line, at WARN or at INFO. */
    private static void write(boolean warn, String line) {
        if (warn) {
            LOG.warn("{}", line);
        } else {
            LOG.info("{}", line);
        }
    }

    /**
     * Reports that an event could not be written. Only the event name and the exception class are logged: an
     * exception message could quote the values the event was about.
     */
    private static void writeFailed(String event, RuntimeException e) {
        LOG.warn("Failed to write the security audit event '{}' ({}).", event, e.getClass().getSimpleName());
    }
}

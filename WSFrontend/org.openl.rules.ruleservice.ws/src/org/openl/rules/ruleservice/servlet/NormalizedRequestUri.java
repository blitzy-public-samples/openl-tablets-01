package org.openl.rules.ruleservice.servlet;

import org.jspecify.annotations.Nullable;

/**
 * Tells whether a request URI holds no dot segment.
 * <p>
 * The servlet container resolves {@code .} and {@code ..} segments before it computes the path info, while CXF routes
 * the request URI as it was sent. For a URI with a dot segment, the two paths can differ:
 * {@code /admin/deploy/../info/a} resolves to the path info {@code /admin/info/a} but is routed to the
 * {@code /admin/deploy} resource. A decision that exempts a request from authorization by its resolved path is
 * therefore safe only for a request URI without dot segments.
 *
 * @see RuleServicesFilter
 */
public final class NormalizedRequestUri {

    private static final String ENCODED_DOT = "%2e";

    private NormalizedRequestUri() {
    }

    /**
     * Checks that no {@code /}-separated segment of a request URI is a dot segment. A segment is a dot segment when,
     * without its {@code ;} path parameters and with each {@code %2e} or {@code %2E} read as {@code .}, it equals
     * {@code .} or {@code ..}.
     *
     * @param requestUri the request URI as sent, without the query string
     * @return {@code true} if the URI holds no dot segment; {@code false} if it holds one or is {@code null}
     */
    public static boolean isNormalized(@Nullable String requestUri) {
        if (requestUri == null) {
            return false;
        }
        int start = 0;
        while (true) {
            int end = requestUri.indexOf('/', start);
            var segment = end < 0 ? requestUri.substring(start) : requestUri.substring(start, end);
            if (isDotSegment(segment)) {
                return false;
            }
            if (end < 0) {
                return true;
            }
            start = end + 1;
        }
    }

    private static boolean isDotSegment(String segment) {
        int parameters = segment.indexOf(';');
        var name = parameters < 0 ? segment : segment.substring(0, parameters);
        int dots = 0;
        int i = 0;
        while (i < name.length()) {
            if (name.charAt(i) == '.') {
                i++;
            } else if (name.regionMatches(true, i, ENCODED_DOT, 0, ENCODED_DOT.length())) {
                i += ENCODED_DOT.length();
            } else {
                return false;
            }
            dots++;
        }
        return dots == 1 || dots == 2;
    }
}

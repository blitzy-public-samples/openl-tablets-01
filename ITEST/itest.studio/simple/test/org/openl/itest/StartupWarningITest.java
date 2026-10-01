package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.StdOut;

import org.openl.itest.core.JettyServer;

/**
 * OpenL Studio runs in single-user mode by default, without a login and with ADMIN for every visitor, so its startup
 * log must say so exactly once to warn anyone who exposes such an instance on a shared network.
 *
 * <p>The suite sets no {@code user.mode}, so the default {@code single} applies. Both captured streams are searched:
 * the webapp's slf4j loggers print to {@code System.err} and its log4j-API events to {@code System.out}.
 */
// V14: single mode must warn at startup that it runs without authentication.
class StartupWarningITest {

    private static final String EXPECTED = "user.mode=single: OpenL Studio runs without authentication and grants"
            + " ADMIN to every visitor; use it only on an isolated workstation.";

    @Test
    @StdIo
    void singleModeWarnsAtStartup(StdOut out, StdErr err) throws Exception {
        try (var client = JettyServer.get().start()) {
            var matches = (out.capturedString() + "\n" + err.capturedString()).lines()
                    .filter(line -> line.contains("WARN") && line.contains("user.mode=single"))
                    .toList();
            assertEquals(1, matches.size(), () -> "Expected exactly one single-mode startup WARN, found: " + matches);
            assertTrue(matches.getFirst().contains(EXPECTED), () -> "Unexpected WARN text: " + matches.getFirst());
        }
    }
}

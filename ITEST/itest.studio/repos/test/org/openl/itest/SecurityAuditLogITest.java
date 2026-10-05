package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.StdOut;

import org.openl.itest.core.JettyServer;

/**
 * V11: proves end to end that OpenL Studio in {@code user.mode=multi} writes exactly one line per security event to
 * the logger {@code org.openl.security.audit}, and that no line leaks a secret.
 *
 * <p>The {@code repos} server is started inside the test method, so the captured standard streams hold the whole
 * run, start-up included. The test creates the administrator's personal access token in Java, then runs each
 * first-level folder of {@code test-resources-audit} with its own {@code client.test} call.
 *
 * <p><b>Slices.</b> Before each step the test takes a mark: the number of characters captured so far on standard
 * output and on standard error. The audit lines between two consecutive marks form the slice of one step, so every
 * event is attributed to the step that caused it:
 * <ol>
 * <li>the token creation, which must write one {@code pat.create} line;</li>
 * <li>one slice per fixture folder, from {@code 010-setup} to {@code 120-group-delete}.</li>
 * </ol>
 * After each step the test polls the open slice until the minimal lines of that step appear, and fails fast when
 * they do not, as on a build without V11. Once the server has stopped, exact counts are checked on the fixed slices,
 * and every audit line must carry {@code user=}, {@code ip=} and an {@code outcome=} its event is written with.
 * Whatever failed before, the whole captured output and the saved responses are then checked for leaks: no line
 * holds a generated secret, and no line names the credential-looking project or group.
 *
 * <p><b>Streams.</b> The webapp's slf4j loggers, the audit logger included, print through the test JVM's
 * slf4j-simple to standard error, and its log4j-API loggers print through {@code log4j2-test.properties} to standard
 * output. Both streams are read and their audit lines are combined without removing duplicates, because each event
 * must reach exactly one of them.
 *
 * <p><b>Fixtures.</b> The {@code repos} server runs {@code user.mode=multi}, which the fixtures must respect:
 * <ul>
 * <li>groups have no management API in this mode, so {@code /rest/admin/management/groups} answers 404; a group is
 * created, and its SID removed, only by the bulk ACL overwrite {@code POST /rest/acls};</li>
 * <li>{@code DELETE /rest/users/<name>} writes an {@code acl.change} line only when the user's SID exists, whether
 * or not the SID still holds an entry, and a bulk overwrite removes the SID of every user it does not list;</li>
 * <li>an HTTP Basic request opens no session, so the session a valid token rides in {@code 040-pat-use} is opened by
 * a form login.</li>
 * </ul>
 *
 * <p><b>Secrets.</b> Every credential is generated at runtime and reaches the fixtures only through
 * {@code localEnv}; the token is created through {@code postForObject}, which compares no body. Failure messages name
 * the step, the event or the variable, never a value, a line or a response body.
 */
class SecurityAuditLogITest {

    /** The logger of the audit trail; it must equal {@code SecurityAuditLog.LOGGER_NAME} of OpenL Studio. */
    private static final String LOGGER_NAME = "org.openl.security.audit";

    /** The fixture root, relative to the module directory the tests run in. */
    private static final String FIXTURES = "test-resources-audit";

    /** The first-level fixture folders, in the order they run; each one is one slice. */
    private static final List<String> SEGMENTS = List.of(
            "010-setup",
            "020-login",
            "030-lockout",
            "040-pat-use",
            "050-pat-revoke",
            "060-project-create",
            "070-project-acl-put",
            "080-project-acl-delete",
            "090-bulk-acl",
            "100-project-delete",
            "110-user-delete",
            "120-group-delete");

    /** The single bulk ACL request; the number of entries it grants bounds the changes of its audit line. */
    private static final String BULK_REQUEST = FIXTURES + "/090-bulk-acl/020-overwrite-acls.req";

    /**
     * The mutator names one of which the {@code acl.change} line of each ACL segment must list. The bulk segment is
     * checked separately, by its exact line count.
     */
    private static final Map<String, Set<String>> ACL_KINDS = Map.of(
            "060-project-create", Set.of("createAcl", "updateAcl"),
            "070-project-acl-put", Set.of("updateAcl", "createAcl"),
            "080-project-acl-delete", Set.of("updateAcl", "deleteAcl"),
            "100-project-delete", Set.of("deleteAcl"),
            "110-user-delete", Set.of("deleteSid"),
            "120-group-delete", Set.of("deleteSid"));

    private static final String AUTH_SUCCESS = "auth.success";
    private static final String AUTH_FAILURE = "auth.failure";
    private static final String AUTH_LOCKOUT = "auth.lockout";
    private static final String PAT_CREATE = "pat.create";
    private static final String PAT_REVOKE = "pat.revoke";
    private static final String ACL_CHANGE = "acl.change";
    private static final String SUCCESS = "success";
    private static final String FAILURE = "failure"; // V11: the outcomes SecurityAuditLog writes besides success
    private static final String LOCKED = "locked";
    private static final String PAT_METHOD = "pat";
    /** The user value of a rejected token, whose owner is never logged. */
    private static final String NO_USER = "-";

    /** V11: the outcomes each event is written with; any other event is unknown. */
    private static final Map<String, Set<String>> OUTCOMES = Map.of(
            AUTH_SUCCESS, Set.of(SUCCESS),
            AUTH_FAILURE, Set.of(FAILURE),
            AUTH_LOCKOUT, Set.of(LOCKED),
            PAT_CREATE, Set.of(SUCCESS),
            PAT_REVOKE, Set.of(SUCCESS),
            ACL_CHANGE, Set.of(SUCCESS, FAILURE));

    /** V11: the authentication events, counted per slice apart from the administrator's setup logins. */
    private static final Set<String> AUTH_EVENTS = Set.of(AUTH_SUCCESS, AUTH_FAILURE, AUTH_LOCKOUT);

    /**
     * V11: the exact number of counted authentication events per segment: two attempts each of the form and the
     * Basic user; five failures and the lockout; two valid-token successes and one rejected token. Any other segment,
     * and the token creation, writes none.
     */
    private static final Map<String, Integer> AUTH_TOTALS = Map.of(
            "020-login", 4,
            "030-lockout", 6,
            "040-pat-use", 3);

    private static final String FORM_USER = "audit_form";
    private static final String BASIC_USER = "audit_basic";
    private static final String LOCK_USER = "audit_lock";

    /** The prefix of a token value as {@code PatToken.parse} accepts it. */
    private static final String PAT_PREFIX = "openl_pat_";
    /** The prefix of an HTTP Basic header value; only the encoded part after it is searched for. */
    private static final String BASIC_PREFIX = "Basic ";

    // Every key is matched only at the start of a token, so a value such as method=pat never reads as a key.
    private static final Pattern EVENT = Pattern.compile("(?<!\\S)event=(\\S+)");
    private static final Pattern OUTCOME = Pattern.compile("(?<!\\S)outcome=(\\S+)");
    private static final Pattern USER = Pattern.compile("(?<!\\S)user=\"([^\"]*)\"");
    private static final Pattern IP = Pattern.compile("(?<!\\S)ip=(\\S+)");
    private static final Pattern METHOD = Pattern.compile("(?<!\\S)method=(\\S+)");
    private static final Pattern PAT = Pattern.compile("(?<!\\S)pat=(\\S+)");
    private static final Pattern CHANGES = Pattern.compile("(?<!\\S)changes=(\\d+)");
    // SecurityAuditLog writes the mutator names as one token, joined with commas.
    private static final Pattern KINDS = Pattern.compile("(?<!\\S)kinds=(\\S+)");

    private static final Pattern LINE_BREAK = Pattern.compile("\\R");
    /** The empty line that ends the request line and the headers of a request file. */
    private static final Pattern HEADER_END = Pattern.compile("\\r?\\n\\r?\\n");

    private static final long POLL_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(20);
    private static final long POLL_INTERVAL_MILLIS = 100;

    @Test
    @StdIo
    void audit(StdOut out, StdErr err) throws Exception {
        assertSegmentFolders();
        int bulkMinChanges = bulkMinChanges();

        // The secret set: every generated credential, searched for in the captured output and in saved responses.
        // V11: the derived ADMIN_AUTH_TOCKEN is part of it, searched for by its Base64 part only. ADMIN_PASSWORD is
        // not, because it equals the administrator name, which the audit lines must carry.
        Map<String, String> generated = new HashMap<>();
        // Generated names that look like credentials; they are not secrets, but no log line may name them.
        Map<String, String> lookalikes = new LinkedHashMap<>();
        List<Mark> marks = new ArrayList<>();
        String patPublicId;
        String invalidPublicId;
        String adminName; // V11: the administrator, whose setup logins are separated from the counted events
        Throwable failure = null;
        try {
            try (var client = JettyServer.get().start()) {
                WebStudioTest.putAdminCredentials(client, generated); // V11: registers ADMIN_AUTH_TOCKEN for the scans
                // V11: the messages name only the variable, never its value
                var admin = Objects.requireNonNull(client.localEnv.get("ADMIN_AUTH_TOCKEN"), "ADMIN_AUTH_TOCKEN");
                // V11: AdminUsers seeds each administrator with its name as the password, so ADMIN_PASSWORD is the name
                adminName = Objects.requireNonNull(client.localEnv.get("ADMIN_PASSWORD"), "ADMIN_PASSWORD");
                putUserCredentials(client.localEnv, generated);
                putLookalikeNames(client.localEnv, lookalikes);

                // The token is created in Java only, and its response is never compared or printed.
                marks.add(mark(out, err));
                JsonNode created = client.postForObject("/rest/users/personal-access-tokens",
                        Map.of("name", "audit-pat"),
                        JsonNode.class,
                        201,
                        "Authorization",
                        admin);
                String patToken = text(created, "token");
                // V11: the token joins the secret set before the public id is required
                generated.put("PAT_TOKEN", patToken);
                generated.put("PAT_SECRET", patToken.substring(patToken.indexOf('.') + 1));
                patPublicId = text(created, "publicId");
                client.localEnv.put("PAT_TOKEN", patToken);
                client.localEnv.put("PAT_PUBLIC_ID", patPublicId);
                invalidPublicId = putInvalidToken(client.localEnv, generated, patPublicId);
                awaitLines("the PAT creation", out, err, marks.getLast(),
                        lines -> count(lines, event(PAT_CREATE)) >= 1);

                for (String segment : SEGMENTS) {
                    marks.add(mark(out, err));
                    client.test(FIXTURES + "/" + segment);
                    awaitLines("segment " + segment, out, err, marks.getLast(),
                            minimum(segment, patPublicId, invalidPublicId));
                }
                marks.add(mark(out, err));
            }
            // The server has stopped, so the captured output is complete.
            // V11: verify checks the events only; the leak checks run in finally
            verify(new Run(marks, patPublicId, invalidPublicId, bulkMinChanges, adminName),
                    out.capturedString(),
                    err.capturedString());
        } catch (Throwable t) {
            failure = t;
            throw t;
        } finally {
            // A scan error is suppressed onto the test failure instead of replacing it.
            // V11: both leak checks run here, whatever failed before: extraction, fixtures, polling, shutdown or verify
            try {
                assertNoLeaks(out.capturedString(), err.capturedString(), generated, lookalikes);
            } catch (AssertionError | RuntimeException scan) {
                if (failure != null) {
                    failure.addSuppressed(scan);
                } else {
                    throw scan;
                }
            }
        }
    }

    /** Fails, naming only folder names, unless the fixture folders are exactly the segments this test asserts. */
    private static void assertSegmentFolders() throws IOException {
        List<String> folders;
        try (Stream<Path> children = Files.list(Path.of(FIXTURES))) {
            folders = children.filter(Files::isDirectory).map(path -> path.getFileName().toString()).sorted().toList();
        }
        assertEquals(SEGMENTS, folders, "First-level folders of " + FIXTURES);
    }

    /**
     * Counts the access control entries the bulk request grants: the sum of the sizes of {@code resources[*].aces} in
     * its JSON body, which follows the first empty line.
     */
    private static int bulkMinChanges() throws IOException {
        String request = Files.readString(Path.of(BULK_REQUEST), StandardCharsets.UTF_8);
        Matcher headerEnd = HEADER_END.matcher(request);
        if (!headerEnd.find()) {
            fail(BULK_REQUEST + " has no body");
        }
        JsonNode body = new ObjectMapper().readTree(request.substring(headerEnd.end()));
        int aces = 0;
        for (JsonNode resource : body.path("resources")) {
            aces += resource.path("aces").size();
        }
        if (aces == 0) {
            fail(BULK_REQUEST + " grants no access control entry");
        }
        return aces;
    }

    /** Generates the passwords and HTTP Basic values of the audit users. */
    private static void putUserCredentials(Map<String, String> env, Map<String, String> generated) {
        String formPassword = WebStudioTest.randomPassword(16);
        String formWrongPassword = differentPassword(formPassword);
        String basicPassword = WebStudioTest.randomPassword(16);
        String basicWrongPassword = differentPassword(basicPassword);
        String lockPassword = WebStudioTest.randomPassword(16);
        String lockWrongPassword = differentPassword(lockPassword);

        Map<String, String> values = new HashMap<>();
        values.put("AUDIT_FORM_PASSWORD", formPassword);
        values.put("AUDIT_FORM_WRONG_PASSWORD", formWrongPassword);
        values.put("AUDIT_BASIC_PASSWORD", basicPassword);
        values.put("AUDIT_BASIC_BASIC", WebStudioTest.basic(BASIC_USER, basicPassword));
        values.put("AUDIT_BASIC_WRONG_BASIC", WebStudioTest.basic(BASIC_USER, basicWrongPassword));
        values.put("AUDIT_LOCK_PASSWORD", lockPassword);
        values.put("AUDIT_LOCK_WRONG_BASIC", WebStudioTest.basic(LOCK_USER, lockWrongPassword));
        values.put("AUDIT_DELETE_PASSWORD", WebStudioTest.randomPassword(16));
        env.putAll(values);
        generated.putAll(values);
        // The raw passwords behind the wrong Basic values are searched for only; no fixture reads them.
        generated.put("AUDIT_BASIC_WRONG_PASSWORD", basicWrongPassword);
        generated.put("AUDIT_LOCK_WRONG_PASSWORD", lockWrongPassword);
    }

    /** A random password that differs from the given one, so a wrong-password attempt is always wrong. */
    private static String differentPassword(String password) {
        String other;
        do {
            other = WebStudioTest.randomPassword(16);
        } while (other.equals(password));
        return other;
    }

    /**
     * Generates a credential-looking project name, its project id and a credential-looking group name.
     *
     * <p>The fixtures insert these values into URLs verbatim, without quoting, so they hold nothing but letters,
     * digits and Base64 padding. The project id is the standard Base64 of {@code design:<name>}; a name is drawn
     * again until that id holds neither {@code +} nor {@code /}, so the standard and the URL-safe alphabet give the
     * same text.
     */
    private static void putLookalikeNames(Map<String, String> env, Map<String, String> lookalikes) {
        String project;
        String projectId;
        do {
            project = "Pw" + WebStudioTest.randomPassword(20);
            projectId = Base64.getEncoder().encodeToString(("design:" + project).getBytes(StandardCharsets.UTF_8));
        } while (projectId.indexOf('+') >= 0 || projectId.indexOf('/') >= 0);
        lookalikes.put("SECRET_LOOKING_PROJECT", project);
        lookalikes.put("SECRET_LOOKING_PROJECT_ID", projectId);
        lookalikes.put("SECRET_LOOKING_GROUP", "Pw" + WebStudioTest.randomPassword(20));
        env.putAll(lookalikes);
    }

    /**
     * Generates a token that {@code PatToken.parse} accepts, Base62 parts of the right lengths, but that matches no
     * stored token.
     *
     * @return the public id of the token, which is not secret and is logged for its failed authentication
     */
    private static String putInvalidToken(Map<String, String> env, Map<String, String> generated, String patPublicId) {
        String publicId;
        do {
            publicId = WebStudioTest.randomPassword(16);
        } while (publicId.equals(patPublicId));
        String secret = WebStudioTest.randomPassword(32);
        String token = PAT_PREFIX + publicId + "." + secret;
        env.put("INVALID_PAT_TOKEN", token);
        generated.put("INVALID_PAT_TOKEN", token);
        generated.put("INVALID_PAT_SECRET", secret);
        return publicId;
    }

    /** The non-blank text of a field of the token creation response; a failure names only the field. */
    private static String text(JsonNode response, String field) {
        JsonNode value = response == null ? null : response.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) {
            fail("The created token response has no " + field);
        }
        return value.asText();
    }

    /** The lines a segment must have written before the next one starts; the poll waits for them. */
    private static Predicate<List<AuditLine>> minimum(String segment, String patPublicId, String invalidPublicId) {
        return switch (segment) {
            // The setup segment only writes administrator lines, which are not counted.
            case "010-setup" -> lines -> true;
            case "020-login" -> lines -> count(lines, user(FORM_USER)) >= 2 && count(lines, user(BASIC_USER)) >= 2;
            case "030-lockout" -> lines -> count(lines, event(AUTH_FAILURE).and(user(LOCK_USER))) >= 5
                    && count(lines, event(AUTH_LOCKOUT)) >= 1;
            case "040-pat-use" -> lines -> count(lines, patSuccess(patPublicId)) >= 2
                    && count(lines, event(AUTH_FAILURE).and(pat(invalidPublicId))) >= 1;
            case "050-pat-revoke" -> lines -> count(lines, event(PAT_REVOKE)) >= 1;
            case "060-project-create", "070-project-acl-put", "080-project-acl-delete", "090-bulk-acl",
                 "100-project-delete", "110-user-delete", "120-group-delete" ->
                    lines -> count(lines, event(ACL_CHANGE)) >= 1;
            default -> throw new IllegalArgumentException("Unknown segment " + segment);
        };
    }

    /**
     * Polls the open slice from the mark every {@value #POLL_INTERVAL_MILLIS} ms until it holds the minimal lines,
     * and fails, naming only the step, when they do not appear within 20 seconds.
     */
    private static void awaitLines(String step,
                                   StdOut out,
                                   StdErr err,
                                   Mark from,
                                   Predicate<List<AuditLine>> minimum) throws InterruptedException {
        long deadline = System.nanoTime() + POLL_TIMEOUT_NANOS;
        while (!minimum.test(parse(slice(out.capturedString(), err.capturedString(), from, null)))) {
            if (System.nanoTime() - deadline >= 0) {
                fail("audit lines missing after " + step);
            }
            Thread.sleep(POLL_INTERVAL_MILLIS);
        }
    }

    /** Checks the fixed slices and every audit line of the finished run; the leak checks are made by the caller. */
    private static void verify(Run run, String outText, String errText) { // V11: the leak inventories moved out
        List<String> allLines = new ArrayList<>(auditLines(outText));
        allLines.addAll(auditLines(errText));
        var parsed = parse(allLines); // V11: parsed once, for the line checks and the whole-run counts
        for (AuditLine line : parsed) {
            // V11: the outcome must be one its event is written with. An unknown event is not named: it is any text.
            String event = line.event();
            Set<String> outcomes = event == null ? Set.of() : OUTCOMES.getOrDefault(event, Set.of());
            String named = outcomes.isEmpty() ? "an unknown event" : "event " + event; // V11: known names only
            assertTrue(line.user() != null && line.ip() != null && line.outcome() != null,
                    () -> "An audit line of " + named + " lacks user=, ip= or outcome=");
            assertTrue(!outcomes.isEmpty(), "An audit line of an unknown event");
            assertTrue(outcomes.contains(line.outcome()),
                    () -> "An audit line of event " + event + " has an outcome other than " + new TreeSet<>(outcomes));
        }
        // V11: no success for the invalid token and no failure for the valid one, anywhere in the run
        assertEquals(0, count(parsed, event(AUTH_SUCCESS).and(pat(run.invalidPublicId()))),
                "The run: auth.success with the public id of INVALID_PAT_TOKEN");
        assertEquals(0, count(parsed, event(AUTH_FAILURE).and(pat(run.patPublicId()))),
                "The run: auth.failure with PAT_PUBLIC_ID");

        List<List<AuditLine>> slices = new ArrayList<>();
        for (int i = 0; i + 1 < run.marks().size(); i++) {
            slices.add(parse(slice(outText, errText, run.marks().get(i), run.marks().get(i + 1))));
        }
        assertEquals(SEGMENTS.size() + 1, slices.size(), "Slices of the run");

        // V11: exact authentication totals per slice. The administrator's setup logins drive the fixtures and vary in
        // number, so they are separated; its token successes carry method=pat, so they are counted.
        var counted = authEvent().and(setupLogin(run.adminName()).negate());
        for (int i = 0; i < slices.size(); i++) {
            String step = i == 0 ? "PAT creation" : SEGMENTS.get(i - 1);
            long expected = i == 0 ? 0 : AUTH_TOTALS.getOrDefault(step, 0);
            long actual = count(slices.get(i), counted);
            assertEquals(expected,
                    actual,
                    step + ": authentication events other than the administrator's setup logins");
        }

        // The token creation is the first slice; segment i is slice i + 1.
        assertEquals(1, count(slices.getFirst(), event(PAT_CREATE).and(pat(run.patPublicId()))),
                "PAT creation: pat.create lines with PAT_PUBLIC_ID");

        var login = slices.get(1 + SEGMENTS.indexOf("020-login"));
        assertEquals(1,
                count(login, event(AUTH_SUCCESS).and(user(FORM_USER))),
                "020-login: auth.success of " + FORM_USER);
        assertEquals(1,
                count(login, event(AUTH_FAILURE).and(user(FORM_USER))),
                "020-login: auth.failure of " + FORM_USER);
        assertEquals(1,
                count(login, event(AUTH_SUCCESS).and(user(BASIC_USER))),
                "020-login: auth.success of " + BASIC_USER);
        assertEquals(1,
                count(login, event(AUTH_FAILURE).and(user(BASIC_USER))),
                "020-login: auth.failure of " + BASIC_USER);

        // The fifth failure writes the lockout line of the lockout provider and the failure line of its wrapper.
        var lockout = slices.get(1 + SEGMENTS.indexOf("030-lockout"));
        assertEquals(5,
                count(lockout, event(AUTH_FAILURE).and(user(LOCK_USER))),
                "030-lockout: auth.failure of " + LOCK_USER);
        assertEquals(1, count(lockout, event(AUTH_LOCKOUT)), "030-lockout: auth.lockout lines");
        assertEquals(1,
                count(lockout, event(AUTH_LOCKOUT).and(user(LOCK_USER)).and(outcome(LOCKED))), // V11: outcome=locked
                "030-lockout: auth.lockout outcome=locked of " + LOCK_USER);

        // One valid token without a session, one on the administrator's own session, which it does not replace.
        var patUse = slices.get(1 + SEGMENTS.indexOf("040-pat-use"));
        assertEquals(2, count(patUse, patSuccess(run.patPublicId())), "040-pat-use: auth.success with PAT_PUBLIC_ID");
        assertEquals(1,
                count(patUse, event(AUTH_FAILURE).and(user(NO_USER)).and(method(PAT_METHOD)) // V11: method=pat
                        .and(pat(run.invalidPublicId()))),
                "040-pat-use: auth.failure method=pat with the public id of INVALID_PAT_TOKEN");

        var revoke = slices.get(1 + SEGMENTS.indexOf("050-pat-revoke"));
        assertEquals(1,
                count(revoke, event(PAT_REVOKE).and(pat(run.patPublicId()))),
                "050-pat-revoke: pat.revoke with PAT_PUBLIC_ID");

        for (String segment : SEGMENTS) {
            var kinds = ACL_KINDS.get(segment);
            if (kinds == null) {
                continue;
            }
            var slice = slices.get(1 + SEGMENTS.indexOf(segment));
            // Kinds are compared as whole tokens, never as substrings.
            var listsKind = committedAclChange(1).and(line -> line.kinds().stream().anyMatch(kinds::contains));
            assertTrue(count(slice, listsKind) >= 1,
                    () -> segment + ": acl.change outcome=success with changes >= 1 and one of the kinds "
                            + new TreeSet<>(kinds));
        }

        // The bulk overwrite runs in one transaction, so it is one event however many entries it touches.
        var bulk = slices.get(1 + SEGMENTS.indexOf("090-bulk-acl"));
        assertEquals(1, count(bulk, event(ACL_CHANGE)), "090-bulk-acl: acl.change lines");
        assertEquals(1,
                count(bulk, committedAclChange(run.bulkMinChanges())),
                "090-bulk-acl: acl.change outcome=success with changes >= " + run.bulkMinChanges());
    }

    /**
     * V11: runs the captured-output check, then the saved-response scan whatever the first one did. A scan failure is
     * attached to a captured-output failure, which is thrown.
     */
    private static void assertNoLeaks(String outText,
                                      String errText,
                                      Map<String, String> generated,
                                      Map<String, String> lookalikes) {
        try {
            assertNoLeakInOutput(outText, errText, generated, lookalikes);
        } catch (AssertionError | RuntimeException leak) {
            try {
                WebStudioTest.assertNoSecretsSaved(generated);
            } catch (AssertionError | RuntimeException scan) {
                leak.addSuppressed(scan);
            }
            throw leak;
        }
        WebStudioTest.assertNoSecretsSaved(generated);
    }

    /**
     * V11: fails, naming only keys, when a generated secret appears anywhere in the captured output, or when a
     * credential-looking name appears in an audit line or anywhere in the captured output.
     */
    private static void assertNoLeakInOutput(String outText,
                                             String errText,
                                             Map<String, String> generated,
                                             Map<String, String> lookalikes) {
        List<String> allLines = new ArrayList<>(auditLines(outText));
        allLines.addAll(auditLines(errText));

        Set<String> leaked = new TreeSet<>();
        for (var entry : generated.entrySet()) {
            String value = entry.getValue();
            if (value == null || value.isEmpty()) {
                continue;
            }
            String needle = value.startsWith(BASIC_PREFIX) ? value.substring(BASIC_PREFIX.length()) : value;
            if (outText.contains(needle) || errText.contains(needle)) {
                leaked.add(entry.getKey());
            }
        }
        assertTrue(leaked.isEmpty(), () -> "Generated secrets found in the captured output: " + leaked);

        Set<String> namedInAudit = new TreeSet<>();
        Set<String> namedAnywhere = new TreeSet<>();
        for (var entry : lookalikes.entrySet()) {
            String value = entry.getValue();
            if (allLines.stream().anyMatch(line -> line.contains(value))) {
                namedInAudit.add(entry.getKey());
            }
            if (outText.contains(value) || errText.contains(value)) {
                namedAnywhere.add(entry.getKey());
            }
        }
        assertTrue(namedInAudit.isEmpty(), () -> "Credential-looking names found in audit lines: " + namedInAudit);
        assertTrue(namedAnywhere.isEmpty(),
                () -> "Credential-looking names found in the captured output: " + namedAnywhere);
    }

    private static Mark mark(StdOut out, StdErr err) {
        return new Mark(out.capturedString().length(), err.capturedString().length());
    }

    /**
     * The audit lines written from one mark to the next, or to the end of the captured text when {@code to} is
     * {@code null}: the standard output lines first, then the standard error lines.
     */
    private static List<String> slice(String outText, String errText, Mark from, Mark to) {
        int outEnd = to == null ? outText.length() : to.out();
        int errEnd = to == null ? errText.length() : to.err();
        List<String> lines = new ArrayList<>(auditLines(outText.substring(from.out(), outEnd)));
        lines.addAll(auditLines(errText.substring(from.err(), errEnd)));
        return lines;
    }

    /** The lines of the text that the audit logger wrote, recognised by the logger name every line prints. */
    private static List<String> auditLines(String text) {
        return LINE_BREAK.splitAsStream(text).filter(line -> line.contains(LOGGER_NAME)).toList();
    }

    private static List<AuditLine> parse(List<String> lines) {
        return lines.stream().map(AuditLine::parse).toList();
    }

    private static long count(List<AuditLine> lines, Predicate<AuditLine> filter) {
        return lines.stream().filter(filter).count();
    }

    private static Predicate<AuditLine> event(String name) {
        return line -> name.equals(line.event());
    }

    private static Predicate<AuditLine> user(String name) {
        return line -> name.equals(line.user());
    }

    private static Predicate<AuditLine> pat(String publicId) {
        return line -> publicId.equals(line.pat());
    }

    // V11: the method and outcome predicates of the exact outcome and method checks
    private static Predicate<AuditLine> method(String name) {
        return line -> name.equals(line.method());
    }

    private static Predicate<AuditLine> outcome(String name) {
        return line -> name.equals(line.outcome());
    }

    /** V11: an authentication event: a success, a failure or a lockout. */
    private static Predicate<AuditLine> authEvent() {
        return line -> line.event() != null && AUTH_EVENTS.contains(line.event());
    }

    /** V11: a setup login: a success of the administrator by any method but a token. */
    private static Predicate<AuditLine> setupLogin(String adminName) {
        return event(AUTH_SUCCESS).and(user(adminName)).and(method(PAT_METHOD).negate());
    }

    /** A successful authentication by the personal access token with the given public id. */
    private static Predicate<AuditLine> patSuccess(String publicId) {
        return event(AUTH_SUCCESS).and(line -> PAT_METHOD.equals(line.method())).and(outcome(SUCCESS)) // V11: success
                .and(pat(publicId));
    }

    /** A committed ACL change of at least the given number of mutations. */
    private static Predicate<AuditLine> committedAclChange(int minChanges) {
        return event(ACL_CHANGE).and(line -> SUCCESS.equals(line.outcome())).and(line -> line.changes() >= minChanges);
    }

    /** A position in the captured streams: the number of characters of standard output and standard error so far. */
    private record Mark(int out, int err) {
    }

    /** What the test learnt while it drove the server, which the checks of the finished run need. */
    // V11: adminName is the administrator, whose setup logins the authentication totals separate
    private record Run(List<Mark> marks,
                       String patPublicId,
                       String invalidPublicId,
                       int bulkMinChanges,
                       String adminName) {
    }

    /**
     * The pairs of one audit line; a pair the line does not carry is {@code null}, or {@code -1} and empty for the
     * ACL change pairs.
     */
    private record AuditLine(String event,
                             String outcome,
                             String user,
                             String ip,
                             String method,
                             String pat,
                             int changes,
                             Set<String> kinds) {

        static AuditLine parse(String text) {
            String user = null;
            String rest = text;
            Matcher matcher = USER.matcher(text);
            if (matcher.find()) {
                user = matcher.group(1);
                // The quoted user value may hold spaces and '=', so the other pairs are read from the rest of the line.
                rest = text.substring(0, matcher.start()) + text.substring(matcher.end());
            }
            String changes = value(CHANGES, rest);
            String kinds = value(KINDS, rest);
            return new AuditLine(value(EVENT, rest),
                    value(OUTCOME, rest),
                    user,
                    value(IP, rest),
                    value(METHOD, rest),
                    value(PAT, rest),
                    changes == null ? -1 : Integer.parseInt(changes),
                    kinds == null ? Set.of() : Set.copyOf(Arrays.asList(kinds.split(",", -1))));
        }

        private static String value(Pattern pattern, String text) {
            Matcher matcher = pattern.matcher(text);
            return matcher.find() ? matcher.group(1) : null;
        }
    }
}

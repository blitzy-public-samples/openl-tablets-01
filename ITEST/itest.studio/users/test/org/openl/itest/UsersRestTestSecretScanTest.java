package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Drives the secret scans of {@link UsersRestTest} with synthetic values generated per run, without a server. Every
 * assertion here uses a fixed message that names only variables and counts, so a regression that renders a value
 * cannot reach the test report through these checks.
 */
class UsersRestTestSecretScanTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final String DIGITS = "0123456789";
    private static final String BASIC_PREFIX = "Basic ";

    @TempDir
    Path responses;

    @Test
    void trackedSecretsCoverTheAdministratorHeaderAndTheVerificationToken() {
        String admin = random(ALPHANUMERIC, 16);
        String adminHeader = basic(admin, admin);
        String jsmith2 = random(ALPHANUMERIC, 16);
        String jsmith3 = random(ALPHANUMERIC, 16);
        String jsmithBasic2 = basic("jsmith", jsmith2);
        String jsmithBasic3 = basic("jsmith", jsmith3);
        Map<String, String> env = new LinkedHashMap<>();
        env.put("ADMIN_PASSWORD", admin);
        env.put("ADMIN_AUTH_TOCKEN", adminHeader);
        env.put("JSMITH_PASSWORD_1", random(ALPHANUMERIC, 16));
        env.put("JSMITH_PASSWORD_2", jsmith2);
        env.put("JSMITH_PASSWORD_3", jsmith3);
        env.put("JDOE_PASSWORD", random(ALPHANUMERIC, 16));
        env.put("JSMITH_BASIC_2", jsmithBasic2);
        env.put("JSMITH_BASIC_3", jsmithBasic3);
        String mailPassword = random(ALPHANUMERIC, 16);
        String token = random(DIGITS, 8);

        Map<String, String> secrets = UsersRestTest.trackedSecrets(env, mailPassword, token);

        assertTrue(List.copyOf(secrets.keySet())
                .equals(List.of("JSMITH_PASSWORD_1",
                        "JSMITH_PASSWORD_2",
                        "JSMITH_PASSWORD_3",
                        "JDOE_PASSWORD",
                        "ADMIN_AUTH_TOCKEN",
                        "ADMIN_AUTH_TOCKEN (base64)",
                        "JSMITH_BASIC_2",
                        "JSMITH_BASIC_2 (base64)",
                        "JSMITH_BASIC_3",
                        "JSMITH_BASIC_3 (base64)",
                        "MAIL_PASSWORD",
                        "MAIL_VERIFICATION_TOKEN")), "the scans track exactly the generated secrets, in order");
        for (String name : List.of("JSMITH_PASSWORD_1",
                "JSMITH_PASSWORD_2",
                "JSMITH_PASSWORD_3",
                "JDOE_PASSWORD",
                "ADMIN_AUTH_TOCKEN",
                "JSMITH_BASIC_2",
                "JSMITH_BASIC_3")) {
            String generated = env.get(name);
            assertTrue(generated != null && generated.equals(secrets.get(name)), "tracked as generated: " + name);
        }
        assertTrue(base64(adminHeader).equals(secrets.get("ADMIN_AUTH_TOCKEN (base64)")),
                "tracked as the Base64 part of its header: ADMIN_AUTH_TOCKEN (base64)");
        assertTrue(base64(jsmithBasic2).equals(secrets.get("JSMITH_BASIC_2 (base64)")),
                "tracked as the Base64 part of its header: JSMITH_BASIC_2 (base64)");
        assertTrue(base64(jsmithBasic3).equals(secrets.get("JSMITH_BASIC_3 (base64)")),
                "tracked as the Base64 part of its header: JSMITH_BASIC_3 (base64)");
        assertTrue(mailPassword.equals(secrets.get("MAIL_PASSWORD")), "tracked as generated: MAIL_PASSWORD");
        assertTrue(token.equals(secrets.get("MAIL_VERIFICATION_TOKEN")),
                "tracked as read from the e-mail: MAIL_VERIFICATION_TOKEN");
    }

    @Test
    void aSavedResponseHoldingAPasswordFailsNamingOnlyTheVariable() throws IOException {
        String password = random(ALPHANUMERIC, 16);
        String marker = random(ALPHANUMERIC, 16);
        save("users-service/users-update.put.req.body",
                "{\"note\":\"" + marker + "\",\"password\":\"" + password + "\"}");
        Map<String, String> secrets = UsersRestTest.trackedSecrets(Map.of("JSMITH_PASSWORD_2", password), null, null);

        AssertionError error = assertThrows(AssertionError.class,
                () -> scan(secrets, "", "", null),
                "a saved response holding JSMITH_PASSWORD_2 fails the scan");

        assertMessage("JSMITH_PASSWORD_2 found in 1 saved response file(s)", error);
        assertValueFree(error, password, marker);
    }

    @Test
    void aSavedResponseHoldingTheBase64PartOfTheAdministratorHeaderFails() throws IOException {
        String admin = random(ALPHANUMERIC, 16);
        String adminHeader = basic(admin, admin);
        String encoded = base64(adminHeader);
        String marker = random(ALPHANUMERIC, 16);
        save("users-service/mail/studio-settings.req.body",
                "{\"note\":\"" + marker + "\",\"auth\":\"" + encoded + "\"}");
        Map<String, String> secrets = UsersRestTest.trackedSecrets(Map.of("ADMIN_AUTH_TOCKEN", adminHeader),
                null,
                null);

        AssertionError error = assertThrows(AssertionError.class,
                () -> scan(secrets, "", "", null),
                "a saved response holding the Base64 part of ADMIN_AUTH_TOCKEN fails the scan");

        assertMessage("ADMIN_AUTH_TOCKEN (base64) found in 1 saved response file(s)", error);
        assertValueFree(error, adminHeader, encoded, admin, marker);
    }

    @Test
    void capturedStdoutAndStderrHoldingSecretsFailNamingEachVariableAndStream() {
        String mailPassword = random(ALPHANUMERIC, 16);
        String token = random(DIGITS, 8);
        String marker = random(ALPHANUMERIC, 16);
        Map<String, String> secrets = UsersRestTest.trackedSecrets(Map.of(), mailPassword, token);
        String stdout = "T [WARN ] " + marker + " smtp " + mailPassword + "\n";
        String stderr = "--------------------\nverify " + token + " and " + token + "\n--------------------\n";

        AssertionError error = assertThrows(AssertionError.class,
                () -> scan(secrets, stdout, stderr, null),
                "captured output holding MAIL_PASSWORD and MAIL_VERIFICATION_TOKEN fails the scan");

        assertMessage("MAIL_PASSWORD found 1 time(s) in captured System.out; "
                + "MAIL_VERIFICATION_TOKEN found 2 time(s) in captured System.err", error);
        assertValueFree(error, mailPassword, token, marker);
    }

    @Test
    void capturedOutputIsMatchedAsTheStreamCharsetRenderedTheValue() {
        // U+00E9 has no US-ASCII encoding, so the stream prints it as '?' and the scan must match that rendering
        String password = random(ALPHANUMERIC, 8) + "\u00e9" + random(ALPHANUMERIC, 8);
        Map<String, String> secrets = UsersRestTest.trackedSecrets(Map.of("JDOE_PASSWORD", password), null, null);
        String stdout = new String(("user jdoe " + password + "\n").getBytes(StandardCharsets.US_ASCII),
                StandardCharsets.US_ASCII);
        String rendered = new String(password.getBytes(StandardCharsets.US_ASCII), StandardCharsets.US_ASCII);

        AssertionError error = assertThrows(AssertionError.class,
                () -> UsersRestTest.assertNoGeneratedSecretsSaved(responses,
                        secrets,
                        stdout,
                        StandardCharsets.US_ASCII,
                        "",
                        StandardCharsets.UTF_8,
                        null),
                "a value printed through a narrower charset is still found");

        assertMessage("JDOE_PASSWORD found 1 time(s) in captured System.out", error);
        assertValueFree(error, password, rendered);
    }

    @Test
    void cleanInputsPass() throws IOException {
        String admin = random(ALPHANUMERIC, 16);
        Map<String, String> env = Map.of("ADMIN_AUTH_TOCKEN",
                basic(admin, admin),
                "JSMITH_PASSWORD_1",
                random(ALPHANUMERIC, 16),
                "JDOE_PASSWORD",
                random(ALPHANUMERIC, 16));
        // testMail has not run, so the verification token is still unset
        Map<String, String> secrets = new LinkedHashMap<>(
                UsersRestTest.trackedSecrets(env, random(ALPHANUMERIC, 16), null));
        secrets.put("EMPTY", ""); // an empty value would match every text, so the scans skip it
        save("users-service/users-1.get.req.body", "{\"users\":[\"" + random(ALPHANUMERIC, 16) + "\"]}");
        String stdout = "users-service/users-1.get.req - OK (12ms)\n";
        String stderr = "--------------------\nHTTP/1.1 200 OK\nContent-Type: application/json\n--------------------\n";

        assertNotThrown(() -> scan(secrets, stdout, stderr, null), "clean saved responses and output pass");
        assertNotThrown(() -> UsersRestTest.assertNoGeneratedSecretsSaved(responses.resolve("absent"),
                secrets,
                stdout,
                StandardCharsets.UTF_8,
                stderr,
                StandardCharsets.UTF_8,
                null), "a missing saved-response root and clean output pass");
    }

    @Test
    void withAPrimaryFailureBothScanErrorsAreSuppressedOntoIt() throws IOException {
        String password = random(ALPHANUMERIC, 16);
        String mailPassword = random(ALPHANUMERIC, 16);
        save("users-service/users-create.put.req.body", "{\"password\":\"" + password + "\"}");
        Map<String, String> secrets = UsersRestTest.trackedSecrets(Map.of("JSMITH_PASSWORD_1", password),
                mailPassword,
                null);
        IllegalStateException primary = new IllegalStateException("teardown failed");

        assertNotThrown(() -> scan(secrets, "", "smtp " + mailPassword + "\n", primary),
                "with a primary failure the scans throw nothing");

        Throwable[] suppressed = primary.getSuppressed();
        assertTrue(suppressed.length == 2, "both scan errors are suppressed onto the primary failure");
        assertMessage("JSMITH_PASSWORD_1 found in 1 saved response file(s)", suppressed[0]);
        assertMessage("MAIL_PASSWORD found 1 time(s) in captured System.err", suppressed[1]);
        assertValueFree(primary, password, mailPassword);
    }

    @Test
    void withoutAPrimaryFailureTheFirstScanErrorIsThrownCarryingTheOther() throws IOException {
        String password = random(ALPHANUMERIC, 16);
        String mailPassword = random(ALPHANUMERIC, 16);
        save("users-service/users-create.put.req.body", "{\"password\":\"" + password + "\"}");
        Map<String, String> secrets = UsersRestTest.trackedSecrets(Map.of("JSMITH_PASSWORD_1", password),
                mailPassword,
                null);

        AssertionError error = assertThrows(AssertionError.class,
                () -> scan(secrets, "smtp " + mailPassword + "\n", "", null),
                "both scans failing without a primary failure throws");

        assertMessage("JSMITH_PASSWORD_1 found in 1 saved response file(s)", error);
        assertTrue(error.getSuppressed().length == 1, "the captured-output error is suppressed onto the thrown one");
        assertMessage("MAIL_PASSWORD found 1 time(s) in captured System.out", error.getSuppressed()[0]);
        assertValueFree(error, password, mailPassword);
    }

    private void scan(Map<String, String> secrets, String stdout, String stderr, @Nullable Throwable failure) {
        UsersRestTest.assertNoGeneratedSecretsSaved(responses,
                secrets,
                stdout,
                StandardCharsets.UTF_8,
                stderr,
                StandardCharsets.UTF_8,
                failure);
    }

    private void save(String name, String content) throws IOException {
        Path file = responses.resolve(name);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    private static void assertMessage(String expected, Throwable error) {
        assertTrue(expected.equals(error.getMessage()), "the scan reports: " + expected);
    }

    // The rendered trace covers the message, the suppressed errors and the causes, as a test report would show them
    private static void assertValueFree(Throwable error, String... forbidden) {
        StringWriter trace = new StringWriter();
        try (PrintWriter writer = new PrintWriter(trace)) {
            error.printStackTrace(writer);
        }
        String rendered = trace.toString();
        for (String value : forbidden) {
            assertFalse(rendered.contains(value), "the failure renders no value, response body or captured text");
        }
    }

    private static void assertNotThrown(Runnable scan, String message) {
        try {
            scan.run();
        } catch (AssertionError | RuntimeException e) {
            fail(message + ", but the scan raised " + e.getClass().getSimpleName());
        }
    }

    private static String random(String alphabet, int length) {
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
        }
        return builder.toString();
    }

    private static String basic(String user, String password) {
        return BASIC_PREFIX + Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    private static String base64(String header) {
        return header.substring(BASIC_PREFIX.length());
    }
}

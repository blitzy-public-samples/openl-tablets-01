package org.openl.itest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

import com.icegreen.greenmail.smtp.SmtpServer;
import com.icegreen.greenmail.store.FolderException;
import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.ServerSetup;
import org.h2.tools.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.openl.itest.core.HttpClient;
import org.openl.itest.core.JettyServer;

class UsersRestTest {

    private static final String INSERT_EXT_GROUPS_SQL = "INSERT INTO OpenL_External_Groups (loginName, groupName) VALUES ('%s', '%s');";
    private static final String TOKEN_PARAM = "token=";
    private static final int TOKEN_LENGTH = 8;

    private static HttpClient client;
    private static GreenMail smtpServer;
    private static String mailUrl;

    private static Server h2Server;
    private static Connection h2Connection;
    private static final String DB_DUMP_FILE = "target/dump-%s.sql".formatted(System.currentTimeMillis());

    // V7: generated at runtime (AAP 0.8.3); alphanumeric, so fixtures embed the values unescaped
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final int SECRET_LENGTH = 16;
    private static final String BASIC_PREFIX = "Basic ";
    private static String mailPassword;
    private static String adminAuth;

    @BeforeAll
    static void setUp() throws Exception {
        h2Server = Server.createTcpServer("-tcp", "-tcpAllowOthers", "-ifNotExists");
        h2Server.start();
        String dbUrl = "jdbc:h2:" + h2Server.getURL() + "/mem:mydb";
        h2Connection = DriverManager.getConnection(dbUrl);
        h2Connection.setAutoCommit(false);

        client = JettyServer.get()
                .withInitParam("db.url", dbUrl)
                .start();

        // V7: credentials are generated or derived at runtime (AAP 0.8.3)
        String adminName = administratorName();
        adminAuth = basic(adminName, adminName); // AdminUsers seeds each administrator with its name as password
        String jsmithPassword1 = randomSecret("jsmith", "jdoe", adminName);
        String jsmithPassword2 = randomSecret("jsmith", "jdoe", adminName, jsmithPassword1);
        String jsmithPassword3 = randomSecret("jsmith", "jdoe", adminName, jsmithPassword1, jsmithPassword2);
        client.localEnv.put("ADMIN_AUTH_TOCKEN", adminAuth);
        client.localEnv.put("JSMITH_PASSWORD_1", jsmithPassword1);
        client.localEnv.put("JSMITH_PASSWORD_2", jsmithPassword2);
        client.localEnv.put("JSMITH_PASSWORD_3", jsmithPassword3);
        client.localEnv.put("JDOE_PASSWORD", randomSecret("jsmith", "jdoe", adminName));
        client.localEnv.put("JSMITH_BASIC_2", basic("jsmith", jsmithPassword2));
        client.localEnv.put("JSMITH_BASIC_3", basic("jsmith", jsmithPassword3));

        mailPassword = randomSecret(); // V7: generated SMTP password instead of a literal
        smtpServer = new GreenMail(new ServerSetup(0, null, ServerSetup.PROTOCOL_SMTP));
        smtpServer.setUser("username@email", mailPassword); // V7: generated at runtime
        smtpServer.start();

        SmtpServer smtp = smtpServer.getSmtp();
        mailUrl = smtp.getProtocol() + "://" + smtp.getBindTo() + ":" + smtp.getPort();

        try (Statement statement = h2Connection.createStatement()) {
            statement.execute("SCRIPT TO '%s'".formatted(DB_DUMP_FILE));
        }
    }

    @AfterAll
    static void tearDown() throws Exception {
        // V7: after shutdown, fail if a generated secret was saved with a mismatching response
        try {
            client.close();
            h2Connection.close();
            h2Server.stop();
            smtpServer.stop();
        } finally {
            assertNoGeneratedSecretsSaved();
        }
    }

    @AfterEach
    void afterEach() throws SQLException, IOException, FolderException {
        try (Statement statement = h2Connection.createStatement()) {
            statement.execute("DROP ALL OBJECTS DELETE FILES;");
            h2Connection.commit();

            String dump = Files.readString(Path.of(DB_DUMP_FILE), Charset.defaultCharset());
            statement.execute(dump);
            h2Connection.commit();
        }
        smtpServer.purgeEmailFromAllMailboxes();
    }

    @Test
    void smoke() {
        client.send("users-service/users-1.get");
        client.send("users-service/users-create.put");
        client.send("users-service/users-2.get");
        client.send("users-service/users-update.put");
        client.send("users-service/users-3.get");
        client.send("users-service/users-user.get");

        client.send("users-service/users-profile-1.get");
        client.send("users-service/users-profile-update.put");
        client.send("users-service/users-profile-2.get");

        client.send("users-service/users-delete-1.delete");
        client.send("users-service/users-delete-2.delete");
        client.send("users-service/users-1.get");
        client.send("users-service/users-info-update.put");
        client.send("users-service/users-4.get");

        client.send("users-service/users-options.get");

        client.send("users-service/users-create-2.put");
    }

    @Test
    void testExternalGroups() throws SQLException {
        client.send("users-service/users-create-1.put");
        client.send("users-service/users-5.get");
        client.send("users-service/users/groups/external/empty.jsmith.get");

        try (Statement statement = h2Connection.createStatement()) {
            statement.addBatch(INSERT_EXT_GROUPS_SQL.formatted("jsmith", "GROUP_1"));
            statement.addBatch(INSERT_EXT_GROUPS_SQL.formatted("jsmith", "GROUP_2"));
            statement.addBatch(INSERT_EXT_GROUPS_SQL.formatted("jsmith", "GROUP_3"));
            statement.addBatch(INSERT_EXT_GROUPS_SQL.formatted("jsmith", "Analysts"));
            statement.addBatch(INSERT_EXT_GROUPS_SQL.formatted("jsmith", "Admiral Nelson"));

            statement.executeBatch();
            h2Connection.commit();
        }

        client.send("users-service/users/user-info.jsmith.get");
        client.send("users-service/users/groups/external/allExternal.jsmith.get");
        client.send("users-service/users/groups/external/matchedExternal.jsmith.get");
        client.send("users-service/users/groups/external/notMatchedExternal.jsmith.get");
        client.send("users-service/users-delete-1.delete");
    }

    @Test
    void testMail() throws IOException, MessagingException {
        client.send("users-service/mail/users-mail-config-1.get");

        var newMailConfig = new MailConfigRequest();
        newMailConfig.password = mailPassword; // V7: generated at runtime
        newMailConfig.url = mailUrl;
        newMailConfig.username = "username@email";
        // V7: the administrator header is derived at runtime
        client.postForObject("/rest/admin/settings/mail", newMailConfig, "Authorization", adminAuth);
        client.send("users-service/mail/studio-settings");

        // V7: the administrator header is derived at runtime
        var mailConfig = client.getForObject("/rest/admin/settings/mail", MailConfigResponse.class, 200, "Authorization", adminAuth);
        assertTrue(mailConfig.password.secret); // password must not be exposed to the user due to security reasons
        assertEquals("username@email", mailConfig.username);
        assertEquals(mailUrl, mailConfig.url);

        int receivedMessagesCounter = 0;
        client.send("users-service/users-1.get");
        assertEquals(smtpServer.getReceivedMessages().length, receivedMessagesCounter);

        client.send("users-service/users-create.put");
        client.send("users-service/users-2.get");
        assertEquals(smtpServer.getReceivedMessages().length, ++receivedMessagesCounter);

        client.send("users-service/users-update.put");
        client.send("users-service/users-3.get");
        assertEquals(smtpServer.getReceivedMessages().length, ++receivedMessagesCounter);

        client.send("users-service/users-profile-1.get");

        client.send("users-service/users-profile-update.put");
        client.send("users-service/users-profile-2.get");
        assertEquals(smtpServer.getReceivedMessages().length, ++receivedMessagesCounter);

        client.send("users-service/users-delete-1.delete");
        client.send("users-service/users-info-update.put");
        client.send("users-service/users-4.get");
        assertEquals(smtpServer.getReceivedMessages().length, ++receivedMessagesCounter);

        client.send("users-service/mail/users-mail-send.post");
        assertEquals(smtpServer.getReceivedMessages().length, ++receivedMessagesCounter);

        MimeMessage message = smtpServer.getReceivedMessages()[smtpServer.getReceivedMessages().length - 1];
        assertEquals("admin@email", message.getRecipients(Message.RecipientType.TO)[0].toString());
        assertEquals("username@email", message.getFrom()[0].toString());

        InputStreamReader inputStreamReader = new InputStreamReader(message.getInputStream());
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        String content = bufferedReader.lines().collect(Collectors.joining());
        int tokenStartIndex = content.indexOf(TOKEN_PARAM) + TOKEN_PARAM.length();
        String token = content.substring(tokenStartIndex, tokenStartIndex + TOKEN_LENGTH);
        // V7: the administrator header is derived at runtime
        client.getForObject("/rest/mail/verify/" + token, String.class, 204, "Authorization", adminAuth);
        inputStreamReader.close();
        bufferedReader.close();

        client.send("users-service/mail/users-mail-verified.get");

        client.send("users-service/mail/reset-mail-config");
        client.send("users-service/mail/users-mail-config-1.get");
    }

    // V7: first administrator configured for the suite; AdminUsers seeds it with its user name as the password
    private static String administratorName() {
        Path file = Path.of("openl-repository", "application.properties");
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            properties.load(reader);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read " + file, e);
        }
        for (String name : properties.getProperty("security.administrators", "").split(",", -1)) {
            if (!name.isBlank()) {
                return name.trim();
            }
        }
        throw new IllegalStateException("security.administrators is not set in " + file);
    }

    // V7: random alphanumeric secret of SECRET_LENGTH characters, different from every excluded value
    private static String randomSecret(String... excluded) {
        List<String> taken = List.of(excluded);
        String secret;
        do {
            StringBuilder builder = new StringBuilder(SECRET_LENGTH);
            for (int i = 0; i < SECRET_LENGTH; i++) {
                builder.append(ALPHANUMERIC.charAt(RANDOM.nextInt(ALPHANUMERIC.length())));
            }
            secret = builder.toString();
        } while (taken.contains(secret));
        return secret;
    }

    // V7: HTTP Basic header value, UTF-8 encoded as Spring's BasicAuthenticationFilter decodes it
    private static String basic(String user, String password) {
        return BASIC_PREFIX + Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    // V7: fails, naming only variables and counts, when a saved mismatching response holds a generated secret.
    // ADMIN_AUTH_TOCKEN is left out: it is derived, not secret, and unedited fixtures still carry it literally.
    private static void assertNoGeneratedSecretsSaved() {
        Path root = Path.of(System.getProperty("server.responses", "target/responses"));
        if (!Files.isDirectory(root)) {
            return;
        }
        Map<String, String> secrets = new LinkedHashMap<>();
        if (client != null) {
            for (String name : List.of("JSMITH_PASSWORD_1", "JSMITH_PASSWORD_2", "JSMITH_PASSWORD_3",
                    "JDOE_PASSWORD")) {
                secrets.put(name, client.localEnv.get(name));
            }
            for (String name : List.of("JSMITH_BASIC_2", "JSMITH_BASIC_3")) {
                String value = client.localEnv.get(name);
                secrets.put(name, value);
                if (value != null && value.startsWith(BASIC_PREFIX)) {
                    secrets.put(name + " (base64)", value.substring(BASIC_PREFIX.length()));
                }
            }
        }
        secrets.put("MAIL_PASSWORD", mailPassword);

        List<Path> files;
        try (Stream<Path> walk = Files.walk(root)) {
            files = walk.filter(Files::isRegularFile).toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (Path file : files) {
            String content;
            try {
                // ISO-8859-1 maps every byte, and the generated values are ASCII
                content = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            secrets.forEach((name, value) -> {
                if (value != null && !value.isEmpty() && content.contains(value)) {
                    counts.merge(name, 1, Integer::sum);
                }
            });
        }
        if (!counts.isEmpty()) {
            List<String> findings = new ArrayList<>();
            counts.forEach((name, count) -> findings.add(name + " found in " + count + " saved response file(s)"));
            fail(String.join("; ", findings));
        }
    }

    public static class MailConfigRequest {
        public String url;
        public String username;
        public String password;
    }

    public static class MailConfigResponse {
        public String url;
        public String username;
        public Wrapper password;
    }

    public static class Wrapper {
        public String value;
        public boolean secret;
    }
}

package org.openl.studio.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.text.Normalizer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import org.apache.commons.lang3.RandomStringUtils;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.DefaultLocale;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * V9: {@link LoginLockoutAuthenticationProvider} over a real {@link DaoAuthenticationProvider} whose user store finds
 * an account the way a database collation does, so a variant of the stored name finds the account too.
 *
 * <p>Two stores stand in for the databases Studio supports whose default comparison is not exact. The SQL Server
 * store ignores case and trailing spaces, as {@code =} pads the shorter value with spaces. The MySQL store ignores case
 * and accents, as the default {@code utf8mb4_0900_ai_ci} collation does. Either returns the account under its stored
 * name, as Studio's user details service does. Only the stored name and its case variants may authenticate and share
 * one counter. Every other variant fails like a wrong password, also with the correct password, and is counted under
 * its own name, so a variant can neither reach the account nor reset its counter.
 *
 * <p>The store counts its lookups, so a test proves whether an attempt reached the delegate. Passwords are generated
 * per run and hashed with a fast bcrypt cost, and no assertion message carries one. The DAO provider localizes its
 * failure message with the default locale, which is pinned so the expected message is deterministic.
 */
@DefaultLocale(language = "en")
class LoginLockoutNameVariantTest {

    private static final int FAILURES_TO_LOCK = 5;

    private static final Duration LOCK_LENGTH = Duration.ofMinutes(15);

    /** The message of a rejected login, for a wrong password, a name variant and a locked name alike. */
    private static final String BAD_CREDENTIALS = "Bad credentials";

    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

    /** The login name the account is stored under. */
    private static final String STORED_NAME = "victim";

    /** The lowest bcrypt cost, so each test hashes and checks its passwords in milliseconds. */
    private static final int BCRYPT_COST = 4;

    /** Variants that the SQL Server comparison resolves to the stored name and that are not case variants of it. */
    private static final List<String> PADDED_VARIANTS = List.of("victim ", "victim  ", "VICTIM ", "Victim   ");

    /** A variant that the MySQL comparison resolves to the stored name: an i with an acute accent, precomposed. */
    private static final String ACCENTED = "v\u00edctim";

    /**
     * Variants that the MySQL comparison resolves to the stored name and that are not case variants of it: accents
     * precomposed and decomposed, alone, combined with case and on several letters.
     */
    private static final List<String> ACCENTED_VARIANTS = List.of(ACCENTED,
            "v\u00ecctim",
            "v\u00efctim",
            "vi\u0301ctim",
            "V\u00cdCTIM",
            "v\u00eect\u00efm");

    private final String password = newPassword();
    private final String wrongPassword = differentFrom(password);
    private final MutableClock clock = new MutableClock(START);
    private final PasswordEncoder encoder = new BCryptPasswordEncoder(BCRYPT_COST);
    private final String passwordHash = encoder.encode(password);

    private final CollatingUserStore sqlServer = new CollatingUserStore(Collation.SQL_SERVER, passwordHash);
    private final LoginLockoutAuthenticationProvider sqlServerLockout = lockout(sqlServer);

    private final CollatingUserStore mySql = new CollatingUserStore(Collation.MYSQL, passwordHash);
    private final LoginLockoutAuthenticationProvider mySqlLockout = lockout(mySql);

    @Test
    void storedNameAuthenticates() {
        assertAuthenticates(sqlServerLockout, sqlServer, STORED_NAME);
        assertAuthenticates(mySqlLockout, mySql, STORED_NAME);
        assertEquals(0, sqlServerLockout.size(), "A success left an entry");
        assertEquals(0, mySqlLockout.size(), "A success left an entry");
    }

    @Test
    void caseVariantsAuthenticateAndShareTheCounterOfTheStoredName() {
        for (String variant : List.of("VICTIM", "Victim", "vIcTiM")) {
            assertAuthenticates(sqlServerLockout, sqlServer, variant);
            assertAuthenticates(mySqlLockout, mySql, variant);
        }

        // Failures through case variants and through the stored name count together, and lock every case variant.
        for (String variant : List.of("VICTIM", "Victim", "vIcTiM", "VICTIM")) {
            failLogin(mySqlLockout, mySql, variant);
        }
        failLogin(mySqlLockout, mySql, STORED_NAME);
        for (String variant : List.of(STORED_NAME, "VICTIM", "Victim")) {
            assertRejectedWithoutDelegate(mySqlLockout, mySql, variant, password);
        }
        assertEquals(1, mySqlLockout.size(), "Case variants must share one entry");
    }

    @Test
    void paddedVariantsWithTheCorrectPasswordFailLikeAWrongPassword() {
        for (String variant : PADDED_VARIANTS) {
            assertVariantRejected(sqlServerLockout, sqlServer, variant);
        }
        assertEquals(namesIgnoringCase(PADDED_VARIANTS), sqlServerLockout.size(),
                "Each variant must be counted under its own name");
        assertAuthenticates(sqlServerLockout, sqlServer, STORED_NAME);
    }

    @Test
    void accentedVariantsWithTheCorrectPasswordFailLikeAWrongPassword() {
        for (String variant : ACCENTED_VARIANTS) {
            assertVariantRejected(mySqlLockout, mySql, variant);
        }
        assertEquals(namesIgnoringCase(ACCENTED_VARIANTS), mySqlLockout.size(),
                "Each variant must be counted under its own name");
        assertAuthenticates(mySqlLockout, mySql, STORED_NAME);
    }

    @Test
    void variantAnswersExactlyLikeAWrongPassword() {
        var wrong = assertThrowsExactly(BadCredentialsException.class,
                () -> mySqlLockout.authenticate(attempt(STORED_NAME, wrongPassword)));
        var variant = assertThrowsExactly(BadCredentialsException.class,
                () -> mySqlLockout.authenticate(attempt(ACCENTED, password)));

        assertSame(wrong.getClass(), variant.getClass());
        assertEquals(wrong.getMessage(), variant.getMessage());
        assertNull(variant.getCause(), "A rejected variant must not wrap another exception");
    }

    @Test
    void fiveCorrectPasswordsThroughOneVariantLockThatVariant() {
        for (int i = 0; i < FAILURES_TO_LOCK; i++) {
            assertVariantRejected(sqlServerLockout, sqlServer, "victim ");
        }
        assertRejectedWithoutDelegate(sqlServerLockout, sqlServer, "victim ", password);

        // The lock of the variant ends like any other; its next attempt is counted again and still fails.
        clock.advance(LOCK_LENGTH.minusMillis(1));
        assertRejectedWithoutDelegate(sqlServerLockout, sqlServer, "victim ", password);
        clock.advance(Duration.ofMillis(1));
        assertVariantRejected(sqlServerLockout, sqlServer, "victim ");
    }

    @Test
    void wrongAndCorrectPasswordsThroughAVariantLockItTogether() {
        for (int i = 0; i < FAILURES_TO_LOCK - 1; i++) {
            failLogin(mySqlLockout, mySql, ACCENTED);
        }
        assertVariantRejected(mySqlLockout, mySql, ACCENTED);
        assertRejectedWithoutDelegate(mySqlLockout, mySql, ACCENTED, password);
    }

    @Test
    void correctPasswordThroughAVariantDoesNotResetTheStoredName() {
        for (int i = 0; i < FAILURES_TO_LOCK - 1; i++) {
            failLogin(sqlServerLockout, sqlServer, STORED_NAME);
        }
        assertVariantRejected(sqlServerLockout, sqlServer, "victim ");

        // The variant's correct password was no success: the next failure of the stored name is its fifth, and locks.
        failLogin(sqlServerLockout, sqlServer, STORED_NAME);
        assertRejectedWithoutDelegate(sqlServerLockout, sqlServer, STORED_NAME, password);
    }

    @Test
    void lockedNameRejectsTheCorrectPasswordThroughEveryVariant() {
        for (int i = 0; i < FAILURES_TO_LOCK; i++) {
            failLogin(sqlServerLockout, sqlServer, STORED_NAME);
            failLogin(mySqlLockout, mySql, STORED_NAME);
        }

        // Case variants share the lock and are rejected before the delegate; every other variant reaches it and fails.
        assertRejectedWithoutDelegate(sqlServerLockout, sqlServer, "VICTIM", password);
        assertRejectedWithoutDelegate(mySqlLockout, mySql, "Victim", password);
        for (String variant : PADDED_VARIANTS) {
            assertVariantRejected(sqlServerLockout, sqlServer, variant);
        }
        for (String variant : ACCENTED_VARIANTS) {
            assertVariantRejected(mySqlLockout, mySql, variant);
        }
        assertRejectedWithoutDelegate(sqlServerLockout, sqlServer, STORED_NAME, password);
        assertRejectedWithoutDelegate(mySqlLockout, mySql, STORED_NAME, password);
    }

    @Test
    void resultOfAnotherNameFromAnotherDelegatePassesThroughUnchanged() {
        // A stand-in for the Active Directory provider, which may answer "victim@example.com" as "victim".
        var lastResult = new AtomicReference<@Nullable Authentication>();
        var calls = new AtomicInteger();
        AuthenticationProvider directory = new AuthenticationProvider() {
            @Override
            public Authentication authenticate(Authentication authentication) {
                calls.incrementAndGet();
                if (!password.equals(authentication.getCredentials())) {
                    throw new BadCredentialsException(BAD_CREDENTIALS);
                }
                var result = UsernamePasswordAuthenticationToken.authenticated(STORED_NAME, null, List.of());
                lastResult.set(result);
                return result;
            }

            @Override
            public boolean supports(Class<?> authentication) {
                return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
            }
        };
        var provider = new LoginLockoutAuthenticationProvider(directory, clock);

        for (int i = 0; i < FAILURES_TO_LOCK - 1; i++) {
            assertThrowsExactly(BadCredentialsException.class,
                    () -> provider.authenticate(attempt("victim@example.com", wrongPassword)));
        }
        Authentication result = provider.authenticate(attempt("victim@example.com", password));
        assertNotNull(result);
        assertSame(lastResult.get(), result, "The delegate's result must be returned unchanged");
        assertEquals(FAILURES_TO_LOCK, calls.get(), "Attempts that reached the delegate");
        assertEquals(0, provider.size(), "The success must reset the counter of the attempt's name");
    }

    /**
     * V11: the lock a variant engages writes exactly one {@code auth.lockout} line, and no captured line carries a
     * password.
     */
    @Test
    @StdIo
    void lockOfAVariantIsAuditedOnce(StdErr err) {
        for (int i = 0; i < FAILURES_TO_LOCK; i++) {
            assertVariantRejected(mySqlLockout, mySql, ACCENTED);
        }
        assertRejectedWithoutDelegate(mySqlLockout, mySql, ACCENTED, password);

        String[] captured = err.capturedLines();
        long lockouts = Arrays.stream(captured).filter(line -> line.contains("event=auth.lockout")).count();
        assertEquals(1, lockouts, "Exactly one lockout line must be written");
        assertTrue(Arrays.stream(captured).noneMatch(line -> line.contains(password) || line.contains(wrongPassword)),
                "No captured line may contain a password");
    }

    /**
     * Expects the correct password through a name variant to reach the delegate, which finds the account, and to fail
     * with the ordinary failed-login exception, wrapping nothing.
     */
    private void assertVariantRejected(LoginLockoutAuthenticationProvider provider,
                                       CollatingUserStore store,
                                       String variant) {
        int lookups = store.lookups();
        int matches = store.matches();
        var thrown = assertThrowsExactly(BadCredentialsException.class,
                () -> provider.authenticate(attempt(variant, password)));
        assertEquals(BAD_CREDENTIALS, thrown.getMessage());
        assertNull(thrown.getCause(), "A rejected variant must not wrap another exception");
        assertEquals(lookups + 1, store.lookups(), "The variant did not reach the delegate");
        assertEquals(matches + 1, store.matches(), "The store did not find the account of the variant");
    }

    /** Expects the wrong password through a name to reach the delegate and to fail like a wrong password. */
    private void failLogin(LoginLockoutAuthenticationProvider provider, CollatingUserStore store, String name) {
        int lookups = store.lookups();
        var thrown = assertThrowsExactly(BadCredentialsException.class,
                () -> provider.authenticate(attempt(name, wrongPassword)));
        assertEquals(BAD_CREDENTIALS, thrown.getMessage());
        assertEquals(lookups + 1, store.lookups(), "The failure did not reach the delegate");
    }

    /** Expects an attempt to be rejected with the ordinary failed-login exception, without calling the delegate. */
    private static void assertRejectedWithoutDelegate(LoginLockoutAuthenticationProvider provider,
                                                      CollatingUserStore store,
                                                      String name,
                                                      String credential) {
        int lookups = store.lookups();
        var thrown = assertThrowsExactly(BadCredentialsException.class,
                () -> provider.authenticate(attempt(name, credential)));
        assertEquals(BAD_CREDENTIALS, thrown.getMessage());
        assertNull(thrown.getCause(), "A locked attempt must not wrap another exception");
        assertEquals(lookups, store.lookups(), "A locked attempt must not reach the delegate");
    }

    /** Expects the correct password through a name to authenticate the account under its stored name. */
    private void assertAuthenticates(LoginLockoutAuthenticationProvider provider,
                                     CollatingUserStore store,
                                     String name) {
        int lookups = store.lookups();
        Authentication result = provider.authenticate(attempt(name, password));
        assertNotNull(result);
        assertTrue(result.isAuthenticated());
        assertEquals(STORED_NAME, result.getName());
        assertEquals(lookups + 1, store.lookups(), "The login did not reach the delegate");
    }

    private LoginLockoutAuthenticationProvider lockout(UserDetailsService store) {
        var dao = new DaoAuthenticationProvider(store);
        dao.setPasswordEncoder(encoder);
        return new LoginLockoutAuthenticationProvider(dao, clock);
    }

    /** Counts the names that differ other than in case, which is how many counters they have. */
    private static int namesIgnoringCase(List<String> names) {
        return (int) names.stream().map(name -> name.toLowerCase(Locale.ROOT)).distinct().count();
    }

    private static Authentication attempt(String name, String credential) {
        return UsernamePasswordAuthenticationToken.unauthenticated(name, credential);
    }

    private static String newPassword() {
        return RandomStringUtils.secure().nextAlphanumeric(16);
    }

    private static String differentFrom(String password) {
        String other;
        do {
            other = newPassword();
        } while (other.equals(password));
        return other;
    }

    /** How a database compares the login column with a submitted name. */
    private enum Collation {

        /** SQL Server's default: case-insensitive, and {@code =} pads the shorter value with trailing spaces. */
        SQL_SERVER {
            @Override
            String comparable(String name) {
                return TRAILING_SPACES.matcher(name).replaceFirst("").toLowerCase(Locale.ROOT);
            }
        },

        /** MySQL 8's default {@code utf8mb4_0900_ai_ci}: accent-insensitive and case-insensitive. */
        MYSQL {
            @Override
            String comparable(String name) {
                String decomposed = Normalizer.normalize(name, Normalizer.Form.NFD);
                return COMBINING_MARKS.matcher(decomposed).replaceAll("").toLowerCase(Locale.ROOT);
            }
        };

        private static final Pattern TRAILING_SPACES = Pattern.compile(" +$");
        private static final Pattern COMBINING_MARKS = Pattern.compile("\\p{M}+");

        /** Returns the form of a name that the collation compares: two names match when their forms are equal. */
        abstract String comparable(String name);
    }

    /**
     * A user store with one account, stored under {@link LoginLockoutNameVariantTest#STORED_NAME}, found by the
     * collation of its database and returned under its stored name, as Studio's user details service returns the
     * login name of the row it found.
     */
    private static final class CollatingUserStore implements UserDetailsService {

        private final Collation collation;
        private final String passwordHash;
        private final AtomicInteger lookups = new AtomicInteger();
        private final AtomicInteger matches = new AtomicInteger();

        CollatingUserStore(Collation collation, String passwordHash) {
            this.collation = collation;
            this.passwordHash = passwordHash;
        }

        @Override
        public UserDetails loadUserByUsername(String name) {
            lookups.incrementAndGet();
            if (!collation.comparable(name).equals(collation.comparable(STORED_NAME))) {
                throw new UsernameNotFoundException("Unknown user");
            }
            matches.incrementAndGet();
            return User.withUsername(STORED_NAME).password(passwordHash).roles("USER").build();
        }

        int lookups() {
            return lookups.get();
        }

        int matches() {
            return matches.get();
        }
    }

    /** A clock that a test moves by hand. */
    private static final class MutableClock extends Clock {

        private final AtomicReference<Instant> now;
        private final ZoneId zone;

        MutableClock(Instant start) {
            this(new AtomicReference<>(start), ZoneOffset.UTC);
        }

        private MutableClock(AtomicReference<Instant> now, ZoneId zone) {
            this.now = now;
            this.zone = zone;
        }

        void advance(Duration duration) {
            now.updateAndGet(instant -> instant.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(now, zone);
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }
}

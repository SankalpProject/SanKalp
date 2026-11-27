package com.myapp.auth.infrastructure.persistence.jdbc;

import com.myapp.auth.application.port.out.AuditLog.AuditEvent;
import com.myapp.auth.application.port.out.AuditLog.EventType;
import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.domain.model.IdentityProvider;
import com.myapp.auth.domain.model.RefreshToken;
import com.myapp.auth.domain.model.User;
import com.myapp.auth.domain.model.UserId;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.jdbc.core.simple.JdbcClient;

import javax.sql.DataSource;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Runs the SQL adapters against a REAL PostgreSQL with the real Flyway migrations. */
class JdbcAdaptersTest {

    private static EmbeddedPostgres postgres;
    /** Superuser connection: plays the migrator/owner (runs Flyway, inspects tables). */
    private static JdbcClient jdbc;
    /** Least-privilege runtime login, exactly as the deployed app connects. */
    private static JdbcClient appJdbc;

    private JdbcUserRepository users;
    private JdbcRefreshTokenStore tokens;
    private final Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS); // PostgreSQL precision

    @BeforeAll
    static void startDatabase() throws IOException {
        postgres = EmbeddedPostgres.start();
        DataSource ownerDataSource = postgres.getPostgresDatabase();
        jdbc = JdbcClient.create(ownerDataSource);
        jdbc.sql("CREATE ROLE sankalp_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE").update();
        Flyway.configure()
                .dataSource(ownerDataSource)
                .locations("classpath:db/migration")
                .placeholders(Map.of("app_role", "sankalp_app"))
                .load()
                .migrate();
        appJdbc = JdbcClient.create(postgres.getDatabase("sankalp_app", "postgres"));
    }

    @AfterAll
    static void stopDatabase() throws IOException {
        postgres.close();
    }

    @BeforeEach
    void cleanTables() {
        jdbc.sql("TRUNCATE users, user_identities, refresh_tokens, audit_events CASCADE").update();
        users = new JdbcUserRepository(jdbc);
        tokens = new JdbcRefreshTokenStore(jdbc, Clock.systemUTC());
    }

    // ---------------- users ----------------

    @Test
    void savesAndFindsUsersByIdAndEmail() {
        User user = User.register(EmailAddress.of("satyam@example.com"), now);
        assertThat(users.saveIfAbsent(user)).isEqualTo(user);
        assertThat(users.findById(user.id())).contains(user);
        assertThat(users.findByEmail(EmailAddress.of("SATYAM@example.com"))).contains(user);
        assertThat(users.findById(UserId.newId())).isEmpty();
    }

    @Test
    void saveIfAbsentReturnsTheExistingUserForADuplicateEmail() {
        User first = users.saveIfAbsent(User.register(EmailAddress.of("dup@example.com"), now));
        User second = users.saveIfAbsent(User.register(EmailAddress.of("dup@example.com"), now));
        assertThat(second.id()).isEqualTo(first.id());
    }

    @Test
    void concurrentSignUpsWithTheSameEmailCreateExactlyOneUser() throws Exception {
        List<User> results = runConcurrently(16,
                () -> users.saveIfAbsent(User.register(EmailAddress.of("race@example.com"), now)));
        assertThat(results).extracting(User::id).containsOnly(results.get(0).id());
        assertThat(jdbc.sql("SELECT count(*) FROM users").query(Long.class).single()).isEqualTo(1L);
    }

    @Test
    void linksAndResolvesExternalIdentitiesIdempotently() {
        User user = users.saveIfAbsent(User.register(EmailAddress.of("g@example.com"), now));
        users.linkExternalIdentity(user.id(), IdentityProvider.GOOGLE, "google-sub-1");
        users.linkExternalIdentity(user.id(), IdentityProvider.GOOGLE, "google-sub-1"); // no error

        assertThat(users.findByExternalIdentity(IdentityProvider.GOOGLE, "google-sub-1")).contains(user);
        assertThat(users.findByExternalIdentity(IdentityProvider.GOOGLE, "unknown")).isEmpty();
    }

    @Test
    void sqlInjectionAttemptIsTreatedAsPlainData() {
        users.saveIfAbsent(User.register(EmailAddress.of("victim@example.com"), now));
        assertThat(users.findByExternalIdentity(IdentityProvider.GOOGLE, "x' OR '1'='1")).isEmpty();
        assertThat(jdbc.sql("SELECT count(*) FROM users").query(Long.class).single()).isEqualTo(1L);
    }

    // ---------------- refresh tokens ----------------

    @Test
    void savesFindsAndRevokesTokenFamilies() {
        User user = users.saveIfAbsent(User.register(EmailAddress.of("t@example.com"), now));
        tokens.save(token("h1", user, "fam-A"));
        tokens.save(token("h2", user, "fam-A"));
        tokens.save(token("h3", user, "fam-B"));

        assertThat(tokens.findByHash("h1")).hasValueSatisfying(t -> {
            assertThat(t.userId()).isEqualTo(user.id());
            assertThat(t.expiresAt()).isEqualTo(now.plus(Duration.ofDays(30)));
            assertThat(t.used()).isFalse();
        });

        tokens.revokeFamily("fam-A");
        assertThat(tokens.findByHash("h1")).hasValueSatisfying(t -> assertThat(t.revoked()).isTrue());
        assertThat(tokens.findByHash("h2")).hasValueSatisfying(t -> assertThat(t.revoked()).isTrue());
        assertThat(tokens.findByHash("h3")).hasValueSatisfying(t -> assertThat(t.revoked()).isFalse());
    }

    @Test
    void markUsedReturnsThePreviousStateSoReuseIsDetected() {
        User user = users.saveIfAbsent(User.register(EmailAddress.of("m@example.com"), now));
        tokens.save(token("h1", user, "fam"));

        assertThat(tokens.markUsed("h1")).hasValueSatisfying(t -> assertThat(t.used()).isFalse()); // first use
        assertThat(tokens.markUsed("h1")).hasValueSatisfying(t -> assertThat(t.used()).isTrue());  // replay
        assertThat(tokens.markUsed("missing")).isEmpty();
    }

    @Test
    void concurrentRefreshWithTheSameTokenSucceedsExactlyOnce() throws Exception {
        User user = users.saveIfAbsent(User.register(EmailAddress.of("c@example.com"), now));
        tokens.save(token("h1", user, "fam"));

        List<Optional<RefreshToken>> results = runConcurrently(16, () -> tokens.markUsed("h1"));
        long firstUses = results.stream().filter(r -> r.isPresent() && !r.get().used()).count();
        assertThat(firstUses).isEqualTo(1); // all others see used=true → reuse detection
    }

    @Test
    void deletingAUserCascadesToIdentitiesAndTokens() {
        User user = users.saveIfAbsent(User.register(EmailAddress.of("d@example.com"), now));
        users.linkExternalIdentity(user.id(), IdentityProvider.GOOGLE, "sub");
        tokens.save(token("h1", user, "fam"));

        jdbc.sql("DELETE FROM users WHERE id = :id").param("id", user.id().value()).update();

        assertThat(tokens.findByHash("h1")).isEmpty();
        assertThat(users.findByExternalIdentity(IdentityProvider.GOOGLE, "sub")).isEmpty();
    }

    @Test
    void purgeRemovesOnlyLongExpiredTokens() {
        User user = users.saveIfAbsent(User.register(EmailAddress.of("p@example.com"), now));
        Instant longAgo = now.minus(Duration.ofDays(40));
        tokens.save(RefreshToken.issue("old", user.id(), "f", longAgo, longAgo.plus(Duration.ofDays(30))));
        tokens.save(token("fresh", user, "f"));

        tokens.purgeExpired();

        assertThat(tokens.findByHash("old")).isEmpty();
        assertThat(tokens.findByHash("fresh")).isPresent();
    }

    // ---------------- least privilege ----------------

    @Test
    void appLoginCanReadAndWriteUserDataButCannotChangeTheSchema() {
        JdbcUserRepository appUsers = new JdbcUserRepository(appJdbc);
        User user = appUsers.saveIfAbsent(User.register(EmailAddress.of("app@example.com"), now));
        assertThat(appUsers.findById(user.id())).contains(user);

        assertDenied(() -> appJdbc.sql("DROP TABLE users").update());
        assertDenied(() -> appJdbc.sql("CREATE TABLE evil (id int)").update());
    }

    // ---------------- audit trail ----------------

    @Test
    void auditEventsAreStoredWithAllFields() {
        JdbcAuditLog audit = new JdbcAuditLog(appJdbc, Clock.systemUTC(), 180);
        UserId userId = UserId.newId();
        audit.record(AuditEvent.of(EventType.LOGIN_SUCCEEDED).method("google").user(userId)
                .email(EmailAddress.of("satyam@example.com")).ip("2001:db8::1"));

        Map<String, Object> row = jdbc.sql("SELECT * FROM audit_events").query().singleRow();
        assertThat(row).containsEntry("event_type", "LOGIN_SUCCEEDED")
                .containsEntry("method", "google")
                .containsEntry("user_id", userId.value())
                .containsEntry("masked_email", "s***@example.com")
                .containsEntry("client_ip", "2001:db8::1");
    }

    @Test
    void appLoginCannotUpdateDeleteOrTruncateAuditEvents() {
        new JdbcAuditLog(appJdbc, Clock.systemUTC(), 180).record(AuditEvent.of(EventType.TOKEN_REUSE_DETECTED));

        assertDenied(() -> appJdbc.sql("UPDATE audit_events SET event_type = 'LOGOUT'").update());
        assertDenied(() -> appJdbc.sql("DELETE FROM audit_events").update());
        assertDenied(() -> appJdbc.sql("TRUNCATE audit_events").update());
        assertThat(count("audit_events")).isEqualTo(1);
    }

    @Test
    void evenTheOwnerCannotRewriteAuditHistory() {
        new JdbcAuditLog(appJdbc, Clock.systemUTC(), 180).record(AuditEvent.of(EventType.LOGIN_FAILED));
        assertThatThrownBy(() -> jdbc.sql("UPDATE audit_events SET event_type = 'LOGIN_SUCCEEDED'").update())
                .hasMessageContaining("append-only");
    }

    @Test
    void retentionDeletesOnlyOldRowsAndRefusesToPurgeRecentHistory() {
        jdbc.sql("""
                        INSERT INTO audit_events (occurred_at, event_type) VALUES
                            (now() - interval '400 days', 'LOGIN_SUCCEEDED'),
                            (now() - interval '10 days',  'LOGIN_SUCCEEDED')
                        """).update();

        assertThat(appJdbc.sql("SELECT purge_audit_events(180)").query(Long.class).single()).isEqualTo(1L);
        assertThat(count("audit_events")).isEqualTo(1);

        assertThatThrownBy(() -> appJdbc.sql("SELECT purge_audit_events(1)").query(Long.class).single())
                .hasMessageContaining("at least 30 days");
        assertThat(count("audit_events")).isEqualTo(1);
    }

    @Test
    void scheduledPurgeUsesConfiguredRetention() {
        jdbc.sql("INSERT INTO audit_events (occurred_at, event_type) VALUES (now() - interval '100 days', 'LOGOUT')")
                .update();
        new JdbcAuditLog(appJdbc, Clock.systemUTC(), 90).purgeExpired();
        assertThat(count("audit_events")).isZero();
    }

    @Test
    void oversizedValuesAreTruncatedInsteadOfFailingTheLogin() {
        new JdbcAuditLog(appJdbc, Clock.systemUTC(), 180)
                .record(AuditEvent.of(EventType.RATE_LIMITED).reason("x".repeat(500)).ip("y".repeat(500)));
        assertThat(count("audit_events")).isEqualTo(1);
    }

    // ---------------- helpers ----------------

    private static long count(String table) {
        return jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single();
    }

    /** PostgreSQL itself must refuse: "permission denied" (no privilege) or "must be owner" (schema change). */
    private static void assertDenied(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).satisfies(e ->
                assertThat(NestedExceptionUtils.getMostSpecificCause(e).getMessage())
                        .containsAnyOf("permission denied", "must be owner"));
    }

    private RefreshToken token(String hash, User user, String family) {
        return RefreshToken.issue(hash, user.id(), family, now, now.plus(Duration.ofDays(30)));
    }

    private static <T> List<T> runConcurrently(int threads, Callable<T> task) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<T>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return task.call();
                }));
            }
            start.countDown();
            List<T> results = new ArrayList<>();
            for (Future<T> f : futures) {
                results.add(f.get());
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }
}

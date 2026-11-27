package com.myapp.auth.infrastructure.persistence.jdbc;

import com.myapp.auth.application.port.out.RefreshTokenStore;
import com.myapp.auth.domain.model.RefreshToken;
import com.myapp.auth.domain.model.UserId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

/**
 * PostgreSQL adapter for {@link RefreshTokenStore}.
 * <p>
 * {@link #markUsed} must be atomic: two requests replaying the same token at the same moment must not both
 * succeed. It is a single statement that locks the row ({@code FOR UPDATE}), so the second request waits,
 * then sees {@code used = true} and triggers reuse detection. This holds across any number of app instances.
 */
public final class JdbcRefreshTokenStore implements RefreshTokenStore {

    private static final Logger log = LoggerFactory.getLogger(JdbcRefreshTokenStore.class);

    /** Keep expired rows a little longer so a late replay is still recognised (and logged) as reuse. */
    private static final Duration PURGE_GRACE = Duration.ofDays(1);

    private static final String COLUMNS = "token_hash, user_id, family_id, issued_at, expires_at, used, revoked";

    private static final RowMapper<RefreshToken> MAPPER = (rs, rowNum) -> new RefreshToken(
            rs.getString("token_hash"),
            new UserId(rs.getObject("user_id", UUID.class)),
            rs.getString("family_id"),
            SqlTime.fromDb(rs, "issued_at"),
            SqlTime.fromDb(rs, "expires_at"),
            rs.getBoolean("used"),
            rs.getBoolean("revoked"));

    private final JdbcClient jdbc;
    private final Clock clock;

    public JdbcRefreshTokenStore(JdbcClient jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    @Override
    public void save(RefreshToken token) {
        jdbc.sql("""
                        INSERT INTO refresh_tokens (token_hash, user_id, family_id, issued_at, expires_at, used, revoked)
                        VALUES (:hash, :userId, :familyId, :issuedAt, :expiresAt, :used, :revoked)
                        """)
                .param("hash", token.tokenHash())
                .param("userId", token.userId().value())
                .param("familyId", token.familyId())
                .param("issuedAt", SqlTime.toDb(token.issuedAt()))
                .param("expiresAt", SqlTime.toDb(token.expiresAt()))
                .param("used", token.used())
                .param("revoked", token.revoked())
                .update();
    }

    @Override
    public Optional<RefreshToken> findByHash(String tokenHash) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM refresh_tokens WHERE token_hash = :hash")
                .param("hash", tokenHash)
                .query(MAPPER)
                .optional();
    }

    @Override
    public Optional<RefreshToken> markUsed(String tokenHash) {
        // Returns the row as it was BEFORE the update (prev.used), in one atomic statement.
        return jdbc.sql("""
                        WITH prev AS (
                            SELECT token_hash, used
                              FROM refresh_tokens
                             WHERE token_hash = :hash
                               FOR UPDATE
                        )
                        UPDATE refresh_tokens t
                           SET used = TRUE
                          FROM prev
                         WHERE t.token_hash = prev.token_hash
                     RETURNING t.token_hash, t.user_id, t.family_id, t.issued_at, t.expires_at,
                               prev.used AS used, t.revoked
                        """)
                .param("hash", tokenHash)
                .query(MAPPER)
                .optional();
    }

    @Override
    public void revokeFamily(String familyId) {
        jdbc.sql("UPDATE refresh_tokens SET revoked = TRUE WHERE family_id = :familyId AND revoked = FALSE")
                .param("familyId", familyId)
                .update();
    }

    /** Housekeeping. Safe to run on every instance at once: deleting already-deleted rows is a no-op. */
    @Scheduled(fixedDelayString = "PT1H", initialDelayString = "PT1M")
    void purgeExpired() {
        int deleted = jdbc.sql("DELETE FROM refresh_tokens WHERE expires_at < :cutoff")
                .param("cutoff", SqlTime.toDb(clock.instant().minus(PURGE_GRACE)))
                .update();
        if (deleted > 0) {
            log.info("Purged {} expired refresh tokens", deleted);
        }
    }
}

package com.myapp.auth.infrastructure.persistence.jdbc;

import com.myapp.auth.application.port.out.UserRepository;
import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.domain.model.IdentityProvider;
import com.myapp.auth.domain.model.User;
import com.myapp.auth.domain.model.UserId;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.util.Optional;
import java.util.UUID;

/**
 * PostgreSQL adapter for {@link UserRepository}.
 * <p>
 * Every query uses bound parameters (never string concatenation), so SQL injection is not possible.
 * Concurrency is handled by the database: {@code ON CONFLICT DO NOTHING} on the unique keys makes
 * "create user" and "link identity" race-safe across threads AND across multiple app instances.
 */
public final class JdbcUserRepository implements UserRepository {

    private static final String USER_COLUMNS = "u.id, u.email, u.created_at";

    private static final RowMapper<User> USER_MAPPER = (rs, rowNum) -> new User(
            new UserId(rs.getObject("id", UUID.class)),
            new EmailAddress(rs.getString("email")),
            SqlTime.fromDb(rs, "created_at"));

    private final JdbcClient jdbc;

    public JdbcUserRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<User> findById(UserId id) {
        return jdbc.sql("SELECT " + USER_COLUMNS + " FROM users u WHERE u.id = :id")
                .param("id", id.value())
                .query(USER_MAPPER)
                .optional();
    }

    @Override
    public Optional<User> findByEmail(EmailAddress email) {
        return jdbc.sql("SELECT " + USER_COLUMNS + " FROM users u WHERE u.email = :email")
                .param("email", email.value())
                .query(USER_MAPPER)
                .optional();
    }

    @Override
    public User saveIfAbsent(User user) {
        jdbc.sql("""
                        INSERT INTO users (id, email, created_at)
                        VALUES (:id, :email, :createdAt)
                        ON CONFLICT (email) DO NOTHING
                        """)
                .param("id", user.id().value())
                .param("email", user.email().value())
                .param("createdAt", SqlTime.toDb(user.createdAt()))
                .update();
        // Whoever won the race, this returns the single row that now exists for the email.
        return findByEmail(user.email())
                .orElseThrow(() -> new IllegalStateException("User row missing after insert"));
    }

    @Override
    public Optional<User> findByExternalIdentity(IdentityProvider provider, String subject) {
        return jdbc.sql("SELECT " + USER_COLUMNS + """
                         FROM user_identities i
                         JOIN users u ON u.id = i.user_id
                        WHERE i.provider = :provider AND i.subject = :subject
                        """)
                .param("provider", provider.name())
                .param("subject", subject)
                .query(USER_MAPPER)
                .optional();
    }

    @Override
    public void linkExternalIdentity(UserId userId, IdentityProvider provider, String subject) {
        jdbc.sql("""
                        INSERT INTO user_identities (provider, subject, user_id)
                        VALUES (:provider, :subject, :userId)
                        ON CONFLICT (provider, subject) DO NOTHING
                        """)
                .param("provider", provider.name())
                .param("subject", subject)
                .param("userId", userId.value())
                .update();
    }
}

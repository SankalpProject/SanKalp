package com.myapp.auth.infrastructure.persistence;

import com.myapp.auth.application.port.out.UserRepository;
import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.domain.model.IdentityProvider;
import com.myapp.auth.domain.model.User;
import com.myapp.auth.domain.model.UserId;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Dev/test adapter. In production, implement {@link UserRepository} with JPA/JDBC on PostgreSQL
 * (unique index on email makes {@link #saveIfAbsent} race-safe).
 */
public final class InMemoryUserRepository implements UserRepository {

    private final ConcurrentMap<String, User> byEmail = new ConcurrentHashMap<>();
    private final ConcurrentMap<UserId, User> byId = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, UserId> byExternalIdentity = new ConcurrentHashMap<>();

    @Override
    public Optional<User> findById(UserId id) {
        return Optional.ofNullable(byId.get(id));
    }

    @Override
    public Optional<User> findByEmail(EmailAddress email) {
        return Optional.ofNullable(byEmail.get(email.value()));
    }

    @Override
    public User saveIfAbsent(User user) {
        return byEmail.computeIfAbsent(user.email().value(), key -> {
            byId.put(user.id(), user);
            return user;
        });
    }

    @Override
    public Optional<User> findByExternalIdentity(IdentityProvider provider, String subject) {
        return Optional.ofNullable(byExternalIdentity.get(key(provider, subject))).flatMap(this::findById);
    }

    @Override
    public void linkExternalIdentity(UserId userId, IdentityProvider provider, String subject) {
        byExternalIdentity.putIfAbsent(key(provider, subject), userId);
    }

    private static String key(IdentityProvider provider, String subject) {
        return provider.name() + ":" + subject;
    }
}

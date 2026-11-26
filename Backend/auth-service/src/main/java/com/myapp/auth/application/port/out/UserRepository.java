package com.myapp.auth.application.port.out;

import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.domain.model.IdentityProvider;
import com.myapp.auth.domain.model.User;
import com.myapp.auth.domain.model.UserId;

import java.util.Optional;

/**
 * Production: PostgreSQL tables {@code users(id, email UNIQUE, created_at)} and
 * {@code user_identities(provider, subject, user_id, PRIMARY KEY(provider, subject))}.
 */
public interface UserRepository {

    Optional<User> findById(UserId id);

    Optional<User> findByEmail(EmailAddress email);

    /** Returns the existing user for this email if one was created concurrently, else the saved user. */
    User saveIfAbsent(User user);

    Optional<User> findByExternalIdentity(IdentityProvider provider, String subject);

    /** Links a provider account to a user. Idempotent. */
    void linkExternalIdentity(UserId userId, IdentityProvider provider, String subject);
}

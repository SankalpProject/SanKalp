package com.myapp.auth.domain.model;

import java.time.Instant;
import java.util.Objects;

/** A user account. The email is always a verified address (via OTP or a provider that verified it). */
public record User(UserId id, EmailAddress email, Instant createdAt) {

    public User {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(email, "email");
        Objects.requireNonNull(createdAt, "createdAt");
    }

    /** Passwordless sign-up: the first successful sign-in registers the user. */
    public static User register(EmailAddress email, Instant now) {
        return new User(UserId.newId(), email, now);
    }
}

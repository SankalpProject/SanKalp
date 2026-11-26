package com.myapp.auth.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * A pending one-time-password challenge for an email address.
 * <p>
 * Only a keyed hash of the code is stored, so a leak of the store does not leak usable codes.
 * {@code attempts} counts every verification attempt (reserved before the code is compared),
 * which makes the attempt limit hold even under concurrent requests.
 */
public record OtpChallenge(EmailAddress email, String codeHash, Instant createdAt, Instant expiresAt, int attempts) {

    public OtpChallenge {
        Objects.requireNonNull(email, "email");
        Objects.requireNonNull(codeHash, "codeHash");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }

    public static OtpChallenge issue(EmailAddress email, String codeHash, Instant now, Duration ttl) {
        return new OtpChallenge(email, codeHash, now, now.plus(ttl), 0);
    }

    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }

    public Instant resendAvailableAt(Duration cooldown) {
        return createdAt.plus(cooldown);
    }

    public OtpChallenge withAttemptRegistered() {
        return new OtpChallenge(email, codeHash, createdAt, expiresAt, attempts + 1);
    }
}

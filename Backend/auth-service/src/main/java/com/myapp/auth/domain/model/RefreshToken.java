package com.myapp.auth.domain.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Server-side record of an issued refresh token.
 * <p>
 * Refresh tokens are opaque random strings; only their keyed hash is persisted.
 * Tokens rotate on every use. All tokens descending from one login share a {@code familyId},
 * so if an already-used token is presented again (a sign of theft) the whole family is revoked.
 */
public record RefreshToken(
        String tokenHash,
        UserId userId,
        String familyId,
        Instant issuedAt,
        Instant expiresAt,
        boolean used,
        boolean revoked) {

    public RefreshToken {
        Objects.requireNonNull(tokenHash, "tokenHash");
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(familyId, "familyId");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }

    public static RefreshToken issue(String tokenHash, UserId userId, String familyId, Instant now, Instant expiresAt) {
        return new RefreshToken(tokenHash, userId, familyId, now, expiresAt, false, false);
    }

    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }

    public RefreshToken markUsed() {
        return new RefreshToken(tokenHash, userId, familyId, issuedAt, expiresAt, true, revoked);
    }

    public RefreshToken revoke() {
        return new RefreshToken(tokenHash, userId, familyId, issuedAt, expiresAt, used, true);
    }
}

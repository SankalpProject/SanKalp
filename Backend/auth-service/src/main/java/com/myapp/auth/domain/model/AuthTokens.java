package com.myapp.auth.domain.model;

import java.time.Instant;

/** Result of a successful login or refresh. */
public record AuthTokens(
        String accessToken,
        Instant accessTokenExpiresAt,
        String refreshToken,
        Instant refreshTokenExpiresAt) {

    @Override
    public String toString() {
        // Never print secrets.
        return "AuthTokens[accessTokenExpiresAt=" + accessTokenExpiresAt
                + ", refreshTokenExpiresAt=" + refreshTokenExpiresAt + "]";
    }
}

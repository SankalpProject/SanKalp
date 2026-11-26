package com.myapp.auth.application.port.out;

import com.myapp.auth.domain.model.User;

import java.time.Instant;

/** Issues short-lived, signed access tokens (JWT in the default adapter). */
public interface AccessTokenIssuer {

    IssuedAccessToken issue(User user, Instant now);

    record IssuedAccessToken(String value, Instant expiresAt) {
    }
}

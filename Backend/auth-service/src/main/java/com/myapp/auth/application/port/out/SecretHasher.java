package com.myapp.auth.application.port.out;

/** Deterministic keyed hash for short-lived secrets (OTP codes, refresh tokens). */
public interface SecretHasher {

    String hash(String secret);

    /** Must use a constant-time comparison to prevent timing attacks. */
    boolean matches(String secret, String expectedHash);
}

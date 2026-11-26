package com.myapp.auth.application.port.out;

import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.domain.model.OtpChallenge;

import java.time.Instant;
import java.util.Optional;

/**
 * Storage for pending OTP challenges (one active challenge per email).
 * Production implementation: Redis with key TTL; {@link #registerAttempt} maps to an atomic HINCRBY / Lua script.
 */
public interface OtpChallengeStore {

    /** Stores the challenge, replacing any previous one for the same email. */
    void save(OtpChallenge challenge);

    Optional<OtpChallenge> find(EmailAddress email);

    /**
     * Atomically increments the attempt counter of the active (non-expired) challenge
     * and returns the updated challenge, or empty if there is none.
     */
    Optional<OtpChallenge> registerAttempt(EmailAddress email, Instant now);

    /** Atomically removes the challenge. Returns true only for the caller that actually removed it. */
    boolean delete(EmailAddress email);
}

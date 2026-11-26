package com.myapp.auth.infrastructure.persistence;

import com.myapp.auth.application.port.out.OtpChallengeStore;
import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.domain.model.OtpChallenge;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Single-node adapter for local development and tests.
 * For multiple instances, replace with a Redis adapter (same port, no other code changes).
 */
public final class InMemoryOtpChallengeStore implements OtpChallengeStore {

    private final ConcurrentMap<String, OtpChallenge> challenges = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryOtpChallengeStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void save(OtpChallenge challenge) {
        challenges.put(challenge.email().value(), challenge);
    }

    @Override
    public Optional<OtpChallenge> find(EmailAddress email) {
        return Optional.ofNullable(challenges.get(email.value()));
    }

    @Override
    public Optional<OtpChallenge> registerAttempt(EmailAddress email, Instant now) {
        AtomicReference<OtpChallenge> updated = new AtomicReference<>();
        challenges.computeIfPresent(email.value(), (key, current) -> {
            if (current.isExpired(now)) {
                return null; // remove expired entry
            }
            OtpChallenge next = current.withAttemptRegistered();
            updated.set(next);
            return next;
        });
        return Optional.ofNullable(updated.get());
    }

    @Override
    public boolean delete(EmailAddress email) {
        return challenges.remove(email.value()) != null;
    }

    @Scheduled(fixedDelayString = "PT1M")
    void purgeExpired() {
        Instant now = clock.instant();
        challenges.values().removeIf(c -> c.isExpired(now));
    }
}

package com.myapp.auth.infrastructure.persistence;

import com.myapp.auth.application.port.out.RefreshTokenStore;
import com.myapp.auth.domain.model.RefreshToken;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;

/** Dev/test adapter. Production: PostgreSQL table (token_hash PK, family_id index) or Redis. */
public final class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private final ConcurrentMap<String, RefreshToken> tokens = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryRefreshTokenStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void save(RefreshToken token) {
        tokens.put(token.tokenHash(), token);
    }

    @Override
    public Optional<RefreshToken> findByHash(String tokenHash) {
        return Optional.ofNullable(tokens.get(tokenHash));
    }

    @Override
    public Optional<RefreshToken> markUsed(String tokenHash) {
        AtomicReference<RefreshToken> before = new AtomicReference<>();
        tokens.computeIfPresent(tokenHash, (key, current) -> {
            before.set(current);
            return current.markUsed();
        });
        return Optional.ofNullable(before.get());
    }

    @Override
    public void revokeFamily(String familyId) {
        tokens.replaceAll((key, token) -> token.familyId().equals(familyId) ? token.revoke() : token);
    }

    @Scheduled(fixedDelayString = "PT10M")
    void purgeExpired() {
        Instant now = clock.instant();
        tokens.values().removeIf(t -> t.isExpired(now));
    }
}

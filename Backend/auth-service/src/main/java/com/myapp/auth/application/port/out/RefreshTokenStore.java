package com.myapp.auth.application.port.out;

import com.myapp.auth.domain.model.RefreshToken;

import java.util.Optional;

public interface RefreshTokenStore {

    void save(RefreshToken token);

    Optional<RefreshToken> findByHash(String tokenHash);

    /**
     * Atomically marks the token as used and returns its state from BEFORE the update.
     * If the returned token already has {@code used == true}, the token is being replayed.
     */
    Optional<RefreshToken> markUsed(String tokenHash);

    void revokeFamily(String familyId);
}

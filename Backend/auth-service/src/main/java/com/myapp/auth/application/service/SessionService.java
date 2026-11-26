package com.myapp.auth.application.service;

import com.myapp.auth.application.port.in.LogoutUseCase;
import com.myapp.auth.application.port.in.RefreshTokenUseCase;
import com.myapp.auth.application.port.out.RefreshTokenStore;
import com.myapp.auth.application.port.out.SecretHasher;
import com.myapp.auth.application.port.out.UserRepository;
import com.myapp.auth.domain.exception.AuthException;
import com.myapp.auth.domain.model.AuthTokens;
import com.myapp.auth.domain.model.RefreshToken;
import com.myapp.auth.domain.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;

/**
 * Refresh-token rotation with reuse detection (OAuth 2.0 Security BCP), and logout.
 */
public final class SessionService implements RefreshTokenUseCase, LogoutUseCase {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final RefreshTokenStore refreshTokenStore;
    private final UserRepository userRepository;
    private final TokenPairIssuer tokenPairIssuer;
    private final SecretHasher hasher;
    private final RateLimitGuard rateLimitGuard;
    private final TokenPolicy policy;
    private final Clock clock;

    public SessionService(RefreshTokenStore refreshTokenStore,
                          UserRepository userRepository,
                          TokenPairIssuer tokenPairIssuer,
                          SecretHasher hasher,
                          RateLimitGuard rateLimitGuard,
                          TokenPolicy policy,
                          Clock clock) {
        this.refreshTokenStore = refreshTokenStore;
        this.userRepository = userRepository;
        this.tokenPairIssuer = tokenPairIssuer;
        this.hasher = hasher;
        this.rateLimitGuard = rateLimitGuard;
        this.policy = policy;
        this.clock = clock;
    }

    @Override
    public AuthTokens refresh(RefreshCommand command) {
        rateLimitGuard.check("token:refresh:ip:" + command.clientIp(), policy.refreshPerIp());
        Instant now = clock.instant();

        RefreshToken previous = refreshTokenStore.markUsed(hasher.hash(command.refreshToken()))
                .orElseThrow(AuthException::invalidRefreshToken);

        if (previous.used()) {
            // The token was already rotated: either an attacker or the legitimate client is replaying it.
            // We cannot tell which, so kill the whole session family.
            refreshTokenStore.revokeFamily(previous.familyId());
            log.warn("Refresh token reuse detected, session family revoked userId={}", previous.userId());
            throw AuthException.invalidRefreshToken();
        }
        if (previous.revoked() || previous.isExpired(now)) {
            throw AuthException.invalidRefreshToken();
        }

        User user = userRepository.findById(previous.userId()).orElseThrow(AuthException::invalidRefreshToken);
        return tokenPairIssuer.rotate(user, previous.familyId(), now);
    }

    @Override
    public void logout(String refreshToken) {
        refreshTokenStore.findByHash(hasher.hash(refreshToken)).ifPresent(token -> {
            refreshTokenStore.revokeFamily(token.familyId());
            log.info("Session logged out userId={}", token.userId());
        });
    }
}

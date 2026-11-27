package com.myapp.auth.application.service;

import com.myapp.auth.application.port.in.LogoutUseCase;
import com.myapp.auth.application.port.in.RefreshTokenUseCase;
import com.myapp.auth.application.port.out.AuditLog;
import com.myapp.auth.application.port.out.AuditLog.AuditEvent;
import com.myapp.auth.application.port.out.AuditLog.EventType;
import com.myapp.auth.application.port.out.RefreshTokenStore;
import com.myapp.auth.application.port.out.SecretHasher;
import com.myapp.auth.application.port.out.UserRepository;
import com.myapp.auth.domain.exception.AuthException;
import com.myapp.auth.domain.model.AuthTokens;
import com.myapp.auth.domain.model.RefreshToken;
import com.myapp.auth.domain.model.User;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * Refresh-token rotation with reuse detection (OAuth 2.0 Security BCP), and logout.
 */
public final class SessionService implements RefreshTokenUseCase, LogoutUseCase {

    private final RefreshTokenStore refreshTokenStore;
    private final UserRepository userRepository;
    private final TokenPairIssuer tokenPairIssuer;
    private final SecretHasher hasher;
    private final RateLimitGuard rateLimitGuard;
    private final AuditLog auditLog;
    private final TokenPolicy policy;
    private final Clock clock;

    public SessionService(RefreshTokenStore refreshTokenStore,
                          UserRepository userRepository,
                          TokenPairIssuer tokenPairIssuer,
                          SecretHasher hasher,
                          RateLimitGuard rateLimitGuard,
                          AuditLog auditLog,
                          TokenPolicy policy,
                          Clock clock) {
        this.refreshTokenStore = refreshTokenStore;
        this.userRepository = userRepository;
        this.tokenPairIssuer = tokenPairIssuer;
        this.hasher = hasher;
        this.rateLimitGuard = rateLimitGuard;
        this.auditLog = auditLog;
        this.policy = policy;
        this.clock = clock;
    }

    @Override
    public AuthTokens refresh(RefreshCommand command) {
        String ip = command.clientIp();
        rateLimitGuard.check("refresh_per_ip", ip, policy.refreshPerIp(), ip);
        Instant now = clock.instant();

        Optional<RefreshToken> found = refreshTokenStore.markUsed(hasher.hash(command.refreshToken()));
        if (found.isEmpty()) {
            fail(null, ip, "unknown_token");
        }
        RefreshToken previous = found.get();

        if (previous.used()) {
            // The token was already rotated: either an attacker or the legitimate client is replaying it.
            // We cannot tell which, so kill the whole session family.
            refreshTokenStore.revokeFamily(previous.familyId());
            auditLog.record(AuditEvent.of(EventType.TOKEN_REUSE_DETECTED).user(previous.userId()).ip(ip)
                    .reason("family_revoked"));
            throw AuthException.invalidRefreshToken();
        }
        if (previous.revoked()) {
            fail(previous, ip, "revoked");
        }
        if (previous.isExpired(now)) {
            fail(previous, ip, "expired");
        }

        Optional<User> user = userRepository.findById(previous.userId());
        if (user.isEmpty()) {
            fail(previous, ip, "user_not_found");
        }
        auditLog.record(AuditEvent.of(EventType.TOKEN_REFRESHED).user(previous.userId()).ip(ip));
        return tokenPairIssuer.rotate(user.get(), previous.familyId(), now);
    }

    @Override
    public void logout(String refreshToken) {
        refreshTokenStore.findByHash(hasher.hash(refreshToken)).ifPresent(token -> {
            refreshTokenStore.revokeFamily(token.familyId());
            auditLog.record(AuditEvent.of(EventType.LOGOUT).user(token.userId()));
        });
    }

    private void fail(RefreshToken token, String ip, String reason) {
        auditLog.record(AuditEvent.of(EventType.TOKEN_REFRESH_FAILED)
                .user(token == null ? null : token.userId()).ip(ip).reason(reason));
        throw AuthException.invalidRefreshToken();
    }
}

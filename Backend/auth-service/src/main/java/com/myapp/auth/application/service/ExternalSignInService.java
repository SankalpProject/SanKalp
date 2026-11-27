package com.myapp.auth.application.service;

import com.myapp.auth.application.port.in.ExternalSignInUseCase;
import com.myapp.auth.application.port.out.AuditLog;
import com.myapp.auth.application.port.out.AuditLog.AuditEvent;
import com.myapp.auth.application.port.out.AuditLog.EventType;
import com.myapp.auth.application.port.out.ExternalIdentityVerifier;
import com.myapp.auth.application.port.out.RateLimiter;
import com.myapp.auth.application.port.out.UserRepository;
import com.myapp.auth.domain.exception.AuthException;
import com.myapp.auth.domain.model.AuthTokens;
import com.myapp.auth.domain.model.ExternalIdentity;
import com.myapp.auth.domain.model.IdentityProvider;
import com.myapp.auth.domain.model.User;

import java.time.Clock;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Signs a user in with a verified provider ID token and issues OUR tokens (the provider token is not reused).
 * <p>
 * Account resolution:
 * <ol>
 *   <li>known provider account (provider + subject) → that user;</li>
 *   <li>otherwise link to the existing user with the same email — ONLY if the provider says the email is
 *       verified (prevents account takeover via an unverified email claim);</li>
 *   <li>otherwise register a new user.</li>
 * </ol>
 * New providers (Apple) only need a new {@link ExternalIdentityVerifier} — this class does not change.
 */
public final class ExternalSignInService implements ExternalSignInUseCase {

    private final Map<IdentityProvider, ExternalIdentityVerifier> verifiers = new EnumMap<>(IdentityProvider.class);
    private final UserRepository userRepository;
    private final TokenPairIssuer tokenPairIssuer;
    private final RateLimitGuard rateLimitGuard;
    private final AuditLog auditLog;
    private final RateLimiter.Rule perIpRule;
    private final Clock clock;

    public ExternalSignInService(List<ExternalIdentityVerifier> verifiers,
                                 UserRepository userRepository,
                                 TokenPairIssuer tokenPairIssuer,
                                 RateLimitGuard rateLimitGuard,
                                 AuditLog auditLog,
                                 RateLimiter.Rule perIpRule,
                                 Clock clock) {
        verifiers.forEach(v -> this.verifiers.put(v.provider(), v));
        this.userRepository = userRepository;
        this.tokenPairIssuer = tokenPairIssuer;
        this.rateLimitGuard = rateLimitGuard;
        this.auditLog = auditLog;
        this.perIpRule = perIpRule;
        this.clock = clock;
    }

    @Override
    public AuthTokens signIn(ExternalSignInCommand command) {
        String ip = command.clientIp();
        String method = command.provider().name().toLowerCase(Locale.ROOT);
        rateLimitGuard.check("external_sign_in_per_ip", ip, perIpRule, ip);

        ExternalIdentityVerifier verifier = verifiers.get(command.provider());
        if (verifier == null) {
            auditLog.record(AuditEvent.of(EventType.LOGIN_FAILED).method(method).ip(ip).reason("provider_disabled"));
            throw AuthException.invalidExternalToken();
        }

        ExternalIdentity identity;
        try {
            identity = verifier.verify(command.idToken());
        } catch (AuthException e) {
            auditLog.record(AuditEvent.of(EventType.LOGIN_FAILED).method(method).ip(ip).reason("invalid_token"));
            throw e;
        }
        if (!identity.emailVerified()) {
            auditLog.record(AuditEvent.of(EventType.LOGIN_FAILED).method(method).email(identity.email()).ip(ip)
                    .reason("email_not_verified"));
            throw AuthException.externalEmailNotVerified();
        }

        Instant now = clock.instant();
        User user = userRepository.findByExternalIdentity(identity.provider(), identity.subject())
                .orElseGet(() -> linkOrRegister(identity, method, ip, now));

        auditLog.record(AuditEvent.of(EventType.LOGIN_SUCCEEDED).method(method).user(user.id())
                .email(identity.email()).ip(ip));
        return tokenPairIssuer.issueNewSession(user, now);
    }

    private User linkOrRegister(ExternalIdentity identity, String method, String ip, Instant now) {
        User user = userRepository.findByEmail(identity.email()).orElseGet(() -> {
            User created = userRepository.saveIfAbsent(User.register(identity.email(), now));
            auditLog.record(AuditEvent.of(EventType.USER_REGISTERED).method(method).user(created.id())
                    .email(identity.email()).ip(ip));
            return created;
        });
        userRepository.linkExternalIdentity(user.id(), identity.provider(), identity.subject());
        auditLog.record(AuditEvent.of(EventType.ACCOUNT_LINKED).method(method).user(user.id())
                .email(identity.email()).ip(ip));
        return user;
    }
}

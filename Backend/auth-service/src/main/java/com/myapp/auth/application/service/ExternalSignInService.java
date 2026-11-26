package com.myapp.auth.application.service;

import com.myapp.auth.application.port.in.ExternalSignInUseCase;
import com.myapp.auth.application.port.out.ExternalIdentityVerifier;
import com.myapp.auth.application.port.out.RateLimiter;
import com.myapp.auth.application.port.out.UserRepository;
import com.myapp.auth.domain.exception.AuthException;
import com.myapp.auth.domain.model.AuthTokens;
import com.myapp.auth.domain.model.ExternalIdentity;
import com.myapp.auth.domain.model.IdentityProvider;
import com.myapp.auth.domain.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
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

    private static final Logger log = LoggerFactory.getLogger(ExternalSignInService.class);

    private final Map<IdentityProvider, ExternalIdentityVerifier> verifiers = new EnumMap<>(IdentityProvider.class);
    private final UserRepository userRepository;
    private final TokenPairIssuer tokenPairIssuer;
    private final RateLimitGuard rateLimitGuard;
    private final RateLimiter.Rule perIpRule;
    private final Clock clock;

    public ExternalSignInService(List<ExternalIdentityVerifier> verifiers,
                                 UserRepository userRepository,
                                 TokenPairIssuer tokenPairIssuer,
                                 RateLimitGuard rateLimitGuard,
                                 RateLimiter.Rule perIpRule,
                                 Clock clock) {
        verifiers.forEach(v -> this.verifiers.put(v.provider(), v));
        this.userRepository = userRepository;
        this.tokenPairIssuer = tokenPairIssuer;
        this.rateLimitGuard = rateLimitGuard;
        this.perIpRule = perIpRule;
        this.clock = clock;
    }

    @Override
    public AuthTokens signIn(ExternalSignInCommand command) {
        rateLimitGuard.check("external:signin:ip:" + command.clientIp(), perIpRule);

        ExternalIdentityVerifier verifier = verifiers.get(command.provider());
        if (verifier == null) {
            throw AuthException.invalidExternalToken();
        }
        ExternalIdentity identity = verifier.verify(command.idToken());
        if (!identity.emailVerified()) {
            throw AuthException.externalEmailNotVerified();
        }

        Instant now = clock.instant();
        User user = userRepository.findByExternalIdentity(identity.provider(), identity.subject())
                .orElseGet(() -> linkOrRegister(identity, now));

        log.info("External sign-in provider={} userId={}", identity.provider(), user.id());
        return tokenPairIssuer.issueNewSession(user, now);
    }

    private User linkOrRegister(ExternalIdentity identity, Instant now) {
        User user = userRepository.findByEmail(identity.email())
                .orElseGet(() -> userRepository.saveIfAbsent(User.register(identity.email(), now)));
        userRepository.linkExternalIdentity(user.id(), identity.provider(), identity.subject());
        return user;
    }
}

package com.myapp.auth.application.service;

import com.myapp.auth.application.port.in.VerifyOtpUseCase;
import com.myapp.auth.application.port.out.OtpChallengeStore;
import com.myapp.auth.application.port.out.SecretHasher;
import com.myapp.auth.application.port.out.UserRepository;
import com.myapp.auth.domain.exception.AuthException;
import com.myapp.auth.domain.model.AuthTokens;
import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.domain.model.OtpChallenge;
import com.myapp.auth.domain.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;

/**
 * Verifies an email OTP and signs the user in (registering them on first login).
 * <p>
 * Brute-force protection:
 * <ul>
 *   <li>an attempt is reserved atomically <em>before</em> the code is compared, so parallel requests
 *       cannot exceed {@code maxAttempts} guesses per challenge;</li>
 *   <li>the challenge is destroyed after the last allowed attempt or on success (single use);</li>
 *   <li>additional per-IP and per-email rate limits.</li>
 * </ul>
 */
public final class VerifyOtpService implements VerifyOtpUseCase {

    private static final Logger log = LoggerFactory.getLogger(VerifyOtpService.class);

    private final OtpChallengeStore challengeStore;
    private final SecretHasher hasher;
    private final UserRepository userRepository;
    private final TokenPairIssuer tokenPairIssuer;
    private final RateLimitGuard rateLimitGuard;
    private final OtpPolicy policy;
    private final Clock clock;

    public VerifyOtpService(OtpChallengeStore challengeStore,
                            SecretHasher hasher,
                            UserRepository userRepository,
                            TokenPairIssuer tokenPairIssuer,
                            RateLimitGuard rateLimitGuard,
                            OtpPolicy policy,
                            Clock clock) {
        this.challengeStore = challengeStore;
        this.hasher = hasher;
        this.userRepository = userRepository;
        this.tokenPairIssuer = tokenPairIssuer;
        this.rateLimitGuard = rateLimitGuard;
        this.policy = policy;
        this.clock = clock;
    }

    @Override
    public AuthTokens verifyOtp(VerifyOtpCommand command) {
        EmailAddress email = command.email();
        rateLimitGuard.check("otp:verify:ip:" + command.clientIp(), policy.verifyPerIp());
        rateLimitGuard.check("otp:verify:email:" + email.value(), policy.verifyPerEmail());

        Instant now = clock.instant();
        OtpChallenge challenge = challengeStore.registerAttempt(email, now)
                .orElseThrow(AuthException::invalidOtp);

        if (challenge.attempts() > policy.maxAttempts()) {
            challengeStore.delete(email);
            throw AuthException.attemptsExceeded();
        }

        if (!OtpCodeHashing.matches(hasher, email, command.code(), challenge.codeHash())) {
            log.info("OTP verification failed email={} attempt={}", email, challenge.attempts());
            if (challenge.attempts() >= policy.maxAttempts()) {
                challengeStore.delete(email);
                throw AuthException.attemptsExceeded();
            }
            throw AuthException.invalidOtp();
        }

        // Single use: only the request that actually removes the challenge may proceed.
        if (!challengeStore.delete(email)) {
            throw AuthException.invalidOtp();
        }

        // The OTP proves ownership of the mailbox, so this email is verified.
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> userRepository.saveIfAbsent(User.register(email, now)));

        log.info("Email OTP verified, session started userId={}", user.id());
        return tokenPairIssuer.issueNewSession(user, now);
    }
}

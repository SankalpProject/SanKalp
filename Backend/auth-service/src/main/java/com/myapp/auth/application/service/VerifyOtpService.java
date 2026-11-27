package com.myapp.auth.application.service;

import com.myapp.auth.application.port.in.VerifyOtpUseCase;
import com.myapp.auth.application.port.out.AuditLog;
import com.myapp.auth.application.port.out.AuditLog.AuditEvent;
import com.myapp.auth.application.port.out.AuditLog.EventType;
import com.myapp.auth.application.port.out.OtpChallengeStore;
import com.myapp.auth.application.port.out.SecretHasher;
import com.myapp.auth.application.port.out.UserRepository;
import com.myapp.auth.domain.exception.AuthException;
import com.myapp.auth.domain.model.AuthTokens;
import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.domain.model.OtpChallenge;
import com.myapp.auth.domain.model.User;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

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

    private static final String METHOD = "email_otp";

    private final OtpChallengeStore challengeStore;
    private final SecretHasher hasher;
    private final UserRepository userRepository;
    private final TokenPairIssuer tokenPairIssuer;
    private final RateLimitGuard rateLimitGuard;
    private final AuditLog auditLog;
    private final OtpPolicy policy;
    private final Clock clock;

    public VerifyOtpService(OtpChallengeStore challengeStore,
                            SecretHasher hasher,
                            UserRepository userRepository,
                            TokenPairIssuer tokenPairIssuer,
                            RateLimitGuard rateLimitGuard,
                            AuditLog auditLog,
                            OtpPolicy policy,
                            Clock clock) {
        this.challengeStore = challengeStore;
        this.hasher = hasher;
        this.userRepository = userRepository;
        this.tokenPairIssuer = tokenPairIssuer;
        this.rateLimitGuard = rateLimitGuard;
        this.auditLog = auditLog;
        this.policy = policy;
        this.clock = clock;
    }

    @Override
    public AuthTokens verifyOtp(VerifyOtpCommand command) {
        EmailAddress email = command.email();
        String ip = command.clientIp();
        rateLimitGuard.check("otp_verify_per_ip", ip, policy.verifyPerIp(), ip);
        rateLimitGuard.check("otp_verify_per_email", email.value(), policy.verifyPerEmail(), ip);

        Instant now = clock.instant();
        Optional<OtpChallenge> reserved = challengeStore.registerAttempt(email, now);
        if (reserved.isEmpty()) {
            audit(EventType.LOGIN_FAILED, email, ip, "no_active_code");
            throw AuthException.invalidOtp();
        }
        OtpChallenge challenge = reserved.get();

        if (challenge.attempts() > policy.maxAttempts()) {
            challengeStore.delete(email);
            audit(EventType.OTP_LOCKED, email, ip, "max_attempts");
            throw AuthException.attemptsExceeded();
        }

        if (!OtpCodeHashing.matches(hasher, email, command.code(), challenge.codeHash())) {
            if (challenge.attempts() >= policy.maxAttempts()) {
                challengeStore.delete(email);
                audit(EventType.OTP_LOCKED, email, ip, "max_attempts");
                throw AuthException.attemptsExceeded();
            }
            audit(EventType.LOGIN_FAILED, email, ip, "wrong_code");
            throw AuthException.invalidOtp();
        }

        // Single use: only the request that actually removes the challenge may proceed.
        if (!challengeStore.delete(email)) {
            audit(EventType.LOGIN_FAILED, email, ip, "code_already_used");
            throw AuthException.invalidOtp();
        }

        // The OTP proves ownership of the mailbox, so this email is verified.
        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User created = userRepository.saveIfAbsent(User.register(email, now));
            auditLog.record(AuditEvent.of(EventType.USER_REGISTERED).method(METHOD).user(created.id()).email(email).ip(ip));
            return created;
        });

        auditLog.record(AuditEvent.of(EventType.LOGIN_SUCCEEDED).method(METHOD).user(user.id()).email(email).ip(ip));
        return tokenPairIssuer.issueNewSession(user, now);
    }

    private void audit(EventType type, EmailAddress email, String ip, String reason) {
        auditLog.record(AuditEvent.of(type).method(METHOD).email(email).ip(ip).reason(reason));
    }
}

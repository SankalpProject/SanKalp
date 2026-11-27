package com.myapp.auth.application.service;

import com.myapp.auth.application.port.in.RequestOtpUseCase;
import com.myapp.auth.application.port.out.AuditLog;
import com.myapp.auth.application.port.out.AuditLog.AuditEvent;
import com.myapp.auth.application.port.out.AuditLog.EventType;
import com.myapp.auth.application.port.out.OtpChallengeStore;
import com.myapp.auth.application.port.out.OtpSender;
import com.myapp.auth.application.port.out.SecretHasher;
import com.myapp.auth.application.port.out.SecureCodeGenerator;
import com.myapp.auth.domain.exception.AuthException;
import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.domain.model.OtpChallenge;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Issues an OTP for an email address.
 * <p>
 * The response is identical whether or not the email belongs to an existing account,
 * so this endpoint cannot be used to enumerate registered users.
 * Rate limits per IP and per email protect against mail bombing a victim and burning sender reputation.
 */
public final class RequestOtpService implements RequestOtpUseCase {

    private final OtpChallengeStore challengeStore;
    private final SecureCodeGenerator codeGenerator;
    private final SecretHasher hasher;
    private final OtpSender otpSender;
    private final RateLimitGuard rateLimitGuard;
    private final AuditLog auditLog;
    private final OtpPolicy policy;
    private final Clock clock;

    public RequestOtpService(OtpChallengeStore challengeStore,
                             SecureCodeGenerator codeGenerator,
                             SecretHasher hasher,
                             OtpSender otpSender,
                             RateLimitGuard rateLimitGuard,
                             AuditLog auditLog,
                             OtpPolicy policy,
                             Clock clock) {
        this.challengeStore = challengeStore;
        this.codeGenerator = codeGenerator;
        this.hasher = hasher;
        this.otpSender = otpSender;
        this.rateLimitGuard = rateLimitGuard;
        this.auditLog = auditLog;
        this.policy = policy;
        this.clock = clock;
    }

    @Override
    public OtpRequested requestOtp(RequestOtpCommand command) {
        EmailAddress email = command.email();
        String ip = command.clientIp();
        Instant now = clock.instant();

        rateLimitGuard.check("otp_request_per_ip", ip, policy.requestPerIp(), ip);
        enforceResendCooldown(email, now);
        rateLimitGuard.check("otp_request_per_email", email.value(), policy.requestPerEmail(), ip);

        String code = codeGenerator.numericCode(policy.codeLength());
        challengeStore.save(OtpChallenge.issue(email, OtpCodeHashing.hash(hasher, email, code), now, policy.ttl()));
        otpSender.send(email, code, policy.ttl());

        auditLog.record(AuditEvent.of(EventType.OTP_REQUESTED).method("email_otp").email(email).ip(ip));
        return new OtpRequested(policy.ttl(), policy.resendCooldown());
    }

    private void enforceResendCooldown(EmailAddress email, Instant now) {
        Optional<OtpChallenge> existing = challengeStore.find(email).filter(c -> !c.isExpired(now));
        if (existing.isPresent()) {
            Instant resendAt = existing.get().resendAvailableAt(policy.resendCooldown());
            if (now.isBefore(resendAt)) {
                throw AuthException.resendTooSoon(Duration.between(now, resendAt));
            }
        }
    }
}

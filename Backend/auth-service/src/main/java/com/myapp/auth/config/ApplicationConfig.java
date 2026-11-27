package com.myapp.auth.config;

import com.myapp.auth.application.port.out.AccessTokenIssuer;
import com.myapp.auth.application.port.out.AuditLog;
import com.myapp.auth.application.port.out.ExternalIdentityVerifier;
import com.myapp.auth.application.port.out.OtpChallengeStore;
import com.myapp.auth.application.port.out.OtpSender;
import com.myapp.auth.application.port.out.RateLimiter;
import com.myapp.auth.application.port.out.RefreshTokenStore;
import com.myapp.auth.application.port.out.SecretHasher;
import com.myapp.auth.application.port.out.SecureCodeGenerator;
import com.myapp.auth.application.port.out.UserRepository;
import com.myapp.auth.application.service.ExternalSignInService;
import com.myapp.auth.application.service.OtpPolicy;
import com.myapp.auth.application.service.RateLimitGuard;
import com.myapp.auth.application.service.RequestOtpService;
import com.myapp.auth.application.service.SessionService;
import com.myapp.auth.application.service.TokenPairIssuer;
import com.myapp.auth.application.service.TokenPolicy;
import com.myapp.auth.application.service.VerifyOtpService;
import com.myapp.auth.infrastructure.crypto.HmacSecretHasher;
import com.myapp.auth.infrastructure.crypto.SecureRandomCodeGenerator;
import com.myapp.auth.infrastructure.notification.DevLoggingOtpSender;
import com.myapp.auth.infrastructure.observability.CompositeAuditLog;
import com.myapp.auth.infrastructure.observability.LoggingAuditLog;
import com.myapp.auth.infrastructure.observability.MetricsAuditLog;
import com.myapp.auth.infrastructure.persistence.jdbc.JdbcAuditLog;
import com.myapp.auth.infrastructure.notification.SmtpOtpSender;
import com.myapp.auth.infrastructure.persistence.InMemoryOtpChallengeStore;
import com.myapp.auth.infrastructure.ratelimit.InMemorySlidingWindowRateLimiter;
import com.myapp.auth.infrastructure.security.GoogleIdTokenVerifier;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.mail.javamail.JavaMailSender;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

/**
 * Composition root: the only place that knows which adapter implements which port.
 * Application services are plain Java objects with constructor injection, so they are trivially unit-testable
 * and the domain never depends on Spring. To move to Redis/Postgres, change only the adapter bean methods
 * below (e.g. return a RedisOtpChallengeStore) — no service code changes (Open/Closed principle).
 */
@Configuration(proxyBeanMethods = false)
public class ApplicationConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    // ---------- Policies (config -> application) ----------

    @Bean
    OtpPolicy otpPolicy(AuthProperties props) {
        AuthProperties.Otp otp = props.otp();
        AuthProperties.RateLimit rl = props.rateLimit();
        return new OtpPolicy(otp.length(), otp.ttl(), otp.maxAttempts(), otp.resendCooldown(),
                rule(rl.otpRequestPerEmail()), rule(rl.otpRequestPerIp()),
                rule(rl.otpVerifyPerEmail()), rule(rl.otpVerifyPerIp()));
    }

    @Bean
    TokenPolicy tokenPolicy(AuthProperties props) {
        return new TokenPolicy(props.jwt().refreshTokenTtl(), rule(props.rateLimit().refreshPerIp()));
    }

    private static RateLimiter.Rule rule(AuthProperties.Rule r) {
        return new RateLimiter.Rule(r.limit(), r.window());
    }

    // ---------- Outbound adapters ----------

    @Bean
    SecretHasher secretHasher(AuthProperties props) {
        return new HmacSecretHasher(props.hashPepper());
    }

    @Bean
    SecureCodeGenerator secureCodeGenerator() {
        return new SecureRandomCodeGenerator();
    }

    @Bean
    InMemoryOtpChallengeStore otpChallengeStore(Clock clock) {
        return new InMemoryOtpChallengeStore(clock);
    }

    // UserRepository + RefreshTokenStore come from PostgresPersistenceConfig or InMemoryPersistenceConfig,
    // selected by auth.persistence. OTP challenges and rate limits stay in memory (single instance);
    // swap these two for Redis adapters when running more than one instance.

    @Bean
    InMemorySlidingWindowRateLimiter rateLimiter(Clock clock) {
        return new InMemorySlidingWindowRateLimiter(clock);
    }

    /** Strategy selection by configuration: auth.otp.sender = LOG (dev) | SMTP. */
    @Bean
    OtpSender otpSender(AuthProperties props, ObjectProvider<JavaMailSender> mailSender) {
        AuthProperties.Otp otp = props.otp();
        return switch (otp.sender()) {
            case LOG -> new DevLoggingOtpSender();
            case SMTP -> {
                JavaMailSender sender = mailSender.getIfAvailable();
                if (sender == null) {
                    throw new IllegalStateException("auth.otp.sender=smtp requires spring.mail.host to be configured");
                }
                if (otp.mailFrom() == null || otp.mailFrom().isBlank()) {
                    throw new IllegalStateException("auth.otp.mail-from must be configured for SMTP");
                }
                yield new SmtpOtpSender(sender, otp.mailFrom(), otp.appName());
            }
        };
    }

    @Bean
    ExternalIdentityVerifier googleIdTokenVerifier(AuthProperties props) {
        return new GoogleIdTokenVerifier(props.google().clientIds());
    }

    /**
     * Audit trail fan-out: AUDIT log lines + Prometheus counters + PostgreSQL table (when persistence=postgres).
     * {@code @Primary}: this composite is what services get; the individual sinks are internal.
     */
    @Bean
    @Primary
    AuditLog auditLog(MeterRegistry meterRegistry, ObjectProvider<JdbcAuditLog> databaseSink) {
        List<AuditLog> sinks = new ArrayList<>(List.of(new LoggingAuditLog(), new MetricsAuditLog(meterRegistry)));
        databaseSink.ifAvailable(sinks::add);
        return new CompositeAuditLog(sinks);
    }

    // ---------- Application services ----------

    @Bean
    RateLimitGuard rateLimitGuard(RateLimiter rateLimiter, AuditLog auditLog) {
        return new RateLimitGuard(rateLimiter, auditLog);
    }

    @Bean
    TokenPairIssuer tokenPairIssuer(AccessTokenIssuer accessTokenIssuer, RefreshTokenStore store,
                                    SecureCodeGenerator generator, SecretHasher hasher, TokenPolicy policy) {
        return new TokenPairIssuer(accessTokenIssuer, store, generator, hasher, policy);
    }

    @Bean
    RequestOtpService requestOtpService(OtpChallengeStore store, SecureCodeGenerator generator, SecretHasher hasher,
                                        OtpSender sender, RateLimitGuard guard, AuditLog auditLog,
                                        OtpPolicy policy, Clock clock) {
        return new RequestOtpService(store, generator, hasher, sender, guard, auditLog, policy, clock);
    }

    @Bean
    VerifyOtpService verifyOtpService(OtpChallengeStore store, SecretHasher hasher, UserRepository users,
                                      TokenPairIssuer issuer, RateLimitGuard guard, AuditLog auditLog,
                                      OtpPolicy policy, Clock clock) {
        return new VerifyOtpService(store, hasher, users, issuer, guard, auditLog, policy, clock);
    }

    @Bean
    ExternalSignInService externalSignInService(List<ExternalIdentityVerifier> verifiers, UserRepository users,
                                                TokenPairIssuer issuer, RateLimitGuard guard, AuditLog auditLog,
                                                AuthProperties props, Clock clock) {
        return new ExternalSignInService(verifiers, users, issuer, guard, auditLog,
                rule(props.rateLimit().externalSignInPerIp()), clock);
    }

    @Bean
    SessionService sessionService(RefreshTokenStore store, UserRepository users, TokenPairIssuer issuer,
                                  SecretHasher hasher, RateLimitGuard guard, AuditLog auditLog,
                                  TokenPolicy policy, Clock clock) {
        return new SessionService(store, users, issuer, hasher, guard, auditLog, policy, clock);
    }
}

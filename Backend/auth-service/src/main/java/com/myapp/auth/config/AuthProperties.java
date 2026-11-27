package com.myapp.auth.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

/**
 * Typed, validated configuration. The app refuses to start with missing/weak security settings (fail closed).
 * Secrets come from environment variables or a secret manager, never from committed files in production.
 */
@Validated
@ConfigurationProperties(prefix = "auth")
public record AuthProperties(
        @DefaultValue("postgres") @NotNull PersistenceType persistence,
        @NotBlank @Size(min = 32) String hashPepper,
        @Valid @NotNull Otp otp,
        @Valid @NotNull Jwt jwt,
        @Valid @NotNull Google google,
        @Valid @NotNull @DefaultValue Audit audit,
        @Valid @NotNull RateLimit rateLimit) {

    /** How long audit rows are kept in PostgreSQL. The database itself refuses anything below 30 days. */
    public record Audit(@DefaultValue("180") @Min(30) @Max(3650) int retentionDays) {
    }

    public enum OtpSenderType { LOG, SMTP }

    /** Where users and refresh tokens are stored. See PostgresPersistenceConfig / InMemoryPersistenceConfig. */
    public enum PersistenceType { POSTGRES, MEMORY }

    public record Otp(
            @Min(4) @Max(8) int length,
            @NotNull Duration ttl,
            @Min(1) @Max(10) int maxAttempts,
            @NotNull Duration resendCooldown,
            /* Required: no default, so production cannot silently run without a sender. */
            @NotNull OtpSenderType sender,
            /* "From" address for SMTP, e.g. "MyApp <no-reply@myapp.com>". */
            String mailFrom,
            @DefaultValue("MyApp") String appName) {
    }

    public record Jwt(
            @NotBlank String issuer,
            @NotBlank String audience,
            @NotNull Duration accessTokenTtl,
            @NotNull Duration refreshTokenTtl,
            Resource publicKey,
            Resource privateKey,
            boolean allowEphemeralKeys) {
    }

    /** OAuth client ids whose Google ID tokens we accept (the "Web client" id used by the mobile app). */
    public record Google(@DefaultValue List<String> clientIds) {
    }

    public record RateLimit(
            @Valid @NotNull Rule otpRequestPerEmail,
            @Valid @NotNull Rule otpRequestPerIp,
            @Valid @NotNull Rule otpVerifyPerEmail,
            @Valid @NotNull Rule otpVerifyPerIp,
            @Valid @NotNull Rule externalSignInPerIp,
            @Valid @NotNull Rule refreshPerIp) {
    }

    public record Rule(@Min(1) int limit, @NotNull Duration window) {
    }
}

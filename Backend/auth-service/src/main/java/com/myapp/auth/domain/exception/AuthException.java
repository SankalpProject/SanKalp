package com.myapp.auth.domain.exception;

import java.time.Duration;
import java.util.Optional;

/** Business-rule failure in the authentication domain. Mapped to HTTP by the web layer. */
public class AuthException extends RuntimeException {

    private final ErrorCode code;
    private final Duration retryAfter;

    private AuthException(ErrorCode code, Duration retryAfter) {
        super(code.defaultMessage(), null, false, false); // no stack trace: these are expected outcomes
        this.code = code;
        this.retryAfter = retryAfter;
    }

    public ErrorCode code() {
        return code;
    }

    public Optional<Duration> retryAfter() {
        return Optional.ofNullable(retryAfter);
    }

    public static AuthException invalidEmail() {
        return new AuthException(ErrorCode.INVALID_EMAIL, null);
    }

    public static AuthException invalidExternalToken() {
        return new AuthException(ErrorCode.INVALID_EXTERNAL_TOKEN, null);
    }

    public static AuthException externalEmailNotVerified() {
        return new AuthException(ErrorCode.EXTERNAL_EMAIL_NOT_VERIFIED, null);
    }

    public static AuthException invalidOtp() {
        return new AuthException(ErrorCode.OTP_INVALID, null);
    }

    public static AuthException attemptsExceeded() {
        return new AuthException(ErrorCode.OTP_ATTEMPTS_EXCEEDED, null);
    }

    public static AuthException resendTooSoon(Duration retryAfter) {
        return new AuthException(ErrorCode.OTP_RESEND_TOO_SOON, retryAfter);
    }

    public static AuthException rateLimited(Duration retryAfter) {
        return new AuthException(ErrorCode.RATE_LIMITED, retryAfter);
    }

    public static AuthException invalidRefreshToken() {
        return new AuthException(ErrorCode.INVALID_REFRESH_TOKEN, null);
    }
}

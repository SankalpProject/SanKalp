package com.myapp.auth.domain.exception;

/**
 * Stable, machine-readable error codes returned to clients.
 * Messages are deliberately generic so they do not reveal whether an email is registered,
 * whether a code expired vs. was wrong, etc.
 */
public enum ErrorCode {
    INVALID_EMAIL("Enter a valid email address."),
    OTP_INVALID("The code is invalid or has expired."),
    OTP_ATTEMPTS_EXCEEDED("Too many incorrect attempts. Request a new code."),
    OTP_RESEND_TOO_SOON("Please wait before requesting another code."),
    RATE_LIMITED("Too many requests. Try again later."),
    INVALID_REFRESH_TOKEN("Your session has expired. Please sign in again."),
    INVALID_EXTERNAL_TOKEN("Sign-in failed. Please try again."),
    EXTERNAL_EMAIL_NOT_VERIFIED("Your account email is not verified with this provider.");

    private final String defaultMessage;

    ErrorCode(String defaultMessage) {
        this.defaultMessage = defaultMessage;
    }

    public String defaultMessage() {
        return defaultMessage;
    }
}

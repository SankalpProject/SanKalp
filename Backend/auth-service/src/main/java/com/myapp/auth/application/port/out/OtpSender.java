package com.myapp.auth.application.port.out;

import com.myapp.auth.domain.model.EmailAddress;

import java.time.Duration;

/**
 * Delivery channel for OTP codes (Strategy pattern).
 * Implementations: SMTP (Gmail, Brevo, SES...), a provider HTTP API, or a dev-only logger.
 */
public interface OtpSender {

    void send(EmailAddress email, String code, Duration validFor);
}

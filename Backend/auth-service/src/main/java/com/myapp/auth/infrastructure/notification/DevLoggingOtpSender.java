package com.myapp.auth.infrastructure.notification;

import com.myapp.auth.application.port.out.OtpSender;
import com.myapp.auth.domain.model.EmailAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

/**
 * DEVELOPMENT ONLY: writes the OTP to the log instead of sending an email.
 * Registered only when {@code auth.otp.sender=log}. Startup fails if no sender is configured.
 */
public final class DevLoggingOtpSender implements OtpSender {

    private static final Logger log = LoggerFactory.getLogger(DevLoggingOtpSender.class);

    public DevLoggingOtpSender() {
        log.warn("DevLoggingOtpSender is active: OTP codes are written to the log. NEVER enable this in production.");
    }

    @Override
    public void send(EmailAddress email, String code, Duration validFor) {
        log.warn("[DEV ONLY] OTP for {} is {}", email, code);
    }
}

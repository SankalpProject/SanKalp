package com.myapp.auth.application.port.out;

import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.domain.model.UserId;

/**
 * Security audit trail: who did what, when, from where, and whether it worked.
 * <p>
 * Services report events here; adapters decide where they go (log lines, metrics, a SIEM, a DB table...).
 * Events must never contain secrets (codes, tokens) and only masked PII.
 */
public interface AuditLog {

    void record(AuditEvent event);

    enum EventType {
        OTP_REQUESTED(false),
        LOGIN_SUCCEEDED(false),
        LOGIN_FAILED(false),
        OTP_LOCKED(true),
        USER_REGISTERED(false),
        ACCOUNT_LINKED(false),
        TOKEN_REFRESHED(false),
        TOKEN_REFRESH_FAILED(false),
        TOKEN_REUSE_DETECTED(true),
        LOGOUT(false),
        RATE_LIMITED(true);

        private final boolean suspicious;

        EventType(boolean suspicious) {
            this.suspicious = suspicious;
        }

        /** Worth a warning / an alert when it spikes. */
        public boolean suspicious() {
            return suspicious;
        }
    }

    /**
     * @param method login method ("email_otp", "google") or null
     * @param reason short machine-readable reason ("wrong_code", "invalid_token"...) or null
     */
    record AuditEvent(EventType type, String method, UserId userId, String maskedEmail, String clientIp, String reason) {

        public static AuditEvent of(EventType type) {
            return new AuditEvent(type, null, null, null, null, null);
        }

        public AuditEvent method(String value) {
            return new AuditEvent(type, value, userId, maskedEmail, clientIp, reason);
        }

        public AuditEvent user(UserId value) {
            return new AuditEvent(type, method, value, maskedEmail, clientIp, reason);
        }

        public AuditEvent email(EmailAddress value) {
            return new AuditEvent(type, method, userId, value == null ? null : value.masked(), clientIp, reason);
        }

        public AuditEvent ip(String value) {
            return new AuditEvent(type, method, userId, maskedEmail, value, reason);
        }

        public AuditEvent reason(String value) {
            return new AuditEvent(type, method, userId, maskedEmail, clientIp, value);
        }
    }
}

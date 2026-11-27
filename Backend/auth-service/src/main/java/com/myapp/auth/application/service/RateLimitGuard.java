package com.myapp.auth.application.service;

import com.myapp.auth.application.port.out.AuditLog;
import com.myapp.auth.application.port.out.AuditLog.AuditEvent;
import com.myapp.auth.application.port.out.AuditLog.EventType;
import com.myapp.auth.application.port.out.RateLimiter;
import com.myapp.auth.domain.exception.AuthException;

/** Turns a rate-limit decision into a domain error, and audits it. */
public final class RateLimitGuard {

    private final RateLimiter rateLimiter;
    private final AuditLog auditLog;

    public RateLimitGuard(RateLimiter rateLimiter, AuditLog auditLog) {
        this.rateLimiter = rateLimiter;
        this.auditLog = auditLog;
    }

    /**
     * @param scope      which limit, e.g. "otp_request_per_ip" (safe to log/tag)
     * @param identifier whose budget, e.g. the IP or email (part of the key only, never logged)
     * @param clientIp   caller IP, for the audit trail
     */
    public void check(String scope, String identifier, RateLimiter.Rule rule, String clientIp) {
        RateLimiter.Decision decision = rateLimiter.tryAcquire(scope + ":" + identifier, rule);
        if (!decision.allowed()) {
            auditLog.record(AuditEvent.of(EventType.RATE_LIMITED).reason(scope).ip(clientIp));
            throw AuthException.rateLimited(decision.retryAfter());
        }
    }
}

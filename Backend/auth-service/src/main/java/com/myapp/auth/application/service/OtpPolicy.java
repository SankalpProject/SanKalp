package com.myapp.auth.application.service;

import com.myapp.auth.application.port.out.RateLimiter.Rule;

import java.time.Duration;

/** OTP rules, supplied by configuration so the application layer stays framework-free. */
public record OtpPolicy(
        int codeLength,
        Duration ttl,
        int maxAttempts,
        Duration resendCooldown,
        Rule requestPerEmail,
        Rule requestPerIp,
        Rule verifyPerEmail,
        Rule verifyPerIp) {
}

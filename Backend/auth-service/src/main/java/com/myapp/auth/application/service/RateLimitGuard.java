package com.myapp.auth.application.service;

import com.myapp.auth.application.port.out.RateLimiter;
import com.myapp.auth.domain.exception.AuthException;

/** Turns a rate-limit decision into a domain error. */
public final class RateLimitGuard {

    private final RateLimiter rateLimiter;

    public RateLimitGuard(RateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    public void check(String key, RateLimiter.Rule rule) {
        RateLimiter.Decision decision = rateLimiter.tryAcquire(key, rule);
        if (!decision.allowed()) {
            throw AuthException.rateLimited(decision.retryAfter());
        }
    }
}

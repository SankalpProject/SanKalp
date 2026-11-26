package com.myapp.auth.application.service;

import com.myapp.auth.application.port.out.RateLimiter.Rule;

import java.time.Duration;

public record TokenPolicy(Duration refreshTokenTtl, Rule refreshPerIp) {

    /** 256 bits of entropy: infeasible to guess. */
    public static final int REFRESH_TOKEN_BYTES = 32;
}

package com.myapp.auth.application.port.out;

import java.time.Duration;

/** Production implementation: Redis (e.g. Bucket4j/Redisson) so limits hold across all instances. */
public interface RateLimiter {

    Decision tryAcquire(String key, Rule rule);

    record Rule(int limit, Duration window) {
    }

    record Decision(boolean allowed, Duration retryAfter) {
        public static Decision allow() {
            return new Decision(true, Duration.ZERO);
        }

        public static Decision deny(Duration retryAfter) {
            return new Decision(false, retryAfter);
        }
    }
}

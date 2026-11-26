package com.myapp.auth.infrastructure.ratelimit;

import com.myapp.auth.application.port.out.RateLimiter;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Sliding-window-log rate limiter for a single node.
 * Behind a load balancer use a shared store (Redis) so the limits are global, and also apply
 * coarse limits at the edge (API gateway / WAF).
 */
public final class InMemorySlidingWindowRateLimiter implements RateLimiter {

    private static final Duration MAX_TRACKED_WINDOW = Duration.ofDays(1);

    private final ConcurrentMap<String, Deque<Instant>> hits = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemorySlidingWindowRateLimiter(Clock clock) {
        this.clock = clock;
    }

    @Override
    public Decision tryAcquire(String key, Rule rule) {
        Instant now = clock.instant();
        Instant windowStart = now.minus(rule.window());
        AtomicReference<Decision> decision = new AtomicReference<>();

        hits.compute(key, (k, existing) -> {
            Deque<Instant> log = existing != null ? existing : new ArrayDeque<>();
            while (!log.isEmpty() && !log.peekFirst().isAfter(windowStart)) {
                log.pollFirst();
            }
            if (log.size() < rule.limit()) {
                log.addLast(now);
                decision.set(Decision.allow());
            } else {
                decision.set(Decision.deny(Duration.between(now, log.peekFirst().plus(rule.window()))));
            }
            return log;
        });
        return decision.get();
    }

    @Scheduled(fixedDelayString = "PT5M")
    void purgeIdleKeys() {
        Instant cutoff = clock.instant().minus(MAX_TRACKED_WINDOW);
        for (String key : hits.keySet()) {
            // computeIfPresent runs atomically with tryAcquire's compute on the same key
            hits.computeIfPresent(key, (k, log) -> {
                Instant last = log.peekLast();
                return last == null || last.isBefore(cutoff) ? null : log;
            });
        }
    }
}

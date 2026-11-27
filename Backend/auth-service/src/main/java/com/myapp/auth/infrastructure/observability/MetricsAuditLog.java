package com.myapp.auth.infrastructure.observability;

import com.myapp.auth.application.port.out.AuditLog;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Turns audit events into counters ({@code auth_events_total{type,method}} in Prometheus) for dashboards
 * and alerts, e.g. "login failure rate", "OTP requests per minute", "any TOKEN_REUSE_DETECTED".
 * <p>
 * Only low-cardinality values become tags (event type, login method). Never user ids or emails:
 * that would explode the number of time series.
 */
public final class MetricsAuditLog implements AuditLog {

    private final MeterRegistry registry;

    public MetricsAuditLog(MeterRegistry registry) {
        this.registry = registry;
    }

    @Override
    public void record(AuditEvent e) {
        Counter.builder("auth.events")
                .description("Authentication and session security events")
                .tag("type", e.type().name())
                .tag("method", e.method() == null ? "none" : e.method())
                .register(registry)
                .increment();
    }
}

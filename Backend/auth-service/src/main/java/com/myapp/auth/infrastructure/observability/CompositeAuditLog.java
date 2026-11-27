package com.myapp.auth.infrastructure.observability;

import com.myapp.auth.application.port.out.AuditLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Composite pattern: fans one event out to several sinks (log + metrics today; a SIEM or audit table later).
 * Auditing must never break a login, so a failing sink is logged and skipped.
 */
public final class CompositeAuditLog implements AuditLog {

    private static final Logger log = LoggerFactory.getLogger(CompositeAuditLog.class);

    private final List<AuditLog> sinks;

    public CompositeAuditLog(List<AuditLog> sinks) {
        this.sinks = List.copyOf(sinks);
    }

    @Override
    public void record(AuditEvent event) {
        for (AuditLog sink : sinks) {
            try {
                sink.record(event);
            } catch (RuntimeException e) {
                log.error("Audit sink {} failed for event {}", sink.getClass().getSimpleName(), event.type(), e);
            }
        }
    }
}

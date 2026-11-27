package com.myapp.auth.infrastructure.persistence.jdbc;

import com.myapp.auth.application.port.out.AuditLog;
import com.myapp.auth.infrastructure.observability.RequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Clock;

/**
 * Durable audit trail in PostgreSQL ({@code audit_events}), one sink of the CompositeAuditLog.
 * <p>
 * Tamper resistance is enforced by the database, not by this class:
 * the app login has only INSERT/SELECT on the table, an UPDATE trigger rejects any change, and rows can only
 * be deleted through {@code purge_audit_events()}, which refuses to delete anything younger than 30 days.
 * <p>
 * Write cost is one small INSERT per security event (a few per login). If volume ever matters, switch this
 * sink to batched/asynchronous writes; services do not change.
 */
public final class JdbcAuditLog implements AuditLog {

    private static final Logger log = LoggerFactory.getLogger(JdbcAuditLog.class);

    private final JdbcClient jdbc;
    private final Clock clock;
    private final int retentionDays;

    public JdbcAuditLog(JdbcClient jdbc, Clock clock, int retentionDays) {
        this.jdbc = jdbc;
        this.clock = clock;
        this.retentionDays = retentionDays;
    }

    @Override
    public void record(AuditEvent e) {
        jdbc.sql("""
                        INSERT INTO audit_events
                            (occurred_at, event_type, method, user_id, masked_email, client_ip, reason, request_id)
                        VALUES (:occurredAt, :type, :method, :userId, :email, :ip, :reason, :requestId)
                        """)
                .param("occurredAt", SqlTime.toDb(clock.instant()))
                .param("type", e.type().name())
                .param("method", fit(e.method(), 20))
                .param("userId", e.userId() == null ? null : e.userId().value())
                .param("email", fit(e.maskedEmail(), 254))
                .param("ip", fit(e.clientIp(), 45))
                .param("reason", fit(e.reason(), 64))
                .param("requestId", fit(RequestContext.requestId(), 64))
                .update();
    }

    /** Daily retention. Safe on several instances at once (deleting already-deleted rows is a no-op). */
    @Scheduled(cron = "0 17 3 * * *")
    void purgeExpired() {
        Long deleted = jdbc.sql("SELECT purge_audit_events(:days)")
                .param("days", retentionDays)
                .query(Long.class)
                .single();
        if (deleted != null && deleted > 0) {
            log.info("Purged {} audit events older than {} days", deleted, retentionDays);
        }
    }

    /** Never let an oversized value make the INSERT fail. */
    private static String fit(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}

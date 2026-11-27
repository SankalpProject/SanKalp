package com.myapp.auth.infrastructure.observability;

import com.myapp.auth.application.port.out.AuditLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.spi.LoggingEventBuilder;

/**
 * Writes audit events to a dedicated "AUDIT" logger, so they can be routed, retained and searched separately
 * from technical logs. Each field is attached as a key-value pair: with JSON (structured) logging in production
 * every field becomes searchable, e.g. {@code event:TOKEN_REUSE_DETECTED}.
 */
public final class LoggingAuditLog implements AuditLog {

    private static final Logger audit = LoggerFactory.getLogger("AUDIT");

    @Override
    public void record(AuditEvent e) {
        LoggingEventBuilder builder = e.type().suspicious() ? audit.atWarn() : audit.atInfo();
        builder.addKeyValue("event", e.type().name());
        add(builder, "method", e.method());
        add(builder, "userId", e.userId() == null ? null : e.userId().toString());
        add(builder, "email", e.maskedEmail());
        add(builder, "clientIp", e.clientIp());
        add(builder, "reason", e.reason());
        builder.log("{} method={} userId={} email={} ip={} reason={}",
                e.type(), e.method(), e.userId(), e.maskedEmail(), e.clientIp(), e.reason());
    }

    private static void add(LoggingEventBuilder builder, String key, String value) {
        if (value != null) {
            builder.addKeyValue(key, value);
        }
    }
}

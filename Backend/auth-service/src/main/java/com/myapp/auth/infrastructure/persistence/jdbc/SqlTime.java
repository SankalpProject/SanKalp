package com.myapp.auth.infrastructure.persistence.jdbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/** Instant <-> TIMESTAMPTZ. The PostgreSQL driver maps OffsetDateTime natively; we always store UTC. */
final class SqlTime {

    private SqlTime() {
    }

    static OffsetDateTime toDb(Instant instant) {
        return instant.atOffset(ZoneOffset.UTC);
    }

    static Instant fromDb(ResultSet rs, String column) throws SQLException {
        return rs.getObject(column, OffsetDateTime.class).toInstant();
    }
}

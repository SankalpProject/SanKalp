-- =============================================================================
-- V2: security audit trail + least-privilege grants for the runtime app role.
--
-- Placeholder ${app_role} = the login the APPLICATION uses at runtime
-- (spring.flyway.placeholders.app_role, defaults to spring.datasource.username).
-- Migrations themselves should run as a separate owner/migrator login (spring.flyway.user).
-- =============================================================================

-- Append-only audit trail. No foreign key to users on purpose: the evidence must outlive the account.
CREATE TABLE audit_events (
    id            BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at   TIMESTAMPTZ  NOT NULL,
    event_type    VARCHAR(40)  NOT NULL,
    method        VARCHAR(20),
    user_id       UUID,
    masked_email  VARCHAR(254),      -- e.g. s***@gmail.com, never the full address
    client_ip     VARCHAR(45),       -- fits IPv6
    reason        VARCHAR(64),
    request_id    VARCHAR(64)        -- joins a DB row to the matching log lines
);

-- "Recent activity for user X" and "all TOKEN_REUSE_DETECTED this week".
CREATE INDEX ix_audit_events_user_time ON audit_events (user_id, occurred_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX ix_audit_events_type_time ON audit_events (event_type, occurred_at DESC);
-- Rows arrive in time order: a tiny BRIN index makes time-range scans and retention deletes cheap.
CREATE INDEX ix_audit_events_time_brin ON audit_events USING brin (occurred_at);

-- Rows can never be modified, by anyone (defence in depth on top of the privileges below).
CREATE FUNCTION audit_events_reject_update() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: rows cannot be updated';
END
$$;

CREATE TRIGGER trg_audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_update();

-- The ONLY way the app can delete audit rows: this function, which refuses to touch anything
-- younger than 30 days. Runs with the owner's rights (SECURITY DEFINER) so the app role itself
-- never needs DELETE on the table. search_path is pinned to prevent function-hijacking.
CREATE FUNCTION purge_audit_events(retention_days INTEGER) RETURNS BIGINT
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public AS
$$
DECLARE
    deleted BIGINT;
BEGIN
    IF retention_days IS NULL OR retention_days < 30 THEN
        RAISE EXCEPTION 'audit retention must be at least 30 days (got %)', retention_days;
    END IF;
    DELETE FROM public.audit_events
     WHERE occurred_at < now() - make_interval(days => retention_days);
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END
$$;
REVOKE ALL ON FUNCTION purge_audit_events(INTEGER) FROM PUBLIC;

-- Least privilege for the runtime role (skipped when app and migrator are the same login,
-- e.g. a single-user setup, or when the role does not exist in this database).
DO
$$
DECLARE
    app_role TEXT := '${app_role}';
BEGIN
    IF app_role <> current_user AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app_role) THEN
        -- PostgreSQL < 15 lets EVERY role create objects in "public". Close that: only the owner may change the
        -- schema. (Already the default on 15+; when not the schema owner, this is a harmless no-op warning.)
        REVOKE CREATE ON SCHEMA public FROM PUBLIC;
        EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', app_role);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON users, user_identities, refresh_tokens TO %I', app_role);
        -- Audit trail: write and read only. No UPDATE, DELETE or TRUNCATE.
        EXECUTE format('GRANT SELECT, INSERT ON audit_events TO %I', app_role);
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM %I', app_role);
        EXECUTE format('GRANT EXECUTE ON FUNCTION purge_audit_events(INTEGER) TO %I', app_role);
        -- Tables created by future migrations get normal read/write for the app automatically.
        EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', app_role);
        EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %I', app_role);
    END IF;
END
$$;

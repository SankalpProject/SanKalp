-- =============================================================================
-- ONE-TIME local database setup for auth-service.  Run in DBeaver:
--   connected as the "postgres" superuser, to the default "postgres" database,
--   with Auto-Commit ON, using "Execute SQL Script" (Alt+X).
--
-- Two logins (least privilege, same as production):
--   sankalp_migrator : owns the database/schema. Used ONLY by Flyway to create/alter tables.
--   sankalp_app      : used by the running application. Can read/write data, but cannot
--                      change the schema, and cannot modify or delete audit records.
--
-- 1. Replace both CHANGE_ME_... passwords below (use two different strong passwords).
-- 2. Put them in Backend/auth-service/secrets.properties:
--      spring.flyway.password=<migrator password>
--      spring.datasource.password=<app password>
--
-- Tables are NOT created here. The app creates and upgrades them itself on startup
-- (Flyway: src/main/resources/db/migration), and grants sankalp_app exactly what it needs.
-- =============================================================================

CREATE ROLE sankalp_migrator WITH LOGIN PASSWORD 'CHANGE_ME_MIGRATOR_PASSWORD'
    NOSUPERUSER NOCREATEDB NOCREATEROLE;

CREATE ROLE sankalp_app WITH LOGIN PASSWORD 'CHANGE_ME_APP_PASSWORD'
    NOSUPERUSER NOCREATEDB NOCREATEROLE;

-- Owned by the migrator, so only migrations can change the schema.
CREATE DATABASE sankalp OWNER sankalp_migrator ENCODING 'UTF8';

-- Nobody else may connect to it.
REVOKE ALL ON DATABASE sankalp FROM PUBLIC;
GRANT CONNECT ON DATABASE sankalp TO sankalp_migrator, sankalp_app;

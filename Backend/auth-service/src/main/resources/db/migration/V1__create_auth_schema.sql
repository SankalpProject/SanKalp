-- =============================================================================
-- V1: authentication schema
-- Flyway applies this once, in order, and records it in flyway_schema_history.
-- NEVER edit a migration that has run anywhere; add V2__..., V3__... instead.
-- =============================================================================

-- Accounts. The email is always verified (OTP or a provider with email_verified=true)
-- and stored lower-cased by the application, so a plain UNIQUE constraint is enough.
CREATE TABLE users (
    id          UUID         PRIMARY KEY,
    email       VARCHAR(254) NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL,
    CONSTRAINT uk_users_email UNIQUE (email),
    CONSTRAINT ck_users_email_lowercase CHECK (email = lower(email))
);

-- External sign-in accounts linked to a user (Google today, Apple later).
-- (provider, subject) is the provider's stable id for the person; emails can change, subjects never do.
CREATE TABLE user_identities (
    provider    VARCHAR(32)  NOT NULL,
    subject     VARCHAR(255) NOT NULL,
    user_id     UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_user_identities PRIMARY KEY (provider, subject)
);
CREATE INDEX ix_user_identities_user_id ON user_identities (user_id);

-- Refresh tokens. Only an HMAC of the token is stored (a DB leak gives no usable tokens).
-- All tokens of one login share family_id so a replayed token can revoke the whole session.
CREATE TABLE refresh_tokens (
    token_hash  VARCHAR(64)  PRIMARY KEY,
    user_id     UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id   VARCHAR(64)  NOT NULL,
    issued_at   TIMESTAMPTZ  NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    used        BOOLEAN      NOT NULL DEFAULT FALSE,
    revoked     BOOLEAN      NOT NULL DEFAULT FALSE
);
CREATE INDEX ix_refresh_tokens_family_id  ON refresh_tokens (family_id);
CREATE INDEX ix_refresh_tokens_user_id    ON refresh_tokens (user_id);
CREATE INDEX ix_refresh_tokens_expires_at ON refresh_tokens (expires_at);

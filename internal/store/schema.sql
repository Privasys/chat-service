-- chat-service schema. Postgres lives on the app's sealed /data volume.

CREATE TABLE IF NOT EXISTS user_tools (
    id                          uuid PRIMARY KEY,
    user_sub                    text NOT NULL,
    -- scope: 'user' (global to the user). A per-fleet scope is a later option.
    scope                       text NOT NULL DEFAULT 'user',
    -- kind: 'enclave' (attestable Privasys app) or 'external' (off-platform).
    kind                        text NOT NULL CHECK (kind IN ('enclave', 'external')),
    -- ref: app id/alias for enclave tools, base_url for external tools.
    ref                         text NOT NULL,
    name                        text NOT NULL,
    label                       text NOT NULL DEFAULT '',
    description                 text NOT NULL DEFAULT '',
    icon                        text NOT NULL DEFAULT '',
    transport                   text NOT NULL DEFAULT 'mcp_sse',
    auth_mode                   text NOT NULL DEFAULT 'none',
    auth_audience               text NOT NULL DEFAULT '',
    auth_scopes                 text[] NOT NULL DEFAULT '{}',
    expected_digest             text NOT NULL DEFAULT '',
    requires_user_confirmation  boolean NOT NULL DEFAULT false,
    enabled                     boolean NOT NULL DEFAULT true,
    -- acknowledged_at is required (non-null) for external tools: the user
    -- accepted that off-platform data is not attested or protected.
    acknowledged_at             timestamptz,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_sub, name)
);

CREATE INDEX IF NOT EXISTS user_tools_user_idx ON user_tools (user_sub);

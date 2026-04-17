CREATE TABLE IF NOT EXISTS trusted_input_sessions (
    id TEXT PRIMARY KEY,
    request_type TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending_input',
    completion_token_hash TEXT NOT NULL,
    opaque_ref TEXT UNIQUE,
    provider_secret_ref TEXT,
    expires_at TEXT NOT NULL,
    completed_at TEXT,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_trusted_input_sessions_status_created
    ON trusted_input_sessions(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_trusted_input_sessions_opaque_ref
    ON trusted_input_sessions(opaque_ref);

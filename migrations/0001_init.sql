CREATE TABLE IF NOT EXISTS secret_broker_requests (
    id TEXT PRIMARY KEY,
    request_type TEXT NOT NULL,
    secret_ref TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    amount_cents INTEGER,
    reason TEXT,
    status TEXT NOT NULL,
    requires_approval INTEGER NOT NULL DEFAULT 1,
    deny_reason TEXT,
    capability_hash TEXT,
    capability_expires_at TEXT,
    capability_used_at TEXT,
    execution_result TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_secret_broker_requests_status_created
    ON secret_broker_requests(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_secret_broker_requests_capability_hash
    ON secret_broker_requests(capability_hash);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_key TEXT NOT NULL,
    action TEXT NOT NULL,
    request_id TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at DESC);

CREATE TABLE IF NOT EXISTS api_keys (
    role TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    rotated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

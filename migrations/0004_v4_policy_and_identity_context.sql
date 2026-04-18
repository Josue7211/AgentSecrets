ALTER TABLE secret_broker_requests
    ADD COLUMN policy_outcome TEXT;

ALTER TABLE secret_broker_requests
    ADD COLUMN policy_risk_score INTEGER;

ALTER TABLE secret_broker_requests
    ADD COLUMN policy_environment TEXT;

ALTER TABLE secret_broker_requests
    ADD COLUMN policy_reasons TEXT;

ALTER TABLE secret_broker_requests
    ADD COLUMN identity_status TEXT;

ALTER TABLE secret_broker_requests
    ADD COLUMN identity_mode TEXT;

ALTER TABLE secret_broker_requests
    ADD COLUMN identity_runtime_id TEXT;

ALTER TABLE secret_broker_requests
    ADD COLUMN identity_host_id TEXT;

ALTER TABLE secret_broker_requests
    ADD COLUMN identity_adapter_id TEXT;

ALTER TABLE secret_broker_requests
    ADD COLUMN identity_verified_at TEXT;

ALTER TABLE secret_broker_requests
    ADD COLUMN capability_request_id TEXT;

ALTER TABLE secret_broker_requests
    ADD COLUMN capability_action TEXT;

ALTER TABLE secret_broker_requests
    ADD COLUMN capability_target TEXT;

ALTER TABLE secret_broker_requests
    ADD COLUMN capability_issued_at TEXT;

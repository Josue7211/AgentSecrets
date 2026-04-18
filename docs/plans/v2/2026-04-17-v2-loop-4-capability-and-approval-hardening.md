# V2 Loop 4 Capability and Approval Hardening

Goal: tighten approval and capability semantics so the broker authorizes one bounded act, not a reusable secret handle.

Scope:
- strengthen capability binding to request, action, and target context
- harden expiry and one-time-use behavior
- make approval payloads truthful and masked
- add denial, drift, and misuse semantics that fail closed
- document the threat-case matrix for approval and capability misuse

Out of scope:
- hardware-backed attestation
- cross-device approval UX redesign
- host-side secure display work

Implementation order:

1. Capability binding model
- add explicit stored capability context for request id, action, target, issuance time, and expiry
- tighten `POST /v1/execute` so action and target checks are mandatory, not optional
- keep tokens single-use and invalidate them on success, expiry, or explicit denial
- add focused tests for replay, action drift, and target substitution

2. Approval payload contract
- add masked approval payload fields that give the approver enough context to decide safely
- ensure approval responses never include plaintext secret material
- persist approval-time context so execution cannot drift from what was approved
- add actor-role tests to confirm only approvers can issue or deny bounded capabilities

3. Expiry and denial hardening
- tighten TTL handling around issuance, stale pending requests, and used capabilities
- fail closed when expiry timestamps are missing, malformed, or stale
- ensure denial paths clear or invalidate any pending capability state
- add audit events for expiry, denial, and drifted execution attempts

4. Threat matrix and docs
- update release, integration, and security docs with the bounded-act capability contract
- add a misuse matrix covering replay, target mismatch, action mismatch, stale approval, and role abuse
- document any stricter defaults introduced by this loop

Verification:
- `cargo test execute_token_is_single_use -- --nocapture`
- `cargo test execute_rejects_action_mismatch -- --nocapture`
- `cargo test execute_rejects_target_mismatch -- --nocapture`
- `cargo test capability_expiry_is_enforced -- --nocapture`
- `cargo test approval_payload_is_masked_and_truthful -- --nocapture`
- `cargo test -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`

Acceptance:
- capabilities cannot be replayed
- capabilities cannot be reused on a different target or action
- approval payloads contain enough context for safe human review without exposing secret content


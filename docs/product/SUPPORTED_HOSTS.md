# Supported Host Matrix

This document is the V3 host-certification source of truth. It is the only external-host ship gate input.

## Certification states

- `shipped`: host has current host-specific evidence and may be included in V3 end-to-end claims
- `preview`: host contract exists, but host-specific certification is incomplete or stale
- `unsupported`: do not make V3 end-to-end claims for this host

## Freshness policy

- Every `shipped` host must list current trusted-input, transcript/log redaction, adapter, identity, and known-limit evidence.
- Evidence is current only when the row has a recent `Last verified` date and the host-specific evidence still matches the documented contract.
- The external-host ship gate treats stale shipped evidence as `preview` until the row is refreshed.
- Use `scripts/check-external-host-ship-gate.sh` to enforce the freshness and downgrade rules.

## Host matrix

| Host | Status | Trusted-input evidence | Transcript/log redaction evidence | Adapter evidence | Identity evidence | Last verified | Known limits |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Local helper harness (`src/bin/e2e-node.rs`) | shipped | `cargo test e2e_harness:: -- --nocapture` | `bash scripts/run-e2e-harness.sh` | `bash scripts/run-e2e-harness.sh` | `cargo test approval_payload_includes_verified_identity_summary -- --nocapture`, `cargo test execute_rejects_identity_mismatch_after_approval -- --nocapture` | `2026-04-17` | Repo-owned certification only; not a user-facing product host |
| OpenClaw-style HTTP host | preview | `cargo test openclaw_host_lane_covers_trusted_input_redaction_and_execution -- --nocapture`, `bash scripts/run-openclaw-e2e.sh` | `bash scripts/run-openclaw-e2e.sh` | `bash scripts/run-openclaw-e2e.sh` | `cargo test approval_payload_includes_verified_identity_summary -- --nocapture`, `cargo test execute_rejects_identity_mismatch_after_approval -- --nocapture`, `cargo test create_request_rejects_replayed_host_signed_identity_envelope -- --nocapture` | `2026-04-17` | Host-specific identity evidence now exists, but the documented host path remains preview; host process stays untrusted; replay rejection is same-process only; see [docs/architecture/OPENCLAW_THREAT_NOTES.md](docs/architecture/OPENCLAW_THREAT_NOTES.md) |
| Claude / Codex / arbitrary external runtimes | unsupported | no host-specific certification | no host-specific certification | no host-specific certification | no host-specific certification | n/a | Do not claim V3 end-to-end safety |

## Per-host threat notes

### Local helper harness

- Trust boundary: helper runtime is the supported host surface under test
- Untrusted sinks: helper stdout, helper stderr, helper artifacts
- Trusted control sink: `RESULT_JSON=` harness control line
- Certification bar:
  - trusted-input ingress must stay plaintext-free
  - helper transcript/log redaction must remain green
  - every shipped adapter path must have a green E2E case
  - helper identity assertions must remain green in stub attestation mode

### OpenClaw-style HTTP host

- Trust boundary: OpenClaw stays untrusted and only talks to the broker API over the documented HTTP contract
- Untrusted sinks: transcript, stdout, stderr, structured logs, retry logs, tool-call payloads, and failure traces
- Trusted contract: broker-issued opaque refs, masked approval payloads, and masked adapter results only
- Certification status: preview for the documented OpenClaw host path
- Evidence: `cargo test openclaw_host_lane_covers_trusted_input_redaction_and_execution -- --nocapture`, `bash scripts/run-openclaw-e2e.sh`
- Identity boundary: broker identity tests now cover the documented OpenClaw host-signed path, but that path remains preview and the replay defense is same-process only

### Unsupported external runtimes

- No certification line
- No end-to-end claim
- No support promise

## Regression policy

- If a shipped host loses its host-specific E2E evidence, downgrade it to `preview` or `unsupported`
- If a shipped host's evidence is older than 30 days, the external-host ship gate treats it as `preview` until refreshed
- If a host changes integration path or version in a way that changes transcript, log, trusted-input, adapter, or identity behavior, re-run host review before keeping `shipped`
- Do not move a host into `shipped` without adding its evidence, identity evidence, and threat notes to this file

# Supported Host Matrix

This document is the V3 host-certification source of truth.

## Certification states

- `shipped`: host has current host-specific evidence and may be included in V3 end-to-end claims
- `preview`: host contract exists, but host-specific certification is incomplete
- `unsupported`: do not make V3 end-to-end claims for this host

## Host matrix

| Host | Status | Trusted input | Transcript/log redaction | Trusted adapters | Evidence | Known limits |
| --- | --- | --- | --- | --- | --- | --- |
| Local helper harness (`src/bin/e2e-node.rs`) | shipped | yes | yes | `password_fill`, `request_sign`, `credential_handoff` | `cargo test e2e_harness:: -- --nocapture`, `bash scripts/run-e2e-harness.sh` | Repo-owned certification only; not a user-facing product host |
| OpenClaw-style HTTP host | shipped | yes | yes | `trusted-input`, `request`, `approve`, `execute` over the documented HTTP path | `cargo test openclaw_host_ -- --nocapture`, `bash scripts/run-openclaw-e2e.sh` | Certified only for the documented OpenClaw host path; see [docs/OPENCLAW_THREAT_NOTES.md](docs/OPENCLAW_THREAT_NOTES.md) |
| Claude / Codex / arbitrary external runtimes | unsupported | no host-specific certification | no host-specific certification | no host-specific certification | none | Do not claim V3 end-to-end safety |

## Per-host threat notes

### Local helper harness

- Trust boundary: helper runtime is the supported host surface under test
- Untrusted sinks: helper stdout, helper stderr, helper artifacts
- Trusted control sink: `RESULT_JSON=` harness control line
- Certification bar:
  - trusted-input ingress must stay plaintext-free
  - helper transcript/log redaction must remain green
  - every shipped adapter path must have a green E2E case

### OpenClaw-style HTTP host

- Trust boundary: OpenClaw stays untrusted and only talks to the broker API over the documented HTTP contract
- Untrusted sinks: transcript, stdout, stderr, structured logs, retry logs, tool-call payloads, and failure traces
- Trusted contract: broker-issued opaque refs, masked approval payloads, and masked adapter results only
- Certification status: shipped for the documented OpenClaw host path
- Evidence: `cargo test openclaw_host_ -- --nocapture`, `bash scripts/run-openclaw-e2e.sh`

### Unsupported external runtimes

- No certification line
- No end-to-end claim
- No support promise

## Regression policy

- If a shipped host loses its host-specific E2E evidence, downgrade it to `preview` or `unsupported`
- If a host changes integration path or version in a way that changes transcript, log, trusted-input, or adapter behavior, re-run host review before keeping `shipped`
- Do not move a host into `shipped` without adding its evidence and threat notes to this file

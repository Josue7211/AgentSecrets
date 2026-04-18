# Release Checklist

Use this when publishing the repo, cutting a tag, or deploying a new host.

## Shared checklist

- Confirm the repo still builds: `cargo fmt --all -- --check`, `cargo check --all-targets --all-features`, `cargo test --all-targets --all-features -- --nocapture`, `cargo clippy --all-targets --all-features -- -D warnings`
- Confirm `LICENSE` is AGPL
- Confirm `.env.example` is present and real secrets are not committed
- Run `bash scripts/check-security-claims.sh`
- Run `bash scripts/run-e2e-harness.sh`
- Run `bash scripts/run-openclaw-e2e.sh`
- Run `bash scripts/check-v2-ship-gate.sh`
- Run `bash scripts/check-v3-ship-gate.sh`
- Run `bash scripts/check-external-host-ship-gate.sh`
- Run `bash scripts/check-v4-ship-gate.sh`
- Run `bash scripts/run-rotation-recovery-drills.sh`
- Run `bash scripts/run-adversarial-suite.sh pr`
- Confirm [docs/IDENTITY_MODEL.md](docs/IDENTITY_MODEL.md) matches the runtime identity tier actually configured for release
- Confirm `docs/SECURITY_GUARANTEES.md` matches the current implementation line
- Confirm docs distinguish broker-level guarantees from end-to-end host guarantees
- Treat a failing or skipped Loop 5 harness run as a V2 release blocker
- Confirm release notes do not claim transcript-safe integrations unless backed by passing end-to-end tests
- If one required Loop 0 through Loop 5 line is missing, cut it from the V2 claim set or ship the release as preview only
- If one required V3 line is missing, cut it from the V3 claim set or ship the release as preview only
- If one required V4 line is missing, cut it from the V4 claim set or ship the release as preview only

## V2 ship gate

Call V2 real only when every Loop 0 through Loop 5 line below is backed by current code, docs, and green evidence:

| Loop | Required line | Required evidence |
| --- | --- | --- |
| Loop 0 | repo truth still says broker-level guarantees only | `bash scripts/check-security-claims.sh` |
| Loop 1 | raw secret ingress stays rejected and masked | `cargo test --all-targets --all-features -- --nocapture` |
| Loop 2 | trusted-side provider bridge stays bounded to the documented contract | `cargo test --all-targets --all-features -- --nocapture` |
| Loop 3 | only the documented stub trusted execution adapter path is claimed | `cargo test --all-targets --all-features -- --nocapture` |
| Loop 4 | capability action, target, and TTL binding stay fail-closed | `cargo test --all-targets --all-features -- --nocapture` |
| Loop 5 | node-to-node harness remains green and redacted | `bash scripts/run-e2e-harness.sh` |

V2 release authority is the combination of:

- green shared checklist evidence
- the [V2 support matrix](#v2-support-matrix)
- the [V2 release-note claims table](#v2-release-note-claims-table)
- completed [manual signoff](#manual-signoff)

## V3 ship gate

Call V3 real only when every Loop 0 through Loop 4 line below is backed by current code, docs, and green evidence:

| Loop | Required line | Required evidence |
| --- | --- | --- |
| Loop 0 | trusted-input sessions mint one-time broker opaque refs and keep plaintext out of the agent-visible request path | `cargo test --all-targets --all-features -- --nocapture` |
| Loop 1 | supported-host helper and preview OpenClaw transcript and log redaction remain fail-closed and green | `cargo test --all-targets --all-features -- --nocapture`, `bash scripts/run-e2e-harness.sh`, `bash scripts/run-openclaw-e2e.sh` |
| Loop 2 | sanctioned adapter registry supports the documented helper paths and the preview OpenClaw host path without exposing plaintext | `cargo test --all-targets --all-features -- --nocapture`, `bash scripts/run-e2e-harness.sh`, `bash scripts/run-openclaw-e2e.sh` |
| Loop 3 | supported hosts and excluded hosts are truthful in [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) | `bash scripts/check-v3-ship-gate.sh`, `bash scripts/check-external-host-ship-gate.sh` |
| Loop 4 | release notes and release docs limit V3 claims to shipped hosts with current evidence | `bash scripts/check-v3-ship-gate.sh`, `bash scripts/check-external-host-ship-gate.sh` |

V3 release authority is the combination of:

- green shared checklist evidence
- the [supported host matrix](docs/SUPPORTED_HOSTS.md)
- the [V3 release-note claims table](#v3-release-note-claims-table)
- completed [V3 manual signoff](#v3-manual-signoff)

## External host ship gate

Call the external-host ship gate before any release or claim that mentions a shipped external host:

- `bash scripts/check-external-host-ship-gate.sh`

The gate is the release truth for [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md).

- It fails if any `shipped` host is missing current trusted-input, transcript/log redaction, adapter, identity, or known-limit evidence.
- It fails if a shipped host's evidence is stale and downgrades that host to `preview` until the row is refreshed.
- It prints the current shipped/preview/unsupported host table in CI on every run.

## V2 support matrix

| Path | Status | What can be claimed |
| --- | --- | --- |
| Broker API with opaque refs, masked responses, role separation, and one-time capabilities | shipped | Supported V2 contract |
| Human approval flow with masked review payload and action/target binding | shipped | Supported V2 contract |
| Stub trusted-side provider bridge behind `SECRET_BROKER_PROVIDER_BRIDGE_MODE=stub` | preview | Contract validation only, not production Bitwarden mediation |
| Stub trusted execution adapter behind `SECRET_BROKER_EXECUTION_ADAPTER_MODE=stub` | preview | Contract validation only, not real browser or host execution |
| Local node-to-node harness artifacts under `target/e2e-artifacts/` | shipped | Required release evidence for the stubbed V2 path |
| External host transcript safety for OpenClaw, Claude, Codex, or other runtimes | unsupported | Do not claim end-to-end transcript safety |
| Direct plaintext secret ingress to `POST /v1/requests` | unsupported | Rejected path, never supported |

## V2 release-note claims table

Use this table verbatim or keep release notes materially equivalent.

| Claim line | Status | Evidence | Required caveat |
| --- | --- | --- | --- |
| Broker API responses stay plaintext-free | allowed | `cargo test --all-targets --all-features -- --nocapture` plus `bash scripts/check-security-claims.sh` | This is a broker-level claim |
| Approval and execute flows are bound to request id, action, and target | allowed | `cargo test --all-targets --all-features -- --nocapture` | Token is one-time and expires |
| Stubbed V2 broker, approver, and untrusted client flow are defended at the local process boundary | allowed | `bash scripts/run-e2e-harness.sh` | This is not supported-host certification |
| Transcript-safe host integrations exist | blocked | none in this repo | Remove this line from V2 release notes |
| Real browser-fill, signing, or production provider mediation ships in V2 | blocked | none in this repo | Remove this line from V2 release notes |

## V3 release-note claims table

Use this table verbatim or keep release notes materially equivalent.

| Claim line | Status | Evidence | Required caveat |
| --- | --- | --- | --- |
| Supported hosts can use broker-owned trusted-input sessions to keep plaintext out of the agent-visible request path | allowed | `cargo test --all-targets --all-features -- --nocapture` | This is still bounded to the hosts and paths listed in [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) |
| The local helper harness path supports masked `password_fill`, `request_sign`, and `credential_handoff` flows without exposing plaintext to helper transcripts or artifacts | allowed | `cargo test --all-targets --all-features -- --nocapture`, `bash scripts/run-e2e-harness.sh` | Repo-owned certification only; not a blanket claim for external runtimes |
| OpenClaw-style HTTP hosts are fully certified for V3 end-to-end claims | blocked | `bash scripts/run-openclaw-e2e.sh`, `bash scripts/check-v3-ship-gate.sh`, `bash scripts/check-external-host-ship-gate.sh` | Keep OpenClaw preview until Task 2 adds host-specific identity evidence |
| Claude, Codex, or arbitrary external runtimes are certified transcript-safe V3 hosts | blocked | none in this repo | Remove this line from V3 release notes |
| Production browser automation or production provider mediation ships in V3 | blocked | none in this repo | Keep adapter claims at the documented helper-path contract |

## Manual signoff

Both signoffs are required before tagging or deployment:

- Claims review signoff:
  - confirm `docs/SECURITY_GUARANTEES.md`, this release checklist, and release notes all say the same thing
  - confirm every preview or unsupported path stays out of the shipped V2 claim set
- Deployment topology review signoff:
  - confirm the planned topology matches [docs/INTEGRATION.md](docs/INTEGRATION.md#supported-v2-topology)
  - confirm private-network placement, trusted-side provider placement, log handling, audit export, and key separation are all still true

If either signoff fails, block the V2 release or downgrade it to preview.

## V3 manual signoff

Both signoffs are required before tagging or deployment:

- Host matrix review signoff:
  - confirm [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) matches the current host evidence
  - confirm every `shipped` host has current trusted-input, transcript/log, adapter, identity, and known-limit evidence
  - confirm every preview or unsupported host stays out of the V3 claim set
- Claims and regression review signoff:
  - confirm `docs/SECURITY_GUARANTEES.md`, this release checklist, and release notes all say the same thing
  - confirm host-version or integration-path drift has been reviewed for every shipped host

If either signoff fails, block the V3 release or downgrade it to preview.

## V4 ship gate

Call V4 real only when every Loop 0 through Loop 5 line below is backed by current code, docs, and green evidence:

| Loop | Required line | Required evidence |
| --- | --- | --- |
| Loop 0 | policy decisions are explainable across action, target, actor, environment, and risk | `cargo test policy_engine_marks_public_request_sign_as_step_up_with_explanation -- --nocapture` |
| Loop 1 | local helper stub identity and preview OpenClaw host-signed identity both fail closed on mismatch or downgrade, with same-process replay rejection on host-signed envelopes | `cargo test approval_payload_includes_verified_identity_summary -- --nocapture`, `cargo test execute_rejects_identity_mismatch_after_approval -- --nocapture`, `cargo test create_request_rejects_replayed_host_signed_identity_envelope -- --nocapture` |
| Loop 2 | audit-chain verification and forensic export remain green and redact-safe | `cargo test audit_chain_verification_detects_tampering -- --nocapture`, `cargo test forensic_bundle_export_is_redact_safe_and_tamper_evident -- --nocapture` |
| Loop 3 | rotation and recovery drills remain repeatable and evidence-backed | `bash scripts/run-rotation-recovery-drills.sh` |
| Loop 4 | PR-safe adversarial checks remain green and extended checks are defined for schedule use | `bash scripts/run-adversarial-suite.sh pr` |
| Loop 5 | release docs, support statements, and CI truth match current V4 evidence | `bash scripts/check-v4-ship-gate.sh` |

V4 release authority is the combination of:

- green shared checklist evidence
- [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md)
- the [V4 platform claims table](#v4-platform-claims-table)
- completed [V4 manual signoff](#v4-manual-signoff)

## V4 platform claims table

| Claim line | Status | Evidence | Required caveat |
| --- | --- | --- | --- |
| Broker policy decisions now explain action, target, actor, environment, and risk | allowed | policy tests plus full suite | Broker-owned policy claim only |
| Local helper paths can verify runtime, host, and adapter identity in stub mode | allowed | identity tests | Local stub-attestation path only |
| OpenClaw preview paths can require host-specific signed identity with same-process replay and downgrade protection | allowed | host-signed identity tests | Keep OpenClaw preview until the host matrix promotes it; do not turn this into a blanket external-runtime trust claim or independent host discovery claim |
| Operators can verify audit-chain integrity and export redact-safe forensic bundles | allowed | forensic tests | Local SQLite evidence path only |
| Rotation/recovery discipline and adversarial verification are part of release gating | allowed | drill script plus adversarial suite | Claim strength depends on current evidence |
| External runtimes now have shipped V4 identity or platform trust | blocked | none in this repo | Keep external runtimes preview or unsupported |

## V4 manual signoff

- Platform support review signoff:
  - confirm [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) matches current evidence
  - confirm [docs/IDENTITY_MODEL.md](docs/IDENTITY_MODEL.md) matches the configured identity tier and host requirements
  - confirm shipped, preview, deprecated, and unsupported statements are still truthful
- Continuous evidence review signoff:
  - confirm adversarial PR lane is green
  - confirm rotation/recovery drill artifacts are current enough for release
  - confirm any missing extended evidence has already downgraded claims where required

If either signoff fails, block the V4 release or downgrade it to preview.

## Linux release checklist

- Install the binary to a stable path
- Install the `systemd` unit files
- Point `SECRET_BROKER_DB` at persistent storage
- Use `SECRET_BROKER_MODE=enforce` for real deployments
- Enable the backup timer
- Confirm `scripts/healthcheck.sh` passes after startup and after restore

## macOS release checklist

- Install the binary to a stable path such as `/usr/local/opt/secret-broker/bin/secret-broker`
- Install `launchd/com.secret-broker.plist`
- Replace placeholder environment values in the plist
- Ensure the SQLite DB lives on encrypted storage
- Confirm `launchctl` starts and restarts the service cleanly

## Windows release checklist

- Install the binary to `C:\Program Files\SecretBroker\secret-broker.exe` or equivalent
- Run `windows/install-secret-broker.ps1` as Administrator
- Set machine-level environment variables before the service starts
- Ensure the SQLite DB lives on encrypted storage
- Confirm `Start-Service`, `Stop-Service`, and `Restart-Service` work cleanly

Windows is supported, but it is not the primary release target.

## Host integration checklist

- Give host runtimes the `client` key only
- Give human approval tooling the `approver` key only
- Keep host runtimes on the untrusted side of the trust boundary
- Keep provider credentials and trusted execution adapter state on the trusted side only
- Do not market host transcript safety unless a supported end-to-end test proves it
- Do not let host runtimes or agent sessions see plaintext secrets
- Keep target allowlists and amount caps conservative
- Confirm approval responses show masked review payloads and execution still requires the approved action and target
- Confirm the OpenClaw lane is green before claiming OpenClaw preview evidence
- Confirm the local node-to-node harness is green before making V2 security claims

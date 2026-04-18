# Platform Support Matrix

This document is the V4 platform-support source of truth. V3 host status still comes from [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) and `scripts/check-external-host-ship-gate.sh`.

## Control matrix

| Control | Status | Evidence | Notes |
| --- | --- | --- | --- |
| Policy engine over action, target, actor, environment, and risk | shipped | `cargo test policy_engine_marks_public_request_sign_as_step_up_with_explanation -- --nocapture` | Repo-owned broker policy only |
| Verified runtime, host, and adapter identity via stub attestation | shipped | `cargo test health_reports_identity_verification_mode -- --nocapture` | Local helper-only shared-key contract |
| Host-specific runtime identity via host-signed attestation | preview | `cargo test approval_payload_includes_verified_identity_summary -- --nocapture`, `cargo test execute_rejects_identity_mismatch_after_approval -- --nocapture` | OpenClaw-specific host key, replay rejection, and host/runtime binding; still not a blanket external-runtime trust claim |
| Audit-chain verification and redact-safe forensic export | shipped | `cargo test audit_chain_verification_detects_tampering -- --nocapture`, `cargo test forensic_bundle_export_is_redact_safe_and_tamper_evident -- --nocapture` | Uses local SQLite evidence |
| Rotation and recovery drills | shipped | `bash scripts/run-rotation-recovery-drills.sh` | Produces local drill artifacts under `target/drill-artifacts/` |
| PR-safe adversarial regression lane | shipped | `bash scripts/run-adversarial-suite.sh pr` | Safe for pull requests |
| Extended adversarial verification lane | shipped | `bash scripts/run-adversarial-suite.sh extended` | Heavier lane for scheduled verification |

## Runtime matrix

| Runtime path | Status | Identity | Notes |
| --- | --- | --- | --- |
| Local helper runtime (`src/bin/e2e-node.rs`) | shipped | stub verified | Repo-owned path only |
| OpenClaw-style HTTP runtime | preview | host-signed preview | Host-specific verification exists, but broader V3/V4 claims still stay preview until the host matrix says otherwise |
| Claude / Codex / arbitrary external runtimes | unsupported | not certified | Do not claim V4 platform trust tier or imply host certification from this matrix |

## Adapter matrix

| Adapter path | Status | Identity | Notes |
| --- | --- | --- | --- |
| `password_fill_stub` | shipped on local helper path | supported in stub mode | Not production browser automation |
| `request_sign_stub` | shipped on local helper path | supported in stub mode | Not production request signing service |
| `credential_handoff_stub` | shipped on local helper path | supported in stub mode | Bounded helper-path contract only |
| OpenClaw documented HTTP host path | preview | requires host-signed mode | Stronger than local shared headers, but still preview-only evidence |

## Claim downgrade policy

- If PR-safe adversarial checks fail, block the V4 ship gate.
- If extended adversarial checks fail, downgrade platform claims until evidence is restored.
- If identity verification is disabled or unverifiable for a path, that path cannot claim the stronger V4 trust tier.
- If a host-signed path falls back to `stub` or `off`, approval and execute-time checks must reject the downgrade.
- If audit-chain verification fails, block release and treat forensic exports as suspect until repaired.
- If the external-host ship gate marks a host stale, keep that host at `preview` until fresh evidence returns.
- Do not use a V3 shipped host label to imply V4 platform trust for an external runtime.

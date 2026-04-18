# Post-V4 Vision Completion Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the gap between the completed V2-V4 broker roadmap and the broader product vision of real external-host, transcript-safe, production-grade secret use.

**Architecture:** Keep the existing broker core and ship outward in narrow bands. First certify one real external host end to end, then replace stub identity and stub adapters with production-backed implementations, then add release authority for each newly shipped host and control surface.

**Tech Stack:** Rust, Axum, SQLite, shell verification scripts, host-specific E2E harnesses, signed identity headers or stronger attestation, release-gate docs.

---

## Why This Exists

The current repo state is strong, but still bounded:

- The broker core is complete through V4.
- The only shipped end-to-end host is the local helper harness.
- OpenClaw is `preview`.
- Claude, Codex, and arbitrary external runtimes are `unsupported`.
- Identity is stub attestation, not strong runtime attestation.
- Trusted adapters are stub contracts, not production browser/signing/provider systems.

This plan defines the shortest honest path from that state to a more complete product vision.

## Delivery Strategy

Do not try to universalize first.

Ship in this order:

1. Certify one real external host.
2. Replace stub identity with stronger verifiable identity for that host.
3. Replace stub adapters with at least one production adapter path.
4. Add provider mediation that keeps secrets on the trusted side.
5. Expand host support only after evidence exists per host.

## Definition Of Vision-Complete

Treat the broader vision as complete only when all of these are true:

- At least one real external host is `shipped` in [docs/product/SUPPORTED_HOSTS.md](../../product/SUPPORTED_HOSTS.md).
- That host has host-specific trusted-input, transcript/log redaction, and adapter E2E evidence.
- At least one non-stub production adapter exists and is release-gated.
- Provider mediation exists for a real secret source without exposing plaintext to the untrusted host path.
- Identity claims for the shipped host are stronger than the current stub-only local contract.
- Release docs and support matrices stay honest about every shipped, preview, and unsupported path.

### Task 1: Certify OpenClaw As The First Real Host

**Files:**
- Modify: `docs/architecture/OPENCLAW.md`
- Modify: `docs/product/SUPPORTED_HOSTS.md`
- Modify: `docs/product/INTEGRATION.md`
- Modify: `docs/product/RELEASE.md`
- Modify: `src/bin/e2e-node.rs`
- Modify: `src/lib.rs`
- Create: `scripts/run-openclaw-e2e.sh`
- Create: `docs/architecture/OPENCLAW_THREAT_NOTES.md`

**Outcome:** Move OpenClaw from contract-only preview to a host with real certification evidence, or keep it preview if any bar fails.

- [ ] Define the exact OpenClaw trust boundary and data-flow contract in `docs/architecture/OPENCLAW.md`.
- [ ] Add host-specific threat notes covering transcript sinks, log sinks, tool-call payloads, retries, and failure paths.
- [ ] Extend the current harness so OpenClaw-style HTTP traffic is exercised as a distinct host path rather than folded into the generic helper path.
- [ ] Add OpenClaw E2E assertions for:
  - trusted-input ingestion
  - transcript/log redaction
  - request approval payload masking
  - adapter execution without plaintext leakage
- [ ] Add `scripts/run-openclaw-e2e.sh` and wire it into CI as preview evidence.
- [ ] Update `docs/product/SUPPORTED_HOSTS.md` so OpenClaw remains `preview` until the new suite is green, then promote it to `shipped`.
- [ ] Commit with message: `feat: certify openclaw host path`

**Verification:**
- `bash scripts/run-openclaw-e2e.sh`
- `bash scripts/check-v3-ship-gate.sh`
- `cargo test --all-targets --all-features -- --nocapture`

### Task 2: Replace Stub Identity With Stronger Runtime Identity

**Files:**
- Modify: `src/identity.rs`
- Modify: `src/handlers/requests.rs`
- Modify: `src/handlers/execution.rs`
- Modify: `src/handlers/health.rs`
- Modify: `src/lib.rs`
- Modify: `docs/product/PLATFORM_SUPPORT.md`
- Modify: `docs/product/SECURITY_GUARANTEES.md`
- Modify: `docs/product/RELEASE.md`
- Create: `docs/product/IDENTITY_MODEL.md`

**Outcome:** Make identity claims mean more than signed local headers and make them host-specific.

- [ ] Define identity tiers in `docs/product/IDENTITY_MODEL.md`: `off`, `stub`, `host-signed`, `hardware-backed` or equivalent.
- [ ] Separate current stub verification from the stronger verification path in `src/identity.rs` instead of treating them as the same trust class.
- [ ] Bind request approval and execute-time checks to the stronger identity tier for the first shipped external host.
- [ ] Add tests for replayed identity envelopes, expired identity, mismatched host/runtime pairs, and downgraded identity mode.
- [ ] Update `docs/product/PLATFORM_SUPPORT.md` so platform claims distinguish stub-only paths from stronger identity paths.
- [ ] Commit with message: `feat: add strong host identity verification`

**Verification:**
- `cargo test approval_payload_includes_verified_identity_summary -- --nocapture`
- `cargo test execute_rejects_identity_mismatch_after_approval -- --nocapture`
- `cargo test --all-targets --all-features -- --nocapture`

### Task 3: Ship The First Production Adapter

**Files:**
- Modify: `src/adapter.rs`
- Modify: `src/handlers/execution.rs`
- Modify: `src/lib.rs`
- Modify: `docs/product/PLATFORM_SUPPORT.md`
- Modify: `docs/product/SECURITY_GUARANTEES.md`
- Modify: `docs/product/RELEASE.md`
- Create: `docs/product/ADAPTERS.md`
- Create: `scripts/run-adapter-e2e.sh`

**Outcome:** Replace at least one stub adapter with a bounded production adapter, without widening claims past evidence.

- [ ] Pick one adapter only for first ship: `request_sign` is the cleanest candidate because it avoids UI automation.
- [ ] Document the adapter boundary, inputs, outputs, audit fields, failure handling, and rollback policy in `docs/product/ADAPTERS.md`.
- [ ] Implement the production adapter behind an explicit config mode separate from the current stub.
- [ ] Add E2E cases proving:
  - no plaintext broker response
  - no plaintext host transcript leak
  - audit coverage on success and failure
  - action/target/policy binding survives the real adapter path
- [ ] Keep `password_fill` and `credential_handoff` as preview until they each have their own proof.
- [ ] Commit with message: `feat: ship first production adapter`

**Verification:**
- `bash scripts/run-adapter-e2e.sh`
- `bash scripts/run-adversarial-suite.sh pr`
- `cargo test --all-targets --all-features -- --nocapture`

### Task 4: Add Production Provider Mediation

**Files:**
- Modify: `src/lib.rs`
- Modify: `src/handlers/trusted_input.rs`
- Modify: `src/handlers/requests.rs`
- Modify: `docs/product/SECURITY_GUARANTEES.md`
- Modify: `docs/product/INTEGRATION.md`
- Modify: `docs/product/RELEASE.md`
- Create: `docs/product/PROVIDER_MEDIATION.md`
- Create: `scripts/run-provider-mediation-e2e.sh`

**Outcome:** Let the broker resolve a real secret source on the trusted side without turning the host into a provider client.

- [ ] Define the provider mediation contract in `docs/product/PROVIDER_MEDIATION.md`, including what material is allowed to cross the broker boundary.
- [ ] Add one real provider integration path behind an explicit production mode.
- [ ] Ensure trusted-input and request creation still accept opaque refs only from the host side.
- [ ] Add tests for provider outage, revoked credential, missing ref, wrong vault/item binding, and audit visibility.
- [ ] Keep all release claims narrow: provider mediation shipped only for the documented provider and mode.
- [ ] Commit with message: `feat: add production provider mediation`

**Verification:**
- `bash scripts/run-provider-mediation-e2e.sh`
- `bash scripts/check-security-claims.sh`
- `cargo test --all-targets --all-features -- --nocapture`

### Task 5: Create A Real External-Host Ship Gate

**Files:**
- Modify: `docs/product/SUPPORTED_HOSTS.md`
- Modify: `docs/product/PLATFORM_SUPPORT.md`
- Modify: `docs/product/RELEASE.md`
- Modify: `.github/workflows/ci.yml`
- Create: `scripts/check-external-host-ship-gate.sh`

**Outcome:** Make external-host support impossible to overclaim.

- [ ] Add a ship gate that fails if any host is marked `shipped` without current host-specific evidence.
- [ ] Require every shipped host to list:
  - trusted-input evidence
  - transcript/log redaction evidence
  - adapter evidence
  - identity evidence
  - known limits
- [ ] Add downgrade rules so stale evidence automatically pushes a host back to `preview`.
- [ ] Add CI summary output that prints the current shipped/preview/unsupported host table on every run.
- [ ] Commit with message: `feat: add external host ship gate`

**Verification:**
- `bash scripts/check-external-host-ship-gate.sh`
- `bash scripts/check-v3-ship-gate.sh`
- `bash scripts/check-v4-ship-gate.sh`

## Recommended Sequencing

Execute in this order:

1. Task 1
2. Task 5
3. Task 2
4. Task 3
5. Task 4

Reason:

- Host certification first gives the product a real external path.
- Ship-gate hardening prevents dishonest expansion while the rest is in flight.
- Stronger identity should land before broader production claims.
- Production adapters and provider mediation should ship one at a time.

## What Not To Do

- Do not claim Claude or Codex support without host-specific evidence in this repo.
- Do not ship multiple production adapters in one jump.
- Do not widen identity claims before the stronger verification mechanism exists.
- Do not treat preview host contracts as shipped just because local helper tests are green.

## Success Bar

This plan succeeds when:

- The repo still preserves its current broker-level guarantees.
- One real external host has current green evidence and moves to `shipped`.
- One stronger-than-stub identity path is live for that host.
- One production adapter and one production provider mediation path are release-gated.
- Docs and CI make overclaiming difficult.

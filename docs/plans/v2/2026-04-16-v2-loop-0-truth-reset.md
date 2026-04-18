# V2 Loop 0 Truth Reset Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the repo honest about its current security guarantees by adding a claims matrix, tightening boundary language across docs, and adding a lightweight automated claim-audit gate to stop future overclaiming.

**Architecture:** This loop is docs-first with a tiny verification script. It does not change broker behavior. Instead, it resets the system contract so every public-facing doc distinguishes broker-level guarantees from end-to-end zero-trust guarantees, and then adds one repeatable check to keep those claims aligned over time.

**Tech Stack:** Markdown docs, Bash, GitHub Actions

---

## File Structure

- Create: `docs/SECURITY_GUARANTEES.md`
- Create: `scripts/check-security-claims.sh`
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/THREAT_MODEL.md`
- Modify: `docs/INTEGRATION.md`
- Modify: `docs/OPENCLAW.md`
- Modify: `docs/QUICKSTART.md`
- Modify: `docs/RELEASE.md`
- Modify: `.github/workflows/ci.yml`

## Task 1: Add The Security Guarantees Matrix

**Files:**
- Create: `docs/SECURITY_GUARANTEES.md`
- Modify: `README.md`

- [ ] **Step 1: Create the guarantees matrix document**

Write `docs/SECURITY_GUARANTEES.md` with this exact content:

```markdown
# Security Guarantees

This document is the source of truth for what AgentSecrets currently guarantees, what it only partially implements, and what it does not yet solve.

## Implemented on the current line

- Broker API responses do not return plaintext secret values.
- Request and approval flows use separate `client` and `approver` roles.
- Capability tokens are single-use and expire.
- Execution results are masked.
- Audit events exist for request lifecycle activity.

## Intended contract, not fully enforced end to end yet

- Opaque secret refs such as `bw://...` should be the only supported secret identifiers.
- Secret resolution should happen only on the trusted side.
- Secret-dependent actions should happen through trusted execution adapters.
- Host apps should remain on the untrusted side of the boundary.

## Not currently guaranteed

- Transcript-safe host integrations.
- Chatbox or session-history redaction across external runtimes.
- Browser-fill or signing adapters that consume secrets entirely on the trusted side.
- Full Bitwarden mediation implemented in this repo.
- End-to-end node-to-node verification across real host integrations.

## Supported trust claim on the current line

AgentSecrets currently provides broker-level no-plaintext-response guarantees. It does **not** yet provide a complete end-to-end zero-trust secret-use system for external host apps.

## Unsafe patterns

Do not treat these as supported:

- Typing a password directly into agent chat or task input.
- Sending raw secret values to `POST /v1/requests`.
- Letting host apps talk directly to Bitwarden.
- Claiming transcript safety without a passing end-to-end test.

## Release rule

If docs, code, or tests drift, reduce the claim. Do not expand the claim before the implementation and verification exist.
```

- [ ] **Step 2: Verify the new document exists and reads cleanly**

Run:

```bash
sed -n '1,220p' docs/SECURITY_GUARANTEES.md
```

Expected:
- the file exists
- the four sections `Implemented on the current line`, `Intended contract, not fully enforced end to end yet`, `Not currently guaranteed`, and `Unsafe patterns` are present

- [ ] **Step 3: Link the guarantees matrix from the README**

Replace the opening of `README.md`:

```markdown
# AgentSecrets

Standalone, open-source, zero-trust secret broker for agents.

## Goal
Allow Claude, Codex, OpenClaw, and other agents to **use** secrets without receiving plaintext secret values.
```

with:

```markdown
# AgentSecrets

Standalone, open-source secret broker for agent workflows.

## Goal
Allow Claude, Codex, OpenClaw, and other agents to request secret-dependent actions without broker API responses exposing plaintext secret values.

## Security Guarantees

The current line provides **broker-level no-plaintext-response guarantees**. It does **not** yet provide a complete end-to-end transcript-safe zero-trust system for external host apps.

Read [docs/SECURITY_GUARANTEES.md](docs/SECURITY_GUARANTEES.md) before relying on any security property.
```

- [ ] **Step 4: Re-read the README introduction to verify the claim is narrower and explicit**

Run:

```bash
sed -n '1,40p' README.md
```

Expected:
- the phrase `zero-trust secret broker for agents` is gone from the opening paragraph
- the README now points readers to `docs/SECURITY_GUARANTEES.md`
- the README explicitly says end-to-end transcript-safe guarantees do not exist yet

- [ ] **Step 5: Commit the guarantees matrix and README truth reset**

Run:

```bash
git add docs/SECURITY_GUARANTEES.md README.md
git commit -m "docs: add security guarantees matrix"
```

Expected:
- a commit is created with only the new guarantees doc and README truth-reset changes

## Task 2: Reset The README And Architecture Contract

**Files:**
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Replace the README security model bullets**

Replace this block in `README.md`:

```markdown
## Security model
- Agent runtimes are treated as untrusted.
- Raw secrets are never returned by API responses.
- High-risk requests can require human approval.
- Approvals are bound to request context and token TTL.
- Capability tokens are one-time and invalid after execution.
```

with:

```markdown
## Security model
- Agent runtimes are treated as untrusted.
- Broker API responses do not return plaintext secret values.
- High-risk requests can require human approval.
- Approvals are bound to request context and token TTL.
- Capability tokens are one-time and invalid after execution.
- External host-app transcript safety is **not** currently guaranteed by this repo.
```

- [ ] **Step 2: Replace the README example flow footer**

Replace this line in the `## Example flow` section:

```markdown
4. Broker returns masked execution result only.
```

with:

```markdown
4. Broker returns a masked execution result only.
5. Any transcript or chatbox safety claim still depends on the host integration, which is not yet fully implemented in this repo.
```

- [ ] **Step 3: Rewrite the architecture doc so it distinguishes current state from target state**

Replace all content in `docs/ARCHITECTURE.md` with:

```markdown
# Architecture

## Current implemented boundary

1. Agent runtime (untrusted)
2. Broker API (policy, approvals, capability issuance, masked execution responses)

## Target boundary for future versions

3. Trusted secret provider adapters (Bitwarden, keychain, HSM)
4. Trusted execution adapters (browser fill, signing, send)
5. Supported host integrations with transcript-safe behavior

## Current contract

- Input: action intent and context
- Output: allow or deny plus masked metadata
- No plaintext secret responses from broker APIs
- No current guarantee of transcript-safe host behavior

## Modes

- `off`: legacy passthrough mode for migration
- `monitor`: records and auto-approves
- `enforce`: approval plus policy required
```

- [ ] **Step 4: Verify the architecture doc no longer implies provider and execution adapters already exist**

Run:

```bash
sed -n '1,200p' docs/ARCHITECTURE.md
```

Expected:
- the doc now has separate `Current implemented boundary` and `Target boundary for future versions` sections
- the doc explicitly says transcript-safe host behavior is not currently guaranteed

- [ ] **Step 5: Commit the README and architecture reset**

Run:

```bash
git add README.md docs/ARCHITECTURE.md
git commit -m "docs: narrow architecture and security claims"
```

Expected:
- a commit is created with only README and architecture truth-reset changes

## Task 3: Reset The Threat Model And Release Gate

**Files:**
- Modify: `docs/THREAT_MODEL.md`
- Modify: `docs/RELEASE.md`

- [ ] **Step 1: Expand the threat model with explicit transcript and claim-gap language**

Replace all content in `docs/THREAT_MODEL.md` with:

```markdown
# Threat Model

This repo is intended to evolve into an end-to-end zero-trust secret-use system. On the current line, it only guarantees broker-level no-plaintext-response behavior.

## Trust boundaries

- Trusted:
  - The broker process
  - Human approval tooling
  - Operator-only audit and log stores
- Untrusted:
  - Agent runtimes
  - OpenClaw or similar host apps
  - Browser content loaded into agent-facing UI
  - Session transcripts
  - Prompt history
  - Agent-visible logs

## Security goals on the current line

- Never expose plaintext secret values in broker API responses.
- Keep secret-dependent actions behind explicit approval where policy requires it.
- Bind approvals to specific request context.
- Make capability tokens single-use and short-lived.
- Preserve an auditable trail of approvals and execution.

## Security goals for future lines

- Prevent plaintext secrets from entering agent-visible transcript surfaces.
- Resolve opaque secret refs only on the trusted side.
- Execute secret-dependent actions through trusted adapters rather than raw secret reveal.
- Prove the above with node-to-node end-to-end tests.

## What this repo must defend against today

- Prompt injection that tries to coerce the broker flow into revealing secrets.
- Stolen or replayed capability tokens.
- Direct provider access from untrusted runtimes.
- Tampering with request history or audit records.
- Security overclaiming in docs and release notes.

## What this repo does not solve yet

- Transcript leakage in external host apps.
- Secure password entry outside agent-visible chat surfaces.
- Full trusted-side provider mediation.
- Full trusted-side execution adapters.

## Operational rules

- Keep the broker on localhost or a private network.
- Keep agent runtimes on the untrusted side of the boundary.
- Give agent runtimes only the `client` key.
- Give approver tools only the `approver` key.
- Treat any raw secret typed into chat or prompt history as outside the current guarantee.
- Reduce the claim before shipping if implementation and docs diverge.
```

- [ ] **Step 2: Tighten the release checklist to require the new claim audit**

Replace all content in `docs/RELEASE.md` with:

```markdown
# Release Checklist

Use this when publishing the repo, cutting a tag, or deploying a new host.

## Shared checklist

- Confirm the repo still builds: `cargo fmt --all -- --check`, `cargo check`, `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`
- Confirm `LICENSE` is Apache 2.0
- Confirm `.env.example` is present and real secrets are not committed
- Run `bash scripts/check-security-claims.sh`
- Confirm `docs/SECURITY_GUARANTEES.md` matches the current implementation line
- Confirm docs distinguish broker-level guarantees from end-to-end host guarantees
- Confirm release notes do not claim transcript-safe integrations unless backed by passing end-to-end tests

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
- Do not market host transcript safety unless a supported end-to-end test proves it
- Do not let host runtimes or agent sessions see plaintext secrets
- Keep target allowlists and amount caps conservative
```

- [ ] **Step 3: Run a focused diff review on the threat and release docs**

Run:

```bash
git diff -- docs/THREAT_MODEL.md docs/RELEASE.md
```

Expected:
- the threat model now contains `What this repo does not solve yet`
- the release checklist now requires `bash scripts/check-security-claims.sh`

- [ ] **Step 4: Commit the threat-model and release-gate reset**

Run:

```bash
git add docs/THREAT_MODEL.md docs/RELEASE.md
git commit -m "docs: reset threat model and release gate"
```

Expected:
- a commit is created with only threat model and release checklist changes

## Task 4: Reset Host-Facing Integration Docs

**Files:**
- Modify: `docs/INTEGRATION.md`
- Modify: `docs/OPENCLAW.md`
- Modify: `docs/QUICKSTART.md`

- [ ] **Step 1: Rewrite the integration guide around supported versus unsupported flows**

Replace all content in `docs/INTEGRATION.md` with:

```markdown
# Integration Guide

## Current supported contract

Use only the **client key** from agent or host runtimes.

Flow:

1. `POST /v1/requests`
2. Wait for approver decision if status is `pending_approval`
3. Receive one-time `capability_token` from an isolated approval channel
4. `POST /v1/execute`

The current repo guarantees broker-level masked responses. It does **not** yet guarantee transcript-safe host behavior.

## Required integration rule

- Never request raw secret values from the broker.
- Treat opaque refs such as `bw://...` as the intended contract.
- Do not put plaintext passwords into prompts, chat boxes, or task memory.

## Approval app pattern

Use only the **approver key**.

- Approve: `POST /v1/requests/:id/approve`
- Deny: `POST /v1/requests/:id/deny`

Suggested approval payload shown to user:

- action
- target
- amount
- masked secret ref

## Host-app integration rule

Treat any OpenClaw-like host app as an untrusted runtime:

- Give the host app only the **client** key.
- Never give the host app the approver key.
- Restrict host egress so it can only reach the broker and allowed APIs.
- Do not let the host app talk directly to Bitwarden.
- Do not claim transcript safety unless an end-to-end test proves it for that host.

## Recommended rollout

1. `SECRET_BROKER_MODE=monitor`
2. Observe requests and tune allowlist and caps
3. `SECRET_BROKER_MODE=enforce`
4. Add trusted provider and execution boundaries before expanding security claims
```

- [ ] **Step 2: Rewrite the OpenClaw doc as an untrusted-host contract, not a finished zero-trust integration**

Replace all content in `docs/OPENCLAW.md` with:

```markdown
# OpenClaw Integration

This doc describes the intended broker contract for OpenClaw-like host apps. It does not certify current end-to-end transcript safety.

## What OpenClaw should do

- Talk only to the broker API.
- Use the `client` key for runtime requests.
- Never embed provider credentials in OpenClaw.
- Never request raw secret values from the broker.
- Treat opaque secret refs such as `bw://...` as the supported contract.
- Stay on the untrusted side of the trust boundary.

## Minimum setup

1. Set `SECRET_BROKER_BIND=127.0.0.1:4815` or expose the broker only to trusted hosts.
2. Configure OpenClaw to call:
   - `POST /v1/requests`
   - `GET /v1/requests`
   - `POST /v1/execute`
3. Configure your approver channel to call:
   - `POST /v1/requests/:id/approve`
   - `POST /v1/requests/:id/deny`
   - `GET /v1/audit`
4. Keep provider systems on the trusted side.

## What this doc does not claim

- It does not claim transcript-safe host behavior.
- It does not claim secure password entry through chat surfaces.
- It does not claim a finished trusted-side browser-fill adapter.

## Drop-in contract

- Agent intent goes in as `secret_ref`, `action`, `target`, and optional `amount_cents`.
- Broker returns masked metadata, request IDs, and single-use capability tokens.
- Execution requires the one-time capability token.
- Broker API responses do not return plaintext secret values.
```

- [ ] **Step 3: Rewrite the quickstart so it warns against chat-based secret entry**

Replace all content in `docs/QUICKSTART.md` with:

```markdown
# Quickstart

This repo currently provides broker-level masked-response guarantees. It does **not** yet provide a fully supported transcript-safe host integration.

The agent runtime should only hold the `client` key. Human approval tooling should only hold the `approver` key. Linux and macOS are the primary host platforms. Windows is supported, but secondary.

## Before you start

- Build the broker once: `cargo build --release`
- Copy `.env.example` to `.env`
- Set strong random values for:
  - `SECRET_BROKER_CLIENT_API_KEY`
  - `SECRET_BROKER_APPROVER_API_KEY`
- Set `SECRET_BROKER_MODE=enforce`
- Do **not** type secrets into prompts, chat boxes, or task memory

## Linux quickstart

1. Install the binary.
2. Install the `systemd` units from [systemd/](../systemd/).
3. Put your environment file at `/etc/secret-broker/secret-broker.env`.
4. Start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now secret-broker.service
```

5. Verify readiness:

```bash
scripts/healthcheck.sh http://127.0.0.1:4815
```

## macOS quickstart

1. Install the binary somewhere stable, such as `/usr/local/opt/secret-broker/bin/secret-broker`.
2. Install [launchd/com.secret-broker.plist](../launchd/com.secret-broker.plist).
3. Replace the placeholder environment values in the plist.
4. Load the service:

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/com.secret-broker.plist
```

5. Verify readiness:

```bash
scripts/healthcheck.sh http://127.0.0.1:4815
```

## Windows quickstart

1. Install the binary to `C:\Program Files\SecretBroker\secret-broker.exe` or equivalent.
2. Run [windows/install-secret-broker.ps1](../windows/install-secret-broker.ps1) from an elevated PowerShell session.
3. Supply the client and approver API keys when prompted.
4. Verify readiness against the local bind address after the service starts.

## Supported use today

Use this flow for current broker-level guarantees:

1. The host sends request intent to the broker with the `client` key.
2. The broker evaluates policy and either approves immediately or returns `pending_approval`.
3. The human approval app uses the `approver` key to approve or deny.
4. The host executes with the one-time capability token.
5. The broker returns masked results only.

## Minimum safety settings

- Keep the broker local or private-network only
- Set a strict `SECRET_BROKER_ALLOWED_TARGET_PREFIXES`
- Keep `SECRET_BROKER_MAX_AMOUNT_CENTS` low
- Use key rotation through `POST /v1/admin/keys/:role/rotate`
- Keep the SQLite DB on encrypted storage
```

- [ ] **Step 4: Verify the host-facing docs all disclaim transcript-safe support**

Run:

```bash
rg -n "transcript-safe|Do \\*\\*not\\*\\* type secrets into prompts|does not certify current end-to-end transcript safety|Broker API responses do not return plaintext secret values" docs/INTEGRATION.md docs/OPENCLAW.md docs/QUICKSTART.md
```

Expected:
- all three files are matched
- at least one match per file appears

- [ ] **Step 5: Commit the host-facing doc reset**

Run:

```bash
git add docs/INTEGRATION.md docs/OPENCLAW.md docs/QUICKSTART.md
git commit -m "docs: reset host integration contract"
```

Expected:
- a commit is created with only the integration, OpenClaw, and quickstart changes

## Task 5: Add The Claim Audit Script And Wire It Into CI

**Files:**
- Create: `scripts/check-security-claims.sh`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/RELEASE.md`

- [ ] **Step 1: Create the claim audit script**

Write `scripts/check-security-claims.sh` with this exact content:

```bash
#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "claim-audit: $1" >&2
  exit 1
}

[[ -f docs/SECURITY_GUARANTEES.md ]] || fail "missing docs/SECURITY_GUARANTEES.md"

grep -Fq "broker-level no-plaintext-response guarantees" README.md || fail "README missing narrowed guarantee"
grep -Fq "does **not** yet provide a complete end-to-end transcript-safe zero-trust system" README.md || fail "README missing transcript-safe disclaimer"
grep -Fq "Current implemented boundary" docs/ARCHITECTURE.md || fail "ARCHITECTURE missing current boundary section"
grep -Fq "No current guarantee of transcript-safe host behavior" docs/ARCHITECTURE.md || fail "ARCHITECTURE missing transcript disclaimer"
grep -Fq "What this repo does not solve yet" docs/THREAT_MODEL.md || fail "THREAT_MODEL missing current gap section"
grep -Fq "Run \`bash scripts/check-security-claims.sh\`" docs/RELEASE.md || fail "RELEASE missing claim audit step"
grep -Fq "The current repo guarantees broker-level masked responses. It does **not** yet guarantee transcript-safe host behavior." docs/INTEGRATION.md || fail "INTEGRATION missing host disclaimer"
grep -Fq "It does not certify current end-to-end transcript safety." docs/OPENCLAW.md || fail "OPENCLAW missing disclaimer"
grep -Fq "Do **not** type secrets into prompts, chat boxes, or task memory" docs/QUICKSTART.md || fail "QUICKSTART missing prompt-entry warning"

echo "claim-audit: ok"
```

- [ ] **Step 2: Make the script executable and prove it passes locally**

Run:

```bash
chmod +x scripts/check-security-claims.sh
bash scripts/check-security-claims.sh
```

Expected:

```text
claim-audit: ok
```

- [ ] **Step 3: Add the claim-audit step to CI**

Insert this step into `.github/workflows/ci.yml` after `Format check` and before `Clippy`:

```yaml
      - name: Claim audit
        run: bash scripts/check-security-claims.sh
```

The resulting middle of the job should look like:

```yaml
      - name: Format check
        run: cargo fmt --all -- --check

      - name: Claim audit
        run: bash scripts/check-security-claims.sh

      - name: Clippy
        run: cargo clippy --all-targets --all-features -- -D warnings
```

- [ ] **Step 4: Run the exact verification commands for the finished loop**

Run:

```bash
bash scripts/check-security-claims.sh
cargo fmt --all -- --check
cargo test --all-targets --all-features -- --nocapture
```

Expected:
- `claim-audit: ok`
- rustfmt exits cleanly
- tests pass

- [ ] **Step 5: Commit the script and CI wiring**

Run:

```bash
git add scripts/check-security-claims.sh .github/workflows/ci.yml docs/RELEASE.md
git commit -m "ci: audit security claims in docs"
```

Expected:
- a commit is created with the script, CI wiring, and any release-checklist adjustments

## Spec Coverage Check

- Roadmap `V2 / Loop 0` requires a rewritten security claims matrix. Covered by Task 1.
- Roadmap `V2 / Loop 0` requires explicit trusted, untrusted, and out-of-scope language. Covered by Tasks 1 through 4.
- Roadmap `V2 / Loop 0` requires release language that distinguishes broker-level guarantees from end-to-end guarantees. Covered by Tasks 2 through 5.
- Roadmap `V2 / Loop 0` requires a repeatable check so the claim matrix cannot silently drift. Covered by Task 5.

## Plan Self-Review

- No placeholders remain.
- Every file path is explicit.
- Every verification command is runnable.
- The loop stays scoped to truth reset only; it does not silently pull in V2 ingress, provider, or adapter implementation work.

## Execution Handoff

Plan complete and saved to `docs/plans/v2/2026-04-16-v2-loop-0-truth-reset.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?

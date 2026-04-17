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

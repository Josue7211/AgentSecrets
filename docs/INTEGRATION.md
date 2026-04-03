# Integration Guide

## 1) Claude / Codex / OpenClaw client pattern

Use only the **client key**.

Flow:
1. `POST /v1/requests`
2. Wait for approver decision if status is `pending_approval`
3. Receive one-time `capability_token` from approver channel
4. `POST /v1/execute`

Never request raw secret values from the broker.
For Bitwarden-backed refs, the broker should resolve `bw://...` against the Bitwarden service running on your services VM, not from local disk.

## 2) iOS approval app pattern

Use only the **approver key**.

- Approve: `POST /v1/requests/:id/approve`
- Deny: `POST /v1/requests/:id/deny`

Suggested approval payload shown to user:
- action
- target
- amount
- masked secret ref

## 3) OpenClaw / host app integration

Treat any OpenClaw-like host app as an untrusted runtime:
- Give OpenClaw only the **client key**.
- Never give OpenClaw approver key.
- Restrict OpenClaw network egress so it can only reach broker + allowed APIs.
- If OpenClaw needs Bitwarden-backed secrets, route only through the broker; do not let it talk directly to the Bitwarden host.
- OpenClaw can run on Linux, macOS, or Windows as long as it can reach the broker over HTTP.
- The broker itself is cross-platform; only the helper deployment examples are OS-specific.

## 4) Recommended rollout

1. `SECRET_BROKER_MODE=monitor`
2. Observe requests and tune allowlist/caps
3. `SECRET_BROKER_MODE=enforce`
4. Add iOS push approvals for high-risk actions

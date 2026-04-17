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

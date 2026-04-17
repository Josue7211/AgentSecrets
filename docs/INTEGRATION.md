# Integration Guide

## Current supported contract

Use only the **client key** from agent or host runtimes.

Flow:

1. `POST /v1/requests`
2. Wait for approver decision if status is `pending_approval`
3. Receive one-time `capability_token` at request creation for auto-approved requests, or from the approval response for pending ones
4. Read the masked `approval_payload` from the approval response when human review is involved
5. `POST /v1/execute` with the same `id`, `capability_token`, `action`, and `target` that were approved

The current repo guarantees broker-level masked responses. It does **not** yet guarantee transcript-safe host behavior.
The current V2 evidence bar now includes a local node-to-node harness for the stubbed broker, approver, and untrusted client flow. That harness is not the same thing as supported-host certification.

## Secret ingress contract

- Send opaque secret references only, for example `bw://vault/item/login`.
- Do not send plaintext passwords or recovery codes to `POST /v1/requests`.
- Treat `raw_secret_rejected` as a hard integration error that must be fixed in the caller.
- Do not put plaintext passwords into prompts, chat boxes, or task memory.
- Do not expect provider credentials or plaintext provider results from the broker.
- Treat `provider_unavailable` and `provider_unsupported` as broker contract failures, not as permission to bypass the broker.

## Approval app pattern

Use only the **approver key**.

- Approve: `POST /v1/requests/:id/approve`
- Deny: `POST /v1/requests/:id/deny`

Suggested approval payload shown to user:

- request type
- action
- target
- masked secret ref
- reason

Approval contract:

- Treat the capability token as one bounded act, not as a reusable secret handle.
- Do not mutate `action` or `target` between approval display and `POST /v1/execute`.
- If the broker returns `action_mismatch`, `target_mismatch`, `capability_expired`, or `invalid_capability_context`, fail closed and create a new request.
- Denied requests invalidate any pending capability state.

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
5. Keep `bash scripts/run-e2e-harness.sh` green before claiming the stubbed V2 flow is defended end to end at the local process-boundary level

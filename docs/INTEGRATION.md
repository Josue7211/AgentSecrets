# Integration Guide

## Current supported contract

Use only the **client key** from agent or host runtimes.

Flow:

1. `POST /v1/trusted-input/sessions`
2. `POST /v1/trusted-input/sessions/:id/complete` on the trusted host input surface
3. `POST /v1/requests` using the returned broker opaque ref
4. Wait for approver decision if status is `pending_approval`
5. Receive one-time `capability_token` at request creation for auto-approved requests, or from the approval response for pending ones
6. Read the masked `approval_payload` from the approval response when human review is involved
7. `POST /v1/execute` with the same `id`, `capability_token`, `action`, and `target` that were approved

The current repo guarantees broker-level masked responses and a broker-owned trusted-input session path for supported hosts. It does **not** yet guarantee universal transcript-safe host behavior.
The local node-to-node harness now covers both the stubbed broker request flow and the trusted-input ingress path. The helper used in that harness also has tested transcript and log redaction coverage for seeded canaries and provider refs. That evidence is still not the same thing as supported-host certification.
Use [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) to decide which hosts are actually release-eligible for V3 end-to-end claims.

## Supported V2 topology

The supported V2 topology is narrow and should remain that way at release time:

- broker runs on localhost or a private network segment, not on a public host surface
- untrusted host runtimes keep only the `client` key and talk to the broker over the narrow HTTP contract
- human approval tooling keeps only the `approver` key
- trusted-side provider placement stays beside the broker boundary, never inside the untrusted host runtime
- trusted execution adapter state stays beside the broker boundary, never inside the untrusted host runtime
- log handling must avoid plaintext request bodies, provider credentials, or host transcript dumps
- audit export must come from `/v1/audit` or backed-up broker artifacts, not from host chat logs
- key handling must preserve role separation and keep rotated keys out of prompts, chat boxes, and task memory

Release operators should review this section together with the support and claims matrices in [docs/RELEASE.md](docs/RELEASE.md).
V3 operators must also review [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) before making any host-specific safety claim.
V4 operators must also review [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) before making platform-level trust claims.

## Secret ingress contract

- Send opaque secret references only, for example `bw://vault/item/login`.
- For transcript-safer supported-host ingress, mint a broker ref through the trusted-input session flow and send only that returned `tir://session/<id>` value into the agent-visible request path.
- Do not send plaintext passwords or recovery codes to `POST /v1/requests`.
- Treat `raw_secret_rejected` as a hard integration error that must be fixed in the caller.
- Do not put plaintext passwords into prompts, chat boxes, or task memory.
- Do not expect provider credentials or plaintext provider results from the broker.
- Treat `provider_unavailable` and `provider_unsupported` as broker contract failures, not as permission to bypass the broker.

## Trusted input session contract

- Start: `POST /v1/trusted-input/sessions`
- Complete: `POST /v1/trusted-input/sessions/:id/complete`
- Read status: `GET /v1/trusted-input/sessions/:id`

Required fields at session start:

- `request_type`
- `action`
- `target`
- optional `reason`

Required fields at session completion:

- `completion_token`
- opaque provider-side `secret_ref` such as `bw://vault/item/login`

Contract rules:

- Completion returns a broker opaque ref only. It does not echo the provider-side ref.
- The broker opaque ref is bound to the original `request_type`, `action`, and `target`.
- The broker opaque ref expires and can only be consumed once into `POST /v1/requests`.
- If the caller tries to reuse the ref, expect `trusted_input_consumed`.
- If the caller changes request context, expect `trusted_input_context_mismatch`.

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

Treat any OpenClaw-like host app as an untrusted runtime unless it is the documented OpenClaw preview path:

- Give the host app only the **client** key.
- Never give the host app the approver key.
- Restrict host egress so it can only reach the broker and allowed APIs.
- Do not let the host app talk directly to Bitwarden.
- If the host wants transcript-safer ingress, keep plaintext entry inside the trusted-input completion path and return only the broker opaque ref to the agent-visible runtime.
- If the host also claims transcript or log redaction, define sink classification and fail-closed behavior explicitly. Use [docs/REDACTION_POLICY.md](docs/REDACTION_POLICY.md) as the current repo-owned example and [docs/OPENCLAW_THREAT_NOTES.md](docs/OPENCLAW_THREAT_NOTES.md) for the documented OpenClaw sink model.
- If `SECRET_BROKER_IDENTITY_VERIFICATION_MODE=stub`, hosts on the baseline path must attach signed identity headers for runtime, host, adapter, timestamp, and signature.
- If `SECRET_BROKER_IDENTITY_VERIFICATION_MODE=host-signed`, hosts on that deployment baseline must also send `x-secret-broker-attestation-id` and must be signed with the configured host-specific key.
- Host-signed envelope replay rejection is currently same-process only. Do not treat it as durable across broker restart.
- Do not claim transcript safety beyond the tested path unless an end-to-end test proves it for that host.
- Keep trusted-side provider placement and trusted execution adapter placement beside the broker, not inside the host runtime.
- OpenClaw remains the preview host exception only for the documented broker HTTP path in [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md).
- Other OpenClaw-like runtimes remain untrusted until they have their own host-specific evidence.

## Recommended rollout

1. `SECRET_BROKER_MODE=monitor`
2. Observe requests and tune allowlist and caps
3. `SECRET_BROKER_MODE=enforce`
4. Add trusted provider and execution boundaries before expanding security claims
5. Keep `bash scripts/run-e2e-harness.sh` green before claiming the stubbed V2 flow is defended end to end at the local process-boundary level
6. Use the V2 ship gate in [docs/RELEASE.md](docs/RELEASE.md#v2-ship-gate) before any V2 release note or deployment claim
7. Use the V3 ship gate in [docs/RELEASE.md](docs/RELEASE.md#v3-ship-gate) plus [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) before any V3 supported-host claim
8. Use the V4 ship gate in [docs/RELEASE.md](docs/RELEASE.md#v4-ship-gate) plus [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) before any V4 platform claim

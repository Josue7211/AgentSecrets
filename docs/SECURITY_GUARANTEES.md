# Security Guarantees

This document is the source of truth for what AgentSecrets currently guarantees, what it only partially implements, and what it does not yet solve.

## Implemented in the current repo state

- Broker API responses do not return plaintext secret values.
- Broker-owned trusted input sessions can mint opaque refs for supported host flows without requiring plaintext secret entry into the agent-visible request path.
- Request and approval flows use separate `client` and `approver` roles.
- Capability tokens are single-use and expire.
- Approved capabilities are bound to request id, action, and target.
- Execution results are masked.
- Audit events exist for request lifecycle activity.
- Trusted-side provider bridge contract exists in stub form behind config.
- Provider resolution failures are masked and do not return plaintext.
- A sanctioned trusted execution adapter registry exists in stub form behind config.
- Unsupported adapter action or target context fails closed.
- Adapter success and failure paths are audited without plaintext.
- Approval responses expose masked review payloads only.
- Missing or malformed capability context fails closed.
- Local Loop 5 node-to-node harness evidence exists for the stubbed V2 flow.
- Local node-to-node harness evidence exists for the trusted-input ingress path in addition to the stubbed V2 request flow.
- The local supported-host helper path has tested transcript and log redaction coverage for seeded canary and provider-ref echo cases.
- The local supported-host helper path has sanctioned adapter-path coverage for `password_fill`, `request_sign`, and `credential_handoff`.
- Policy decisions now account for actor, environment, and risk in addition to action and target.
- Supported local identity paths can verify runtime, host, and adapter claims in stub attestation mode.
- Operators can verify audit-chain integrity and export redact-safe forensic bundles.
- The repo now includes repeatable rotation/recovery drills and adversarial verification lanes.

## Intended contract, not fully enforced end to end yet

- Opaque secret refs such as `bw://...` should be the only supported secret identifiers.
- Secret resolution should happen only on the trusted side.
- Secret-dependent actions should happen through trusted execution adapters.
- Host apps should remain on the untrusted side of the boundary.

## Not currently guaranteed

- Universal transcript-safe host integrations.
- Universal transcript and log redaction across arbitrary runtimes.
- Chatbox or session-history redaction across external runtimes.
- Real browser-fill or signing adapters beyond the current stubbed sanctioned-adapter contract.
- Production Bitwarden mediation implemented in this repo.
- End-to-end node-to-node verification across real host integrations.
- Supported-host certification for Claude, Codex, or arbitrary external runtime.
- Strong V4 identity claims for external runtimes beyond the local stub attestation path.

## Supported trust claim in the current repo state

AgentSecrets currently provides broker-level no-plaintext-response guarantees. It does **not** yet provide a complete end-to-end zero-trust secret-use system for external host apps.
For supported hosts that use the trusted-input session flow, the repo now also provides a narrow ingress contract where the agent-visible path only handles broker-issued opaque refs.
For the local supported-host helper path exercised by the harness, the repo also provides a narrow redaction contract for untrusted transcript and log sinks plus sanctioned adapter-path coverage.
For the preview OpenClaw host path, the repo now also provides host-specific evidence for trusted-input ingress, transcript/log redaction, approval masking, and adapter execution without plaintext leakage.
Those claims do not automatically extend to external host apps.
Use [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) as the only host-certification authority for V3 claims.
Use [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) as the only V4 control and claim authority.

## Unsafe patterns

Do not treat these as supported:

- Typing a password directly into agent chat or task input.
- Sending raw secret values to `POST /v1/requests`.
- Bypassing trusted-input sessions for a host flow that claims transcript-safer ingress.
- Letting host apps talk directly to Bitwarden.
- Claiming transcript safety without a passing end-to-end test.

## Release rule

If docs, code, or tests drift, reduce the claim. Do not expand the claim before the implementation and verification exist.

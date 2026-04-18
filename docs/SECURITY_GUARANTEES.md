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
- A bounded Bitwarden production provider mediation path exists behind `SECRET_BROKER_PROVIDER_BRIDGE_MODE=bitwarden-production`; it resolves `bw://...` refs on the trusted side, keeps provider credentials out of the host-visible request path, and masks outages, revoked credentials, missing refs, and binding mismatches.
- Provider resolution failures are masked and do not return plaintext.
- A sanctioned trusted execution adapter registry exists in stub form behind config.
- A bounded production `request_sign` adapter exists behind `SECRET_BROKER_EXECUTION_ADAPTER_MODE=request-sign-production`; it talks to an explicit trusted-side HTTP signing service via `SECRET_BROKER_REQUEST_SIGN_ADAPTER_URL`, returns only masked output, and does not claim browser automation.
- Unsupported adapter action or target context fails closed.
- Adapter success and failure paths are audited without plaintext.
- Approval responses expose masked review payloads only.
- Missing or malformed capability context fails closed.
- Local Loop 5 node-to-node harness evidence exists for the stubbed V2 flow.
- Local node-to-node harness evidence exists for the trusted-input ingress path in addition to the stubbed V2 request flow.
- The local supported-host helper path has tested transcript and log redaction coverage for seeded canary and provider-ref echo cases.
- The local supported-host helper path has sanctioned adapter-path coverage for `password_fill` and `credential_handoff` in stub mode, plus `request_sign` in production mode.
- Policy decisions now account for actor, environment, and risk in addition to action and target.
- Supported local identity paths can verify runtime, host, and adapter claims in stub attestation mode.
- The documented OpenClaw host path can now use host-specific signed identity envelopes with same-process replay rejection and host/runtime binding checks for the claimed host id.
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
- Real browser-fill adapters or additional signing adapters beyond the bounded `request_sign` production path.
- Additional browser-fill adapters beyond the preview `password_fill` path.
- Additional signing adapters beyond the bounded `request_sign` production path.
- Universal provider mediation beyond the documented Bitwarden production mode.
- End-to-end node-to-node verification across real host integrations.
- Supported-host certification for Claude, Codex, or arbitrary external runtime.
- Strong V4 identity claims for arbitrary external runtimes beyond the documented OpenClaw host-signed preview path.

## Supported trust claim in the current repo state

AgentSecrets currently provides broker-level no-plaintext-response guarantees. It does **not** yet provide a complete end-to-end zero-trust secret-use system for external host apps.
For supported hosts that use the trusted-input session flow, the repo now also provides a narrow ingress contract where the agent-visible path only handles broker-issued opaque refs.
For the local supported-host helper path exercised by the harness, the repo also provides a narrow redaction contract for untrusted transcript and log sinks plus sanctioned adapter-path coverage.
That coverage now splits by adapter mode: `password_fill` and `credential_handoff` remain preview-only stub paths, while `request_sign` is covered by the bounded production adapter mode.
For the preview OpenClaw host path, the repo now also provides host-specific evidence for trusted-input ingress, transcript/log redaction, approval masking, and adapter execution without plaintext leakage.
For that same preview OpenClaw path, the broker can now require a deployment-wide `host-signed` runtime identity baseline with host-specific keys, one-time attestation envelopes, host/runtime pair checks, and same-process replay rejection for the claimed host id.
The repo also now supports a narrow Bitwarden production provider mediation path on the trusted side. That path resolves opaque `bw://...` refs without exposing provider credentials or plaintext secret material to the host-visible request path, and it audits the documented failure cases.
Stronger per-host tiers above a weaker deployment baseline are not a supported secure shape in this repo. Startup rejects that configuration.
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

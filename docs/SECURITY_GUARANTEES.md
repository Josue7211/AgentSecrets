# Security Guarantees

This document is the source of truth for what AgentSecrets currently guarantees, what it only partially implements, and what it does not yet solve.

## Implemented in the current repo state

- Broker API responses do not return plaintext secret values.
- Request and approval flows use separate `client` and `approver` roles.
- Capability tokens are single-use and expire.
- Execution results are masked.
- Audit events exist for request lifecycle activity.
- Trusted-side provider bridge contract exists in stub form behind config.
- Provider resolution failures are masked and do not return plaintext.
- One trusted execution adapter path exists in stub form behind config.
- Unsupported adapter action or target context fails closed.
- Adapter success and failure paths are audited without plaintext.

## Intended contract, not fully enforced end to end yet

- Opaque secret refs such as `bw://...` should be the only supported secret identifiers.
- Secret resolution should happen only on the trusted side.
- Secret-dependent actions should happen through trusted execution adapters.
- Host apps should remain on the untrusted side of the boundary.

## Not currently guaranteed

- Transcript-safe host integrations.
- Chatbox or session-history redaction across external runtimes.
- Real browser-fill or signing adapters beyond the current stub contract.
- Production Bitwarden mediation implemented in this repo.
- End-to-end node-to-node verification across real host integrations.

## Supported trust claim in the current repo state

AgentSecrets currently provides broker-level no-plaintext-response guarantees. It does **not** yet provide a complete end-to-end zero-trust secret-use system for external host apps.

## Unsafe patterns

Do not treat these as supported:

- Typing a password directly into agent chat or task input.
- Sending raw secret values to `POST /v1/requests`.
- Letting host apps talk directly to Bitwarden.
- Claiming transcript safety without a passing end-to-end test.

## Release rule

If docs, code, or tests drift, reduce the claim. Do not expand the claim before the implementation and verification exist.

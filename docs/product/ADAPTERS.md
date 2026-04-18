# Adapter Contracts

This file is the source of truth for trusted execution adapter boundaries in this repo.

## Boundary

- Trusted side owns provider resolution, adapter dispatch, and audit emission.
- Untrusted side only sees masked request/execute JSON and host transcripts.
- The first shipped production adapter is `request_sign_production_v1`.
- `password_fill_stub` and `credential_handoff_stub` remain preview-only.

## Shipped Adapter

### `request_sign_production_v1`

| Field | Contract |
| --- | --- |
| Mode | `SECRET_BROKER_EXECUTION_ADAPTER_MODE=request-sign-production` |
| Service boundary | Broker issues an HTTP `POST` to `SECRET_BROKER_REQUEST_SIGN_ADAPTER_URL` |
| Action | `request_sign` |
| Target | HTTPS targets ending in `/sign` only |
| Inputs | action, target, provider-resolved secret bytes encoded as `secret_hex`, masked secret ref |
| Outputs | adapter id, outcome `signed`, target echo, masked secret ref, masked signature ref |
| Audit fields | adapter, mode, action, target, policy outcome, policy risk score, policy environment, policy reasons |
| Failure handling | unsupported action -> `400 adapter_action_unsupported`; target mismatch -> `400 adapter_target_mismatch`; provider unavailable -> `502 adapter_unavailable` or `adapter_provider_missing`; disabled -> `502 adapter_disabled` |
| Rollback policy | switch the mode back to `stub` or `off`; no schema migration or data rewrite is required |

## Preview Adapters

| Adapter | Status | Scope | Notes |
| --- | --- | --- | --- |
| `password_fill_stub` | preview | `password_fill` only | Not production browser automation |
| `credential_handoff_stub` | preview | `credential_handoff` only | Bounded local helper handoff path |

## Invariants

- The adapter boundary never returns plaintext secret material.
- The adapter boundary never returns raw signature bytes.
- The shipped production path crosses a broker-to-adapter HTTP boundary instead of using the old in-process stub helper.
- Execute-time audits must retain action, target, and policy binding for success and failure.
- If the shipped adapter misbehaves, rollback is configuration-only: use `stub` or `off` and keep the stub preview paths intact.

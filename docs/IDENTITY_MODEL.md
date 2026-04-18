# Identity Model

This document defines the runtime identity tiers used by the broker. It exists to keep V4 identity claims narrow, explicit, and host-specific.

## Tiers

| Tier | Meaning | What it proves | Current repo status |
| --- | --- | --- | --- |
| `off` | No runtime identity verification | Nothing about runtime, host, or adapter identity | Supported only as an explicit downgrade |
| `stub` | Shared repo-local signed headers | A local helper knew the shared attestation key and signed runtime, host, adapter, and timestamp claims | Shipped for the local helper harness only |
| `host-signed` | Host-specific signed identity envelope | A configured host key signed runtime, host, adapter, timestamp, and a one-time attestation envelope id; the broker also enforces host/runtime pairing and same-process replay rejection for the claimed host id | Implemented for the documented OpenClaw host path, still preview until host-certification docs promote it |
| `hardware-backed` | Host identity rooted in hardware or equivalent remote attestation | Stronger proof that the host and runtime are the expected platform instance | Not implemented in this repo |

## Tier semantics

### `off`

- Broker accepts requests without runtime identity headers.
- No V4 identity claim is allowed.
- Approval and execute flows must not be described as identity-bound.

### `stub`

- Uses the shared `SECRET_BROKER_IDENTITY_ATTESTATION_KEY`.
- Verifies runtime id, host id, adapter id, and timestamp.
- Good enough for repo-owned helper and harness coverage.
- Not strong enough for an external-host trust claim because any path with the shared key is in the same trust class.

### `host-signed`

- Uses a host-specific signing key from `SECRET_BROKER_IDENTITY_HOST_SIGNING_KEYS`.
- Requires a host/runtime binding from `SECRET_BROKER_TRUSTED_HOST_RUNTIME_PAIRS`.
- Requires a one-time `x-secret-broker-attestation-id` envelope id.
- Rejects stale timestamps, same-process replayed envelopes, mismatched host/runtime pairs, and adapter/action drift.
- Approval checks tier-lock the stored verified identity tier to the current deployment baseline.
- Execute checks require the current request identity to stay at least as strong as the stored approved tier and to match runtime, host, and adapter claims.
- Current replay scope is process-local to the running broker instance. Restarting the broker clears that cache.

## Current host mapping

- Local helper harness: `stub`
- OpenClaw-style HTTP host: `host-signed` verification path exists when the deployment baseline is `host-signed`, but platform plus host claims stay preview until the host-certification documents are promoted

## Header contract

All non-`off` tiers use:

- `x-secret-broker-runtime-id`
- `x-secret-broker-host-id`
- `x-secret-broker-adapter-id`
- `x-secret-broker-attestation-ts`
- `x-secret-broker-attestation-sig`

`host-signed` additionally requires:

- `x-secret-broker-attestation-id`

## Claim discipline

- Do not use `stub` evidence to certify an external host.
- Do not use `host-signed` as a blanket claim for all external runtimes.
- Do not claim `hardware-backed` until there is real attestation plumbing and verification evidence in this repo.

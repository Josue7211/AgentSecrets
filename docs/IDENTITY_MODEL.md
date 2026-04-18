# Identity Model

This document defines the runtime identity tiers used by the broker. It exists to keep V4 identity claims narrow, explicit, and host-specific.

## Tiers

| Tier | Meaning | What it proves | Current repo status |
| --- | --- | --- | --- |
| `off` | No runtime identity verification | Nothing about runtime, host, or adapter identity | Supported only as an explicit downgrade |
| `stub` | Shared repo-local signed headers | A local helper knew the shared attestation key and signed runtime, host, adapter, and timestamp claims | Shipped for the local helper harness only |
| `host-signed` | Host-specific signed identity envelope | A specific trusted host key signed runtime, host, adapter, timestamp, and a one-time attestation envelope id; the broker also enforces host/runtime pairing and replay rejection | Implemented for the documented OpenClaw host path, still preview until host-certification docs promote it |
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
- Rejects stale timestamps, replayed envelopes, mismatched host/runtime pairs, and adapter/action drift.
- Approval and execute-time checks fail closed if a request that was approved at `host-signed` is later evaluated under a weaker configured mode.

## Current host mapping

- Local helper harness: `stub`
- OpenClaw-style HTTP host: `host-signed` verification path exists in repo, but platform and host claims stay preview until the host-certification documents are promoted

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

# Provider Mediation

This document defines the only production provider mediation path shipped in this repo.

## Scope

- Provider mediation is supported only for Bitwarden-backed `bw://...` refs.
- The explicit production mode is `SECRET_BROKER_PROVIDER_BRIDGE_MODE=bitwarden-production`.
- The host/runtime side stays untrusted. It does not become a provider client.

## Boundary

Allowed to cross the broker boundary:

- From host to broker: opaque refs such as `bw://vault/item/login` or `tir://session/<id>`.
- From broker to provider: broker-authenticated provider lookup requests containing the opaque `secret_ref` and broker-side credentials.
- From provider back to broker: the resolved secret bytes, the masked ref, and provider status needed for broker-side execution.
- From broker back to host: masked refs, masked provider metadata, approval artifacts, and audit-visible error codes.

Not allowed to cross the broker boundary:

- Provider credentials or access tokens.
- Plaintext secret values in broker responses.
- Provider transcripts, vault dumps, or raw secret bytes in host-visible logs.
- A direct provider client path from the host/runtime side.

## Failure Contract

The broker must fail closed and audit the failure when provider mediation sees:

- provider outage
- revoked credential
- missing ref
- vault/item binding mismatch

These failures are broker-side contract failures, not permissions to bypass the broker or fall back to plaintext ingress.

## Observability

The broker may record:

- provider name
- provider mode
- masked secret ref
- failure code
- failure reason

The broker must not record plaintext secret material or provider credentials in audit events, responses, or transcripts.

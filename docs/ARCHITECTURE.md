# Architecture

## Current implemented boundary

1. Agent runtime (untrusted)
2. Broker API (policy, approvals, capability issuance, masked execution responses)
3. Broker-owned trusted input session boundary that mints opaque refs for supported-host ingress
4. Trusted provider boundary in stub form for `bw://...` preflight resolution
5. Trusted execution adapter registry in stub form for masked `password_fill`, `request_sign`, and `credential_handoff`
6. Policy engine over actor, environment, and risk
7. Stub identity verification over runtime, host, and adapter claims
8. Audit verification and forensic export tooling

## Target boundary for future versions

6. Trusted secret provider adapters (Bitwarden, keychain, HSM)
7. Additional trusted execution adapters (browser fill, signing, send)
8. Supported host integrations with transcript-safe behavior

## Current contract

- Input: action intent and context
- Output: allow or deny, masked metadata, and bounded capability material in current flows that issue it
- No plaintext secret responses from broker APIs
- Supported hosts can now originate requestable secret use through a trusted-input session that returns a broker opaque ref only
- Provider preflight can happen on the trusted side in stub form only
- Multiple sanctioned trusted execution adapter paths can consume provider-resolved secret bytes without returning plaintext on documented targets
- Adapter dispatch is fail-closed for unsupported action or target context drift
- Policy output is explainable and can return allow, require-approval, step-up, or deny
- Supported local paths can bind verified identity into request, approval, and execute context
- The local supported-host helper path now has a documented transcript/log redaction boundary with a separate trusted control sink for harness-only flow control
- No current guarantee of universal transcript-safe host behavior beyond the broker-owned trusted-input ingress path, the local helper redaction contract, and the local helper adapter paths listed in [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md)

## Modes

- `off`: compatibility / auto-approve mode for migration
- `monitor`: records and auto-approves
- `enforce`: approval plus policy required

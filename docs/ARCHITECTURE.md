# Architecture

## Current implemented boundary

1. Agent runtime (untrusted)
2. Broker API (policy, approvals, capability issuance, masked execution responses)
3. Trusted provider boundary in stub form for `bw://...` preflight resolution
4. Trusted execution adapter boundary in stub form for masked `password_fill` on login targets

## Target boundary for future versions

5. Trusted secret provider adapters (Bitwarden, keychain, HSM)
6. Additional trusted execution adapters (browser fill, signing, send)
7. Supported host integrations with transcript-safe behavior

## Current contract

- Input: action intent and context
- Output: allow or deny, masked metadata, and bounded capability material in current flows that issue it
- No plaintext secret responses from broker APIs
- Provider preflight can happen on the trusted side in stub form only
- One trusted execution adapter path can consume provider-resolved secret bytes without returning plaintext
- Adapter dispatch is fail-closed for unsupported action or target context drift
- No current guarantee of transcript-safe host behavior

## Modes

- `off`: compatibility / auto-approve mode for migration
- `monitor`: records and auto-approves
- `enforce`: approval plus policy required

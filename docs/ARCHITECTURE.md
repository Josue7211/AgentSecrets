# Architecture

## Current implemented boundary

1. Agent runtime (untrusted)
2. Broker API (policy, approvals, capability issuance, masked execution responses)
3. Trusted provider boundary in stub form for `bw://...` preflight resolution

## Target boundary for future versions

4. Trusted secret provider adapters (Bitwarden, keychain, HSM)
5. Trusted execution adapters (browser fill, signing, send)
6. Supported host integrations with transcript-safe behavior

## Current contract

- Input: action intent and context
- Output: allow or deny, masked metadata, and bounded capability material in current flows that issue it
- No plaintext secret responses from broker APIs
- Provider preflight can happen on the trusted side in stub form only
- No current guarantee of transcript-safe host behavior

## Modes

- `off`: compatibility / auto-approve mode for migration
- `monitor`: records and auto-approves
- `enforce`: approval plus policy required

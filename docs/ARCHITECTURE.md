# Architecture

## Trust boundaries
1. Agent runtime (untrusted)
2. Broker API (policy + approvals)
3. Secret provider adapters (Bitwarden, keychain, HSM)
4. Optional execution adapters (browser fill, signing, send)

## Contract
- Input: action intent and context
- Output: allow/deny + masked metadata
- No plaintext secret responses

## Modes
- `off`: legacy passthrough mode (for migration)
- `monitor`: records and auto-approves
- `enforce`: approval + policy required

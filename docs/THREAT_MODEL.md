# Threat Model

This broker is designed to keep plaintext secrets away from agent runtimes such as OpenClaw, Claude, and Codex.

## Trust boundaries

- Trusted:
  - The broker process
  - The Bitwarden service running on the services VM
  - Human approval tooling
  - The local SQLite database file on the broker host
- Untrusted:
  - Agent runtimes
  - OpenClaw or similar host apps
  - Browser content loaded into any agent-facing UI
  - Remote network paths outside the private network

## Security goals

- Never expose plaintext secret values to the agent runtime
- Keep secret-dependent actions behind explicit approval
- Bind approvals to specific request context
- Make capability tokens single-use and short-lived
- Preserve an auditable trail of approvals and execution

## What the broker must defend against

- Prompt injection that tries to coerce the agent into revealing secrets
- Malicious or compromised OpenClaw plugins
- Stolen or replayed capability tokens
- Abuse of privileged secret-dependent actions
- Direct access to Bitwarden from the agent side
- Tampering with request history or audit records

## What the broker does not try to solve

- Host compromise of the machine running the broker
- A fully compromised Bitwarden server
- Malicious local administrators with direct disk access
- Phishing of the human approver outside the broker workflow
- Side channels from the user interface or browser extensions

## Operational rules

- Keep the broker on localhost or a private network
- Keep Bitwarden on the services VM
- Give agent runtimes only the `client` key
- Give approver tools only the `approver` key
- Use `SECRET_BROKER_MODE=enforce` for real use
- Keep allowlists and amount caps strict
- Rotate keys through the admin API

## Review focus

When changing this repo, review:

- Authentication and key rotation
- Request approval and execution transitions
- Any code that might return secret material or identifiers too early
- Any browser or UI path that could expose credentials
- Any deployment path that broadens network reach unexpectedly

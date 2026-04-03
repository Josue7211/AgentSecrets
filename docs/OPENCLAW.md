# OpenClaw Integration

This broker is intended to be a drop-in secrets layer for any OpenClaw deployment that can make HTTP requests. Linux and macOS are the primary host platforms; Windows is supported but secondary.

## What OpenClaw should do

- Talk only to the broker API.
- Use the `client` key for agent runtime requests.
- Never embed Bitwarden credentials in OpenClaw.
- Never let OpenClaw read plaintext secret values.
- Route any Bitwarden-backed secret use through the broker over the private network.
- Do not require OpenClaw to know where Bitwarden lives beyond the broker endpoint.

## Minimum setup

1. Set `SECRET_BROKER_BIND=127.0.0.1:4815` or expose the broker only to trusted hosts.
2. Configure OpenClaw to call:
   - `POST /v1/requests`
   - `GET /v1/requests`
   - `POST /v1/execute`
3. Configure your approver channel to call:
   - `POST /v1/requests/:id/approve`
   - `POST /v1/requests/:id/deny`
   - `GET /v1/audit`
4. Keep Bitwarden on the services VM and let the broker mediate `bw://...` refs.

## Drop-in contract

Any OpenClaw setup should be able to work with this contract:

- Agent intent goes in as `secret_ref`, `action`, `target`, and optional `amount_cents`.
- Broker returns masked metadata, request IDs, and single-use capability tokens.
- Execution requires the one-time capability token.
- Raw secret values never leave the trusted broker side.

## Host platforms

- Linux hosts can use the `systemd` example files.
- macOS hosts can use the `launchd` plist example.
- Windows hosts can run the broker as a service or as a scheduled startup task, as long as the broker endpoint is reachable over HTTPS or localhost.

## If your OpenClaw install is more complex

- If OpenClaw has multiple runtimes, give each runtime only the `client` key.
- If you want iOS or dispatch-style approvals, wire the approver channel to the same broker endpoints.
- If OpenClaw is remote, keep the broker on the private network and lock down egress so only the broker and approved APIs are reachable.

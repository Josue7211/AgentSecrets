# OpenClaw Integration

This doc describes the intended broker contract for OpenClaw-like host apps. It does not certify current end-to-end transcript safety.

## What OpenClaw should do

- Talk only to the broker API.
- Use the `client` key for runtime requests.
- Never embed provider credentials in OpenClaw.
- Never send raw secret values to the broker.
- Use opaque refs such as `bw://...` only.
- If the broker returns `raw_secret_rejected`, the host flow is violating the trusted-boundary contract.
- Stay on the untrusted side of the trust boundary.

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
4. Keep provider systems on the trusted side.

## What this doc does not claim

- It does not claim transcript-safe host behavior.
- It does not claim secure password entry through chat surfaces.
- It does not claim a finished trusted-side browser-fill adapter.
- It does not treat the local Loop 5 node-to-node harness as OpenClaw host certification.

## Drop-in contract

- Agent intent goes in as `secret_ref`, `action`, `target`, and optional `amount_cents`.
- Broker returns masked metadata, request IDs, and single-use capability tokens at request creation for auto-approved requests or in approval responses for pending ones.
- Approval responses include a masked review payload with request type, masked secret ref, action, target, and reason.
- Execution requires the one-time capability token plus the same approved `action` and `target`.
- Broker API responses do not return plaintext secret values.

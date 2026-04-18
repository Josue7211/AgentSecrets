# OpenClaw Integration

OpenClaw is a documented external host path in this repo, and host-specific identity evidence now exists for the documented broker HTTP path. It still remains `preview`. The host process itself stays untrusted. The current boundary is the OpenClaw runtime talking to the broker over HTTP with the client key, plus the separate approver channel for approvals.

Use [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) as the status source of truth and [docs/OPENCLAW_THREAT_NOTES.md](docs/OPENCLAW_THREAT_NOTES.md) for the sink and failure-path details.

## Trust boundary

- OpenClaw gets the `client` key only.
- The approver channel keeps the `approver` key and stays outside OpenClaw.
- OpenClaw may talk to the broker API only.
- OpenClaw must not talk directly to Bitwarden or any other trusted-side system.
- Transcript, stdout, stderr, crash logs, and retry logs inside OpenClaw are untrusted sinks.
- Tool-call payloads and failure payloads inside OpenClaw are untrusted sinks too.

## Data-flow contract

1. OpenClaw starts a trusted-input session with `POST /v1/trusted-input/sessions`.
2. The trusted host-input surface completes the session with `POST /v1/trusted-input/sessions/:id/complete`.
3. Completion returns only a broker-issued `tir://session/<id>` opaque ref.
4. OpenClaw submits that opaque ref to `POST /v1/requests` with the client key.
5. The approver channel reviews the masked payload and calls `POST /v1/requests/:id/approve` or `POST /v1/requests/:id/deny`.
6. OpenClaw executes only with the approved `id`, `capability_token`, `action`, and `target`.
7. Broker responses stay masked; adapter execution does not return plaintext secret values.

## What OpenClaw must not do

- Do not send raw secret values to the broker.
- Do not keep plaintext secrets in agent-visible transcript surfaces.
- Do not leak provider credentials into OpenClaw logs or task memory.
- Do not retry a failed trusted-input completion with a different request context.
- Do not mutate approved `action` or `target` after approval.

## Evidence

- `bash scripts/run-openclaw-e2e.sh`
- `bash scripts/check-v3-ship-gate.sh`
- `cargo test --all-targets --all-features -- --nocapture`

If this evidence goes red, keep OpenClaw at `preview` and remove any shipped claim until the lane is green again and the host path is re-reviewed.

Identity note:
- The documented OpenClaw path can now use `host-signed` runtime identity when the broker deployment baseline is `host-signed`.
- Host-signed envelope replay rejection is currently process-local to the running broker instance.

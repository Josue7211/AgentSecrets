# AgentSecrets

Standalone, open-source secret broker for agent workflows.

## Goal
Allow Claude, Codex, OpenClaw, and other agents to request secret-dependent actions without broker API responses exposing plaintext secret values.

## Security Guarantees

The current implementation provides **broker-level no-plaintext-response guarantees** and a **broker-owned trusted-input session path** that can mint opaque refs for supported hosts. It still does **not** yet provide a complete end-to-end transcript-safe zero-trust system for arbitrary external host apps.

Read [docs/SECURITY_GUARANTEES.md](docs/SECURITY_GUARANTEES.md) before relying on any security property.
Read [docs/REDACTION_POLICY.md](docs/REDACTION_POLICY.md) for the current supported-host transcript and log redaction boundary.
Read [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) for the current V3 host-certification boundary.
Read [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) for the current V4 control and support boundary.

## Production-grade defaults
- Role-separated API keys (`client` and `approver`)
- Modes: `off`, `monitor`, `enforce`
- Single-use capability tokens with TTL
- Replay protection (`capability_used_at` lock)
- Approval-time binding of request id, action, and target
- Policy checks (target prefix allowlist, amount caps)
- Automatic expiry of stale requests
- Masked-only execution responses
- Audit log with hash-chain tamper evidence
- Request-level rate limiting
- Registry-backed trusted execution adapter paths for masked `password_fill`, `request_sign`, and `credential_handoff`
- Broker-owned trusted input sessions that mint one-time opaque refs
- Supported-host helper transcript and log redaction hooks for the local harness path
- Explainable policy decisions over action, target, actor, environment, and risk
- Stub attestation support for runtime, host, and adapter identity on supported local paths
- Audit-chain verification and redact-safe forensic bundle export
- Repeatable rotation/recovery drills and adversarial verification lanes

## Security model
- Agent runtimes are treated as untrusted.
- Broker API responses do not return plaintext secret values.
- `secret_ref` must be an opaque identifier such as `bw://vault/item/login` or a broker-issued `tir://session/<id>` ref.
- Plaintext secret values are rejected at request creation.
- Rejected ingress attempts are audited without echoing the submitted secret content.
- Trusted input sessions are bounded, expire, and can only be consumed once into a matching request context.
- High-risk requests can require human approval.
- Approval responses include masked review payloads.
- Approvals are bound to request id, action, target, and token TTL.
- Capability tokens are one-time and invalid after execution.
- External host-app transcript safety is **not** currently guaranteed by this repo outside the supported matrix.
- The local supported-host helper path now has tested transcript and log redaction coverage plus sanctioned adapter coverage, but that claim does not automatically extend to arbitrary host runtimes.

## Code layout
- [src/lib.rs](src/lib.rs): config, DB init, router wiring, runtime entrypoint
- [src/adapter.rs](src/adapter.rs): trusted execution adapter contract and stub runtime
- [src/handlers/health.rs](src/handlers/health.rs): liveness and readiness endpoints
- [src/handlers/requests.rs](src/handlers/requests.rs): request lifecycle and audit listing
- [src/handlers/trusted_input.rs](src/handlers/trusted_input.rs): trusted input session lifecycle and opaque ref issuance
- [src/handlers/execution.rs](src/handlers/execution.rs): capability-guarded execution path
- [src/auth.rs](src/auth.rs): API key auth and rate limiting
- [src/keys.rs](src/keys.rs): DB-backed API key seeding and rotation
- [src/policy.rs](src/policy.rs): validation and policy decisions
- [src/audit.rs](src/audit.rs): append-only hash-chain audit logging
- [migrations/0001_init.sql](migrations/0001_init.sql): source of truth for the initial schema
- [migrations/0002_capability_binding.sql](migrations/0002_capability_binding.sql): approval-time capability binding fields
- [migrations/0003_trusted_input_sessions.sql](migrations/0003_trusted_input_sessions.sql): trusted input session persistence and opaque ref issuance

## API
- `GET /healthz` (no auth)
- `GET /readyz` (no auth, DB readiness)
- `POST /v1/trusted-input/sessions` (`client` or `approver`)
- `GET /v1/trusted-input/sessions/:id` (`client` or `approver`)
- `POST /v1/trusted-input/sessions/:id/complete` (`client` or `approver`)
- `POST /v1/requests` (`client` or `approver`)
- `GET /v1/requests` (`client` or `approver`)
- `POST /v1/requests/:id/approve` (`approver`)
- `POST /v1/requests/:id/deny` (`approver`)
- `POST /v1/execute` (`client` or `approver`)
- `GET /v1/audit` (`approver`)
- `POST /v1/admin/keys/:role/rotate` (`approver`)

## Auth
Use either:
- `Authorization: Bearer <key>`
- `x-api-key: <key>`

## Configuration
Copy `.env.example` and set:
- `SECRET_BROKER_MODE=enforce`
- `SECRET_BROKER_CLIENT_API_KEY=...`
- `SECRET_BROKER_APPROVER_API_KEY=...`

Optional:
- `SECRET_BROKER_ALLOWED_TARGET_PREFIXES`
- `SECRET_BROKER_MAX_AMOUNT_CENTS`
- `SECRET_BROKER_CAPABILITY_TTL_SECONDS`
- `SECRET_BROKER_PROVIDER_BRIDGE_MODE=off|stub`
- `SECRET_BROKER_EXECUTION_ADAPTER_MODE=off|stub`
- `SECRET_BROKER_REQUEST_TTL_SECONDS`
- `SECRET_BROKER_RATE_LIMIT_PER_MINUTE`
- `SECRET_BROKER_IDENTITY_VERIFICATION_MODE=off|stub`
- `SECRET_BROKER_IDENTITY_ATTESTATION_KEY`
- `SECRET_BROKER_IDENTITY_ATTESTATION_MAX_AGE_SECONDS`
- `SECRET_BROKER_TRUSTED_RUNTIME_IDS`
- `SECRET_BROKER_TRUSTED_HOST_IDS`

`enforce` mode startup validations:
- Refuses to run with default dev API keys
- Requires distinct client and approver keys
- Requires keys with minimum length

Startup behavior:
- Env keys seed the `api_keys` table on first run
- Active auth keys are served from the database
- Rotated keys take effect immediately without restart
- Schema is applied through SQL migrations on startup
- Provider bridge modes:
  - `off`: default, no trusted-side provider resolution path
- `stub`: enables the stub Bitwarden provider bridge for contract verification
- Execution adapter modes:
  - `off`: default, no trusted-side secret-consumption path
  - `stub`: enables the V3 sanctioned adapter registry for `password_fill`, `request_sign`, and `credential_handoff` on documented targets

## Run
```bash
cargo run
```

Default bind: `127.0.0.1:4815`.

Cross-platform deployment:
- Primary platforms:
  - Linux:
    - [systemd/secret-broker.service](systemd/secret-broker.service)
    - [systemd/secret-broker-backup.service](systemd/secret-broker-backup.service)
    - [systemd/secret-broker-backup.timer](systemd/secret-broker-backup.timer)
  - macOS:
    - [launchd/com.secret-broker.plist](launchd/com.secret-broker.plist)
- Secondary platform:
  - Windows:
    - [docs/OPERATIONS.md](docs/OPERATIONS.md#windows-service)
    - [windows/install-secret-broker.ps1](windows/install-secret-broker.ps1)
- Release checklist:
  - [docs/RELEASE.md](docs/RELEASE.md)
  - includes the V2, V3, and V4 ship gates, claims tables, and manual signoff
- Quickstart:
  - [docs/QUICKSTART.md](docs/QUICKSTART.md)
- Threat model:
  - [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- Troubleshooting:
  - [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

Container:
```bash
docker build -t secret-broker .
docker run --rm -p 4815:4815 --env-file .env secret-broker
```

## Test
```bash
cargo test
```

Loop 5 node-to-node E2E harness:
```bash
bash scripts/run-e2e-harness.sh
```

Harness artifacts are written to `target/e2e-artifacts/` with redacted logs and summaries.

Static checks:
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Healthcheck:
```bash
scripts/healthcheck.sh http://127.0.0.1:4815
```

Forensics:
```bash
cargo run --bin forensics -- verify-chain --db sqlite://secret-broker.db?mode=rwc
```

Quick install on one box:
```bash
sudo install -d /opt/secret-broker /etc/secret-broker /var/lib/secret-broker /var/backups/secret-broker
sudo install -m 755 target/release/secret-broker /opt/secret-broker/secret-broker
sudo install -m 644 systemd/secret-broker.service /etc/systemd/system/secret-broker.service
sudo install -m 644 systemd/secret-broker-backup.service /etc/systemd/system/secret-broker-backup.service
sudo install -m 644 systemd/secret-broker-backup.timer /etc/systemd/system/secret-broker-backup.timer
sudo systemctl daemon-reload
sudo systemctl enable --now secret-broker.service secret-broker-backup.timer
```

## Example flow
1. Supported host starts a trusted input session (`POST /v1/trusted-input/sessions`).
2. Trusted host input completes the session and receives a broker opaque ref (`POST /v1/trusted-input/sessions/:id/complete`).
3. Agent creates request with that opaque ref (`POST /v1/requests`).
4. Approver approves (`POST /v1/requests/:id/approve`) and receives one-time capability token.
5. Approval response includes masked review context (`request_type`, masked `secret_ref`, `action`, `target`, `reason`).
6. Agent executes with capability (`POST /v1/execute`) and must present the approved `action` and `target`.
7. Broker returns masked execution result only, including masked adapter summaries when the trusted adapter registry is enabled.
8. Local harness evidence now proves the stubbed broker flow, the trusted-input ingress path, and the sanctioned helper adapter paths stay free of plaintext secret material in untrusted helper transcripts and redacted artifacts.
9. Any broader host transcript or chatbox safety claim still depends on the specific host integration and its certification status in [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md).

## Integration notes
- Any OpenClaw, Claude, Codex, or custom agent runtime should call broker instead of direct secret routes.
- Agent runtimes should use the `client` key only.
- Human approval apps, including iOS dispatch-style flows, should use the `approver` key.
- Supported hosts that want transcript-safer ingress should use the trusted-input session flow and pass only the broker opaque ref back to the agent runtime.
- Bitwarden is intended to stay on your services VM; future target architecture may mediate `bw://...` refs over the private network.
- The repo now has a trusted-side provider boundary in stub form.
- The repo now has a trusted-side sanctioned adapter registry in stub form for masked `password_fill`, `request_sign`, and `credential_handoff`.
- The repo now has a broker-owned trusted input surface for supported hosts, but still does **not** claim production Bitwarden mediation, real browser automation, or universal transcript-safe host execution.
- Use [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) as the only V3 host-certification source of truth.
- See [docs/OPENCLAW.md](docs/OPENCLAW.md) for the generic OpenClaw drop-in contract.

## Platform support
- The broker binary is intended to run on Linux and macOS first.
- Linux gets `systemd` examples because that is the simplest self-hosted path.
- macOS uses `launchd`.
- Windows remains supported, but as a secondary path; see [docs/OPERATIONS.md](docs/OPERATIONS.md#windows-service).
- If your OpenClaw setup is remote, keep the broker private-network only and let the host app talk to the broker over HTTP.

## Production checklist
- Set strong random values for `SECRET_BROKER_CLIENT_API_KEY` and `SECRET_BROKER_APPROVER_API_KEY`
- Keep broker on private network or localhost
- Keep Bitwarden on the services VM behind private network access
- Enable `SECRET_BROKER_MODE=enforce`
- Set strict `SECRET_BROKER_ALLOWED_TARGET_PREFIXES`
- Set conservative `SECRET_BROKER_MAX_AMOUNT_CENTS`
- Monitor `/v1/audit` and export logs
- Use [operations runbook](docs/OPERATIONS.md)
- Keep CI required on pull requests [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
- Rotate keys through `/v1/admin/keys/:role/rotate` instead of editing env files in place
- Use [docs/RELEASE.md](docs/RELEASE.md) as the only V2 and V3 ship authority
- Use [docs/RELEASE.md](docs/RELEASE.md) and [docs/PLATFORM_SUPPORT.md](docs/PLATFORM_SUPPORT.md) as the only V4 platform ship authority

# AgentSecrets

Standalone, open-source secret broker for agent workflows.

## Goal
Allow Claude, Codex, OpenClaw, and other agents to request secret-dependent actions without broker API responses exposing plaintext secret values.

## Security Guarantees

The current implementation provides **broker-level no-plaintext-response guarantees**. It does **not** yet provide a complete end-to-end transcript-safe zero-trust system for external host apps.

Read [docs/SECURITY_GUARANTEES.md](docs/SECURITY_GUARANTEES.md) before relying on any security property.

## Production-grade defaults
- Role-separated API keys (`client` and `approver`)
- Modes: `off`, `monitor`, `enforce`
- Single-use capability tokens with TTL
- Replay protection (`capability_used_at` lock)
- Policy checks (target prefix allowlist, amount caps)
- Automatic expiry of stale requests
- Masked-only execution responses
- Audit log with hash-chain tamper evidence
- Request-level rate limiting

## Security model
- Agent runtimes are treated as untrusted.
- Broker API responses do not return plaintext secret values.
- `secret_ref` must be an opaque identifier such as `bw://vault/item/login`.
- Plaintext secret values are rejected at request creation.
- Rejected ingress attempts are audited without echoing the submitted secret content.
- High-risk requests can require human approval.
- Approvals are bound to request context and token TTL.
- Capability tokens are one-time and invalid after execution.
- External host-app transcript safety is **not** currently guaranteed by this repo.

## Code layout
- [src/lib.rs](src/lib.rs): config, DB init, router wiring, runtime entrypoint
- [src/handlers/health.rs](src/handlers/health.rs): liveness and readiness endpoints
- [src/handlers/requests.rs](src/handlers/requests.rs): request lifecycle and audit listing
- [src/handlers/execution.rs](src/handlers/execution.rs): capability-guarded execution path
- [src/auth.rs](src/auth.rs): API key auth and rate limiting
- [src/keys.rs](src/keys.rs): DB-backed API key seeding and rotation
- [src/policy.rs](src/policy.rs): validation and policy decisions
- [src/audit.rs](src/audit.rs): append-only hash-chain audit logging
- [migrations/0001_init.sql](migrations/0001_init.sql): source of truth for the initial schema

## API
- `GET /healthz` (no auth)
- `GET /readyz` (no auth, DB readiness)
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
- `SECRET_BROKER_REQUEST_TTL_SECONDS`
- `SECRET_BROKER_RATE_LIMIT_PER_MINUTE`

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
  - `stub`: enables the Loop 2 stub Bitwarden provider bridge for contract verification

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

Static checks:
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Healthcheck:
```bash
scripts/healthcheck.sh http://127.0.0.1:4815
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
1. Agent creates request (`POST /v1/requests`).
2. Approver approves (`POST /v1/requests/:id/approve`) and receives one-time capability token.
3. Agent executes with capability (`POST /v1/execute`).
4. Broker returns masked execution result only.
5. Any transcript or chatbox safety claim still depends on the host integration, which is not yet fully implemented in this repo.

## Integration notes
- Any OpenClaw, Claude, Codex, or custom agent runtime should call broker instead of direct secret routes.
- Agent runtimes should use the `client` key only.
- Human approval apps, including iOS dispatch-style flows, should use the `approver` key.
- Bitwarden is intended to stay on your services VM; future target architecture may mediate `bw://...` refs over the private network.
- The repo now has a trusted-side provider boundary in stub form.
- The repo still does **not** claim production Bitwarden mediation or trusted execution adapters.
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

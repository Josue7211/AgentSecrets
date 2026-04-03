# Operations

## Runtime requirements
- Run behind a trusted reverse proxy (TLS termination)
- Restrict network access to trusted clients only
- Mount persistent storage for SQLite database file
- Apply migrations on startup from `migrations/0001_init.sql`
- Treat Bitwarden as a remote service on the services VM; only the broker should mediate access to `bw://...` refs

## Environment
Required in production:
- `SECRET_BROKER_MODE=enforce`
- `SECRET_BROKER_CLIENT_API_KEY=<strong random key>`
- `SECRET_BROKER_APPROVER_API_KEY=<strong random key>`

These env keys are bootstrap values:
- They seed the `api_keys` table on first launch
- Later rotations happen through the admin API

Recommended:
- `SECRET_BROKER_ALLOWED_TARGET_PREFIXES=<strict csv allowlist>`
- `SECRET_BROKER_MAX_AMOUNT_CENTS=<small safe limit>`
- `SECRET_BROKER_RATE_LIMIT_PER_MINUTE=<fit to workload>`

## Health checks
- Liveness: `GET /healthz`
- Readiness: `GET /readyz`
- Local script: `scripts/healthcheck.sh http://127.0.0.1:4815`

## One-box service
- Install [systemd/secret-broker.service](../systemd/secret-broker.service)
- Install [systemd/secret-broker-backup.service](../systemd/secret-broker-backup.service)
- Install [systemd/secret-broker-backup.timer](../systemd/secret-broker-backup.timer)
- Put the environment file at `/etc/secret-broker/secret-broker.env`
- Keep the database at `/var/lib/secret-broker/secret-broker.db`
- Keep backups under `/var/backups/secret-broker`

## macOS service
- Install the broker binary somewhere stable, such as `/usr/local/opt/secret-broker/bin/secret-broker`
- Copy [launchd/com.secret-broker.plist](../launchd/com.secret-broker.plist) to `/Library/LaunchDaemons/com.secret-broker.plist`
- Replace placeholder paths and environment values in the plist
- Load it with `sudo launchctl bootstrap system /Library/LaunchDaemons/com.secret-broker.plist`
- Unload with `sudo launchctl bootout system /Library/LaunchDaemons/com.secret-broker.plist`
- Keep the SQLite DB on an encrypted volume if possible

## Windows service
- Install the broker binary to a stable path, such as `C:\Program Files\SecretBroker\secret-broker.exe`
- Run [windows/install-secret-broker.ps1](../windows/install-secret-broker.ps1) from an elevated PowerShell session
- Set required environment variables at the machine level before starting the service
- For shutdown and restart, use `Stop-Service SecretBroker` and `Restart-Service SecretBroker`
- Keep the SQLite DB on an encrypted Windows volume if possible

## Logging and audits
- Retain application logs with timestamps
- Poll/export `GET /v1/audit` using approver key
- Alert on repeated `invalid_capability`, `rate_limited`, and `forbidden` events
- Audit any direct access path to the Bitwarden host VM

## Backups
- Backup SQLite DB on a fixed schedule
- Test restore regularly
- Verify each backup with `scripts/healthcheck.sh` after restore into a scratch DB
- Include migration files in source control and backup procedures

## Encryption at rest
- Prefer full-disk encryption on the host
- Keep the SQLite DB on an encrypted volume if possible
- Treat the DB file as sensitive even though the broker never stores plaintext secrets

## Incident response
1. Rotate both API keys immediately
2. Use `POST /v1/admin/keys/:role/rotate` to roll new keys without redeploying
3. Restart broker if you need to force all instances onto the latest DB state
4. Review `/v1/audit` chain and surrounding request records
5. Tighten target allowlist and amount cap if needed

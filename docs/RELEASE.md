# Release Checklist

Use this when publishing the repo, cutting a tag, or deploying a new host.

## Shared checklist

- Confirm the repo still builds: `cargo fmt --all -- --check`, `cargo check`, `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`
- Confirm `LICENSE` is AGPL
- Confirm `.env.example` is present and real secrets are not committed
- Run the release claim-audit step once the claim-audit script lands
- Confirm `docs/SECURITY_GUARANTEES.md` matches the current implementation line
- Confirm docs distinguish broker-level guarantees from end-to-end host guarantees
- Confirm release notes do not claim transcript-safe integrations unless backed by passing end-to-end tests

## Linux release checklist

- Install the binary to a stable path
- Install the `systemd` unit files
- Point `SECRET_BROKER_DB` at persistent storage
- Use `SECRET_BROKER_MODE=enforce` for real deployments
- Enable the backup timer
- Confirm `scripts/healthcheck.sh` passes after startup and after restore

## macOS release checklist

- Install the binary to a stable path such as `/usr/local/opt/secret-broker/bin/secret-broker`
- Install `launchd/com.secret-broker.plist`
- Replace placeholder environment values in the plist
- Ensure the SQLite DB lives on encrypted storage
- Confirm `launchctl` starts and restarts the service cleanly

## Windows release checklist

- Install the binary to `C:\Program Files\SecretBroker\secret-broker.exe` or equivalent
- Run `windows/install-secret-broker.ps1` as Administrator
- Set machine-level environment variables before the service starts
- Ensure the SQLite DB lives on encrypted storage
- Confirm `Start-Service`, `Stop-Service`, and `Restart-Service` work cleanly

Windows is supported, but it is not the primary release target.

## Host integration checklist

- Give host runtimes the `client` key only
- Give human approval tooling the `approver` key only
- Keep host runtimes on the untrusted side of the trust boundary
- Do not market host transcript safety unless a supported end-to-end test proves it
- Do not let host runtimes or agent sessions see plaintext secrets
- Keep target allowlists and amount caps conservative

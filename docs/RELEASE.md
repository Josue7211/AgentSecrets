# Release Checklist

Use this when publishing the repo, cutting a tag, or deploying a new host.

## Shared checklist

- Confirm the repo still builds: `cargo fmt --all -- --check`, `cargo check`, `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`
- Confirm `LICENSE` is Apache 2.0
- Confirm `.env.example` is present and real secrets are not committed
- Confirm docs describe the broker as a drop-in OpenClaw-compatible secret broker
- Confirm the Bitwarden host stays separate from agent runtimes
- Confirm the broker never returns plaintext secrets

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

## OpenClaw compatibility checklist

- Give OpenClaw the `client` key only
- Give human approval tooling the `approver` key only
- Keep OpenClaw on the untrusted side of the trust boundary
- Use the broker for any `bw://...` handling
- Do not let OpenClaw or the agent runtime see plaintext secrets
- Keep target allowlists and amount caps conservative

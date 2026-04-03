# Troubleshooting

## Broker will not start

- Check `SECRET_BROKER_MODE`, `SECRET_BROKER_CLIENT_API_KEY`, and `SECRET_BROKER_APPROVER_API_KEY`.
- In `enforce` mode, the client and approver keys must be distinct and non-default.
- Make sure the database path exists and is writable.
- Confirm the bind address is not already in use.

## Readiness check fails

- Hit `GET /readyz` directly and confirm the DB migration completed.
- Make sure the SQLite file lives on persistent storage.
- Check for permission errors on the database directory.
- Re-run the service after fixing file ownership or path issues.

## Requests stay pending

- Confirm the approver key is being used by the approval channel.
- Check that the request does not violate target prefix or amount policy.
- Verify the broker clock is correct if approvals seem to expire too early.
- Inspect `/v1/audit` for `forbidden`, `rate_limited`, or `invalid_capability` events.

## Execute returns `invalid_capability`

- Make sure the capability token came from the approved request.
- Confirm the token has not already been used.
- Check that the token was not copied with extra whitespace.
- Verify the token has not expired.

## Linux-specific issues

- Ensure `systemd` has the correct `WorkingDirectory` and `EnvironmentFile`.
- Check `journalctl -u secret-broker.service`.
- Confirm the backup timer is enabled if backups are expected.

## macOS-specific issues

- Ensure the `launchd` plist uses real paths, not placeholders.
- Check `launchctl print system/com.secret-broker`.
- Confirm the plist file is owned and permissioned correctly for a LaunchDaemon.

## Windows-specific issues

- Ensure the service was installed from an elevated PowerShell session.
- Confirm the machine-level environment variables are present.
- Check that the DB path is writable by the service account.
- Verify the service binary path matches the installed location.

## OpenClaw integration issues

- Make sure OpenClaw only has the `client` key.
- Make sure the approver channel has the `approver` key.
- Confirm OpenClaw talks to the broker over HTTP, not directly to Bitwarden.
- Verify the broker endpoint is reachable from the OpenClaw host.

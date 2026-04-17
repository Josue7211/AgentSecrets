# Quickstart

This repo currently provides broker-level masked-response guarantees. It does **not** yet provide a fully supported transcript-safe host integration.

The agent runtime should only hold the `client` key. Human approval tooling should only hold the `approver` key. Linux and macOS are the primary host platforms. Windows is supported, but secondary.

## Before you start

- Build the broker once: `cargo build --release`
- Copy `.env.example` to `.env`
- Set strong random values for:
  - `SECRET_BROKER_CLIENT_API_KEY`
  - `SECRET_BROKER_APPROVER_API_KEY`
- Set `SECRET_BROKER_MODE=enforce`
- Do **not** type secrets into prompts, chat boxes, or task memory

## Linux quickstart

1. Install the binary.
2. Install the `systemd` units from [systemd/](../systemd/).
3. Put your environment file at `/etc/secret-broker/secret-broker.env`.
4. Start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now secret-broker.service
```

5. Verify readiness:

```bash
scripts/healthcheck.sh http://127.0.0.1:4815
```

## macOS quickstart

1. Install the binary somewhere stable, such as `/usr/local/opt/secret-broker/bin/secret-broker`.
2. Install [launchd/com.secret-broker.plist](../launchd/com.secret-broker.plist).
3. Replace the placeholder environment values in the plist.
4. Load the service:

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/com.secret-broker.plist
```

5. Verify readiness:

```bash
scripts/healthcheck.sh http://127.0.0.1:4815
```

## Windows quickstart

1. Install the binary to `C:\Program Files\SecretBroker\secret-broker.exe` or equivalent.
2. Run [windows/install-secret-broker.ps1](../windows/install-secret-broker.ps1) from an elevated PowerShell session.
3. Supply the client and approver API keys when prompted.
4. Verify readiness against the local bind address after the service starts.

## Supported use today

Use this flow for current broker-level guarantees:

1. The host sends request intent to the broker with the `client` key.
2. The broker evaluates policy and either approves immediately or returns `pending_approval`.
3. The human approval app uses the `approver` key to approve or deny.
4. The host executes with the one-time capability token.
5. The broker returns masked results only.

## Minimum safety settings

- Keep the broker local or private-network only
- Set a strict `SECRET_BROKER_ALLOWED_TARGET_PREFIXES`
- Keep `SECRET_BROKER_MAX_AMOUNT_CENTS` low
- Use key rotation through `POST /v1/admin/keys/:role/rotate`
- Keep the SQLite DB on encrypted storage

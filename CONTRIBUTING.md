# Contributing

This repository is open source under the AGPL-3.0-or-later license.

## Before you submit changes

- Keep secrets out of the repo.
- Avoid machine-specific paths and local tunnel IDs.
- Run the relevant checks for the area you changed.
- Prefer small, reviewable commits.

## Local workflow

- Run `cargo check` and `cargo test` before submitting changes.
- Use the scripts under `scripts/` for backups and health checks.
- Update `README.md` and the docs when you change public behavior.

## Security

If you are changing anything around auth, approvals, Bitwarden integration, or execution adapters, run a security review before merge.

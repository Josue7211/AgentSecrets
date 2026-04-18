#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Running Bitwarden production provider mediation E2E evidence lane..."
cargo test --all-targets --all-features bitwarden_production_provider -- --nocapture

#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Running OpenClaw host E2E evidence lane..."
cargo test openclaw_host_ -- --nocapture
echo "Artifacts are stored under target/e2e-artifacts/"

#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Running request_sign production adapter E2E evidence lane..."
cargo test --all-targets --all-features request_sign_production -- --nocapture
echo "Artifacts are stored under target/e2e-artifacts/"

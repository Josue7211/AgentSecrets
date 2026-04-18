#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Running Loop 5 node-to-node E2E harness..."
cargo test e2e_harness:: -- --nocapture
echo "Artifacts are stored under target/e2e-artifacts/"

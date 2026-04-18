#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "v4-ship-gate: $1" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing $1"
}

require_grep() {
  local pattern="$1"
  local path="$2"
  grep -Fq "$pattern" "$path" || fail "$path missing: $pattern"
}

require_file docs/product/RELEASE.md
require_file docs/product/PLATFORM_SUPPORT.md
require_file docs/operations/OPERATIONS.md
require_file .github/workflows/ci.yml

require_grep '## V4 ship gate' docs/product/RELEASE.md
require_grep '## V4 platform claims table' docs/product/RELEASE.md
require_grep '## V4 manual signoff' docs/product/RELEASE.md
require_grep 'bash scripts/check-v4-ship-gate.sh' docs/product/RELEASE.md
require_grep 'bash scripts/run-rotation-recovery-drills.sh' docs/product/RELEASE.md
require_grep 'bash scripts/run-adversarial-suite.sh pr' docs/product/RELEASE.md
require_grep 'If one required V4 line is missing, cut it from the V4 claim set or ship the release as preview only' docs/product/RELEASE.md

require_grep 'This document is the V4 platform-support source of truth.' docs/product/PLATFORM_SUPPORT.md
require_grep 'V3 host status still comes from [docs/product/SUPPORTED_HOSTS.md](docs/product/SUPPORTED_HOSTS.md) and `scripts/check-external-host-ship-gate.sh`.' docs/product/PLATFORM_SUPPORT.md
require_grep 'If the external-host ship gate marks a host stale, keep that host at `preview` until fresh evidence returns.' docs/product/PLATFORM_SUPPORT.md
require_grep 'Policy engine over action, target, actor, environment, and risk | shipped' docs/product/PLATFORM_SUPPORT.md
require_grep 'Verified runtime, host, and adapter identity via stub attestation | shipped' docs/product/PLATFORM_SUPPORT.md
require_grep 'Host-specific runtime identity via host-signed attestation | preview' docs/product/PLATFORM_SUPPORT.md
require_grep 'PR-safe adversarial regression lane | shipped' docs/product/PLATFORM_SUPPORT.md
require_grep 'Extended adversarial verification lane | shipped' docs/product/PLATFORM_SUPPORT.md

require_grep 'Verify audit integrity with `cargo run --bin forensics -- verify-chain --db <sqlite-url>`' docs/operations/OPERATIONS.md
require_grep 'Run `bash scripts/run-rotation-recovery-drills.sh` after containment to verify recovery discipline' docs/operations/OPERATIONS.md
require_grep 'Run `bash scripts/run-adversarial-suite.sh extended` before restoring stronger claims' docs/operations/OPERATIONS.md

require_grep 'Rotation and recovery drills' .github/workflows/ci.yml
require_grep 'PR-safe adversarial suite' .github/workflows/ci.yml
require_grep 'External host ship gate summary' .github/workflows/ci.yml
require_grep 'V4 ship gate summary' .github/workflows/ci.yml
require_grep 'schedule:' .github/workflows/ci.yml
require_grep 'bash scripts/run-adversarial-suite.sh extended' .github/workflows/ci.yml

echo "v4-ship-gate: ok"

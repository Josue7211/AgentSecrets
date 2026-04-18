#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "v2-ship-gate: $1" >&2
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
require_file docs/product/INTEGRATION.md
require_file .github/workflows/ci.yml

require_grep '## V2 ship gate' docs/product/RELEASE.md
require_grep '## V2 support matrix' docs/product/RELEASE.md
require_grep '## V2 release-note claims table' docs/product/RELEASE.md
require_grep '## Manual signoff' docs/product/RELEASE.md
require_grep 'bash scripts/check-v2-ship-gate.sh' docs/product/RELEASE.md
require_grep 'If one required Loop 0 through Loop 5 line is missing, cut it from the V2 claim set or ship the release as preview only' docs/product/RELEASE.md

require_grep '## Supported V2 topology' docs/product/INTEGRATION.md
require_grep 'trusted-side provider placement stays beside the broker boundary' docs/product/INTEGRATION.md
require_grep 'audit export must come from `/v1/audit` or backed-up broker artifacts' docs/product/INTEGRATION.md
require_grep 'key handling must preserve role separation' docs/product/INTEGRATION.md

require_grep 'Claim audit' .github/workflows/ci.yml
require_grep 'Check' .github/workflows/ci.yml
require_grep 'Node-to-node E2E harness' .github/workflows/ci.yml
require_grep 'Unit and integration tests' .github/workflows/ci.yml
require_grep 'V2 ship gate summary' .github/workflows/ci.yml

echo "v2-ship-gate: ok"

#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "v3-ship-gate: $1" >&2
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
require_file docs/product/SUPPORTED_HOSTS.md
require_file docs/product/INTEGRATION.md
require_file README.md
require_file .github/workflows/ci.yml

require_grep '## V3 ship gate' docs/product/RELEASE.md
require_grep '## V3 release-note claims table' docs/product/RELEASE.md
require_grep '## External host ship gate' docs/product/RELEASE.md
require_grep '## V3 manual signoff' docs/product/RELEASE.md
require_grep 'bash scripts/check-v3-ship-gate.sh' docs/product/RELEASE.md
require_grep 'bash scripts/check-external-host-ship-gate.sh' docs/product/RELEASE.md
require_grep 'bash scripts/run-openclaw-e2e.sh' docs/product/RELEASE.md
require_grep 'If one required V3 line is missing, cut it from the V3 claim set or ship the release as preview only' docs/product/RELEASE.md

require_grep 'This document is the V3 host-certification source of truth.' docs/product/SUPPORTED_HOSTS.md
require_grep 'It is the only external-host ship gate input.' docs/product/SUPPORTED_HOSTS.md
require_grep '## Freshness policy' docs/product/SUPPORTED_HOSTS.md
require_grep 'Local helper harness (`src/bin/e2e-node.rs`) | shipped' docs/product/SUPPORTED_HOSTS.md
require_grep 'OpenClaw-style HTTP host | preview' docs/product/SUPPORTED_HOSTS.md
require_grep 'Host-specific identity evidence now exists, but the documented host path remains preview' docs/product/SUPPORTED_HOSTS.md
require_grep 'bash scripts/run-openclaw-e2e.sh' docs/product/SUPPORTED_HOSTS.md
require_grep 'Claude / Codex / arbitrary external runtimes | unsupported' docs/product/SUPPORTED_HOSTS.md

require_grep 'Use [docs/product/SUPPORTED_HOSTS.md](docs/product/SUPPORTED_HOSTS.md) to decide which hosts are actually release-eligible for V3 end-to-end claims.' docs/product/INTEGRATION.md
require_grep 'OpenClaw remains the preview host exception only for the documented broker HTTP path' docs/product/INTEGRATION.md
require_grep 'Use the V3 ship gate in [docs/product/RELEASE.md](docs/product/RELEASE.md#v3-ship-gate) plus [docs/product/SUPPORTED_HOSTS.md](docs/product/SUPPORTED_HOSTS.md) before any V3 supported-host claim' docs/product/INTEGRATION.md
require_grep 'docs/architecture/OPENCLAW_THREAT_NOTES.md' docs/product/INTEGRATION.md

require_grep 'Read [docs/product/SUPPORTED_HOSTS.md](docs/product/SUPPORTED_HOSTS.md) for the current V3 host-certification boundary.' README.md
require_grep 'Use [docs/product/SUPPORTED_HOSTS.md](docs/product/SUPPORTED_HOSTS.md) as the only V3 host-certification source of truth.' README.md

require_grep 'V3 ship gate summary' .github/workflows/ci.yml
require_grep 'External host ship gate summary' .github/workflows/ci.yml
require_grep 'OpenClaw-style HTTP hosts are fully certified for V3 end-to-end claims | blocked' docs/product/RELEASE.md

echo "v3-ship-gate: ok"

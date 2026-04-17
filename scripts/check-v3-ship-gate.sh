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

require_file docs/RELEASE.md
require_file docs/SUPPORTED_HOSTS.md
require_file docs/INTEGRATION.md
require_file README.md
require_file .github/workflows/ci.yml

require_grep '## V3 ship gate' docs/RELEASE.md
require_grep '## V3 release-note claims table' docs/RELEASE.md
require_grep '## V3 manual signoff' docs/RELEASE.md
require_grep 'bash scripts/check-v3-ship-gate.sh' docs/RELEASE.md
require_grep 'bash scripts/run-openclaw-e2e.sh' docs/RELEASE.md
require_grep 'If one required V3 line is missing, cut it from the V3 claim set or ship the release as preview only' docs/RELEASE.md

require_grep 'This document is the V3 host-certification source of truth.' docs/SUPPORTED_HOSTS.md
require_grep 'Local helper harness (`src/bin/e2e-node.rs`) | shipped' docs/SUPPORTED_HOSTS.md
require_grep 'OpenClaw-style HTTP host | shipped' docs/SUPPORTED_HOSTS.md
require_grep 'bash scripts/run-openclaw-e2e.sh' docs/SUPPORTED_HOSTS.md
require_grep 'Claude / Codex / arbitrary external runtimes | unsupported' docs/SUPPORTED_HOSTS.md

require_grep 'Use [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) to decide which hosts are actually release-eligible for V3 end-to-end claims.' docs/INTEGRATION.md
require_grep 'OpenClaw is the certified host exception only for the documented broker HTTP path' docs/INTEGRATION.md
require_grep 'Use the V3 ship gate in [docs/RELEASE.md](docs/RELEASE.md#v3-ship-gate) plus [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) before any V3 supported-host claim' docs/INTEGRATION.md
require_grep 'docs/OPENCLAW_THREAT_NOTES.md' docs/INTEGRATION.md

require_grep 'Read [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) for the current V3 host-certification boundary.' README.md
require_grep 'Use [docs/SUPPORTED_HOSTS.md](docs/SUPPORTED_HOSTS.md) as the only V3 host-certification source of truth.' README.md

require_grep 'V3 ship gate summary' .github/workflows/ci.yml

echo "v3-ship-gate: ok"

#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "claim-audit: $1" >&2
  exit 1
}

[[ -f docs/SECURITY_GUARANTEES.md ]] || fail "missing docs/SECURITY_GUARANTEES.md"

grep -Fq "broker-level no-plaintext-response guarantees" README.md || fail "README missing narrowed guarantee"
grep -Fq "does **not** yet provide a complete end-to-end transcript-safe zero-trust system" README.md || fail "README missing transcript-safe disclaimer"
grep -Fq "Current implemented boundary" docs/ARCHITECTURE.md || fail "ARCHITECTURE missing current boundary section"
grep -Fq "No current guarantee of transcript-safe host behavior" docs/ARCHITECTURE.md || fail "ARCHITECTURE missing transcript disclaimer"
grep -Fq "What this repo does not solve yet" docs/THREAT_MODEL.md || fail "THREAT_MODEL missing current gap section"
grep -Fq "Run \`bash scripts/check-security-claims.sh\`" docs/RELEASE.md || fail "RELEASE missing claim audit step"
grep -Fq "The current repo guarantees broker-level masked responses. It does **not** yet guarantee transcript-safe host behavior." docs/INTEGRATION.md || fail "INTEGRATION missing host disclaimer"
grep -Fq "It does not certify current end-to-end transcript safety." docs/OPENCLAW.md || fail "OPENCLAW missing disclaimer"
grep -Fq "Do **not** type secrets into prompts, chat boxes, or task memory" docs/QUICKSTART.md || fail "QUICKSTART missing prompt-entry warning"

echo "claim-audit: ok"

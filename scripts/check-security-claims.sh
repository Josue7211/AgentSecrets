#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "claim-audit: $1" >&2
  exit 1
}

[[ -f docs/SECURITY_GUARANTEES.md ]] || fail "missing docs/SECURITY_GUARANTEES.md"
grep -Fq "Supported trust claim in the current repo state" docs/SECURITY_GUARANTEES.md || fail "SECURITY_GUARANTEES missing supported trust claim section"
grep -Fq "AgentSecrets currently provides broker-level no-plaintext-response guarantees. It does **not** yet provide a complete end-to-end zero-trust secret-use system for external host apps." docs/SECURITY_GUARANTEES.md || fail "SECURITY_GUARANTEES missing canonical guarantee"
grep -Fq "For the preview OpenClaw host path, the repo now also provides host-specific evidence for trusted-input ingress, transcript/log redaction, approval masking, and adapter execution without plaintext leakage." docs/SECURITY_GUARANTEES.md || fail "SECURITY_GUARANTEES missing OpenClaw preview note"

grep -Fq "broker-level no-plaintext-response guarantees" README.md || fail "README missing narrowed guarantee"
grep -Fq "does **not** yet provide a complete end-to-end transcript-safe zero-trust system" README.md || fail "README missing transcript-safe disclaimer"
grep -Fq "Current implemented boundary" docs/ARCHITECTURE.md || fail "ARCHITECTURE missing current boundary section"
grep -Fq "No current guarantee of universal transcript-safe host behavior beyond the preview OpenClaw host path" docs/ARCHITECTURE.md || fail "ARCHITECTURE missing transcript disclaimer"
grep -Fq "What this repo does not solve yet" docs/THREAT_MODEL.md || fail "THREAT_MODEL missing current gap section"
grep -Fq "Run \`bash scripts/check-security-claims.sh\`" docs/RELEASE.md || fail "RELEASE missing claim audit step"
grep -Fq "OpenClaw remains the preview host exception only for the documented broker HTTP path" docs/INTEGRATION.md || fail "INTEGRATION missing preview OpenClaw boundary"
grep -Fq 'OpenClaw is a documented external host path in this repo, and host-specific identity evidence now exists for the documented broker HTTP path. It still remains `preview`.' docs/OPENCLAW.md || fail "OPENCLAW missing preview boundary"
[[ -f docs/OPENCLAW_THREAT_NOTES.md ]] || fail "missing docs/OPENCLAW_THREAT_NOTES.md"
grep -Fq "Do **not** type secrets into prompts, chat boxes, or task memory" docs/QUICKSTART.md || fail "QUICKSTART missing prompt-entry warning"

echo "claim-audit: ok"

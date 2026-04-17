#!/usr/bin/env bash
set -euo pipefail

stamp="$(date +%Y%m%d-%H%M%S)"
artifact_dir="target/drill-artifacts/${stamp}"
mkdir -p "$artifact_dir"

run_and_capture() {
  local name="$1"
  shift
  echo "rotation-recovery-drill: running ${name}"
  "$@" >"${artifact_dir}/${name}.log" 2>&1
}

run_and_capture "rotate-client" cargo test rotating_client_key_invalidates_old_key -- --nocapture
run_and_capture "rotate-approver" cargo test rotating_approver_key_invalidates_old_key -- --nocapture
run_and_capture "deny-recovery" cargo test deny_clears_capability_state -- --nocapture
run_and_capture "audit-tamper-detect" cargo test audit_chain_verification_detects_tampering -- --nocapture

cat >"${artifact_dir}/summary.json" <<EOF
{
  "ok": true,
  "generated_at": "$(date '+%Y-%m-%dT%H:%M:%S%:z')",
  "artifact_dir": "${artifact_dir}",
  "checks": [
    "rotating_client_key_invalidates_old_key",
    "rotating_approver_key_invalidates_old_key",
    "deny_clears_capability_state",
    "audit_chain_verification_detects_tampering"
  ]
}
EOF

echo "rotation-recovery-drill: ok"
echo "rotation-recovery-drill: artifacts at ${artifact_dir}"

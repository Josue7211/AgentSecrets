#!/usr/bin/env bash
set -euo pipefail

mode="${1:-pr}"
if [[ "$mode" != "pr" && "$mode" != "extended" ]]; then
  echo "adversarial-suite: mode must be pr or extended" >&2
  exit 1
fi

stamp="$(date +%Y%m%d-%H%M%S)"
artifact_dir="target/adversarial-artifacts/${mode}-${stamp}"
mkdir -p "$artifact_dir"

run_and_capture() {
  local name="$1"
  shift
  echo "adversarial-suite: running ${name}"
  "$@" >"${artifact_dir}/${name}.log" 2>&1
}

run_and_capture "plaintext-rejection" cargo test request_rejects_plaintext_secret_ref -- --nocapture
run_and_capture "ingress-audit-redaction" cargo test ingress_rejection_is_audited_without_echoing_secret -- --nocapture
run_and_capture "action-mismatch" cargo test execute_rejects_action_mismatch -- --nocapture
run_and_capture "target-mismatch" cargo test execute_rejects_target_mismatch -- --nocapture
run_and_capture "identity-missing" cargo test create_request_rejects_missing_identity_headers_when_attestation_required -- --nocapture
run_and_capture "identity-mismatch" cargo test execute_rejects_identity_mismatch_after_approval -- --nocapture
run_and_capture "transcript-redaction" cargo test supported_host_redaction_filters_canary_and_provider_refs -- --nocapture
run_and_capture "redaction-fail-closed" cargo test supported_host_redaction_failure_fails_closed -- --nocapture

if [[ "$mode" == "extended" ]]; then
  run_and_capture "audit-tamper-detect" cargo test audit_chain_verification_detects_tampering -- --nocapture
  run_and_capture "forensic-export" cargo test forensic_bundle_export_is_redact_safe_and_tamper_evident -- --nocapture
  run_and_capture "node-harness" bash scripts/run-e2e-harness.sh
fi

cat >"${artifact_dir}/summary.json" <<EOF
{
  "ok": true,
  "mode": "${mode}",
  "generated_at": "$(date '+%Y-%m-%dT%H:%M:%S%:z')",
  "artifact_dir": "${artifact_dir}"
}
EOF

echo "adversarial-suite: ok"
echo "adversarial-suite: artifacts at ${artifact_dir}"

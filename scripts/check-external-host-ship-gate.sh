#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "external-host-ship-gate: $1" >&2
  exit 1
}

doc="docs/product/SUPPORTED_HOSTS.md"
[[ -f "$doc" ]] || fail "missing $doc"

python - "$doc" <<'PY'
from __future__ import annotations

import datetime as dt
import os
import re
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8").read().splitlines()

def norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())

header_idx = None
for idx, line in enumerate(text):
    stripped = line.strip()
    if not stripped.startswith("|"):
        continue
    cells = [cell.strip() for cell in stripped.strip("|").split("|")]
    normalized = [norm(cell) for cell in cells]
    if normalized[:2] == [norm("Host"), norm("Status")] and len(normalized) >= 8:
        header_idx = idx
        break

if header_idx is None:
    print("external-host-ship-gate: missing host matrix table", file=sys.stderr)
    raise SystemExit(1)

headers = [cell.strip() for cell in text[header_idx].strip().strip("|").split("|")]
normalized_headers = [norm(cell) for cell in headers]
required_headers = {
    norm("Host"): "Host",
    norm("Status"): "Status",
    norm("Trusted-input evidence"): "Trusted-input evidence",
    norm("Transcript/log redaction evidence"): "Transcript/log redaction evidence",
    norm("Adapter evidence"): "Adapter evidence",
    norm("Identity evidence"): "Identity evidence",
    norm("Last verified"): "Last verified",
    norm("Known limits"): "Known limits",
}
missing_headers = [label for key, label in required_headers.items() if key not in normalized_headers]
if missing_headers:
    print(
        "external-host-ship-gate: missing required host matrix columns: "
        + ", ".join(missing_headers),
        file=sys.stderr,
    )
    raise SystemExit(1)

rows: list[dict[str, str]] = []
table_seen = False
for line_no, line in enumerate(text[header_idx + 2 :], start=header_idx + 3):
    stripped = line.strip()
    if not stripped:
        if table_seen:
            break
        continue
    if not stripped.startswith("|"):
        if table_seen:
            break
        continue
    if set(stripped) <= {"|", "-", ":", " "}:
        continue
    cells = [cell.strip() for cell in stripped.strip("|").split("|")]
    if len(cells) != len(headers):
        print(
            f"external-host-ship-gate: malformed host row at line {line_no}: expected {len(headers)} cells, got {len(cells)}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    row = {normalized_headers[idx]: cells[idx] for idx in range(len(cells))}
    rows.append(row)
    table_seen = True

if not rows:
    print("external-host-ship-gate: no host rows found", file=sys.stderr)
    raise SystemExit(1)

today_raw = os.environ.get("EXTERNAL_HOST_SHIP_GATE_TODAY")
if today_raw:
    try:
        today = dt.date.fromisoformat(today_raw)
    except ValueError:
        print(
            f"external-host-ship-gate: invalid EXTERNAL_HOST_SHIP_GATE_TODAY value {today_raw!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)
else:
    today = dt.date.today()
freshness_days = 30

allowed_statuses = {"shipped", "preview", "unsupported"}
issues: list[str] = []
rendered: list[dict[str, str]] = []

def parse_date(value: str) -> dt.date | None:
    value = value.strip("` ")
    if value.lower() in {"n/a", "na", "none"}:
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None

def looks_like_runnable_evidence(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in ("cargo test", "bash scripts/", "cargo run"))

def evidence_matches(value: str, tokens: tuple[str, ...]) -> bool:
    lowered = value.lower()
    return looks_like_runnable_evidence(value) and any(token in lowered for token in tokens)

def looks_like_limit_statement(value: str) -> bool:
    lowered = value.lower()
    if len(lowered) < 20:
        return False
    return any(
        token in lowered
        for token in (
            "only",
            "not",
            "untrusted",
            "preview",
            "bounded",
            "certified",
            "unsupported",
        )
    )

def host_policy(host: str) -> dict[str, tuple[str, ...]]:
    lowered = host.lower()
    if "local helper harness" in lowered or "e2e-node" in lowered:
        return {
            "Trusted-input evidence": ("e2e_harness", "e2e-harness"),
            "Transcript/log redaction evidence": ("run-e2e-harness.sh", "e2e-harness"),
            "Adapter evidence": ("run-e2e-harness.sh", "e2e-harness"),
            "Identity evidence": ("identity", "attestation"),
        }
    if "openclaw" in lowered:
        return {
            "Trusted-input evidence": ("openclaw_host", "run-openclaw-e2e.sh", "trusted_input"),
            "Transcript/log redaction evidence": ("run-openclaw-e2e.sh", "openclaw"),
            "Adapter evidence": ("run-openclaw-e2e.sh", "openclaw"),
            "Identity evidence": ("openclaw", "identity"),
        }
    return {}

def require_evidence(host: str, field: str, value: str, tokens: tuple[str, ...]) -> str | None:
    if not value.strip():
        return f"{host}: shipped host is missing {field}"
    if not evidence_matches(value, tokens):
        return f"{host}: shipped host {field} is not runnable host-specific evidence: {value!r}"
    return None

for row in rows:
    host = row.get(norm("Host"), "").strip()
    declared_status = row.get(norm("Status"), "").strip().lower()
    current_status = declared_status
    row_issues: list[str] = []

    if declared_status not in allowed_statuses:
        row_issues.append(f"{host or '<unknown host>'}: invalid status {declared_status!r}")
        current_status = "preview"

    if declared_status == "shipped":
        policy = host_policy(host)
        if not policy:
            row_issues.append(
                f"{host}: shipped host has no validation policy for host-specific evidence"
            )
            current_status = "preview"
        else:
            for field, tokens in policy.items():
                issue = require_evidence(
                    host, field, row.get(norm(field), "").strip(), tokens
                )
                if issue:
                    row_issues.append(issue)

        known_limits = row.get(norm("Known limits"), "").strip()
        if not known_limits:
            row_issues.append(f"{host}: shipped host is missing Known limits")
        elif not looks_like_limit_statement(known_limits):
            row_issues.append(
                f"{host}: shipped host Known limits is too vague to be a real limit statement: {known_limits!r}"
            )

        last_verified = parse_date(row.get(norm("Last verified"), ""))
        if last_verified is None:
            row_issues.append(f"{host}: shipped host has invalid or missing Last verified date")
        else:
            age_days = (today - last_verified).days
            if age_days < 0:
                row_issues.append(
                    f"{host}: shipped host has a future Last verified date ({last_verified.isoformat()})"
                )
            elif age_days > freshness_days:
                row_issues.append(
                    f"{host}: shipped host evidence is stale ({age_days} days old); downgrade to preview"
                )

        if row_issues:
            current_status = "preview"
            issues.extend(row_issues)
        else:
            # row stayed shipped
            pass
    else:
        if row_issues:
            issues.extend(row_issues)

    rendered.append(
        {
            "Host": host,
            "Status": current_status,
            "Trusted-input evidence": row.get(norm("Trusted-input evidence"), "").strip(),
            "Transcript/log redaction evidence": row.get(
                norm("Transcript/log redaction evidence"), ""
            ).strip(),
            "Adapter evidence": row.get(norm("Adapter evidence"), "").strip(),
            "Identity evidence": row.get(norm("Identity evidence"), "").strip(),
            "Last verified": row.get(norm("Last verified"), "").strip(),
            "Known limits": row.get(norm("Known limits"), "").strip(),
        }
    )

summary_lines = [
    "## External host support truth",
    "",
    "| Host | Status | Trusted-input evidence | Transcript/log redaction evidence | Adapter evidence | Identity evidence | Last verified | Known limits |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
]
for row in rendered:
    summary_lines.append(
        "| {Host} | {Status} | {Trusted-input evidence} | {Transcript/log redaction evidence} | {Adapter evidence} | {Identity evidence} | {Last verified} | {Known limits} |".format(
            **row
        )
    )

summary = "\n".join(summary_lines)
print(summary)

step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
if step_summary_path:
    with open(step_summary_path, "a", encoding="utf-8") as fh:
        fh.write(summary + "\n")
        if issues:
            fh.write("\n## Gate findings\n")
            for issue in issues:
                fh.write(f"- {issue}\n")

if issues:
    print("\n## Gate findings")
    for issue in issues:
        print(f"- {issue}")
    raise SystemExit(1)

print("external-host-ship-gate: ok")
PY

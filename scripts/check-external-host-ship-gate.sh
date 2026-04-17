#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "external-host-ship-gate: $1" >&2
  exit 1
}

doc="docs/SUPPORTED_HOSTS.md"
[[ -f "$doc" ]] || fail "missing $doc"

python - "$doc" <<'PY'
from __future__ import annotations

import datetime as dt
import os
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8").read().splitlines()

header_idx = None
for idx, line in enumerate(text):
    if line.startswith("| Host | Status | Trusted-input evidence |"):
        header_idx = idx
        break

if header_idx is None:
    print("external-host-ship-gate: missing host matrix table", file=sys.stderr)
    raise SystemExit(1)

headers = [cell.strip() for cell in text[header_idx].strip().strip("|").split("|")]
rows: list[dict[str, str]] = []
for line in text[header_idx + 2 :]:
    stripped = line.strip()
    if not stripped.startswith("|"):
        if rows:
            break
        continue
    cells = [cell.strip() for cell in stripped.strip("|").split("|")]
    if len(cells) != len(headers):
        continue
    rows.append(dict(zip(headers, cells)))

if not rows:
    print("external-host-ship-gate: no host rows found", file=sys.stderr)
    raise SystemExit(1)

today = dt.date.today()
freshness_days = 30
required_empty_markers = {
    "",
    "n/a",
    "na",
    "none",
    "no host-specific certification",
    "not certified",
}

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

for row in rows:
    host = row.get("Host", "").strip()
    declared_status = row.get("Status", "").strip().lower()
    current_status = declared_status

    if declared_status not in allowed_statuses:
        issues.append(f"{host or '<unknown host>'}: invalid status {declared_status!r}")
        current_status = "preview"

    if declared_status == "shipped":
        required_fields = [
            "Trusted-input evidence",
            "Transcript/log redaction evidence",
            "Adapter evidence",
            "Identity evidence",
            "Last verified",
            "Known limits",
        ]
        missing = []
        for field in required_fields:
            value = row.get(field, "").strip()
            normalized = value.strip("` ").lower()
            if normalized in required_empty_markers:
                missing.append(field)
        if missing:
            issues.append(
                f"{host}: shipped host is missing current evidence fields: {', '.join(missing)}"
            )
            current_status = "preview"

        last_verified = parse_date(row.get("Last verified", ""))
        if last_verified is None:
            if not missing or "Last verified" not in missing:
                issues.append(f"{host}: shipped host has invalid or missing Last verified date")
            current_status = "preview"
        else:
            age_days = (today - last_verified).days
            if age_days < 0:
                issues.append(
                    f"{host}: shipped host has a future Last verified date ({last_verified.isoformat()})"
                )
                current_status = "preview"
            elif age_days > freshness_days:
                issues.append(
                    f"{host}: shipped host evidence is stale ({age_days} days old); downgrade to preview"
                )
                current_status = "preview"

    rendered.append(
        {
            "Host": host,
            "Status": current_status,
            "Trusted-input evidence": row.get("Trusted-input evidence", "").strip(),
            "Transcript/log redaction evidence": row.get(
                "Transcript/log redaction evidence", ""
            ).strip(),
            "Adapter evidence": row.get("Adapter evidence", "").strip(),
            "Identity evidence": row.get("Identity evidence", "").strip(),
            "Last verified": row.get("Last verified", "").strip(),
            "Known limits": row.get("Known limits", "").strip(),
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

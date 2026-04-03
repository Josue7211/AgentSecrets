#!/usr/bin/env bash
set -euo pipefail

db_path="${1:-secret-broker.db}"
backup_path="${2:-${db_path}.$(date +%Y%m%d%H%M%S).bak}"

if [[ ! -f "$db_path" ]]; then
  echo "database not found: $db_path" >&2
  exit 1
fi

cp -a "$db_path" "$backup_path"
echo "$backup_path"

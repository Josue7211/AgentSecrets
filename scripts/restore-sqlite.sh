#!/usr/bin/env bash
set -euo pipefail

backup_path="${1:?usage: restore-sqlite.sh <backup-file> [target-db]}"
target_path="${2:-secret-broker.db}"

if [[ ! -f "$backup_path" ]]; then
  echo "backup not found: $backup_path" >&2
  exit 1
fi

cp -a "$backup_path" "$target_path"
echo "$target_path"

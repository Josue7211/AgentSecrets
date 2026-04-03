#!/usr/bin/env bash
set -euo pipefail

base_url="${1:-http://127.0.0.1:4815}"

curl --fail --silent --show-error "$base_url/readyz" >/dev/null

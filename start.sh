#!/usr/bin/env bash

set -euo pipefail

if [[ -z "${SECRET_KEY:-}" ]]; then
  echo "ERROR: SECRET_KEY environment variable is required." >&2
  exit 1
fi

: "${PORT:=8000}"

exec uvicorn notos_api:app --host 0.0.0.0 --port "${PORT}"

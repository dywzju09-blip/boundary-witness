#!/usr/bin/env bash
set -euo pipefail
if cargo tree -p bw-blind-runner --locked | rg 'bw-blind-curator'; then
  echo "bw-blind-runner must not depend on bw-blind-curator" >&2
  exit 1
fi

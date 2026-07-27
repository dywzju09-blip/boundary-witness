#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config="${1:-${repo_root}/experiments/configs/d2-baselines.toml}"
records_root="${2:-${BW_D2_RECORDS_ROOT:-}}"

if [[ -n "$records_root" ]]; then
  cargo run -p bw-experiment --bin bw-d2-compare --locked -- "$config" --records-root "$records_root" >/dev/null
else
  cargo run -p bw-experiment --bin bw-d2-compare --locked -- "$config" >/dev/null
fi

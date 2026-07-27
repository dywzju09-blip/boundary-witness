#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: build-d0-targets.sh [--repo <repo>] [--config <d0-builds.toml>] --out <output-dir> [--dry-run]

Builds the D0 replay runner variants described by experiments/configs/d0-builds.toml.
The script is intended to run inside the pinned Linux D0 container.
EOF
}

fail() {
  printf 'build-d0-targets: %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

repo="."
config=""
out_dir=""
dry_run=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      [[ $# -ge 2 ]] || fail "--repo requires a value"
      repo="$2"
      shift 2
      ;;
    --config)
      [[ $# -ge 2 ]] || fail "--config requires a value"
      config="$2"
      shift 2
      ;;
    --out)
      [[ $# -ge 2 ]] || fail "--out requires a value"
      out_dir="$2"
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$out_dir" ]] || fail "--out is required"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

repo="$(cd "$repo" && pwd -P)"
git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not a git repository: $repo"
repo="$(cd "$(git -C "$repo" rev-parse --show-toplevel)" && pwd -P)"
config="${config:-${repo}/experiments/configs/d0-builds.toml}"
[[ -f "$config" ]] || fail "config not found: $config"

out_dir="$(mkdir -p "$out_dir" && cd "$out_dir" && pwd -P)"
logs_dir="${out_dir}/logs"
mkdir -p "$logs_dir"

commit="$(git -C "$repo" rev-parse HEAD)"
cargo_lock_sha="$(sha256_file "${repo}/Cargo.lock")"
config_sha="$(sha256_file "$config")"

run_or_print() {
  if [[ "$dry_run" == true ]]; then
    printf 'dry-run:'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

(
  cd "$repo"
  run_or_print cargo build -p bw-experiment --bin bw-d0 --locked
  run_or_print env RUSTFLAGS="-Zsanitizer=address" cargo +nightly build \
    -p bw-experiment \
    --bin bw-d0 \
    --target x86_64-unknown-linux-gnu \
    --locked
) >"${logs_dir}/build.stdout" 2>"${logs_dir}/build.stderr"

BW_COMMIT="$commit" \
BW_CARGO_LOCK_SHA="$cargo_lock_sha" \
BW_CONFIG_SHA="$config_sha" \
BW_DRY_RUN="$dry_run" \
python3 - "${out_dir}/build-manifest.json" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

manifest = {
    "schema_version": "boundary-witness.d0-build-manifest/0.1",
    "source_commit": os.environ["BW_COMMIT"],
    "cargo_lock_sha256": os.environ["BW_CARGO_LOCK_SHA"],
    "config_sha256": os.environ["BW_CONFIG_SHA"],
    "dry_run": os.environ["BW_DRY_RUN"] == "true",
    "builds": [
        {"id": "d0-debug", "sanitizer": "none", "binary": "bw-d0"},
        {"id": "d0-asan", "sanitizer": "address", "binary": "bw-d0"},
    ],
    "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
}

with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
PY

printf '{"status":"ok","commit":"%s","out":"%s","dry_run":%s}\n' "$commit" "$out_dir" "$dry_run"

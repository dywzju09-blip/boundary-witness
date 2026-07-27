#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: sync-results.sh --source-run <server-or-local-run-dir> --dest-root <mac-data-root> [--verify-bin <bw-verify-run>]

Copies only finalized, checksum-valid run directories into:
  <dest-root>/runs/<RUN_ID>

The script never deletes the source run.
EOF
}

fail() {
  printf 'sync-results: %s\n' "$*" >&2
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

cleanup_dir() {
  local path="$1"
  if [[ -d "$path" ]]; then
    find "$path" -type f -delete
    find "$path" -depth -type d -empty -delete
  fi
}

source_run=""
dest_root=""
verify_bin="${BW_VERIFY_RUN_BIN:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-run)
      [[ $# -ge 2 ]] || fail "--source-run requires a value"
      source_run="$2"
      shift 2
      ;;
    --dest-root)
      [[ $# -ge 2 ]] || fail "--dest-root requires a value"
      dest_root="$2"
      shift 2
      ;;
    --verify-bin)
      [[ $# -ge 2 ]] || fail "--verify-bin requires a value"
      verify_bin="$2"
      shift 2
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

[[ -n "$source_run" ]] || fail "--source-run is required"
[[ -n "$dest_root" ]] || fail "--dest-root is required"
[[ -d "$source_run" ]] || fail "source run directory not found: $source_run"

run_id="$(basename "$source_run")"
[[ "$run_id" != *.partial ]] || fail "refusing to sync .partial run: $run_id"
[[ -f "${source_run}/checksums.sha256" ]] || fail "source run is missing checksums.sha256"

if [[ -z "$verify_bin" ]]; then
  verify_bin="$(command -v bw-verify-run || true)"
fi
[[ -n "$verify_bin" && -x "$verify_bin" ]] || fail "bw-verify-run not found; pass --verify-bin"

"$verify_bin" "$source_run" >/dev/null
source_digest="$(sha256_file "${source_run}/checksums.sha256")"

dest_root="$(mkdir -p "$dest_root" && cd "$dest_root" && pwd -P)"
runs_dir="${dest_root}/runs"
mkdir -p "$runs_dir"
dest_run="${runs_dir}/${run_id}"

if [[ -e "$dest_run" ]]; then
  "$verify_bin" "$dest_run" >/dev/null
  [[ -f "${dest_run}/checksums.sha256" ]] || fail "destination run missing checksums.sha256: $dest_run"
  dest_digest="$(sha256_file "${dest_run}/checksums.sha256")"
  if [[ "$source_digest" == "$dest_digest" ]]; then
    printf '{"status":"ok","mode":"already-synced","run_id":"%s","dest":"%s"}\n' "$run_id" "$dest_run"
    exit 0
  fi
  fail "destination run exists with different checksum digest: $dest_run"
fi

tmp_parent="${runs_dir}/.${run_id}.sync.$$"
mkdir -p "$tmp_parent"
trap 'cleanup_dir "$tmp_parent"' EXIT

cp -R "$source_run" "${tmp_parent}/${run_id}"
"$verify_bin" "${tmp_parent}/${run_id}" >/dev/null
mv "${tmp_parent}/${run_id}" "$dest_run"
rmdir "$tmp_parent"
trap - EXIT

printf '{"status":"ok","mode":"synced","run_id":"%s","dest":"%s"}\n' "$run_id" "$dest_run"

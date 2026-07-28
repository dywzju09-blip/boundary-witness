#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
sync_tool="${repo_root}/tools/deploy/sync-results.sh"
cargo_target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"
verify_bin="${cargo_target_dir}/debug/bw-verify-run"

fail() {
  printf 'result-sync-policy: %s\n' "$*" >&2
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

write_checksums() {
  local run_dir="$1"
  (
    cd "$run_dir"
    find . -type f ! -name checksums.sha256 | sed 's#^\./##' | sort | while IFS= read -r rel; do
      printf '%s  %s\n' "$(sha256_file "$rel")" "$rel"
    done > checksums.sha256
  )
}

create_run() {
  local run_dir="$1"
  local note="$2"
  mkdir -p "$run_dir/traces" "$run_dir/logs" "$run_dir/input" "$run_dir/artifacts"
  printf '{"schema_version":"bw.run/0.1","note":"%s"}\n' "$note" > "$run_dir/manifest.json"
  printf '{"schema_version":"boundary-witness.run-integrity/0.1","run_id":"%s","status":"finalized","finalized_at_utc":"test","required_trace_files":["trace.jsonl"],"required_log_files":["stdout.log"],"user_summary":{"note":"%s"}}\n' "$(basename "$run_dir")" "$note" > "$run_dir/summary.json"
  printf '{"event":"trace"}\n' > "$run_dir/traces/trace.jsonl"
  printf 'stdout %s\n' "$note" > "$run_dir/logs/stdout.log"
  printf '' > "$run_dir/findings.jsonl"
  printf 'complete\n' > "$run_dir/COMPLETE"
  write_checksums "$run_dir"
}

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
[[ -x "$sync_tool" ]] || fail "missing executable sync tool: $sync_tool"

cargo build -p bw-experiment --bin bw-verify-run --locked > /dev/null

tmp="$(mktemp -d -t bw-result-sync.XXXXXX)"
trap 'cleanup_dir "$tmp"' EXIT

source_root="${tmp}/source"
dest_root="${tmp}/dest"
mkdir -p "$source_root" "$dest_root"

valid="${source_root}/run-ok"
create_run "$valid" "valid"
"$sync_tool" --source-run "$valid" --dest-root "$dest_root" --verify-bin "$verify_bin" >"${tmp}/sync.out" 2>"${tmp}/sync.err"
[[ -f "${dest_root}/runs/run-ok/summary.json" ]] || fail "valid run was not copied"
"$verify_bin" "${dest_root}/runs/run-ok" > /dev/null
"$sync_tool" --source-run "$valid" --dest-root "$dest_root" --verify-bin "$verify_bin" >"${tmp}/sync-again.out" 2>"${tmp}/sync-again.err"

partial="${source_root}/run-partial.partial"
create_run "$partial" "partial"
if "$sync_tool" --source-run "$partial" --dest-root "$dest_root" --verify-bin "$verify_bin" >"${tmp}/partial.out" 2>"${tmp}/partial.err"; then
  fail ".partial run was accepted"
fi

bad_checksum="${source_root}/run-bad-checksum"
create_run "$bad_checksum" "bad-checksum"
printf 'tampered\n' >> "${bad_checksum}/logs/stdout.log"
if "$sync_tool" --source-run "$bad_checksum" --dest-root "$dest_root" --verify-bin "$verify_bin" >"${tmp}/bad-checksum.out" 2>"${tmp}/bad-checksum.err"; then
  fail "checksum mismatch was accepted"
fi

missing_file="${source_root}/run-missing-file"
create_run "$missing_file" "missing-file"
unlink "${missing_file}/traces/trace.jsonl"
if "$sync_tool" --source-run "$missing_file" --dest-root "$dest_root" --verify-bin "$verify_bin" >"${tmp}/missing-file.out" 2>"${tmp}/missing-file.err"; then
  fail "run with missing file was accepted"
fi

conflict="${source_root}/run-conflict"
create_run "$conflict" "first"
"$sync_tool" --source-run "$conflict" --dest-root "$dest_root" --verify-bin "$verify_bin" >"${tmp}/conflict-first.out" 2>"${tmp}/conflict-first.err"
printf 'changed\n' > "${conflict}/logs/stdout.log"
write_checksums "$conflict"
if "$sync_tool" --source-run "$conflict" --dest-root "$dest_root" --verify-bin "$verify_bin" >"${tmp}/conflict-second.out" 2>"${tmp}/conflict-second.err"; then
  fail "existing destination with different digest was accepted"
fi

printf 'result-sync-policy: ok\n'

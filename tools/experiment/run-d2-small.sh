#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config="${1:-${repo_root}/experiments/configs/d2-baselines.toml}"
records_root="${2:-${BW_D2_RECORDS_ROOT:-}}"
rustup_toolchain="${BW_D2_RUSTUP_TOOLCHAIN:-nightly-2026-07-08}"

toml_get() {
  cargo run -q -p bw-experiment --bin bw-d2-compare --locked -- "$config" --print-field "$1"
}

run_compare() {
  cargo run -p bw-experiment --bin bw-d2-compare --locked -- "$config" --records-root "$records_root"
}

if [[ -z "$records_root" ]]; then
  cargo run -p bw-experiment --bin bw-d2-compare --locked -- "$config"
  exit 0
fi

if [[ "${BW_D2_GENERATE_RECORDS:-0}" != "1" ]]; then
  run_compare
  exit 0
fi

records_root="$(mkdir -p "$records_root" && cd "$records_root" && pwd)"
run_root="$(dirname "$records_root")"
shared_dir="${repo_root}/benchmarks/historical-cves/rusqlite/shared"
d1_bin="${shared_dir}/target/debug/bw-rusqlite-d1"
logs_dir="${run_root}/logs"
input_corpus="${run_root}/input/update-hook-corpus"
corpus_jsonl="${repo_root}/experiments/corpus/d1/update-hook/safe-fragments.jsonl"
seconds="$(($(toml_get shared_budget.cpu_minutes) * 60))"

mkdir -p "$logs_dir" "$records_root"

for group in random_action coverage_only coverage_state; do
  if [[ -s "${records_root}/${group}/campaign-records.jsonl" ]]; then
    echo "run-d2-small: refusing to append to existing ${records_root}/${group}/campaign-records.jsonl" >&2
    echo "run-d2-small: choose a fresh records root for an auditable D2 run" >&2
    exit 1
  fi
done

cargo build --manifest-path "${shared_dir}/Cargo.toml" --bin bw-rusqlite-d1 --locked \
  >"${logs_dir}/build-d1-cli.stdout.log" \
  2>"${logs_dir}/build-d1-cli.stderr.log"

if [[ -d "$input_corpus" ]] && [[ -n "$(find "$input_corpus" -mindepth 1 -print -quit)" ]]; then
  echo "run-d2-small: refusing to reuse existing base corpus at ${input_corpus}" >&2
  echo "run-d2-small: choose a fresh run root so libFuzzer corpus mutations cannot leak across runs" >&2
  exit 1
fi

"$d1_bin" materialize-corpus "$corpus_jsonl" "$input_corpus" \
  >"${logs_dir}/materialize-corpus.stdout.log" \
  2>"${logs_dir}/materialize-corpus.stderr.log"

"$d1_bin" d2-random-records "$config" "$records_root" \
  >"${logs_dir}/d2-random-records.stdout.log" \
  2>"${logs_dir}/d2-random-records.stderr.log"

for target in update_hook_coverage_only update_hook_state_feedback; do
  (
    cd "$shared_dir"
    cargo +"$rustup_toolchain" fuzz build "$target"
  ) >"${logs_dir}/fuzz-build-${target}.stdout.log" \
    2>"${logs_dir}/fuzz-build-${target}.stderr.log"
done

run_coverage_group() {
  local group="$1"
  local target_path="$2"
  local target
  target="$(toml_get "$target_path")"
  local index=0
  while IFS= read -r seed; do
    index=$((index + 1))
    local campaign_id
    campaign_id="$(printf '%s-%03d' "$group" "$index")"
    local campaign_dir="${records_root}/${group}/campaigns/${campaign_id}"
    local artifact_dir="${campaign_dir}/artifacts"
    local campaign_corpus="${campaign_dir}/corpus"
    local counters_path="${campaign_dir}/counters.json"
    mkdir -p "$artifact_dir" "${campaign_dir}/logs"
    if [[ -d "$campaign_corpus" ]] && [[ -n "$(find "$campaign_corpus" -mindepth 1 -print -quit)" ]]; then
      echo "run-d2-small: refusing to reuse existing campaign corpus at ${campaign_corpus}" >&2
      echo "run-d2-small: choose a fresh records root for an auditable D2 run" >&2
      exit 1
    fi
    mkdir -p "$campaign_corpus"
    cp -R "$input_corpus/." "$campaign_corpus/"
    local started_ms
    started_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"
    set +e
    (
      cd "$shared_dir"
      BW_D1_COUNTERS_PATH="$counters_path" cargo +"$rustup_toolchain" fuzz run "$target" "$campaign_corpus" -- \
        -max_total_time="$seconds" \
        -seed="$seed" \
        -artifact_prefix="${artifact_dir}/" \
        -print_final_stats=1
    ) >"${campaign_dir}/logs/fuzz.stdout.log" 2>"${campaign_dir}/logs/fuzz.stderr.log"
    local status=$?
    set -e
    local ended_ms
    ended_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"

    if [[ ! -s "$counters_path" ]]; then
      python3 - "$counters_path" <<'PY'
import json
import sys

with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump({
        "schema_version": "boundary-witness.d1-fuzz-counters/0.1",
        "executions": 0,
        "valid_sequence_count": 0,
        "invalid_sequence_count": 0,
        "progress_count": 0,
        "secondary_count": 0,
        "primary_count": 0,
        "tool_error_count": 0,
        "time_to_first_primary_ms": None,
        "feedback_snapshot_coverage_count": 0,
    }, f, indent=2, sort_keys=True)
    f.write("\n")
PY
    fi

    "$d1_bin" d2-coverage-record \
      "$config" \
      "$group" \
      "$records_root" \
      "$index" \
      "$seed" \
      "$counters_path" \
      "$artifact_dir" \
      "$status" \
      "$((ended_ms - started_ms))" \
      >"${campaign_dir}/logs/d2-coverage-record.stdout.log" \
      2>"${campaign_dir}/logs/d2-coverage-record.stderr.log"
  done < <(toml_get shared_budget.seed_list)
}

run_coverage_group coverage_only coverage_only.target
run_coverage_group coverage_state coverage_state.target

run_compare | tee "${run_root}/d2-comparison-summary.json"

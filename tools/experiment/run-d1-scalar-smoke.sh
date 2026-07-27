#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: run-d1-scalar-smoke.sh --repo-root <source-dir> --runs-root <runs-dir> --commit <git-commit> --deployment-sha256 <sha256> [options]

Options:
  --image-digest <digest>        Image/environment digest recorded in manifest. Default: native-linux
  --rustup-toolchain <toolchain> Nightly toolchain for cargo-fuzz. Default: nightly-2026-07-08
  --campaigns <n>               Number of scalar smoke campaigns. Default: 3
  --cpu-minutes <n>             Per-campaign max_total_time in minutes. Default: 5
EOF
}

fail() {
  printf 'run-d1-scalar-smoke: %s\n' "$*" >&2
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

repo_root=""
runs_root=""
commit=""
deployment_sha256=""
image_digest="native-linux"
rustup_toolchain="nightly-2026-07-08"
campaigns="3"
cpu_minutes="5"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root)
      [[ $# -ge 2 ]] || fail "--repo-root requires a value"
      repo_root="$2"
      shift 2
      ;;
    --runs-root)
      [[ $# -ge 2 ]] || fail "--runs-root requires a value"
      runs_root="$2"
      shift 2
      ;;
    --commit)
      [[ $# -ge 2 ]] || fail "--commit requires a value"
      commit="$2"
      shift 2
      ;;
    --deployment-sha256)
      [[ $# -ge 2 ]] || fail "--deployment-sha256 requires a value"
      deployment_sha256="$2"
      shift 2
      ;;
    --image-digest)
      [[ $# -ge 2 ]] || fail "--image-digest requires a value"
      image_digest="$2"
      shift 2
      ;;
    --rustup-toolchain)
      [[ $# -ge 2 ]] || fail "--rustup-toolchain requires a value"
      rustup_toolchain="$2"
      shift 2
      ;;
    --campaigns)
      [[ $# -ge 2 ]] || fail "--campaigns requires a value"
      campaigns="$2"
      shift 2
      ;;
    --cpu-minutes)
      [[ $# -ge 2 ]] || fail "--cpu-minutes requires a value"
      cpu_minutes="$2"
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

[[ -n "$repo_root" ]] || fail "--repo-root is required"
[[ -n "$runs_root" ]] || fail "--runs-root is required"
[[ -n "$commit" ]] || fail "--commit is required"
[[ -n "$deployment_sha256" ]] || fail "--deployment-sha256 is required"
[[ "$campaigns" =~ ^[0-9]+$ && "$campaigns" -gt 0 ]] || fail "--campaigns must be a positive integer"
[[ "$cpu_minutes" =~ ^[0-9]+$ && "$cpu_minutes" -gt 0 ]] || fail "--cpu-minutes must be a positive integer"
[[ -d "$repo_root" ]] || fail "repo root not found: $repo_root"

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v hostname >/dev/null 2>&1 || fail "hostname is required"

repo_root="$(cd "$repo_root" && pwd -P)"
runs_root="$(mkdir -p "$runs_root" && cd "$runs_root" && pwd -P)"
config_path="${repo_root}/experiments/configs/d1-campaigns.toml"
corpus_jsonl="${repo_root}/experiments/corpus/d1/scalar-function/safe-fragments.jsonl"
shared_dir="${repo_root}/benchmarks/historical-cves/rusqlite/shared"
config_digest="$(sha256_file "$config_path")"
run_id="unix$(date +%s)-${commit:0:7}-d1scalar"
partial_run="${runs_root}/${run_id}.partial"
final_run="${runs_root}/${run_id}"

[[ ! -e "$partial_run" && ! -e "$final_run" ]] || fail "run already exists: $run_id"
mkdir -p "$partial_run"/{input,artifacts,logs,traces}
touch "${partial_run}/findings.jsonl"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
stable_toolchain="$(rustc --version)"
host="$(hostname)"
build_id="build:d1:scalar-smoke"

RUN_ID="$run_id" \
COMMIT="$commit" \
DEPLOYMENT_SHA256="$deployment_sha256" \
IMAGE_DIGEST="$image_digest" \
CONFIG_DIGEST="$config_digest" \
HOST="$host" \
STABLE_TOOLCHAIN="$stable_toolchain" \
NIGHTLY_TOOLCHAIN="$rustup_toolchain" \
STARTED_AT="$started_at" \
BUILD_ID="$build_id" \
python3 - "${partial_run}/manifest.json" <<'PY'
import json
import os
import sys

manifest = {
    "schema_version": "bw.run/0.1",
    "run_id": os.environ["RUN_ID"],
    "build_id": os.environ["BUILD_ID"],
    "git_commit": os.environ["COMMIT"],
    "deployment_sha256": os.environ["DEPLOYMENT_SHA256"],
    "image_digest": os.environ["IMAGE_DIGEST"],
    "config_digest": os.environ["CONFIG_DIGEST"],
    "host": os.environ["HOST"],
    "cpu_limit": 1,
    "seed": None,
    "toolchains": {
        "stable": os.environ["STABLE_TOOLCHAIN"],
        "compiler_nightly": os.environ["NIGHTLY_TOOLCHAIN"],
    },
    "started_at_utc": os.environ["STARTED_AT"],
    "completed_at_utc": None,
    "execution": {
        "kind": "d1_scalar_smoke",
        "api": "create_scalar_function",
        "container_status": "deferred_native_linux",
    },
}

with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
PY

cargo build --manifest-path "${shared_dir}/Cargo.toml" --bin bw-rusqlite-d1 --locked \
  >"${partial_run}/logs/build-d1-cli.stdout.log" \
  2>"${partial_run}/logs/build-d1-cli.stderr.log"

d1_bin="${shared_dir}/target/debug/bw-rusqlite-d1"
"$d1_bin" materialize-corpus "$corpus_jsonl" "${partial_run}/input/scalar-function-corpus" \
  >"${partial_run}/logs/materialize-corpus.stdout.log" \
  2>"${partial_run}/logs/materialize-corpus.stderr.log"

(
  cd "$shared_dir"
  cargo +"$rustup_toolchain" fuzz build scalar_function_actions
) >"${partial_run}/logs/fuzz-build-scalar.stdout.log" \
  2>"${partial_run}/logs/fuzz-build-scalar.stderr.log"

seconds=$((cpu_minutes * 60))
records_jsonl="${partial_run}/artifacts/campaign-records.jsonl"
touch "$records_jsonl"

for index in $(seq 1 "$campaigns"); do
  campaign_id="$(printf 'd1-scalar-smoke-%03d' "$index")"
  seed=$((4000 + index))
  campaign_dir="${partial_run}/artifacts/${campaign_id}"
  mkdir -p "${campaign_dir}/artifacts" "${campaign_dir}/logs"
  counters_path="${campaign_dir}/counters.json"
  started_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"
  set +e
  (
    cd "$shared_dir"
    BW_D1_COUNTERS_PATH="$counters_path" cargo +"$rustup_toolchain" fuzz run scalar_function_actions "${partial_run}/input/scalar-function-corpus" -- \
      -max_total_time="$seconds" \
      -seed="$seed" \
      -artifact_prefix="${campaign_dir}/artifacts/" \
      -print_final_stats=1
  ) >"${campaign_dir}/logs/fuzz.stdout.log" 2>"${campaign_dir}/logs/fuzz.stderr.log"
  status=$?
  set -e
  ended_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"
  artifact_path="$(find "${campaign_dir}/artifacts" -type f -print -quit)"
  outcome="no_primary"
  replay_success=""
  minimized_len=""
  digest=""
  primary_rule_id=""
  normalized_signature=""
  has_register="false"
  has_owner_end="false"
  has_later_trigger="false"
  if [[ -n "$artifact_path" ]]; then
    outcome="primary_found"
    digest="$(sha256_file "$artifact_path")"
    "$d1_bin" decode "$artifact_path" "${campaign_dir}/decoded-actions.json"
    "$d1_bin" minimize --api create_scalar_function "${campaign_dir}/decoded-actions.json" "${campaign_dir}/minimized.json"
    "$d1_bin" replay --api create_scalar_function "${campaign_dir}/minimized.json" "${campaign_dir}/replay-summary.json" --repeat 20
    read -r replay_success minimized_len primary_rule_id normalized_signature has_register has_owner_end has_later_trigger < <(
      python3 - "${campaign_dir}/minimized.json" "${campaign_dir}/replay-summary.json" <<'PY'
import json
import sys
minimized = json.load(open(sys.argv[1], encoding="utf-8"))
replay = json.load(open(sys.argv[2], encoding="utf-8"))
stages = minimized["witness_stages"]
print(
    replay["success_count"],
    len(minimized["sequence"]["actions"]),
    minimized["classification"].get("primary_rule_id") or "",
    minimized["classification"].get("normalized_signature") or "",
    str(bool(stages.get("has_register"))).lower(),
    str(bool(stages.get("has_owner_end"))).lower(),
    str(bool(stages.get("has_later_trigger"))).lower(),
)
PY
    )
  elif [[ "$status" -ne 0 ]]; then
    outcome="tool_error"
  fi

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
    }, f, indent=2, sort_keys=True)
    f.write("\n")
PY
  fi

  CAMPAIGN_ID="$campaign_id" \
  SEED="$seed" \
  CPU_MINUTES="$cpu_minutes" \
  OUTCOME="$outcome" \
  STATUS="$status" \
  STARTED_MS="$started_ms" \
  ENDED_MS="$ended_ms" \
  ARTIFACT_DIGEST="$digest" \
  REPLAY_SUCCESS="$replay_success" \
  MINIMIZED_LEN="$minimized_len" \
  PRIMARY_RULE="$primary_rule_id" \
  NORMALIZED_SIGNATURE="$normalized_signature" \
  HAS_REGISTER="$has_register" \
  HAS_OWNER_END="$has_owner_end" \
  HAS_LATER_TRIGGER="$has_later_trigger" \
  COUNTERS_PATH="$counters_path" \
  python3 - "$records_jsonl" <<'PY'
import json
import os
import sys
with open(os.environ["COUNTERS_PATH"], encoding="utf-8") as f:
    counters = json.load(f)
time_to_first = counters.get("time_to_first_primary_ms")
if time_to_first is None and os.environ["OUTCOME"] == "primary_found":
    time_to_first = int(os.environ["ENDED_MS"]) - int(os.environ["STARTED_MS"])
primary_count = int(counters.get("primary_count", 0))
if os.environ["OUTCOME"] == "primary_found" and primary_count == 0:
    primary_count = 1
record = {
    "campaign_id": os.environ["CAMPAIGN_ID"],
    "api": "create_scalar_function",
    "target": "scalar_function_actions",
    "seed": int(os.environ["SEED"]),
    "cpu_minutes": int(os.environ["CPU_MINUTES"]),
    "outcome": os.environ["OUTCOME"],
    "exit_status": int(os.environ["STATUS"]),
    "elapsed_ms": int(os.environ["ENDED_MS"]) - int(os.environ["STARTED_MS"]),
    "executions": int(counters.get("executions", 0)),
    "valid_sequence_count": int(counters.get("valid_sequence_count", 0)),
    "invalid_sequence_count": int(counters.get("invalid_sequence_count", 0)),
    "progress_count": int(counters.get("progress_count", 0)),
    "secondary_count": int(counters.get("secondary_count", 0)),
    "primary_count": primary_count,
    "time_to_first_primary_ms": time_to_first,
    "representative_artifact_digest": os.environ["ARTIFACT_DIGEST"] or None,
    "primary_rule_id": os.environ["PRIMARY_RULE"] or None,
    "normalized_signature": os.environ["NORMALIZED_SIGNATURE"] or None,
    "replay_success_count": int(os.environ["REPLAY_SUCCESS"]) if os.environ["REPLAY_SUCCESS"] else None,
    "minimized_len": int(os.environ["MINIMIZED_LEN"]) if os.environ["MINIMIZED_LEN"] else None,
    "witness_stages": {
        "has_register": os.environ["HAS_REGISTER"] == "true",
        "has_owner_end": os.environ["HAS_OWNER_END"] == "true",
        "has_later_trigger": os.environ["HAS_LATER_TRIGGER"] == "true",
    },
}
with open(sys.argv[1], "a", encoding="utf-8") as f:
    f.write(json.dumps(record, sort_keys=True) + "\n")
PY
done

completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMPLETED_AT="$completed_at" \
python3 - "${partial_run}/manifest.json" "${partial_run}/summary.json" "$records_jsonl" <<'PY'
import json
import os
import sys
manifest_path, summary_path, records_path = sys.argv[1:4]
with open(manifest_path, "r", encoding="utf-8") as f:
    manifest = json.load(f)
manifest["completed_at_utc"] = os.environ["COMPLETED_AT"]
with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
records = []
with open(records_path, "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            records.append(json.loads(line))
summary = {
    "schema_version": "boundary-witness.d1-scalar-smoke-summary/0.1",
    "campaigns": records,
    "campaign_count": len(records),
    "primary_found_campaigns": sum(1 for record in records if record["outcome"] == "primary_found"),
    "tool_error_campaigns": sum(1 for record in records if record["outcome"] == "tool_error"),
    "executions": sum(record["executions"] for record in records),
    "valid_sequence_count": sum(record["valid_sequence_count"] for record in records),
    "invalid_sequence_count": sum(record["invalid_sequence_count"] for record in records),
    "progress_count": sum(record["progress_count"] for record in records),
    "secondary_count": sum(record["secondary_count"] for record in records),
    "primary_count": sum(record["primary_count"] for record in records),
}
with open(summary_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, sort_keys=True)
    f.write("\n")
PY

printf '%s\n' "$completed_at" > "${partial_run}/COMPLETE"

(
  cd "$partial_run"
  find . -type f ! -name checksums.sha256 -print | sed 's#^\./##' | sort | while IFS= read -r path; do
    digest="$(sha256_file "$path")"
    printf '%s  %s\n' "$digest" "$path"
  done > checksums.sha256
)

mv "$partial_run" "$final_run"
printf '{"status":"ok","run_id":"%s","path":"%s"}\n' "$run_id" "$final_run"

#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: run-scan.sh --manifest <corpus-manifest.jsonl> [options]

Runs the V3.2.x core-effect scan over every crate in a corpus manifest and
writes one finalized run directory. Each stage is a `bw` subcommand; the stage
output paths are read back from each stage's stdout JSON rather than hardcoded.

The manifest must use source_kind local_archive or registry_snapshot: the
scanner never downloads sources. Use materialize-corpus.sh to turn a crates.io
selection into such a manifest.

Options:
  --run-id <id>            Run identity. Default: scan-<utc-timestamp>
  --runs-root <dir>        Run output root. Default: $BW_RUNS_ROOT, else <repo-root>/runs
  --repo-root <dir>        Repository root. Default: the repository containing this script
  --bw <path>              bw binary. Default: cargo run -p bw-cli --bin bw --locked --
  --rustc-wrapper <path>   bw-rustc wrapper for static fact extraction. Required unless --skip-static-facts
  --contract <path>        Lifecycle contract TOML. Default: contracts/callback-retention/contract.toml
  --api-map <path>         API map TOML; repeatable. Default: every *-api-map.toml next to the contract
  --component-id <id>      Contract component id. Default: callback-retention
  --records-per-part <n>   Candidate partition size. Default: 1000
  --witness-limit <n>      Witness plans to emit. Default: 10
  --toolchain <name>       Toolchain the rustc wrapper links against. Default: nightly-2026-07-08
  --cargo-locked           Pass --locked to the cargo stages. Off by default
  --skip-static-facts      Skip MIR extraction; downstream stages run without static facts
  --keep-partial           Keep the .partial directory when a stage fails

--cargo-locked is off by default because published .crate archives carry no
Cargo.lock for library targets, so --locked makes every materialized crates.io
crate fail the precheck. Leaving it off lets cargo resolve dependencies, which
means the resolved versions are not pinned by the corpus manifest hash alone;
scan-summary.json records which mode was used, and runs are only comparable
within the same mode. Use --cargo-locked for a corpus whose trees ship lockfiles.

A failing stage stops the run: later stages consume its artifacts. The failure
is recorded in scan-summary.json with stage name, exit code and log reference,
and the run is classified orchestration_blocked. Per-crate failures are not
stage failures; build-precheck and extract-static-facts classify those into
their own status records, which build-failure-taxonomy then aggregates.
EOF
}

fail() {
  printf 'run-scan: %s\n' "$*" >&2
  exit 1
}

note() {
  printf 'run-scan: %s\n' "$*" >&2
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

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${script_dir}/../.." && pwd -P)"

manifest=""
run_id=""
runs_root=""
bw_bin=""
rustc_wrapper=""
contract=""
component_id="callback-retention"
records_per_part="1000"
witness_limit="10"
skip_static_facts="false"
keep_partial="false"
cargo_locked="false"
toolchain="nightly-2026-07-08"
api_maps=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      [[ $# -ge 2 ]] || fail "--manifest requires a value"
      manifest="$2"; shift 2 ;;
    --run-id)
      [[ $# -ge 2 ]] || fail "--run-id requires a value"
      run_id="$2"; shift 2 ;;
    --runs-root)
      [[ $# -ge 2 ]] || fail "--runs-root requires a value"
      runs_root="$2"; shift 2 ;;
    --repo-root)
      [[ $# -ge 2 ]] || fail "--repo-root requires a value"
      repo_root="$(cd "$2" && pwd -P)"; shift 2 ;;
    --bw)
      [[ $# -ge 2 ]] || fail "--bw requires a value"
      bw_bin="$2"; shift 2 ;;
    --rustc-wrapper)
      [[ $# -ge 2 ]] || fail "--rustc-wrapper requires a value"
      rustc_wrapper="$2"; shift 2 ;;
    --contract)
      [[ $# -ge 2 ]] || fail "--contract requires a value"
      contract="$2"; shift 2 ;;
    --api-map)
      [[ $# -ge 2 ]] || fail "--api-map requires a value"
      api_maps+=("$2"); shift 2 ;;
    --component-id)
      [[ $# -ge 2 ]] || fail "--component-id requires a value"
      component_id="$2"; shift 2 ;;
    --records-per-part)
      [[ $# -ge 2 ]] || fail "--records-per-part requires a value"
      records_per_part="$2"; shift 2 ;;
    --witness-limit)
      [[ $# -ge 2 ]] || fail "--witness-limit requires a value"
      witness_limit="$2"; shift 2 ;;
    --toolchain)
      [[ $# -ge 2 ]] || fail "--toolchain requires a value"
      toolchain="$2"; shift 2 ;;
    --cargo-locked)
      cargo_locked="true"; shift ;;
    --skip-static-facts)
      skip_static_facts="true"; shift ;;
    --keep-partial)
      keep_partial="true"; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      fail "unknown argument: $1" ;;
  esac
done

[[ -n "$manifest" ]] || { usage; fail "--manifest is required"; }
[[ -f "$manifest" ]] || fail "manifest not found: $manifest"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

manifest="$(cd "$(dirname "$manifest")" && pwd -P)/$(basename "$manifest")"

if [[ -z "$contract" ]]; then
  contract="${repo_root}/contracts/callback-retention/contract.toml"
fi
[[ -f "$contract" ]] || fail "contract not found: $contract"

if [[ ${#api_maps[@]} -eq 0 ]]; then
  while IFS= read -r found; do
    api_maps+=("$found")
  done < <(find "$(dirname "$contract")" -maxdepth 1 -name '*-api-map.toml' | sort)
fi
[[ ${#api_maps[@]} -gt 0 ]] || fail "no API map TOML found next to $contract"

if [[ "$skip_static_facts" != "true" && -z "$rustc_wrapper" ]]; then
  fail "--rustc-wrapper is required unless --skip-static-facts is given"
fi

# The wrapper is a rustc_private binary. Without its toolchain's lib directory on
# the loader path it cannot start at all, and the stage reports only exit 127.
toolchain_lib=""
if [[ "$skip_static_facts" != "true" ]]; then
  toolchain_lib="$(rustc "+${toolchain}" --print sysroot 2>/dev/null)/lib"
  [[ -d "$toolchain_lib" ]] || fail "toolchain ${toolchain} is not installed: ${toolchain_lib}"
fi

if [[ -z "$run_id" ]]; then
  run_id="scan-$(date -u +%Y%m%dT%H%M%SZ)"
fi
[[ "$run_id" =~ ^[A-Za-z0-9._-]+$ ]] || fail "run id must be [A-Za-z0-9._-]+: $run_id"

if [[ -z "$runs_root" ]]; then
  runs_root="${BW_RUNS_ROOT:-${repo_root}/runs}"
fi
mkdir -p "$runs_root"
runs_root="$(cd "$runs_root" && pwd -P)"

partial_run="${runs_root}/${run_id}.partial"
final_run="${runs_root}/${run_id}"
[[ ! -e "$final_run" ]] || fail "run already exists and must not be overwritten: $final_run"
[[ ! -e "$partial_run" ]] || fail "partial run already exists: $partial_run"

mkdir -p "$partial_run"/{stages,logs}

# `bw` may be a built binary or a cargo invocation; keep it as a word array.
if [[ -n "$bw_bin" ]]; then
  bw_cmd=("$bw_bin")
else
  bw_cmd=(cargo run --quiet --manifest-path "${repo_root}/Cargo.toml" -p bw-cli --bin bw --locked --)
fi

stage_index=0
stage_status_file="${partial_run}/stages/status.jsonl"
: > "$stage_status_file"
run_status="ok"
failed_stage=""

# Runs one `bw` stage, stores its stdout JSON under stages/, and records status.
# Returns non-zero when the stage fails so the caller can stop the run.
run_stage() {
  local name="$1"; shift
  stage_index=$((stage_index + 1))
  local label
  label="$(printf '%02d-%s' "$stage_index" "$name")"
  local out_file="${partial_run}/stages/${label}.json"
  local err_file="${partial_run}/logs/${label}.stderr"
  local exit_code=0

  note "stage ${label}"
  # Only the static-fact stage spawns the wrapper; scoping the loader path to it
  # keeps the other stages running against the toolchain they were built with.
  local -a stage_env=()
  if [[ "$name" == "extract-static-facts" && -n "$toolchain_lib" ]]; then
    # RUSTUP_TOOLCHAIN makes cargo build the crate and its path dependencies with
    # the same toolchain the wrapper links against. Without it a crate that depends
    # on this repository fails with E0514: its deps come from the default stable
    # toolchain while the wrapper compiles the crate itself as nightly.
    stage_env=(
      env
      "LD_LIBRARY_PATH=${toolchain_lib}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
      "RUSTUP_TOOLCHAIN=${toolchain}"
    )
  fi
  if "${stage_env[@]}" "${bw_cmd[@]}" "$name" "$@" > "$out_file" 2> "$err_file"; then
    exit_code=0
  else
    exit_code=$?
  fi

  python3 - "$stage_status_file" "$label" "$name" "$exit_code" "$out_file" "$err_file" <<'PY'
import json, pathlib, sys
status_path, label, name, exit_code, out_file, err_file = sys.argv[1:7]
summary = None
text = pathlib.Path(out_file).read_text(encoding="utf-8").strip()
if text:
    try:
        summary = json.loads(text.splitlines()[-1])
    except json.JSONDecodeError:
        summary = None
record = {
    "stage": label,
    "command": name,
    "exit_code": int(exit_code),
    "status": "ok" if int(exit_code) == 0 else "failed",
    "stdout_ref": f"stages/{label}.json",
    "stderr_ref": f"logs/{label}.stderr",
    "summary": summary,
}
with open(status_path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True) + "\n")
PY

  if [[ "$exit_code" -ne 0 ]]; then
    run_status="orchestration_blocked"
    failed_stage="$label"
    note "stage ${label} failed with exit ${exit_code}; see logs/${label}.stderr"
    return 1
  fi
  return 0
}

# Reads a path field out of a finished stage's stdout JSON.
stage_path() {
  local label="$1" field="$2"
  jq -er ".${field}" "${partial_run}/stages/${label}.json" \
    || fail "stage ${label} did not report ${field}"
}

contracts_dir="${partial_run}/contracts"
static_dir="${partial_run}/static"
candidates_dir="${partial_run}/candidates"
evidence_dir="${partial_run}/evidence"
analysis_dir="${partial_run}/analysis"
legacy_dir="${partial_run}/legacy-ranking"
effort_dir="${partial_run}/adapter-effort"
taxonomy_dir="${partial_run}/taxonomy"
witness_dir="${partial_run}/witness"
buildability_path="${partial_run}/buildability.jsonl.zst"
boundary_index_path="${partial_run}/boundary-index.jsonl.zst"

locked_arg=()
if [[ "$cargo_locked" == "true" ]]; then
  locked_arg=(--locked)
fi

api_map_args=()
api_map_scan_args=()
for map in "${api_maps[@]}"; do
  api_map_args+=(--api-map-toml "$map")
  api_map_scan_args+=(--api-map "$map")
done

scan() {
  run_stage materialize-lifecycle-contracts \
    --contract-toml "$contract" \
    "${api_map_args[@]}" \
    --component-id "$component_id" \
    --run-id "$run_id" \
    --output-dir "$contracts_dir" || return 1

  run_stage audit-lifecycle-contracts \
    --contracts "${contracts_dir}/lifecycle-contracts.jsonl" \
    --registry-manifest "${contracts_dir}/registry-manifest.json" \
    --run-id "$run_id" \
    --output-dir "${partial_run}/contract-audit" || return 1

  run_stage build-precheck \
    --manifest "$manifest" \
    --output "$buildability_path" \
    --logs-root "${partial_run}/logs" \
    --run-id "$run_id" \
    "${locked_arg[@]}" || return 1

  local static_facts_arg=() mir_coverage_arg=()
  if [[ "$skip_static_facts" != "true" ]]; then
    run_stage extract-static-facts \
      --manifest "$manifest" \
      --output-dir "$static_dir" \
      --logs-root "${partial_run}/logs" \
      --run-id "$run_id" \
      --rustc-wrapper "$rustc_wrapper" \
      "${locked_arg[@]}" || return 1
    static_facts_arg=(--static-facts "${static_dir}/static-facts.jsonl")
    mir_coverage_arg=(--mir-coverage "${static_dir}/mir-coverage.json")
  fi

  # 同一份 API map 同时喂给 boundary 扫描与 compiler，两侧对"什么算注册"保持一致。
  run_stage index-boundaries \
    --manifest "$manifest" \
    --buildability "$buildability_path" \
    "${api_map_scan_args[@]}" \
    --output "$boundary_index_path" \
    --logs-root "${partial_run}/logs" \
    --run-id "$run_id" || return 1

  run_stage emit-candidates \
    --boundary-index "$boundary_index_path" \
    "${static_facts_arg[@]}" \
    --output-dir "$candidates_dir" \
    --records-per-part "$records_per_part" \
    --run-id "$run_id" || return 1

  run_stage extract-lifecycle-evidence \
    --manifest "$manifest" \
    --boundary-index "$boundary_index_path" \
    --candidates "$candidates_dir" \
    "${static_facts_arg[@]}" \
    "${mir_coverage_arg[@]}" \
    --output-dir "$evidence_dir" \
    --run-id "$run_id" || return 1

  # graph-v3 and rank-lifecycle-v2 must share an output directory: --graph-dir is
  # a relative name resolved under rank's own --output-dir, not a path.
  run_stage build-lifecycle-graph-v3 \
    --candidates "$candidates_dir" \
    --evidence "${evidence_dir}/lifecycle-evidence.jsonl.zst" \
    --facts "${evidence_dir}/lifecycle-facts.jsonl.zst" \
    "${static_facts_arg[@]}" \
    --contracts "${contracts_dir}/lifecycle-contracts.jsonl" \
    --registry-manifest "${contracts_dir}/registry-manifest.json" \
    --output-dir "$analysis_dir" \
    --run-id "$run_id" || return 1

  run_stage rank-lifecycle-v2 \
    --features "${analysis_dir}/lifecycle-features.jsonl.zst" \
    --graph-dir graphs-v3 \
    --output-dir "$analysis_dir" \
    --run-id "$run_id" || return 1

  # adapter effort 与 failure taxonomy 属于 V3.2 pilot 计量链，消费的是 legacy
  # ranked candidate schema；核心效果链走 graph-v3 + rank-lifecycle-v2。两者并存，
  # 不能把 v2 输出喂给 legacy 消费者。
  run_stage rank-lifecycle \
    --candidates "$candidates_dir" \
    --output-dir "$legacy_dir" \
    --run-id "$run_id" || return 1

  run_stage account-adapter-effort \
    --ranked-candidates "$legacy_dir" \
    --output-dir "$effort_dir" \
    --run-id "$run_id" || return 1

  run_stage build-failure-taxonomy \
    --buildability "$buildability_path" \
    --boundary-index "$boundary_index_path" \
    --adapter-effort "${effort_dir}/adapter-effort.jsonl.zst" \
    --output-dir "$taxonomy_dir" \
    --run-id "$run_id" || return 1

  # --facts 决定 plan 能否带上可执行 target：api_id 只存在于事实里，ranked candidate
  # 与 graph 都不携带它。缺少它时 plan 退化成人工待办清单。
  # resolved-dependencies 让 plan 的 target 带上"声明该 API 的 crate"的版本。缺了它
  # plan 仍然绑定 API，只是不可自动执行——所以跳过静态事实时这里也不该硬失败。
  local resolved_dependencies_arg=()
  if [[ -f "${static_dir}/resolved-dependencies.jsonl" ]]; then
    resolved_dependencies_arg=(--resolved-dependencies "${static_dir}/resolved-dependencies.jsonl")
  fi

  run_stage build-witness-plan \
    --ranked-candidates "${analysis_dir}/ranked-candidates.jsonl.zst" \
    --graphs-dir "${analysis_dir}/graphs-v3" \
    --facts "${evidence_dir}/lifecycle-facts.jsonl.zst" \
    "${api_map_scan_args[@]}" \
    "${resolved_dependencies_arg[@]}" \
    --limit "$witness_limit" \
    --output-dir "$witness_dir" \
    --run-id "$run_id" || return 1

  return 0
}

scan || true

# Run identity. Only the fields this orchestrator can establish itself are
# written; dataset_version and any freeze identity stay the caller's job.
code_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf 'unknown')"
worktree_clean="true"
if [[ -n "$(git -C "$repo_root" status --porcelain 2>/dev/null)" ]]; then
  worktree_clean="false"
fi
contract_hash="$(sha256_file "$contract")"
manifest_hash="$(sha256_file "$manifest")"
toolchain="$(rustc --version 2>/dev/null || printf 'unknown')"

python3 - \
  "${partial_run}/scan-summary.json" \
  "$run_id" "$run_status" "$failed_stage" "$stage_status_file" \
  "$code_commit" "$worktree_clean" "$contract_hash" "$manifest_hash" "$toolchain" \
  "$manifest" "$skip_static_facts" "$cargo_locked" <<'PY'
import json, pathlib, sys

(summary_path, run_id, run_status, failed_stage, status_path, code_commit,
 worktree_clean, contract_hash, manifest_hash, toolchain, manifest,
 skip_static_facts, cargo_locked) = sys.argv[1:14]

stages = []
for line in pathlib.Path(status_path).read_text(encoding="utf-8").splitlines():
    if line.strip():
        stages.append(json.loads(line))

def stage_summary(command):
    for stage in stages:
        if stage["command"] == command and stage["status"] == "ok":
            return stage.get("summary") or {}
    return {}

precheck = stage_summary("build-precheck")
ranked = stage_summary("rank-lifecycle-v2")
candidates = stage_summary("emit-candidates")

summary = {
    "schema_version": "boundary-witness.scan-summary/0.1",
    "run_id": run_id,
    "status": run_status,
    "failed_stage": failed_stage or None,
    "run_identity": {
        "code_commit": code_commit,
        "worktree_clean": worktree_clean == "true",
        "toolchain": toolchain,
        "contract_hash": contract_hash,
        "corpus_manifest_hash": manifest_hash,
        "corpus_manifest_ref": pathlib.Path(manifest).name,
        "static_facts_extracted": skip_static_facts != "true",
        "cargo_locked": cargo_locked == "true",
    },
    "counts": {
        "crates_prechecked": precheck.get("record_count"),
        "crates_buildable": precheck.get("buildable_count"),
        "crates_build_failed": precheck.get("failed_count"),
        "candidates_emitted": candidates.get("candidate_count"),
        "ranked_candidates": ranked.get("ranked_count"),
        "max_score": ranked.get("max_score"),
    },
    "stages": stages,
}
pathlib.Path(summary_path).write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

if [[ "$run_status" != "ok" ]]; then
  if [[ "$keep_partial" == "true" ]]; then
    note "run incomplete; partial run kept at ${partial_run}"
  else
    note "run incomplete at stage ${failed_stage}; partial run at ${partial_run}"
  fi
  jq -c '{run_id, status, failed_stage}' "${partial_run}/scan-summary.json"
  exit 1
fi

mv "$partial_run" "$final_run"
jq -c '{run_id, status, counts}' "${final_run}/scan-summary.json"
note "finalized run at ${final_run}"

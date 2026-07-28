#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: run-witness.sh --scan-run <finalized-scan-run-dir> [options]

Runs the dynamic half of a detection: takes the witness plans a scan produced,
generates a harness per bound plan, builds and executes it, extracts the
harness's own static facts, bridges the runtime site ids into them, and lets the
oracle decide. Writes one witness run directory with per-plan findings.

Options:
  --run-id <id>            Witness run identity. Default: witness-<utc-timestamp>
  --runs-root <dir>        Output root. Default: $BW_RUNS_ROOT, else <repo-root>/runs
  --repo-root <dir>        Repository root. Default: the repository holding this script
  --bw <path>              bw binary. Default: cargo run -p bw-cli --bin bw --locked --
  --rustc-wrapper <path>   bw-rustc wrapper. Required.
  --toolchain <name>       Toolchain for harness builds. Default: nightly-2026-07-08
  --timeout-seconds <n>    Per-harness execution timeout. Default: 120
  --keep-partial           Keep the .partial directory on failure

A harness must be built with the same toolchain the wrapper links against.
Harnesses carry path dependencies on this repository, so building them with the
default stable toolchain while the wrapper is nightly-linked fails with E0514.

Findings are not defect conclusions. The harness template reproduces a
callback-retention lifecycle by construction, so a violation reported here
confirms that the pipeline observed the sequence it set out to observe. Treating
it as a finding about the scanned crate requires a harness derived from that
crate's own shape, which this generator does not yet produce.
EOF
}

fail() { printf 'run-witness: %s\n' "$*" >&2; exit 1; }
note() { printf 'run-witness: %s\n' "$*" >&2; }

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${script_dir}/../.." && pwd -P)"

scan_run=""
run_id=""
runs_root=""
bw_bin=""
rustc_wrapper=""
toolchain="nightly-2026-07-08"
timeout_seconds="120"
keep_partial="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scan-run) [[ $# -ge 2 ]] || fail "--scan-run requires a value"; scan_run="$2"; shift 2 ;;
    --run-id) [[ $# -ge 2 ]] || fail "--run-id requires a value"; run_id="$2"; shift 2 ;;
    --runs-root) [[ $# -ge 2 ]] || fail "--runs-root requires a value"; runs_root="$2"; shift 2 ;;
    --repo-root) [[ $# -ge 2 ]] || fail "--repo-root requires a value"; repo_root="$(cd "$2" && pwd -P)"; shift 2 ;;
    --bw) [[ $# -ge 2 ]] || fail "--bw requires a value"; bw_bin="$2"; shift 2 ;;
    --rustc-wrapper) [[ $# -ge 2 ]] || fail "--rustc-wrapper requires a value"; rustc_wrapper="$2"; shift 2 ;;
    --toolchain) [[ $# -ge 2 ]] || fail "--toolchain requires a value"; toolchain="$2"; shift 2 ;;
    --timeout-seconds) [[ $# -ge 2 ]] || fail "--timeout-seconds requires a value"; timeout_seconds="$2"; shift 2 ;;
    --keep-partial) keep_partial="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "$scan_run" ]] || { usage; fail "--scan-run is required"; }
[[ -d "$scan_run" ]] || fail "scan run not found: $scan_run"
[[ -n "$rustc_wrapper" ]] || fail "--rustc-wrapper is required"
[[ -x "$rustc_wrapper" ]] || fail "rustc wrapper is not executable: $rustc_wrapper"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"

scan_run="$(cd "$scan_run" && pwd -P)"
plans="${scan_run}/witness/witness-plans.jsonl.zst"
[[ -f "$plans" ]] || fail "scan run has no witness plans: $plans"

# The wrapper is a rustc_private binary; without its toolchain's lib directory on
# the loader path it cannot start, and cargo reports a bare exit 127.
toolchain_lib="$(rustc "+${toolchain}" --print sysroot 2>/dev/null)/lib"
[[ -d "$toolchain_lib" ]] || fail "toolchain ${toolchain} is not installed"

[[ -n "$run_id" ]] || run_id="witness-$(date -u +%Y%m%dT%H%M%SZ)"
[[ "$run_id" =~ ^[A-Za-z0-9._-]+$ ]] || fail "run id must be [A-Za-z0-9._-]+: $run_id"

[[ -n "$runs_root" ]] || runs_root="${BW_RUNS_ROOT:-${repo_root}/runs}"
mkdir -p "$runs_root"
runs_root="$(cd "$runs_root" && pwd -P)"
partial_run="${runs_root}/${run_id}.partial"
final_run="${runs_root}/${run_id}"
[[ ! -e "$final_run" ]] || fail "run already exists and must not be overwritten: $final_run"
[[ ! -e "$partial_run" ]] || fail "partial run already exists: $partial_run"
mkdir -p "$partial_run"/{harnesses,findings,traces,logs,build}

if [[ -n "$bw_bin" ]]; then
  bw_cmd=("$bw_bin")
else
  bw_cmd=(cargo run --quiet --manifest-path "${repo_root}/Cargo.toml" -p bw-cli --bin bw --locked --)
fi

note "generating harnesses from ${plans}"
"${bw_cmd[@]}" generate-witness-harness \
  --plans "$plans" \
  --output-dir "${partial_run}/harnesses" \
  --repo-root "$repo_root" > "${partial_run}/harness-generation.json"

generated_dirs=()
while IFS= read -r line; do
  [[ -n "$line" ]] && generated_dirs+=("$line")
done < <(jq -r '.generated[].harness_dir' "${partial_run}/harnesses/generation-manifest.json")

note "generated ${#generated_dirs[@]} harness(es); refused $(jq -r '.refused | length' "${partial_run}/harnesses/generation-manifest.json")"

results_file="${partial_run}/witness-results.jsonl"
: > "$results_file"

# Runs one harness through build, static extraction, execution, bridge and oracle.
# Every failure is recorded as an outcome rather than aborting the run: one
# unbuildable harness must not hide the results of the others.
run_one_harness() {
  local harness_dir="$1"
  local name outcome detail findings_path
  name="$(basename "$harness_dir")"
  outcome="ok"
  detail=""
  findings_path=""

  local build_dir="${partial_run}/build/${name}"
  local static_dir="${partial_run}/build/${name}-static"
  local trace_dir="${partial_run}/traces/${name}"
  local log="${partial_run}/logs/${name}.log"
  mkdir -p "$trace_dir"

  if ! (cd "$harness_dir" && CARGO_TARGET_DIR="$build_dir" \
        cargo "+${toolchain}" build --quiet) >>"$log" 2>&1; then
    outcome="harness_build_failed"
    detail="cargo build failed; see logs/${name}.log"
  fi

  if [[ "$outcome" == "ok" ]]; then
    printf '{"output_dir":"%s","allowlist":[{"crate_name":"%s","target":"bin"}]}' \
      "$static_dir" "$name" > "${partial_run}/build/${name}-rustc.json"
    if ! (cd "$harness_dir" \
          && LD_LIBRARY_PATH="$toolchain_lib" \
             RUSTC_WRAPPER="$rustc_wrapper" \
             BW_RUSTC_CONFIG="${partial_run}/build/${name}-rustc.json" \
             CARGO_TARGET_DIR="${build_dir}-wrapped" \
             cargo "+${toolchain}" check --quiet) >>"$log" 2>&1; then
      outcome="static_extraction_failed"
      detail="wrapper run failed; see logs/${name}.log"
    fi
  fi

  local build_id=""
  if [[ "$outcome" == "ok" ]]; then
    if [[ -s "${static_dir}/static-facts.jsonl" ]]; then
      build_id="$(head -1 "${static_dir}/static-facts.jsonl" | jq -r '.build_id')"
    else
      outcome="static_extraction_empty"
      detail="the wrapper produced no static facts"
    fi
  fi

  if [[ "$outcome" == "ok" ]]; then
    # The harness writes its trace to the filesystem and reports nothing on stdout;
    # the five BW_* variables are the same contract the D0 runner uses.
    if ! timeout "$timeout_seconds" env -i \
        PATH="/usr/bin:/bin" HOME="$HOME" \
        BW_RUN_ID="${run_id}:${name}" \
        BW_TRACE_ID="${run_id}:${name}:trace" \
        BW_TRACE_DIR="$trace_dir" \
        BW_TRACE_COMPRESS=0 \
        BW_BUILD_ID="$build_id" \
        "${build_dir}/debug/${name}" >>"$log" 2>&1; then
      outcome="harness_execution_failed"
      detail="harness exited non-zero or timed out; see logs/${name}.log"
    fi
  fi

  if [[ "$outcome" == "ok" ]]; then
    # The runtime numbers events from 1 per trace; the oracle requires 0-based
    # sequences over the concatenated segments, so flatten before analysing.
    if ! python3 "${script_dir}/flatten_trace.py" \
        --trace-dir "$trace_dir" \
        --output "${partial_run}/traces/${name}.jsonl" >>"$log" 2>&1; then
      outcome="trace_flatten_failed"
      detail="trace segments could not be flattened; see logs/${name}.log"
    fi
  fi

  if [[ "$outcome" == "ok" ]]; then
    if ! "${bw_cmd[@]}" bridge-witness-facts \
        --static-facts "${static_dir}/static-facts.jsonl" \
        --bridge "${harness_dir}/site-bridge.json" \
        --output "${static_dir}/static-facts-bridged.jsonl" >>"$log" 2>&1; then
      outcome="site_bridge_failed"
      detail="runtime site ids could not be bridged; see logs/${name}.log"
    fi
  fi

  if [[ "$outcome" == "ok" ]]; then
    findings_path="${partial_run}/findings/${name}.jsonl"
    local analyze_status=0
    "${bw_cmd[@]}" analyze \
      --static "${static_dir}/static-facts-bridged.jsonl" \
      --contract "${repo_root}/contracts/callback-retention/contract.toml" \
      --trace "${partial_run}/traces/${name}.jsonl" \
      --output "$findings_path" >>"$log" 2>&1 || analyze_status=$?
    # analyze exits 1 when the oracle produced findings; that is a result, not a failure.
    if [[ "$analyze_status" -gt 1 ]]; then
      outcome="oracle_rejected_trace"
      detail="analyze exited ${analyze_status}; see logs/${name}.log"
      findings_path=""
    fi
  fi

  python3 - "$results_file" "$name" "$harness_dir" "$outcome" "$detail" "$findings_path" <<'PY'
import json, pathlib, sys
results, name, harness_dir, outcome, detail, findings_path = sys.argv[1:7]
findings = []
if findings_path and pathlib.Path(findings_path).is_file():
    for line in pathlib.Path(findings_path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            findings.append({
                "rule_id": record["rule_id"],
                "classification": record["classification"],
                "normalized_signature": record["normalized_signature"],
            })
record = {
    "harness": name,
    "harness_dir": harness_dir,
    "outcome": outcome,
    "detail": detail or None,
    "finding_count": len(findings),
    "findings": findings,
}
with open(results, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True) + "\n")
PY
  note "  ${name}: ${outcome}"
}

for harness_dir in "${generated_dirs[@]:-}"; do
  [[ -n "$harness_dir" ]] || continue
  run_one_harness "$harness_dir"
done

python3 - "$partial_run" "$run_id" "$scan_run" "$repo_root" <<'PY'
import json, pathlib, subprocess, sys

partial_run, run_id, scan_run, repo_root = sys.argv[1:5]
root = pathlib.Path(partial_run)

results = []
results_path = root / "witness-results.jsonl"
if results_path.is_file():
    for line in results_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            results.append(json.loads(line))

manifest = json.loads((root / "harnesses" / "generation-manifest.json").read_text(encoding="utf-8"))

def commit():
    try:
        return subprocess.run(
            ["git", "-C", repo_root, "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        return "unknown"

outcomes = {}
for record in results:
    outcomes[record["outcome"]] = outcomes.get(record["outcome"], 0) + 1

summary = {
    "schema_version": "boundary-witness.witness-run-summary/0.1",
    "run_id": run_id,
    "scan_run": pathlib.Path(scan_run).name,
    "code_commit": commit(),
    "counts": {
        "plans_bound": len(manifest["generated"]),
        "plans_refused": len(manifest["refused"]),
        "harnesses_executed": len(results),
        "harnesses_with_findings": sum(1 for r in results if r["finding_count"] > 0),
        "confirmed_violations": sum(
            1
            for r in results
            for f in r["findings"]
            if f["classification"] == "confirmed_violation"
        ),
    },
    "outcomes": outcomes,
    "refused_plans": manifest["refused"],
    "notes": [
        "a finding here means the harness reproduced the lifecycle it was generated to reproduce",
        "it is not a defect conclusion about the scanned crate",
        "refused plans are dynamic coverage gaps, not errors",
    ],
}
(root / "witness-summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

if [[ ! -s "$results_file" ]] && [[ "${#generated_dirs[@]}" -gt 0 ]]; then
  if [[ "$keep_partial" != "true" ]]; then
    note "no harness produced a result; partial run kept at ${partial_run}"
  fi
  exit 1
fi

mv "$partial_run" "$final_run"
jq -c '{run_id, counts, outcomes}' "${final_run}/witness-summary.json"
note "finalized witness run at ${final_run}"

#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: verify-d1-formal.sh <final-d1-formal-run-directory>

Checks D1 formal run integrity and the hard update_hook acceptance gates:
  - exactly 30 campaigns
  - all campaigns use update_hook_actions with 30 CPU minutes
  - commit/deployment/image/config digests are consistent
  - seeds and campaign IDs are unique
  - at least 18/30 campaigns find a primary objective
  - primary artifacts replay 20/20 and retain register/owner-end/later-trigger stages
  - safe-only control produces no artifact
  - checksums cover every file in the final run directory
EOF
}

fail() {
  printf 'verify-d1-formal: %s\n' "$*" >&2
  exit 2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ $# -eq 1 ]] || fail "expected exactly one run directory"
run_dir="$1"
[[ -d "$run_dir" ]] || fail "run directory does not exist: $run_dir"
[[ "$run_dir" != *.partial ]] || fail "refusing to verify .partial run directory"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

python3 - "$run_dir" <<'PY'
import hashlib
import json
import pathlib
import sys


def die(message: str) -> None:
    print(f"verify-d1-formal: {message}", file=sys.stderr)
    raise SystemExit(2)


run = pathlib.Path(sys.argv[1]).resolve()
required = ["manifest.json", "summary.json", "findings.jsonl", "COMPLETE", "checksums.sha256"]
for relative in required:
    if not (run / relative).is_file():
        die(f"missing required file: {relative}")


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


expected = {}
for index, line in enumerate((run / "checksums.sha256").read_text(encoding="utf-8").splitlines(), 1):
    if not line.strip():
        continue
    parts = line.split("  ", 1)
    if len(parts) != 2:
        die(f"invalid checksum line {index}")
    digest, relative = parts
    if len(digest) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in digest):
        die(f"invalid checksum digest on line {index}")
    if relative.startswith("/") or ".." in pathlib.PurePosixPath(relative).parts:
        die(f"unsafe checksum path: {relative}")
    expected[relative] = digest.lower()

for relative in required[:-1]:
    if relative not in expected:
        die(f"required file is not checksummed: {relative}")

actual_files = []
for path in run.rglob("*"):
    if path.is_symlink():
        die(f"symlink is not allowed in run directory: {path.relative_to(run)}")
    if path.is_file() and path.name != "checksums.sha256":
        actual_files.append(path.relative_to(run).as_posix())

for relative in sorted(actual_files):
    if relative not in expected:
        die(f"file is not checksummed: {relative}")
    actual = sha256(run / relative)
    if actual != expected[relative]:
        die(f"checksum mismatch for {relative}: actual {actual}, expected {expected[relative]}")

for relative in expected:
    if relative not in actual_files:
        die(f"checksummed file is missing: {relative}")

manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))

if summary.get("schema_version") != "boundary-witness.d1-formal-summary/0.1":
    die(f"unexpected summary schema: {summary.get('schema_version')}")
if summary.get("campaign_count") != 30:
    die(f"campaign_count must be 30, got {summary.get('campaign_count')}")

campaigns = summary.get("campaigns")
if not isinstance(campaigns, list) or len(campaigns) != 30:
    die("summary.campaigns must contain exactly 30 records")

manifest_keys = ["git_commit", "deployment_sha256", "image_digest", "config_digest", "build_id"]
for key in manifest_keys:
    if not manifest.get(key):
        die(f"manifest.{key} must not be empty")

campaign_ids = set()
seeds = set()
primary_found = 0
timeout_count = 0
tool_error_count = 0
totals = {
    "executions": 0,
    "valid_sequence_count": 0,
    "invalid_sequence_count": 0,
    "progress_count": 0,
    "secondary_count": 0,
    "primary_count": 0,
}

for record in campaigns:
    cid = record.get("campaign_id")
    if not cid:
        die("campaign_id must not be empty")
    if cid in campaign_ids:
        die(f"duplicate campaign_id: {cid}")
    campaign_ids.add(cid)
    seed = record.get("seed")
    if seed in seeds:
        die(f"duplicate seed: {seed}")
    seeds.add(seed)

    if record.get("api") != "update_hook":
        die(f"{cid}: api must be update_hook")
    if record.get("target") != "update_hook_actions":
        die(f"{cid}: target must be update_hook_actions")
    if record.get("cpu_minutes") != 30:
        die(f"{cid}: cpu_minutes must be 30")
    if record.get("replay_repeat_count") != 20:
        die(f"{cid}: replay_repeat_count must be 20")
    for key in manifest_keys:
        if record.get(key) != manifest.get(key):
            die(f"{cid}: {key} does not match manifest")

    executions = int(record.get("executions", 0))
    valid = int(record.get("valid_sequence_count", 0))
    invalid = int(record.get("invalid_sequence_count", 0))
    if executions <= 0:
        die(f"{cid}: executions must be greater than zero")
    if valid + invalid != executions:
        die(f"{cid}: valid+invalid must equal executions")

    for key in totals:
        totals[key] += int(record.get(key, 0))

    outcome = record.get("outcome")
    if outcome == "primary_found":
        primary_found += 1
        if int(record.get("primary_count", 0)) <= 0:
            die(f"{cid}: primary_found requires primary_count > 0")
        digest = record.get("representative_artifact_digest")
        if not isinstance(digest, str) or len(digest) != 64:
            die(f"{cid}: missing representative artifact digest")
        if record.get("replay_success_count") != 20:
            die(f"{cid}: replay_success_count must be 20")
        if int(record.get("minimized_len", 0)) < 3:
            die(f"{cid}: minimized_len must preserve a semantic witness")
        stages = record.get("witness_stages") or {}
        for stage in ["has_register", "has_owner_end", "has_later_trigger"]:
            if stages.get(stage) is not True:
                die(f"{cid}: minimized witness missing {stage}")
    elif outcome == "timeout":
        timeout_count += 1
        if int(record.get("primary_count", 0)) != 0:
            die(f"{cid}: timeout campaign cannot have primary_count")
    elif outcome == "tool_error":
        tool_error_count += 1
    elif outcome in {"no_primary", "crash_without_primary"}:
        pass
    else:
        die(f"{cid}: unsupported outcome {outcome!r}")

if primary_found != summary.get("primary_found_campaigns"):
    die("primary_found_campaigns does not match campaign records")
if primary_found < 18:
    die(f"primary success gate failed: {primary_found}/30 < 18/30")
if timeout_count != summary.get("timeout_campaigns"):
    die("timeout_campaigns does not match campaign records")
if tool_error_count != summary.get("tool_error_campaigns"):
    die("tool_error_campaigns does not match campaign records")

for key, value in totals.items():
    if summary.get(key) != value:
        die(f"summary.{key} does not match campaign records")

safe = summary.get("safe_only") or {}
if safe.get("target") != "update_hook_safe_only":
    die("safe_only.target must be update_hook_safe_only")
if safe.get("artifact_count") != 0:
    die(f"safe-only produced artifacts: {safe.get('artifact_count')}")
if safe.get("cpu_minutes") != 30:
    die("safe-only cpu_minutes must be 30")

print(json.dumps({
    "status": "ok",
    "path": str(run),
    "campaign_count": len(campaigns),
    "primary_found_campaigns": primary_found,
    "safe_only_artifact_count": safe.get("artifact_count"),
}, sort_keys=True))
PY

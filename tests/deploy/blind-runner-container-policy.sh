#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 022

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
engine="${BW_CONTAINER_ENGINE:-docker}"
image="${BW_CONTAINER_IMAGE:-boundary-witness-d0:test}"
require_container="${BW_REQUIRE_CONTAINER:-0}"
cargo_target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"
bin_dir="${cargo_target_dir}/debug"
policy_tmp_root="${BW_BLIND_RUNNER_CONTAINER_POLICY_TMP_ROOT:-}"
policy_tmp_owned=0
if [[ -z "$policy_tmp_root" ]]; then
  policy_tmp_root="$(mktemp -d -t bw-blind-runner-container-policy.XXXXXX)"
  policy_tmp_owned=1
else
  mkdir -p "$policy_tmp_root"
fi
tmp_root="${policy_tmp_root}/blind-runner-container-policy"
reveal_root="${policy_tmp_root}/blind-runner-container-policy-reveal"

cleanup() {
  # Only remove the scratch root we created; an explicitly provided root is left
  # in place so its receipts and reveal output remain inspectable.
  if [[ "$policy_tmp_owned" == "1" ]]; then
    rm -rf "$policy_tmp_root"
  fi
}
trap cleanup EXIT

fail() {
  printf 'blind-runner-container-policy: %s\n' "$*" >&2
  exit 1
}

skip_or_fail() {
  local message="$1"
  if [[ "$require_container" == "1" ]]; then
    fail "$message"
  fi
  printf 'blind-runner-container-policy: skipped (%s)\n' "$message"
  exit 0
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

[[ "$(uname -s)" == "Linux" ]] || skip_or_fail "Linux-only trusted container policy"
command -v "$engine" >/dev/null 2>&1 || skip_or_fail "container engine unavailable: $engine"
"$engine" image inspect "$image" >/dev/null 2>&1 \
  || skip_or_fail "container image unavailable: $image"

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v zstd >/dev/null 2>&1 || fail "zstd is required"

rm -rf "$tmp_root" "$reveal_root"
mkdir -p "$tmp_root" "$reveal_root/container" "$reveal_root/native"

method_commit="$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}')"
pack="$tmp_root/pack"
archive_out="$tmp_root/archive"
packs_root="$tmp_root/installed-packs"
receipts_root="$tmp_root/install-receipts"
runs_root="$tmp_root/runs"
native_runs_root="$tmp_root/native-runs"
private_source="$tmp_root/private-source"
private_truth="$private_source/ground-truth/nday-gate.json"
receipt_key="$tmp_root/receipt-key.hex"
receipt_key_id="container-policy-key"
receipt_secret="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
case_a="blind-8f34a923d01c77ab"
case_b="blind-0123456789abcdef"

mkdir -p "$pack/cases/$case_a/adapter/bin" "$pack/cases/$case_b/adapter/bin" \
  "$(dirname "$private_truth")"
printf 'complete\n' > "$pack/cases/$case_a/COMPLETE"
printf 'complete\n' > "$pack/cases/$case_b/COMPLETE"

write_adapter() {
  local path="$1"
  local prefix="$2"
  local findings="$3"
  local witness="$4"
  local setup="$5"
  cat > "$path" <<EOF
#!/bin/sh
set -eu
$prefix
$setup
findings='$findings'
witness='$witness'
printf '{"schema_version":"boundary-witness.blind-observed/0.1","suite_id":"%s","split":"%s","case_id":"%s","method_commit":"%s","public_manifest_sha256":"%s","status":"completed","findings":%s,"witness":%s}\\n' \
  "\$BW_BLIND_SUITE_ID" "\$BW_BLIND_SPLIT" "\$BW_BLIND_CASE_ID" "\$BW_BLIND_METHOD_COMMIT" "\$BW_BLIND_MANIFEST_SHA256" "\$findings" "\$witness" > "\$BW_CHILD_WORK_DIR/observation.json"
EOF
  chmod 755 "$path"
}

# Case A tries to leave a process that modifies the next case. Its container sees only /case
# for case A, so neither the future snapshot nor its work directory is reachable.
write_adapter "$pack/cases/$case_a/adapter/bin/driver" \
  '(setsid sh -c '\''sleep 1; printf "tampered\\n" > /case/../blind-0123456789abcdef/adapter/bin/driver'\'' >/dev/null 2>&1 &)' \
  '[{"rule_id":"synthetic.lifecycle.rule","classification":"confirmed_violation","normalized_signature":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","evidence_complete":true}]' \
  '{"artifact_path":"witness/replay.json","artifact_sha256":"d21cecdce219c5c7211bf9459717c2d5c21a5538484d7b46d443ebe9df764642","replay_attempts":3,"replay_successes":3}' \
  'mkdir -p "$BW_CHILD_WORK_DIR/witness"; printf "synthetic witness\\n" > "$BW_CHILD_WORK_DIR/witness/replay.json"'
write_adapter "$pack/cases/$case_b/adapter/bin/driver" \
  'printf "case-b-audited\\n" > "$BW_CHILD_WORK_DIR/case-b-marker"' \
  '[]' \
  'null' \
  ''

python3 - "$pack" "$method_commit" "$case_a" "$case_b" <<'PY'
import hashlib
import json
import pathlib
import sys

pack = pathlib.Path(sys.argv[1])
method_commit, case_a, case_b = sys.argv[2:]
policy = """schema_version = \"boundary-witness.blind-policy/0.1\"\nminimum_replay_attempts = 3\ngate_minimum_confirmed_cases = 1\nforbidden_public_filename_tokens = [\"ground-truth\", \"ground_truth\", \"cve-\", \"ghsa-\", \"advisory\", \"poc\", \"proof-of-concept\", \"proof_of_concept\", \"expected-result\", \"expected_result\", \"expected result\", \"private\"]\n"""
(pack / "policy.toml").write_text(policy, encoding="utf-8")

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def case_digest(case_id):
    root = pack / "cases" / case_id
    digest = hashlib.sha256()
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.relative_to(root).as_posix()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(sha256(path).encode())
    return digest.hexdigest()

manifest = {
    "schema_version": "boundary-witness.blind-public/0.1",
    "suite_id": "container-policy-suite",
    "split": "gate",
    "method_commit": method_commit,
    "policy_sha256": sha256(pack / "policy.toml"),
    "cases": [
        {
            "case_id": case_id,
            "case_root": f"cases/{case_id}",
            "case_sha256": case_digest(case_id),
            "command": {"program": "adapter/bin/driver", "args": [], "env": {}},
            "timeout_seconds": 10,
        }
        for case_id in (case_a, case_b)
    ],
}
(pack / "manifest.json").write_text(json.dumps(manifest, separators=(",", ":")) + "\n", encoding="utf-8")

entries = []
for path in sorted((item for item in pack.rglob("*") if item.is_file()), key=lambda item: item.relative_to(pack).as_posix()):
    if path.name != "checksums.sha256":
        entries.append(f"{sha256(path)}  {path.relative_to(pack).as_posix()}")
(pack / "checksums.sha256").write_text("\n".join(entries) + "\n", encoding="utf-8")
PY

python3 - "$pack/manifest.json" "$private_truth" "$case_a" "$case_b" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
truth_path = pathlib.Path(sys.argv[2])
case_a, case_b = sys.argv[3:]
manifest = manifest_path.read_bytes()
truth = {
    "schema_version": "boundary-witness.blind-ground-truth/0.1",
    "suite_id": "container-policy-suite",
    "split": "gate",
    "public_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
    "cases": [
        {
            "case_id": case_a,
            "curator_key": "synthetic-alpha",
            "role": "violation",
            "component": "synthetic-component",
            "api": "synthetic-api",
            "root_cause_key": "synthetic-root",
            "paired_case_ids": [case_b],
            "source_revision": "synthetic-revision",
        },
        {
            "case_id": case_b,
            "curator_key": "synthetic-beta",
            "role": "safe_control",
            "component": "synthetic-component",
            "api": "synthetic-api",
            "root_cause_key": "synthetic-root",
            "paired_case_ids": [case_a],
            "source_revision": "synthetic-revision",
        },
    ],
}
truth_path.write_text(json.dumps(truth, separators=(",", ":")) + "\n", encoding="utf-8")
PY

printf '%s\n' "$receipt_secret" > "$receipt_key"

"$repo_root/tools/blind/create-public-archive.sh" "$pack" "$archive_out" "$method_commit" >/dev/null
install_json="$(
  BW_BLIND_PACKS_ROOT="$packs_root" \
  BW_BLIND_RECEIPTS_ROOT="$receipts_root" \
  BW_BLIND_RECEIPT_KEY_ID="$receipt_key_id" \
  BW_BLIND_RECEIPT_KEY_HEX="$receipt_secret" \
  BW_BLIND_HOST_ID="container-policy-host" \
  "$repo_root/tools/blind/install-public-archive.sh" \
    "$archive_out/blind-pack.tar.zst" \
    "$archive_out/blind-pack.sha256" \
    "$archive_out/blind-deployment.json"
)"
install_receipt="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["install_receipt"])' <<<"$install_json")"
deployment_sha="$(sha256_file "$archive_out/blind-pack.tar.zst")"
pack_root="$packs_root/$deployment_sha"

cargo build -p bw-blind-runner --bin bw-blind-audit --bin bw-blind-run \
  -p bw-blind-curator --bin bw-blind-reveal --locked >/dev/null
"${bin_dir}/bw-blind-audit" "$pack_root" >/dev/null
run_json="$(
  BW_CONTAINER_ENGINE="$engine" \
  "${bin_dir}/bw-blind-run" \
    --pack "$pack_root" \
    --runs-root "$runs_root" \
    --commit "$method_commit" \
    --deployment-sha256 "$deployment_sha" \
    --image-digest "$image" \
    --stable-toolchain "synthetic-container-policy" \
    --install-receipt "$install_receipt" \
    --receipt-key "$receipt_key" \
    --receipt-key-id "$receipt_key_id" \
    --isolation container \
    --runner-commit "$method_commit" \
    --runner-host-id "container-policy-host"
)"
run_path="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["run_path"])' <<<"$run_json")"
runner_receipt="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["runner_receipt_path"])' <<<"$run_json")"

[[ -f "$run_path/artifacts/observations.jsonl" ]] || fail "formal run did not finalize observations"
grep -Fq "\"case_id\":\"$case_b\"" "$run_path/artifacts/observations.jsonl" \
  || fail "case B observation is missing"
find "$run_path/logs/children" -name case-b-marker -type f -exec sh -c \
  'grep -Fqx "case-b-audited" "$1" && printf found' _ {} \; | grep -q found \
  || fail "case B did not execute its audited adapter bytes"

container_reveal_out="$reveal_root/container/container-reveal.json"
container_decision="$(
  "${bin_dir}/bw-blind-reveal" \
    --manifest "$pack_root/manifest.json" \
    --policy "$pack_root/policy.toml" \
    --run "$run_path" \
    --ground-truth "$private_truth" \
    --install-receipt "$install_receipt" \
    --runner-receipt "$runner_receipt" \
    --receipt-key "$receipt_key" \
    --receipt-key-id "$receipt_key_id" \
    --out "$container_reveal_out"
)"
python3 -c 'import json,sys; assert json.load(sys.stdin)["gate_passed"], "container-backed receipt did not pass gate"' \
  <<<"$container_decision" \
  || fail "container-backed receipt did not pass gate"

native_run_json="$(
  "${bin_dir}/bw-blind-run" \
    --pack "$pack_root" \
    --runs-root "$native_runs_root" \
    --commit "$method_commit" \
    --deployment-sha256 "$deployment_sha" \
    --image-digest native-untrusted-smoke \
    --stable-toolchain "synthetic-native-smoke" \
    --install-receipt "$install_receipt" \
    --receipt-key "$receipt_key" \
    --receipt-key-id "$receipt_key_id" \
    --isolation native-untrusted-smoke \
    --runner-commit "$method_commit" \
    --runner-host-id "container-policy-host"
)"
native_run_path="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["run_path"])' <<<"$native_run_json")"
native_runner_receipt="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["runner_receipt_path"])' <<<"$native_run_json")"
native_reveal_log="$reveal_root/native/native-untrusted-smoke-reveal.log"
if "${bin_dir}/bw-blind-reveal" \
  --manifest "$pack_root/manifest.json" \
  --policy "$pack_root/policy.toml" \
  --run "$native_run_path" \
  --ground-truth "$private_truth" \
  --install-receipt "$install_receipt" \
  --runner-receipt "$native_runner_receipt" \
  --receipt-key "$receipt_key" \
  --receipt-key-id "$receipt_key_id" \
  --out "$reveal_root/native/native-untrusted-smoke.json" >"$native_reveal_log" 2>&1; then
  fail "native-untrusted-smoke receipt unexpectedly revealed"
fi
grep -Fq "formal reveal requires trusted isolation" "$native_reveal_log" \
  || fail "native-untrusted-smoke reveal did not report untrusted isolation"

printf 'blind-runner-container-policy: ok\n'

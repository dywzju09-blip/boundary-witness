#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"

fail() {
  printf 'rusqlite-m12-v3-pack-policy: %s\n' "$*" >&2
  exit 1
}

for program in cargo find grep python3; do
  command -v "$program" >/dev/null 2>&1 || fail "$program is required"
done

tmp_parent="${repo_root}/target/tmp"
mkdir -p "$tmp_parent"
tmp="$(mktemp -d "${tmp_parent}/bw-rusqlite-m12-v3-pack.XXXXXX")"
cleanup() {
  rm -R "$tmp"
}
trap cleanup EXIT

artifact_root="${tmp}/artifacts"
tool_root="${tmp}/tools"
source_root="${tmp}/source"
public_out="${tmp}/public"
private_out="${tmp}/curator-private"
policy="${repo_root}/experiments/configs/nday-blind-policy.toml"
mkdir -p "${artifact_root}/bin" "${artifact_root}/static" "$tool_root"

for index in 1 2 3 4 5 6 7 8 9 10; do
  case_id="case-$(printf '%04d' "$index")"
  printf 'anonymous runtime case\n' > "${artifact_root}/bin/${case_id}"
  printf 'anonymous static facts\n' > "${artifact_root}/static/${case_id}.jsonl"
done
printf 'anonymous adapter\n' > "${tool_root}/adapter"
printf 'anonymous analyzer\n' > "${tool_root}/bw"
printf 'anonymous contract\n' > "${tool_root}/contract.toml"

cd "$repo_root"

cargo run --locked --manifest-path benchmarks/historical-cves/rusqlite/shared/Cargo.toml --bin bw-rusqlite-stage-artifacts -- \
  v3-source m12 "$artifact_root" "$source_root" "${tool_root}/adapter" "${tool_root}/bw" "${tool_root}/contract.toml" \
  > "${tmp}/v3-source.json"

cargo run -p bw-blind-curator --bin bw-blind-pack --locked -- \
  --source "$source_root" \
  --policy "$policy" \
  --public-out "$public_out" \
  --private-out "$private_out" \
  --id-salt-hex 00112233445566778899aabbccddeeff \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  > "${tmp}/pack-report.json"

cargo run -p bw-blind-runner --bin bw-blind-audit --locked -- \
  "$public_out/nday-gate" \
  > "${tmp}/audit.json"

case_count="$(
  python3 - "$public_out/nday-gate/manifest.json" <<'PY'
import json
import sys
print(len(json.load(open(sys.argv[1], encoding="utf-8"))["cases"]))
PY
)"
[[ "$case_count" == "10" ]] || fail "expected 10 gate cases, got $case_count"

find "$public_out" -type f -print | LC_ALL=C sort > "${tmp}/public-files.txt"
if grep -Eiq 'vulnerable|fixed|ground-truth|ground_truth|cve-|ghsa-|advisory|poc|expected-result|expected_result' "${tmp}/public-files.txt"; then
  fail "public pack path leaked forbidden token"
fi
if find "$public_out" -type f ! -name policy.toml -print0 \
  | xargs -0 grep -I -Eiq 'm12-case|ground-truth|ground_truth|cve-|ghsa-|advisory|poc|expected-result|expected_result'; then
  fail "public pack contents leaked forbidden token"
fi

printf 'rusqlite-m12-v3-pack-policy: ok\n'

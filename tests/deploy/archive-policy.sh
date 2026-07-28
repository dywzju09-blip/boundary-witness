#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
create_tool="${repo_root}/tools/deploy/create-archive.sh"
verify_tool="${repo_root}/tools/deploy/verify-archive.sh"
install_tool="${repo_root}/tools/deploy/install-archive.sh"

fail() {
  printf 'archive-policy: %s\n' "$*" >&2
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

assert_exists() {
  [[ -e "$1" ]] || fail "expected path to exist: $1"
}

assert_not_in_archive() {
  local listing="$1"
  local pattern="$2"
  if grep -Eq "$pattern" "$listing"; then
    fail "archive unexpectedly contains pattern: $pattern"
  fi
}

for tool in "$create_tool" "$verify_tool" "$install_tool"; do
  [[ -x "$tool" ]] || fail "missing executable deploy tool: $tool"
done

command -v zstd >/dev/null 2>&1 || fail "zstd is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

tmp="$(mktemp -d -t bw-archive-policy.XXXXXX)"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

fixture_repo="${tmp}/repo"
dist="${tmp}/dist"
install_root="${tmp}/install-root"
mkdir -p "$fixture_repo" "$dist" "$install_root"

git -C "$fixture_repo" init -q
git -C "$fixture_repo" config user.email "bw-test@example.invalid"
git -C "$fixture_repo" config user.name "BoundaryWitness Test"

cp "${repo_root}/.gitattributes" "${fixture_repo}/.gitattributes"
cp "${repo_root}/.gitignore" "${fixture_repo}/.gitignore"
mkdir -p \
  "${fixture_repo}/benchmarks/historical-cves/rusqlite/update-hook/vulnerable" \
  "${fixture_repo}/crates/demo/src" \
  "${fixture_repo}/tools/demo" \
  "${fixture_repo}/experiments/configs" \
  "${fixture_repo}/experiments/ground-truth" \
  "${fixture_repo}/experiments/schemas" \
  "${fixture_repo}/experiments/artifacts/d0/static" \
  "${fixture_repo}/fixtures/demo" \
  "${fixture_repo}/fixtures/vulnerable" \
  "${fixture_repo}/docs" \
  "${fixture_repo}/target" \
  "${fixture_repo}/runs/demo" \
  "${fixture_repo}/scratch"

cat > "${fixture_repo}/Cargo.toml" <<'EOF'
[workspace]
members = ["crates/demo"]
resolver = "3"
EOF
cat > "${fixture_repo}/Cargo.lock" <<'EOF'
# fixture lock
EOF
cat > "${fixture_repo}/crates/demo/Cargo.toml" <<'EOF'
[package]
name = "demo"
version = "0.1.0"
edition = "2024"
EOF
cat > "${fixture_repo}/crates/demo/src/lib.rs" <<'EOF'
pub fn answer() -> u8 { 42 }
EOF
printf 'pub fn epoch() -> u8 { 0 }\n' > "${fixture_repo}/crates/demo/src/epoch.rs"
printf 'server input\n' > "${fixture_repo}/tools/demo/input.txt"
printf 'historical benchmark source must not deploy to blind runtime\n' > "${fixture_repo}/benchmarks/historical-cves/rusqlite/update-hook/vulnerable/main.rs"
printf 'case = "demo"\n' > "${fixture_repo}/experiments/configs/demo.toml"
printf 'ground truth must not deploy to blind runtime\n' > "${fixture_repo}/experiments/ground-truth/rusqlite-m12.toml"
printf '{}\n' > "${fixture_repo}/experiments/schemas/blind-ground-truth.schema.json"
printf 'generated artifact must not deploy\n' > "${fixture_repo}/experiments/artifacts/d0/static/generated.jsonl"
printf 'fixture\n' > "${fixture_repo}/fixtures/demo/input.txt"
printf 'fixture answer marker must not deploy\n' > "${fixture_repo}/fixtures/vulnerable/borrowed-callback-uaf.trace.jsonl"
printf 'private docs must not deploy\n' > "${fixture_repo}/docs/private.md"
printf 'target artifact must not deploy\n' > "${fixture_repo}/target/object.o"
printf 'run artifact must not deploy\n' > "${fixture_repo}/runs/demo/result.json"
printf 'scratch artifact must not deploy\n' > "${fixture_repo}/scratch/tmp.txt"

git -C "$fixture_repo" add .
git -C "$fixture_repo" commit -q -m "fixture"
commit="$(git -C "$fixture_repo" rev-parse HEAD)"

printf 'untracked file must not deploy\n' > "${fixture_repo}/untracked-secret.txt"
printf 'dirty change\n' >> "${fixture_repo}/tools/demo/input.txt"
if "$create_tool" --repo "$fixture_repo" --out "${dist}/dirty" >"${tmp}/dirty.out" 2>"${tmp}/dirty.err"; then
  fail "dirty worktree was accepted"
fi
git -C "$fixture_repo" restore tools/demo/input.txt

"$create_tool" --repo "$fixture_repo" --out "$dist" >"${tmp}/create.out" 2>"${tmp}/create.err"

archive="${dist}/source.tar.zst"
sha_file="${dist}/source.sha256"
manifest="${dist}/deployment.json"
assert_exists "$archive"
assert_exists "$sha_file"
assert_exists "$manifest"

"$verify_tool" --archive "$archive" --sha256 "$sha_file" --manifest "$manifest" >"${tmp}/verify.out" 2>"${tmp}/verify.err"

manifest_commit="$(
  python3 - "$manifest" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["commit"])
PY
)"
[[ "$manifest_commit" == "$commit" ]] || fail "manifest commit mismatch: $manifest_commit != $commit"

listing="${tmp}/archive.list"
zstd -dc "$archive" | tar -tf - > "$listing"
grep -Eq '^boundary-witness/Cargo.toml$' "$listing" || fail "archive is missing committed Cargo.toml"
grep -Eq '^boundary-witness/crates/demo/src/lib.rs$' "$listing" || fail "archive is missing committed crate source"
assert_not_in_archive "$listing" '^boundary-witness/docs/'
assert_not_in_archive "$listing" '^boundary-witness/experiments/artifacts/'
assert_not_in_archive "$listing" '^boundary-witness/target/'
assert_not_in_archive "$listing" '^boundary-witness/runs/'
assert_not_in_archive "$listing" '^boundary-witness/scratch/'
assert_not_in_archive "$listing" '^boundary-witness/untracked-secret\.txt$'

"$create_tool" --profile staging-builder --repo "$fixture_repo" --out "${dist}/staging-builder" >"${tmp}/create-staging.out" 2>"${tmp}/create-staging.err"
staging_archive="${dist}/staging-builder/source.tar.zst"
staging_sha_file="${dist}/staging-builder/source.sha256"
staging_manifest="${dist}/staging-builder/deployment.json"
assert_exists "$staging_archive"
assert_exists "$staging_sha_file"
assert_exists "$staging_manifest"

"$verify_tool" --archive "$staging_archive" --sha256 "$staging_sha_file" --manifest "$staging_manifest" >"${tmp}/verify-staging.out" 2>"${tmp}/verify-staging.err"

staging_listing="${tmp}/archive-staging.list"
zstd -dc "$staging_archive" | tar -tf - > "$staging_listing"
grep -Eq '^boundary-witness/benchmarks/historical-cves/rusqlite/update-hook/vulnerable/main.rs$' "$staging_listing" \
  || fail "staging-builder archive is missing historical benchmark source"
assert_not_in_archive "$staging_listing" '^boundary-witness/experiments/ground-truth/'

staging_profile="$(
  python3 - "$staging_manifest" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["profile"])
PY
)"
[[ "$staging_profile" == "staging-builder" ]] || fail "staging deployment profile mismatch: $staging_profile"

"$create_tool" --profile blind-runtime --repo "$fixture_repo" --out "${dist}/blind-runtime" >"${tmp}/create-blind.out" 2>"${tmp}/create-blind.err"
blind_archive="${dist}/blind-runtime/source.tar.zst"
blind_sha_file="${dist}/blind-runtime/source.sha256"
blind_manifest="${dist}/blind-runtime/deployment.json"
assert_exists "$blind_archive"
assert_exists "$blind_sha_file"
assert_exists "$blind_manifest"

"$verify_tool" --archive "$blind_archive" --sha256 "$blind_sha_file" --manifest "$blind_manifest" >"${tmp}/verify-blind.out" 2>"${tmp}/verify-blind.err"

blind_listing="${tmp}/archive-blind.list"
zstd -dc "$blind_archive" | tar -tf - > "$blind_listing"
grep -Eq '^boundary-witness/Cargo.toml$' "$blind_listing" || fail "blind archive is missing Cargo.toml"
grep -Eq '^boundary-witness/crates/demo/src/lib.rs$' "$blind_listing" || fail "blind archive is missing crate source"
grep -Eq '^boundary-witness/crates/demo/src/epoch.rs$' "$blind_listing" || fail "blind archive incorrectly rejected epoch source path"
assert_not_in_archive "$blind_listing" '^boundary-witness/experiments/ground-truth/'
assert_not_in_archive "$blind_listing" '^boundary-witness/experiments/schemas/'
assert_not_in_archive "$blind_listing" '^boundary-witness/benchmarks/historical-cves/'
assert_not_in_archive "$blind_listing" '^boundary-witness/fixtures/'
python3 - "$blind_listing" <<'PY'
import re
import sys

forbidden = (
    "vulnerable",
    "fixed",
    "ground-truth",
    "ground_truth",
    "cve-",
    "ghsa-",
    "advisory",
    "proof-of-concept",
    "expected-result",
    "expected_result",
)
poc = re.compile(r"(?<![0-9a-z])poc(?![0-9a-z])")
for line in open(sys.argv[1], encoding="utf-8"):
    relative = line.strip().lower()
    if any(token in relative for token in forbidden) or poc.search(relative):
        raise SystemExit(f"archive-policy: blind archive leaked forbidden token: {relative}")
PY

blind_profile="$(
  python3 - "$blind_manifest" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["profile"])
PY
)"
[[ "$blind_profile" == "blind-runtime" ]] || fail "blind deployment profile mismatch: $blind_profile"

tampered="${tmp}/source-tampered.tar.zst"
cp "$archive" "$tampered"
printf 'x' >> "$tampered"
if "$verify_tool" --archive "$tampered" --sha256 "$sha_file" --manifest "$manifest" >"${tmp}/tamper.out" 2>"${tmp}/tamper.err"; then
  fail "tampered archive passed sha256 verification"
fi

"$install_tool" --archive "$archive" --sha256 "$sha_file" --manifest "$manifest" --root "$install_root" >"${tmp}/install.out" 2>"${tmp}/install.err"
installed="${install_root}/deployments/${commit}"
assert_exists "${installed}/source/Cargo.toml"
assert_exists "${installed}/deployment.json"

"$install_tool" --archive "$archive" --sha256 "$sha_file" --manifest "$manifest" --root "$install_root" >"${tmp}/install-again.out" 2>"${tmp}/install-again.err"

# Deployment archives are run-identity inputs, so the same commit must always
# produce the same archive_sha256. Re-create each profile and compare digests.
for repeat_profile in full-experiment staging-builder; do
  repeat_dist="${tmp}/dist-repeat/${repeat_profile}"
  mkdir -p "$repeat_dist"
  "$create_tool" --profile "$repeat_profile" --repo "$fixture_repo" --out "$repeat_dist" \
    >"${tmp}/create-repeat-${repeat_profile}.out" 2>"${tmp}/create-repeat-${repeat_profile}.err"
  case "$repeat_profile" in
    full-experiment) baseline="$archive" ;;
    staging-builder) baseline="$staging_archive" ;;
  esac
  [[ "$(sha256_file "${repeat_dist}/source.tar.zst")" == "$(sha256_file "$baseline")" ]] \
    || fail "${repeat_profile} archive creation was not deterministic"
done

# The fixture repository above is synthetic. Exercise the tools against the real
# repository too, so deployment policy drift is caught on the tree that actually
# ships (for example a top-level directory missing from the allowlist).
if [[ -n "$(git -C "$repo_root" status --porcelain)" ]]; then
  printf 'archive-policy: skipping real-repository round (dirty worktree)\n' >&2
else
  real_dist="${tmp}/dist-real"
  for real_profile in full-experiment staging-builder; do
    real_out="${real_dist}/${real_profile}"
    mkdir -p "$real_out"
    "$create_tool" --profile "$real_profile" --repo "$repo_root" --out "$real_out" \
      >"${tmp}/create-real-${real_profile}.out" 2>"${tmp}/create-real-${real_profile}.err" \
      || fail "real-repository ${real_profile} archive creation failed"
    "$verify_tool" --archive "${real_out}/source.tar.zst" --sha256 "${real_out}/source.sha256" \
      --manifest "${real_out}/deployment.json" \
      >"${tmp}/verify-real-${real_profile}.out" 2>"${tmp}/verify-real-${real_profile}.err" \
      || fail "real-repository ${real_profile} archive verification failed"
  done

  real_listing="${tmp}/archive-real.list"
  zstd -dc "${real_dist}/full-experiment/source.tar.zst" | tar -tf - > "$real_listing"
  # schemas/ is read from disk at runtime by bw-model schema tests, so it must ship.
  grep -Eq '^boundary-witness/schemas/' "$real_listing" \
    || fail "real-repository archive is missing schemas/"
  grep -Eq '^boundary-witness/Cargo.toml$' "$real_listing" \
    || fail "real-repository archive is missing Cargo.toml"
  assert_not_in_archive "$real_listing" '^boundary-witness/docs/'
  assert_not_in_archive "$real_listing" '^boundary-witness/target/'

fi

printf 'archive-policy: ok\n'

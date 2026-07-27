#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
runner="${repo_root}/tools/experiment/run-d2-small.sh"

fail() {
  printf 'd2-runner-corpus-policy: %s\n' "$*" >&2
  exit 1
}

[[ -x "$runner" ]] || fail "missing executable runner: $runner"

if grep -F 'fuzz run "$target" "$input_corpus"' "$runner" >/dev/null; then
  fail "coverage campaign must not pass shared input_corpus directly to libFuzzer"
fi

grep -F 'campaign_corpus=' "$runner" >/dev/null \
  || fail "runner must create a per-campaign corpus path"
grep -F 'cp -R "$input_corpus/."' "$runner" >/dev/null \
  || fail "runner must copy base corpus into each campaign corpus"
grep -F 'fuzz run "$target" "$campaign_corpus"' "$runner" >/dev/null \
  || fail "runner must pass the per-campaign corpus to libFuzzer"

printf 'd2-runner-corpus-policy: ok\n'

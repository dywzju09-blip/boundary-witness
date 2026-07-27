#!/usr/bin/env bash
set -euo pipefail

image="${1:-boundary-witness-d0:test}"
expected_commit="${BW_EXPECTED_COMMIT:-}"
expected_archive_sha256="${BW_EXPECTED_ARCHIVE_SHA256:-}"

fail() {
  printf 'd0-image-smoke: %s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker image inspect "$image" >/dev/null 2>&1 || fail "image not found: $image"

revision="$(
  docker image inspect \
    --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
    "$image"
)"
archive_sha256="$(
  docker image inspect \
    --format '{{ index .Config.Labels "org.boundarywitness.archive-sha256" }}' \
    "$image"
)"

if [[ -n "$expected_commit" && "$revision" != "$expected_commit" ]]; then
  fail "label revision mismatch: got $revision expected $expected_commit"
fi
if [[ -n "$expected_archive_sha256" && "$archive_sha256" != "$expected_archive_sha256" ]]; then
  fail "label archive sha256 mismatch: got $archive_sha256 expected $expected_archive_sha256"
fi
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || fail "missing or invalid revision label"
[[ "$archive_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "missing or invalid archive sha256 label"

docker run --rm --network none "$image" bash -lc '
set -euo pipefail
[[ "$(id -u)" != "0" ]]
[[ "$PWD" == "/workspace" ]]
rustc --version | grep -F "rustc 1.97.0"
cargo --version >/dev/null
rustup run nightly-2026-07-08 rustc --version | grep -F "nightly"
clang --version >/dev/null
zstd --version >/dev/null
bw --help >/dev/null
'

printf '{ "image": "%s", "labels": "ok", "toolchains": "ok", "network_probe": "blocked" }\n' "$image"

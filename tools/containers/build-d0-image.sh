#!/usr/bin/env bash
set -euo pipefail

image_tag="${1:-boundary-witness-d0:test}"
build_network="${BW_DOCKER_BUILD_NETWORK:-default}"
ubuntu_apt_mirror="${BW_UBUNTU_APT_MIRROR:-http://mirrors.ustc.edu.cn/ubuntu}"
rustup_init_url="${BW_RUSTUP_INIT_URL:-https://mirrors.tuna.tsinghua.edu.cn/rustup/rustup/dist/x86_64-unknown-linux-gnu/rustup-init}"
rustup_dist_server="${BW_RUSTUP_DIST_SERVER:-https://mirrors.ustc.edu.cn/rust-static}"
rustup_update_root="${BW_RUSTUP_UPDATE_ROOT:-https://mirrors.ustc.edu.cn/rust-static/rustup}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
candidate_root="$(cd "${script_dir}/../.." && pwd)"
git_available=0
if git -C "$candidate_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  repo_root="$(git -C "$candidate_root" rev-parse --show-toplevel)"
  git_available=1
else
  repo_root="$candidate_root"
fi
lock_path="${repo_root}/infra/containers/image-lock.json"

fail() {
  printf 'build-d0-image: %s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "docker is not installed"

if [[ "$git_available" == "1" && "${BW_ALLOW_DIRTY_IMAGE_BUILD:-0}" != "1" ]]; then
  git -C "$repo_root" diff --quiet || fail "worktree has unstaged changes; commit first or set BW_ALLOW_DIRTY_IMAGE_BUILD=1 for local-only testing"
  git -C "$repo_root" diff --cached --quiet || fail "worktree has staged changes; commit first or set BW_ALLOW_DIRTY_IMAGE_BUILD=1 for local-only testing"
  if [[ -n "$(git -C "$repo_root" ls-files --others --exclude-standard)" ]]; then
    fail "worktree has untracked files; commit first or set BW_ALLOW_DIRTY_IMAGE_BUILD=1 for local-only testing"
  fi
fi

if [[ "$git_available" == "1" ]]; then
  source_commit="$(git -C "$repo_root" rev-parse HEAD)"
  archive_path="$(mktemp -t boundary-witness-d0-source.XXXXXX.tar)"
  archive_gz_path="${archive_path}.gz"

  cleanup() {
    rm -f "$archive_path" "$archive_gz_path"
  }
  trap cleanup EXIT

  git -C "$repo_root" archive --format=tar --prefix=boundary-witness/ HEAD > "$archive_path"
  gzip -n -c "$archive_path" > "$archive_gz_path"
  if command -v sha256sum >/dev/null 2>&1; then
    archive_sha256="$(sha256sum "$archive_gz_path" | awk '{print $1}')"
  else
    archive_sha256="$(shasum -a 256 "$archive_gz_path" | awk '{print $1}')"
  fi
else
  source_commit="${BW_SOURCE_COMMIT:-}"
  archive_sha256="${BW_ARCHIVE_SHA256:-}"
  [[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || fail "BW_SOURCE_COMMIT must be set to the deployed commit when building from an archive without .git"
  [[ "$archive_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "BW_ARCHIVE_SHA256 must be set to the deployed archive sha256 when building from an archive without .git"
fi

docker build \
  --file "${repo_root}/infra/containers/d0.Dockerfile" \
  --network "$build_network" \
  --label "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --build-arg "SOURCE_COMMIT=${source_commit}" \
  --build-arg "ARCHIVE_SHA256=${archive_sha256}" \
  --build-arg "UBUNTU_APT_MIRROR=${ubuntu_apt_mirror}" \
  --build-arg "RUSTUP_INIT_URL=${rustup_init_url}" \
  --build-arg "RUSTUP_DIST_SERVER=${rustup_dist_server}" \
  --build-arg "RUSTUP_UPDATE_ROOT=${rustup_update_root}" \
  --tag "$image_tag" \
  "$repo_root"

image_id="$(docker image inspect --format '{{ .Id }}' "$image_tag")"
repo_digest="$(
  docker image inspect \
    --format '{{ if .RepoDigests }}{{ index .RepoDigests 0 }}{{ end }}' \
    "$image_tag"
)"

mkdir -p "$(dirname "$lock_path")"
tmp_lock="$(mktemp -t boundary-witness-d0-lock.XXXXXX.json)"
IMAGE_TAG="$image_tag" \
BUILD_NETWORK="$build_network" \
UBUNTU_APT_MIRROR="$ubuntu_apt_mirror" \
RUSTUP_INIT_URL="$rustup_init_url" \
RUSTUP_DIST_SERVER="$rustup_dist_server" \
RUSTUP_UPDATE_ROOT="$rustup_update_root" \
IMAGE_ID="$image_id" \
REPO_DIGEST="$repo_digest" \
SOURCE_COMMIT="$source_commit" \
ARCHIVE_SHA256="$archive_sha256" \
python3 - "$tmp_lock" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

payload = {
    "schema_version": "boundary-witness.image-lock/0.1",
    "image_tag": os.environ["IMAGE_TAG"],
    "build_network": os.environ["BUILD_NETWORK"],
    "ubuntu_apt_mirror": os.environ["UBUNTU_APT_MIRROR"],
    "rustup_init_url": os.environ["RUSTUP_INIT_URL"],
    "rustup_dist_server": os.environ["RUSTUP_DIST_SERVER"],
    "rustup_update_root": os.environ["RUSTUP_UPDATE_ROOT"],
    "image_id": os.environ["IMAGE_ID"],
    "repo_digest": os.environ["REPO_DIGEST"],
    "source_commit": os.environ["SOURCE_COMMIT"],
    "archive_sha256": os.environ["ARCHIVE_SHA256"],
    "base_image": "docker.1panel.live/library/ubuntu@sha256:0d779ea97881505f5ef0039336ee85edba27519bdba968c284c86ee066a973c8",
    "base_upstream": "docker.io/library/ubuntu@sha256:0d779ea97881505f5ef0039336ee85edba27519bdba968c284c86ee066a973c8",
    "rust_stable": "1.97.0",
    "rust_nightly": "nightly-2026-07-08",
    "built_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(payload, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY
mv "$tmp_lock" "$lock_path"

printf 'image=%s\n' "$image_tag"
printf 'source_commit=%s\n' "$source_commit"
printf 'archive_sha256=%s\n' "$archive_sha256"
printf 'image_id=%s\n' "$image_id"
printf 'lock_path=%s\n' "$lock_path"

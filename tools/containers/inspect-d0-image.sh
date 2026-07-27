#!/usr/bin/env bash
set -euo pipefail

image="${1:-boundary-witness-d0:test}"

fail() {
  printf 'inspect-d0-image: %s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker image inspect "$image" >/dev/null 2>&1 || fail "image not found: $image"

docker image inspect \
  --format '{
  "image": "{{ .RepoTags }}",
  "image_id": "{{ .Id }}",
  "revision": "{{ index .Config.Labels "org.opencontainers.image.revision" }}",
  "archive_sha256": "{{ index .Config.Labels "org.boundarywitness.archive-sha256" }}",
  "base_image": "{{ index .Config.Labels "org.boundarywitness.base-image" }}",
  "rust_stable": "{{ index .Config.Labels "org.boundarywitness.rust-stable" }}",
  "rust_nightly": "{{ index .Config.Labels "org.boundarywitness.rust-nightly" }}",
  "ubuntu_apt_mirror": "{{ index .Config.Labels "org.boundarywitness.ubuntu-apt-mirror" }}",
  "rustup_init_url": "{{ index .Config.Labels "org.boundarywitness.rustup-init-url" }}",
  "rustup_dist_server": "{{ index .Config.Labels "org.boundarywitness.rustup-dist-server" }}",
  "rustup_update_root": "{{ index .Config.Labels "org.boundarywitness.rustup-update-root" }}"
}' \
  "$image"

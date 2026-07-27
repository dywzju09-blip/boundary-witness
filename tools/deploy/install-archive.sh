#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: install-archive.sh --archive <source.tar.zst> --sha256 <source.sha256> --manifest <deployment.json> [--root <install-root>]

Verifies and installs a committed-source archive under:
  <install-root>/deployments/<commit>
EOF
}

fail() {
  printf 'install-archive: %s\n' "$*" >&2
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

archive=""
sha_file=""
manifest=""
install_root="${BW_DEPLOY_ROOT:-/root/boundary-witness}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive)
      [[ $# -ge 2 ]] || fail "--archive requires a value"
      archive="$2"
      shift 2
      ;;
    --sha256)
      [[ $# -ge 2 ]] || fail "--sha256 requires a value"
      sha_file="$2"
      shift 2
      ;;
    --manifest)
      [[ $# -ge 2 ]] || fail "--manifest requires a value"
      manifest="$2"
      shift 2
      ;;
    --root)
      [[ $# -ge 2 ]] || fail "--root requires a value"
      install_root="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$archive" ]] || fail "--archive is required"
[[ -n "$sha_file" ]] || fail "--sha256 is required"
[[ -n "$manifest" ]] || fail "--manifest is required"
command -v zstd >/dev/null 2>&1 || fail "zstd is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"${script_dir}/verify-archive.sh" --archive "$archive" --sha256 "$sha_file" --manifest "$manifest" >/dev/null

commit="$(
  python3 - "$manifest" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    print(json.load(f)["commit"])
PY
)"
archive_sha="$(sha256_file "$archive")"

install_root="$(mkdir -p "$install_root" && cd "$install_root" && pwd -P)"
deployments="${install_root}/deployments"
mkdir -p "$deployments"

target="${deployments}/${commit}"
if [[ -e "$target" ]]; then
  existing_sha_file="${target}/archive.sha256"
  [[ -f "$existing_sha_file" ]] || fail "deployment already exists without archive.sha256: $target"
  existing_sha="$(awk 'NR == 1 {print $1}' "$existing_sha_file")"
  if [[ "$existing_sha" == "$archive_sha" ]]; then
    printf '{"status":"ok","mode":"already-installed","commit":"%s","path":"%s"}\n' "$commit" "$target"
    exit 0
  fi
  fail "deployment already exists with different content: $target"
fi

tmp_dir="$(mktemp -d "${deployments}/.${commit}.install.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

extract_dir="${tmp_dir}/extract"
mkdir -p "$extract_dir"
zstd -dc "$archive" | tar -x -C "$extract_dir"
[[ -d "${extract_dir}/boundary-witness" ]] || fail "archive did not extract expected source directory"

mv "${extract_dir}/boundary-witness" "${tmp_dir}/source"
cp "$manifest" "${tmp_dir}/deployment.json"
printf '%s  source.tar.zst\n' "$archive_sha" > "${tmp_dir}/archive.sha256"
chmod 0444 "${tmp_dir}/deployment.json" "${tmp_dir}/archive.sha256"

mv "$tmp_dir" "$target"
trap - EXIT

printf '{"status":"ok","mode":"installed","commit":"%s","path":"%s"}\n' "$commit" "$target"

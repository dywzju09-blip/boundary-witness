#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: create-archive.sh [--profile full-experiment|staging-builder|blind-runtime] --repo <git-repo> --out <output-dir>

Creates a committed-source deployment bundle:
  source.tar.zst
  source.sha256
  deployment.json
EOF
}

fail() {
  printf 'create-archive: %s\n' "$*" >&2
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

repo="."
out_dir=""
profile="full-experiment"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      [[ $# -ge 2 ]] || fail "--profile requires a value"
      profile="$2"
      shift 2
      ;;
    --repo)
      [[ $# -ge 2 ]] || fail "--repo requires a value"
      repo="$2"
      shift 2
      ;;
    --out)
      [[ $# -ge 2 ]] || fail "--out requires a value"
      out_dir="$2"
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

[[ -n "$out_dir" ]] || fail "--out is required"
case "$profile" in
  full-experiment|staging-builder|blind-runtime) ;;
  *) fail "--profile must be full-experiment, staging-builder, or blind-runtime" ;;
esac
command -v git >/dev/null 2>&1 || fail "git is required"
command -v zstd >/dev/null 2>&1 || fail "zstd is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

repo="$(cd "$repo" && pwd -P)"
git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not a git repository: $repo"
repo="$(cd "$(git -C "$repo" rev-parse --show-toplevel)" && pwd -P)"

git -C "$repo" rev-parse --verify HEAD >/dev/null 2>&1 || fail "repository has no HEAD commit"
git -C "$repo" diff --quiet -- || fail "tracked working tree has uncommitted changes"
git -C "$repo" diff --cached --quiet -- || fail "index has staged but uncommitted changes"

commit="$(git -C "$repo" rev-parse HEAD)"
repo_name="$(basename "$repo")"
out_dir="$(mkdir -p "$out_dir" && cd "$out_dir" && pwd -P)"

archive="${out_dir}/source.tar.zst"
sha_file="${out_dir}/source.sha256"
manifest="${out_dir}/deployment.json"

for path in "$archive" "$sha_file" "$manifest"; do
  [[ ! -e "$path" ]] || fail "refusing to overwrite existing output: $path"
done

tmp_dir="$(mktemp -d "${out_dir}/.create-archive.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

archive_tmp="${tmp_dir}/source.tar.zst"
sha_tmp="${tmp_dir}/source.sha256"
manifest_tmp="${tmp_dir}/deployment.json"

export_dir="${tmp_dir}/export"
mkdir -p "$export_dir"
git -C "$repo" archive --format=tar --prefix=boundary-witness/ HEAD \
  | tar -x -C "$export_dir"
rm -rf \
  "${export_dir}/boundary-witness/experiments/artifacts" \
  "${export_dir}/boundary-witness/docs" \
  "${export_dir}/boundary-witness/target" \
  "${export_dir}/boundary-witness/runs" \
  "${export_dir}/boundary-witness/scratch"
if [[ "$profile" != "full-experiment" ]]; then
  rm -rf "${export_dir}/boundary-witness/experiments/ground-truth"
fi
if [[ "$profile" == "blind-runtime" ]]; then
  rm -rf \
    "${export_dir}/boundary-witness/benchmarks/historical-cves" \
    "${export_dir}/boundary-witness/experiments/schemas" \
    "${export_dir}/boundary-witness/fixtures"
fi
if [[ "$profile" == "blind-runtime" ]]; then
  python3 - "${export_dir}/boundary-witness" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
forbidden = (
    "vulnerable",
    "fixed",
    "ground-truth",
    "ground_truth",
    "cve-",
    "ghsa-",
    "advisory",
    "poc",
    "proof-of-concept",
    "expected-result",
    "expected_result",
)

def contains_forbidden_token(value: str, token: str) -> bool:
    if token == "poc":
        return bool(re.search(r"(?<![0-9a-z])poc(?![0-9a-z])", value))
    return token in value

for path in root.rglob("*"):
    relative = path.relative_to(root).as_posix().lower()
    if any(contains_forbidden_token(relative, token) for token in forbidden):
        raise SystemExit(f"blind-runtime archive path contains forbidden token: {relative}")
PY
fi
tar_tmp="${tmp_dir}/source.tar"
python3 - "$export_dir" "$tar_tmp" <<'PY'
import pathlib
import stat
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
tar_path = sys.argv[2]
paths = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())

with tarfile.open(tar_path, "w", format=tarfile.GNU_FORMAT) as archive:
    for path in paths:
        relative = path.relative_to(root).as_posix()
        source_stat = path.lstat()
        if stat.S_ISDIR(source_stat.st_mode):
            info = tarfile.TarInfo(relative + "/")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.size = 0
            file_object = None
        elif stat.S_ISREG(source_stat.st_mode):
            info = tarfile.TarInfo(relative)
            info.type = tarfile.REGTYPE
            info.mode = 0o755 if source_stat.st_mode & 0o111 else 0o644
            info.size = source_stat.st_size
            file_object = path.open("rb")
        else:
            raise SystemExit(f"unsupported deployment archive path: {relative}")
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        info.mtime = 0
        try:
            archive.addfile(info, file_object)
        finally:
            if file_object is not None:
                file_object.close()
PY

zstd -q -19 -f "$tar_tmp" -o "$archive_tmp"

archive_sha="$(sha256_file "$archive_tmp")"
printf '%s  source.tar.zst\n' "$archive_sha" > "$sha_tmp"

BW_REPO_NAME="$repo_name" \
BW_COMMIT="$commit" \
BW_ARCHIVE_SHA256="$archive_sha" \
BW_DEPLOYMENT_PROFILE="$profile" \
python3 - "$manifest_tmp" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

manifest_path = sys.argv[1]
allowed_top_level = [
    ".dockerignore",
    ".gitattributes",
    ".github",
    ".gitignore",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "Cargo.lock",
    "Cargo.toml",
    "LICENSE",
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "README.md",
    "SECURITY.md",
    "benchmarks",
    "compiler",
    "contracts",
    "crates",
    "docs",
    "experiments",
    "fixtures",
    "infra",
    "rust-toolchain.toml",
    "schemas",
    "tests",
    "tools",
]

manifest = {
    "schema_version": "boundary-witness.deployment/0.1",
    "repository": os.environ["BW_REPO_NAME"],
    "commit": os.environ["BW_COMMIT"],
    "archive_name": "source.tar.zst",
    "archive_format": "tar+zstd",
    "archive_sha256": os.environ["BW_ARCHIVE_SHA256"],
    "source_prefix": "boundary-witness/",
    "allowed_top_level": allowed_top_level,
    "profile": os.environ["BW_DEPLOYMENT_PROFILE"],
    "generated_at_utc": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    "tool_version": "create-archive.sh/0.1",
}

with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
PY

mv "$archive_tmp" "$archive"
mv "$sha_tmp" "$sha_file"
mv "$manifest_tmp" "$manifest"

printf '{"status":"ok","commit":"%s","archive_sha256":"%s","out":"%s"}\n' \
  "$commit" "$archive_sha" "$out_dir"

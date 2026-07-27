#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: verify-archive.sh --archive <source.tar.zst> --sha256 <source.sha256> --manifest <deployment.json>

Verifies archive digest, manifest consistency, and safe tar contents.
EOF
}

fail() {
  printf 'verify-archive: %s\n' "$*" >&2
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

lower_hex() {
  printf '%s' "$1" | tr 'A-F' 'a-f'
}

archive=""
sha_file=""
manifest=""

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
[[ -f "$archive" ]] || fail "archive not found: $archive"
[[ -f "$sha_file" ]] || fail "sha256 file not found: $sha_file"
[[ -f "$manifest" ]] || fail "manifest not found: $manifest"
command -v zstd >/dev/null 2>&1 || fail "zstd is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

expected="$(awk 'NR == 1 {print $1}' "$sha_file")"
[[ "$expected" =~ ^[0-9A-Fa-f]{64}$ ]] || fail "invalid sha256 file format"
actual="$(sha256_file "$archive")"
expected="$(lower_hex "$expected")"
actual="$(lower_hex "$actual")"
[[ "$actual" == "$expected" ]] || fail "sha256 mismatch: actual=$actual expected=$expected"

tmp_dir="$(mktemp -d -t bw-verify-archive.XXXXXX)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

tar_path="${tmp_dir}/source.tar"
zstd -dc "$archive" > "$tar_path"

python3 - "$manifest" "$tar_path" "$actual" <<'PY'
import json
import pathlib
import re
import sys
import tarfile

manifest_path, tar_path, archive_sha256 = sys.argv[1:4]

allowed_top_level = [
    ".dockerignore",
    ".gitattributes",
    ".gitignore",
    "AGENTS.md",
    "Cargo.lock",
    "Cargo.toml",
    "benchmarks",
    "compiler",
    "contracts",
    "crates",
    "experiments",
    "fixtures",
    "infra",
    "rust-toolchain.toml",
    "tests",
    "tools",
]
blocked_top_level = {
    ".git",
    ".superpowers",
    ".worktrees",
    "dist",
    "docs",
    "runs",
    "scratch",
    "target",
}

def die(message: str) -> None:
    print(f"verify-archive: {message}", file=sys.stderr)
    sys.exit(1)

with open(manifest_path, "r", encoding="utf-8") as f:
    manifest = json.load(f)

required = {
    "schema_version",
    "repository",
    "commit",
    "archive_name",
    "archive_format",
    "archive_sha256",
    "source_prefix",
    "allowed_top_level",
    "generated_at_utc",
    "tool_version",
}
missing = sorted(required - set(manifest))
if missing:
    die(f"manifest missing required fields: {', '.join(missing)}")

if manifest["schema_version"] != "boundary-witness.deployment/0.1":
    die("unsupported manifest schema_version")
if manifest["archive_name"] != "source.tar.zst":
    die("unexpected manifest archive_name")
if manifest["archive_format"] != "tar+zstd":
    die("unexpected manifest archive_format")
if manifest["source_prefix"] != "boundary-witness/":
    die("unexpected manifest source_prefix")
if manifest["allowed_top_level"] != allowed_top_level:
    die("manifest allowed_top_level does not match deployment policy")
profile = manifest.get("profile", "full-experiment")
if profile not in {"full-experiment", "staging-builder", "blind-runtime"}:
    die(f"unsupported deployment profile: {profile}")
if not re.fullmatch(r"[0-9a-f]{40}", manifest["commit"]):
    die("manifest commit must be a full lowercase git SHA-1")
if manifest["archive_sha256"].lower() != archive_sha256:
    die("manifest archive_sha256 does not match archive")

prefix = manifest["source_prefix"]
seen_members = 0
seen_cargo_toml = False
blind_forbidden_tokens = (
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

with tarfile.open(tar_path, "r:") as tf:
    for member in tf.getmembers():
        name = member.name
        seen_members += 1
        if not name or "\x00" in name:
            die("archive contains an empty or NUL path")
        if name.startswith("/") or name.startswith("\\"):
            die(f"archive contains absolute path: {name}")
        raw_parts = pathlib.PurePosixPath(name).parts
        if ".." in raw_parts:
            die(f"archive contains parent traversal: {name}")
        if name != prefix.rstrip("/") and not name.startswith(prefix):
            die(f"archive member is outside expected prefix: {name}")

        rel = name[len(prefix):] if name.startswith(prefix) else ""
        rel = rel.rstrip("/")
        if not rel:
            continue

        parts = rel.split("/")
        if any(part in ("", ".", "..") for part in parts):
            die(f"archive contains unsafe path component: {name}")
        top = parts[0]
        if top in blocked_top_level:
            die(f"archive contains blocked top-level path: {top}")
        if top not in allowed_top_level:
            die(f"archive contains unknown top-level path: {top}")
        if rel == "Cargo.toml":
            seen_cargo_toml = True
        rel_lower = rel.lower()
        if profile in {"staging-builder", "blind-runtime"}:
            if rel_lower == "experiments/ground-truth" or rel_lower.startswith("experiments/ground-truth/"):
                die(f"{profile} archive contains ground truth path: {rel}")
        if profile == "blind-runtime":
            if rel_lower == "benchmarks/historical-cves" or rel_lower.startswith("benchmarks/historical-cves/"):
                die(f"blind-runtime archive contains historical benchmark path: {rel}")
            if rel_lower == "experiments/schemas" or rel_lower.startswith("experiments/schemas/"):
                die(f"blind-runtime archive contains schema path: {rel}")
            if rel_lower == "fixtures" or rel_lower.startswith("fixtures/"):
                die(f"blind-runtime archive contains fixture path: {rel}")
            if any(contains_forbidden_token(rel_lower, token) for token in blind_forbidden_tokens):
                die(f"blind-runtime archive path contains forbidden token: {rel}")

        if member.ischr() or member.isblk() or member.isfifo():
            die(f"archive contains unsupported special file: {name}")
        if member.issym() or member.islnk():
            link = member.linkname
            link_parts = pathlib.PurePosixPath(link).parts
            if link.startswith("/") or link.startswith("\\") or ".." in link_parts:
                die(f"archive contains escaping link: {name} -> {link}")

if seen_members == 0:
    die("archive has no members")
if not seen_cargo_toml:
    die("archive is missing Cargo.toml")

print(json.dumps({
    "status": "ok",
    "commit": manifest["commit"],
    "archive_sha256": archive_sha256,
    "profile": profile,
}, sort_keys=True))
PY

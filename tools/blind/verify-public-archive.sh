#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: verify-public-archive.sh BLIND_PACK_ARCHIVE BLIND_PACK_SHA256 BLIND_DEPLOYMENT_JSON

Snapshots and verifies the archive digest, deployment binding, canonical archive
metadata, and public-pack policy, then prints audit JSON.
EOF
}

fail() {
  printf 'verify-public-archive: %s\n' "$*" >&2
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

[[ $# -eq 3 ]] || {
  usage
  exit 1
}

archive_input="$1"
sha_input="$2"
deployment_input="$3"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v zstd >/dev/null 2>&1 || fail "zstd is required"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd -P)"
tmp_dir="$(mktemp -d -t bw-verify-public-archive.XXXXXX)"
tmp_dir="$(cd "$tmp_dir" && pwd -P)"
chmod 700 "$tmp_dir"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

archive="${tmp_dir}/blind-pack.tar.zst"
sha_file="${tmp_dir}/blind-pack.sha256"
deployment="${tmp_dir}/blind-deployment.json"
python3 - \
  "$archive_input" "$archive" \
  "$sha_input" "$sha_file" \
  "$deployment_input" "$deployment" <<'PY'
import os
import stat
import sys

arguments = sys.argv[1:]
for source, destination in zip(arguments[::2], arguments[1::2]):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
        before = os.fstat(descriptor)
    except OSError as error:
        raise SystemExit(f"verify-public-archive: cannot snapshot input {source}: {error}")
    if not stat.S_ISREG(before.st_mode):
        os.close(descriptor)
        raise SystemExit(f"verify-public-archive: input is not a regular file: {source}")
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as input_file, open(destination, "xb") as output_file:
            while True:
                chunk = input_file.read(1024 * 1024)
                if not chunk:
                    break
                output_file.write(chunk)
            after = os.fstat(input_file.fileno())
    except OSError as error:
        raise SystemExit(f"verify-public-archive: cannot snapshot input {source}: {error}")
    stable = (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )
    if not stable:
        raise SystemExit(f"verify-public-archive: input changed while snapshotting: {source}")
    os.chmod(destination, 0o600)
PY

expected="$(python3 - "$sha_file" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.fullmatch(r"([0-9a-f]{64})  blind-pack\.tar\.zst\n?", text)
if not match:
    raise SystemExit("verify-public-archive: invalid sha256 file format")
print(match.group(1))
PY
)"
actual="$(sha256_file "$archive")"
[[ "$actual" == "$expected" ]] \
  || fail "archive sha256 mismatch: actual=$actual expected=$expected"

deployment_values="$(BW_ARCHIVE_SHA256="$actual" python3 - "$deployment" <<'PY'
from datetime import datetime
import json
import os
import pathlib
import re
import sys

required_fields = {
    "method_commit",
    "public_manifest_sha256",
    "archive_sha256",
    "created_at_utc",
    "source_git_status",
    "tool_version",
}
forbidden_tokens = (
    "private", "ground-truth", "ground_truth", "cve-", "ghsa-", "advisory", "poc",
)
supported_tool_versions = {"create-public-archive.sh/0.2"}

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

try:
    deployment_text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    deployment = json.loads(deployment_text, object_pairs_hook=reject_duplicate_keys)
except (OSError, UnicodeError, ValueError) as error:
    raise SystemExit(f"verify-public-archive: invalid deployment JSON: {error}")
if not isinstance(deployment, dict) or set(deployment) != required_fields:
    raise SystemExit("verify-public-archive: deployment JSON must contain exactly the supported fields")
if any(not isinstance(key, str) for key in deployment) or any(
    not isinstance(value, str) for value in deployment.values()
):
    raise SystemExit("verify-public-archive: deployment keys and values must be strings")
for text in (*deployment.keys(), *deployment.values()):
    lowercase = text.lower()
    if any(token in lowercase for token in forbidden_tokens):
        raise SystemExit("verify-public-archive: deployment JSON contains forbidden public metadata")
canonical_text = json.dumps(deployment, indent=2, sort_keys=True) + "\n"
if deployment_text != canonical_text:
    raise SystemExit("verify-public-archive: deployment JSON is not canonically serialized")
for field, length in (("method_commit", 40), ("public_manifest_sha256", 64), ("archive_sha256", 64)):
    value = deployment[field]
    if re.fullmatch(f"[0-9a-f]{{{length}}}", value) is None:
        raise SystemExit(f"verify-public-archive: invalid deployment field: {field}")
if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", deployment["created_at_utc"]) is None:
    raise SystemExit("verify-public-archive: invalid deployment field: created_at_utc")
try:
    datetime.strptime(deployment["created_at_utc"], "%Y-%m-%dT%H:%M:%SZ")
except ValueError as error:
    raise SystemExit(f"verify-public-archive: invalid deployment field: created_at_utc: {error}")
if deployment["source_git_status"] != "clean":
    raise SystemExit("verify-public-archive: invalid deployment field: source_git_status")
if deployment["tool_version"] not in supported_tool_versions:
    raise SystemExit("verify-public-archive: unsupported deployment tool_version")
if deployment["archive_sha256"] != os.environ["BW_ARCHIVE_SHA256"]:
    raise SystemExit("verify-public-archive: deployment archive_sha256 mismatch")
print(deployment["method_commit"])
print(deployment["public_manifest_sha256"])
PY
)"
deployment_method_commit="$(sed -n '1p' <<<"$deployment_values")"
deployment_manifest_sha="$(sed -n '2p' <<<"$deployment_values")"

python3 - "$archive" <<'PY'
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
cursor = 0

def die(message: str) -> None:
    raise SystemExit(f"verify-public-archive: {message}")

def take(length: int, label: str) -> bytes:
    global cursor
    end = cursor + length
    if end > len(data):
        die(f"truncated Zstandard frame while reading {label}")
    value = data[cursor:end]
    cursor = end
    return value

if take(4, "magic") != bytes.fromhex("28b52ffd"):
    die("archive is not exactly one standard Zstandard frame")

descriptor = take(1, "frame header descriptor")[0]
if descriptor & 0x18:
    die("Zstandard frame header uses reserved bits")
frame_content_size_flag = descriptor >> 6
single_segment = bool(descriptor & 0x20)
has_checksum = bool(descriptor & 0x04)
dictionary_id_flag = descriptor & 0x03

if not single_segment:
    take(1, "window descriptor")

dictionary_id_size = (0, 1, 2, 4)[dictionary_id_flag]
take(dictionary_id_size, "dictionary id")
if frame_content_size_flag == 0:
    frame_content_size_length = 1 if single_segment else 0
else:
    frame_content_size_length = (2, 4, 8)[frame_content_size_flag - 1]
take(frame_content_size_length, "frame content size")

last_block = False
while not last_block:
    block_header = int.from_bytes(take(3, "block header"), "little")
    last_block = bool(block_header & 1)
    block_type = (block_header >> 1) & 0x03
    block_size = block_header >> 3
    if block_type == 3:
        die("Zstandard frame contains a reserved block type")
    payload_size = 1 if block_type == 1 else block_size
    take(payload_size, "block payload")

if has_checksum:
    take(4, "content checksum")
if cursor != len(data):
    die("archive contains skippable, concatenated, or trailing Zstandard data")
PY

tar_path="${tmp_dir}/blind-pack.tar"
extract_dir="${tmp_dir}/pack"
mkdir -m 700 "$extract_dir"
zstd -q -dc "$archive" > "$tar_path"

python3 - "$tar_path" <<'PY'
import pathlib
import stat
import sys
import tarfile

tar_path = sys.argv[1]
required = {"cases", "checksums.sha256", "manifest.json", "policy.toml"}
root_files = {"checksums.sha256", "manifest.json", "policy.toml"}
forbidden_tokens = (
    "private", "ground-truth", "ground_truth", "cve-", "ghsa-", "advisory", "poc",
)

def die(message: str) -> None:
    print(f"verify-public-archive: {message}", file=sys.stderr)
    raise SystemExit(1)

def parse_octal(field: bytes, label: str) -> int:
    value = field.rstrip(b"\0 ").lstrip(b" ")
    if not value or any(byte < ord("0") or byte > ord("7") for byte in value):
        die(f"archive contains invalid tar {label}")
    return int(value, 8)

tar_bytes = pathlib.Path(tar_path).read_bytes()
block_size = 512
zero_block = bytes(block_size)
if not tar_bytes or len(tar_bytes) % block_size != 0:
    die("raw tar stream is not aligned to 512-byte records")

offset = 0
zero_blocks = 0
end_of_archive = False
raw_member_count = 0
raw_headers = []
while offset < len(tar_bytes):
    header = tar_bytes[offset:offset + block_size]
    offset += block_size
    if end_of_archive:
        if header != zero_block:
            die("raw tar stream contains nonzero data after end-of-archive padding")
        continue
    if header == zero_block:
        zero_blocks += 1
        if zero_blocks == 2:
            end_of_archive = True
        continue
    if zero_blocks:
        die("raw tar stream contains an incomplete end-of-archive marker")

    expected_checksum = parse_octal(header[148:156], "header checksum")
    actual_checksum = sum(header[:148]) + (8 * ord(" ")) + sum(header[156:])
    if actual_checksum != expected_checksum:
        die("raw tar stream contains an invalid header checksum")

    typeflag = header[156:157]
    if typeflag not in {b"0", b"5"}:
        display = typeflag.decode("ascii", "backslashreplace") if typeflag else "NUL"
        die(f"raw tar stream contains unsupported typeflag: {display}")
    size = parse_octal(header[124:136], "member size")
    if typeflag == b"5" and size != 0:
        die("raw tar stream contains a directory with data")
    padded_size = ((size + block_size - 1) // block_size) * block_size
    if offset + padded_size > len(tar_bytes):
        die("raw tar stream ends inside member data")
    if any(tar_bytes[offset + size:offset + padded_size]):
        die("raw tar stream contains nonzero member padding")
    offset += padded_size
    raw_headers.append(header)
    raw_member_count += 1

if not end_of_archive:
    die("raw tar stream is missing the end-of-archive marker")

try:
    with tarfile.open(tar_path, "r:") as archive:
        members = archive.getmembers()
except (OSError, tarfile.TarError) as error:
    die(f"invalid tar archive: {error}")

if len(members) != raw_member_count:
    die("raw tar headers do not match logical archive members")

names = [member.name for member in members]
if not names or names != sorted(names):
    die("archive member names are not sorted")
destinations = set()
for member, raw_header in zip(members, raw_headers):
    name = member.name
    if not name or name.startswith(("/", "\\")) or "\\" in name:
        die(f"archive contains unsafe path: {name}")
    raw_parts = name.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        die(f"archive member name is not canonical: {name}")
    canonical = pathlib.PurePosixPath(*raw_parts).as_posix()
    if name != canonical:
        die(f"archive member name is not canonical: {name}")
    if canonical in destinations:
        die(f"archive contains duplicate extraction destination: {name}")
    destinations.add(canonical)
    parts = tuple(raw_parts)
    if parts[0] not in {"manifest.json", "policy.toml", "checksums.sha256", "cases"}:
        die(f"archive contains disallowed path: {name}")
    if parts[0] != "cases" and len(parts) != 1:
        die(f"archive contains disallowed path: {name}")
    lowercase = name.lower()
    if ".git" in parts or any(token in lowercase for token in forbidden_tokens):
        die(f"archive contains forbidden path: {name}")
    if member.uid != 0 or member.gid != 0 or member.mtime != 0:
        die(f"archive contains non-canonical metadata: {name}")
    if member.uname or member.gname or member.pax_headers:
        die(f"archive contains non-canonical owner or extension metadata: {name}")
    if member.linkname:
        die(f"archive contains non-canonical link metadata: {name}")
    if member.isdir():
        if member.mode != 0o755 or name in root_files:
            die(f"archive contains non-canonical directory metadata: {name}")
    elif member.isfile():
        if member.mode not in {0o644, 0o755} or name == "cases":
            die(f"archive contains non-canonical file metadata: {name}")
        if name in root_files and member.mode != 0o644:
            die(f"archive contains non-canonical root file mode: {name}")
    else:
        die(f"archive contains unsupported file type: {name}")
    canonical = tarfile.TarInfo(name + "/" if member.isdir() else name)
    canonical.type = tarfile.DIRTYPE if member.isdir() else tarfile.REGTYPE
    canonical.mode = member.mode
    canonical.size = member.size
    canonical.uid = 0
    canonical.gid = 0
    canonical.uname = ""
    canonical.gname = ""
    canonical.mtime = 0
    try:
        canonical_header = canonical.tobuf(
            format=tarfile.USTAR_FORMAT,
            encoding="utf-8",
            errors="strict",
        )
    except (UnicodeError, ValueError) as error:
        die(f"archive member cannot be encoded as canonical USTAR: {name}: {error}")
    if raw_header != canonical_header:
        die(f"archive contains a non-canonical USTAR header: {name}")

if not required.issubset(destinations):
    die("archive is missing required public pack members")
PY

COPYFILE_DISABLE=1 tar -xf "$tar_path" -C "$extract_dir"
audit_json="$({
  cd "$repo_root"
  cargo run -p bw-blind-runner --bin bw-blind-audit --locked -- "$extract_dir"
})"
audit_method_commit="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["method_commit"])' <<<"$audit_json")" \
  || fail "bw-blind-audit returned invalid JSON"
audit_manifest_sha="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["manifest_sha256"])' <<<"$audit_json")" \
  || fail "bw-blind-audit returned invalid JSON"
[[ "$audit_method_commit" == "$deployment_method_commit" ]] \
  || fail "deployment method_commit mismatch"
[[ "$audit_manifest_sha" == "$deployment_manifest_sha" ]] \
  || fail "deployment public_manifest_sha256 mismatch"

BW_ARCHIVE_SHA256="$actual" \
BW_METHOD_COMMIT="$audit_method_commit" \
python3 -c '
import json
import os
import sys

audit = json.load(sys.stdin)
print(json.dumps({
    "archive_sha256": os.environ["BW_ARCHIVE_SHA256"],
    "method_commit": os.environ["BW_METHOD_COMMIT"],
    "manifest_sha256": audit["manifest_sha256"],
    "case_count": audit["case_count"],
}, sort_keys=True))
' <<<"$audit_json"

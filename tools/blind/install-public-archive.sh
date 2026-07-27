#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 022

usage() {
  cat >&2 <<'EOF'
usage: install-public-archive.sh BLIND_PACK_ARCHIVE BLIND_PACK_SHA256 BLIND_DEPLOYMENT_JSON

Installs to /root/boundary-witness/blind-packs/<archive_sha256>/.
For tests or non-root staging, BW_BLIND_PACKS_ROOT may override the packs root.
EOF
}

fail() {
  printf 'install-public-archive: %s\n' "$*" >&2
  exit 1
}

conflict() {
  printf 'install-public-archive: %s\n' "$*" >&2
  exit 2
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

tree_digest() {
  python3 - "$1" <<'PY'
import hashlib
import pathlib
import stat
import struct
import sys

root = pathlib.Path(sys.argv[1])
hasher = hashlib.sha256()

def add_directory(path: bytes, mode: int) -> None:
    hasher.update(b"D")
    hasher.update(struct.pack(">Q", len(path)))
    hasher.update(path)
    hasher.update(struct.pack(">I", mode))

def add_file(path: bytes, mode: int, size: int, content_sha256: bytes) -> None:
    hasher.update(b"F")
    hasher.update(struct.pack(">Q", len(path)))
    hasher.update(path)
    hasher.update(struct.pack(">I", mode))
    hasher.update(struct.pack(">Q", size))
    hasher.update(content_sha256)

root_metadata = root.lstat()
root_mode = stat.S_IMODE(root_metadata.st_mode)
if not stat.S_ISDIR(root_metadata.st_mode) or root_mode != 0o755:
    raise SystemExit(f"non-canonical installed root metadata: {root}")
add_directory(b".", root_mode)
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative_text = path.relative_to(root).as_posix()
    relative = relative_text.encode()
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISDIR(metadata.st_mode):
        if mode != 0o755:
            raise SystemExit(f"non-canonical directory mode in installed pack: {path}")
        add_directory(relative, mode)
    elif stat.S_ISREG(metadata.st_mode):
        expected_modes = {0o644} if relative_text in {"manifest.json", "policy.toml", "checksums.sha256"} else {0o644, 0o755}
        if mode not in expected_modes:
            raise SystemExit(f"non-canonical file mode in installed pack: {path}")
        content_hasher = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                content_hasher.update(chunk)
        add_file(relative, mode, metadata.st_size, content_hasher.digest())
    else:
        raise SystemExit(f"unsupported file type in installed pack: {path}")
print(hasher.hexdigest())
PY
}

validate_receipt_key() {
  python3 - "$receipt_key_id" "$receipt_key_hex" <<'PY'
import re
import sys

key_id, key_hex = sys.argv[1:]
forbidden = (
    "ground-truth",
    "ground_truth",
    "cve-",
    "ghsa-",
    "advisory",
    "poc",
    "proof-of-concept",
    "proof_of_concept",
    "expected-result",
    "expected_result",
    "expected result",
    "private",
)

if not key_id:
    raise SystemExit("invalid receipt key id: must be non-empty")
if any(token in key_id.lower() for token in forbidden):
    raise SystemExit("invalid receipt key id: contains forbidden public token")
if not key_hex or len(key_hex) % 2 or re.fullmatch(r"[0-9a-f]+", key_hex) is None:
    raise SystemExit("invalid receipt key hex: must be non-empty even-length lowercase hexadecimal")
PY
}

resolve_host_id() {
  if [[ -n "${BW_BLIND_HOST_ID:-}" ]]; then
    printf '%s\n' "$BW_BLIND_HOST_ID"
    return
  fi

  local hostname_value
  hostname_value="$(hostname 2>/dev/null || true)"
  if [[ -n "$hostname_value" ]]; then
    printf '%s\n' "$hostname_value"
  else
    printf '%s\n' "unknown-host"
  fi
}

validate_receipt_public_fields() {
  python3 - "$host_id" "$target" <<'PY'
import sys

host_id, installed_path = sys.argv[1:]
forbidden = (
    "ground-truth",
    "ground_truth",
    "cve-",
    "ghsa-",
    "advisory",
    "poc",
    "proof-of-concept",
    "proof_of_concept",
    "expected-result",
    "expected_result",
    "expected result",
    "private",
)

for field, value in (("host id", host_id), ("installed path", installed_path)):
    if not value:
        raise SystemExit(f"invalid receipt {field}: must be non-empty")
    if any(token in value.lower() for token in forbidden):
        raise SystemExit(f"invalid receipt {field}: contains forbidden public token")
PY
}

normalize_receipt_root_outside_target() {
  python3 - "$install_receipts_root" "$target" <<'PY'
import os
import sys

receipt_root = os.path.realpath(os.path.abspath(sys.argv[1]))
target = os.path.abspath(sys.argv[2])
if os.path.commonpath((receipt_root, target)) == target:
    raise SystemExit("install receipt root must not be inside installed pack")
print(receipt_root)
PY
}

emit_install_receipt() {
  local receipt_tmp receipt_path

  mkdir -p "$install_receipts_root"
  receipt_path="${install_receipts_root}/${archive_sha}.json"
  receipt_tmp="$(mktemp "${install_receipts_root}/.${archive_sha}.XXXXXX")"
  chmod 600 "$receipt_tmp"
  BW_RECEIPT_PATH="$receipt_tmp" \
  BW_ARCHIVE_SHA256="$archive_sha" \
  BW_DEPLOYMENT_JSON_SHA256="$deployment_json_sha" \
  BW_PUBLIC_MANIFEST_SHA256="$actual_manifest_sha" \
  BW_POLICY_SHA256="$policy_sha" \
  BW_TREE_SHA256="$incoming_digest" \
  BW_INSTALLED_PATH="$target" \
  BW_METHOD_COMMIT="$actual_method_commit" \
  BW_HOST_ID="$host_id" \
  BW_RECEIPT_KEY_ID="$receipt_key_id" \
  BW_RECEIPT_KEY_HEX="$receipt_key_hex" \
  python3 - <<'PY'
from datetime import datetime, timezone
import hashlib
import json
import os
import pathlib

payload = {
    "schema_version": "boundary-witness.blind-install-receipt/0.1",
    "installer_version": "install-public-archive.sh/0.3",
    "installer_commit": os.environ["BW_METHOD_COMMIT"],
    "method_commit": os.environ["BW_METHOD_COMMIT"],
    "archive_sha256": os.environ["BW_ARCHIVE_SHA256"],
    "deployment_json_sha256": os.environ["BW_DEPLOYMENT_JSON_SHA256"],
    "public_manifest_sha256": os.environ["BW_PUBLIC_MANIFEST_SHA256"],
    "policy_sha256": os.environ["BW_POLICY_SHA256"],
    "installed_pack_tree_sha256": os.environ["BW_TREE_SHA256"],
    "installed_path": os.environ["BW_INSTALLED_PATH"],
    "created_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "host_id": os.environ["BW_HOST_ID"],
}
canonical = json.dumps(
    payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
).encode("utf-8")
signature = hashlib.sha256(
    b"boundary-witness.receipt-test-signature/0.1\0"
    + os.environ["BW_RECEIPT_KEY_ID"].encode("utf-8")
    + b"\0"
    + canonical
    + b"\0"
    + bytes.fromhex(os.environ["BW_RECEIPT_KEY_HEX"])
).hexdigest()
payload["trust"] = {
    "key_id": os.environ["BW_RECEIPT_KEY_ID"],
    "signature_sha256": signature,
}
with pathlib.Path(os.environ["BW_RECEIPT_PATH"]).open("w", encoding="utf-8") as output:
    json.dump(payload, output, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    output.write("\n")
PY
  mv -f "$receipt_tmp" "$receipt_path"
  chmod 600 "$receipt_path"
  printf '%s\n' "$receipt_path"
}

print_install_result() {
  BW_ARCHIVE_SHA256="$archive_sha" \
  BW_INSTALL_PATH="$target" \
  BW_INSTALL_MODE="$1" \
  BW_INSTALL_RECEIPT="$2" \
  python3 - <<'PY'
import json
import os

print(json.dumps({
    "status": "ok",
    "mode": os.environ["BW_INSTALL_MODE"],
    "archive_sha256": os.environ["BW_ARCHIVE_SHA256"],
    "path": os.environ["BW_INSTALL_PATH"],
    "install_receipt": os.environ["BW_INSTALL_RECEIPT"],
}, sort_keys=True))
PY
}

[[ $# -eq 3 ]] || {
  usage
  exit 1
}

archive_input="$1"
sha_input="$2"
deployment_input="$3"
packs_root="${BW_BLIND_PACKS_ROOT:-/root/boundary-witness/blind-packs}"
install_receipts_root="${BW_BLIND_RECEIPTS_ROOT:-/root/boundary-witness/blind-receipts/install}"
receipt_key_id="${BW_BLIND_RECEIPT_KEY_ID:-}"
receipt_key_hex="${BW_BLIND_RECEIPT_KEY_HEX:-}"
host_id="$(resolve_host_id)"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v zstd >/dev/null 2>&1 || fail "zstd is required"
validate_receipt_key

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd -P)"
input_tmp="$(mktemp -d -t bw-install-public-archive-input.XXXXXX)"
input_tmp="$(cd "$input_tmp" && pwd -P)"
chmod 700 "$input_tmp"
tmp_dir=""
cleanup() {
  [[ -z "$tmp_dir" ]] || rm -rf "$tmp_dir"
  rm -rf "$input_tmp"
}
trap cleanup EXIT

archive="${input_tmp}/blind-pack.tar.zst"
sha_file="${input_tmp}/blind-pack.sha256"
deployment="${input_tmp}/blind-deployment.json"
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
        raise SystemExit(f"install-public-archive: cannot snapshot input {source}: {error}")
    if not stat.S_ISREG(before.st_mode):
        os.close(descriptor)
        raise SystemExit(f"install-public-archive: input is not a regular file: {source}")
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as input_file, open(destination, "xb") as output_file:
            while True:
                chunk = input_file.read(1024 * 1024)
                if not chunk:
                    break
                output_file.write(chunk)
            after = os.fstat(input_file.fileno())
    except OSError as error:
        raise SystemExit(f"install-public-archive: cannot snapshot input {source}: {error}")
    stable = (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )
    if not stable:
        raise SystemExit(f"install-public-archive: input changed while snapshotting: {source}")
    os.chmod(destination, 0o600)
PY

verify_json="$("${script_dir}/verify-public-archive.sh" "$archive" "$sha_file" "$deployment")"
archive_sha="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["archive_sha256"])' <<<"$verify_json")" \
  || fail "archive verifier returned invalid JSON"
expected_manifest_sha="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["manifest_sha256"])' <<<"$verify_json")" \
  || fail "archive verifier returned invalid JSON"
expected_method_commit="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["method_commit"])' <<<"$verify_json")" \
  || fail "archive verifier returned invalid JSON"
deployment_json_sha="$(sha256_file "$deployment")"

packs_root="$(python3 - "$packs_root" <<'PY'
import os
import sys

print(os.path.realpath(os.path.abspath(sys.argv[1])))
PY
)"
target="${packs_root}/${archive_sha}"
[[ ! -L "$target" ]] \
  || fail "install target must not be a symlink: $target"
validate_receipt_public_fields
install_receipts_root="$(normalize_receipt_root_outside_target)" \
  || fail "install receipt root must not be inside installed pack"
mkdir -p "$packs_root"
tmp_dir="$(mktemp -d "${packs_root}/.${archive_sha}.install.XXXXXX")"
chmod 755 "$tmp_dir"

zstd -q -dc "$archive" | COPYFILE_DISABLE=1 tar -xf - -C "$tmp_dir"
audit_json="$({
  cd "$repo_root"
  cargo run -p bw-blind-runner --bin bw-blind-audit --locked -- "$tmp_dir"
})"
actual_manifest_sha="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["manifest_sha256"])' <<<"$audit_json")" \
  || fail "post-extraction audit returned invalid JSON"
actual_method_commit="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["method_commit"])' <<<"$audit_json")" \
  || fail "post-extraction audit returned invalid JSON"
[[ "$actual_manifest_sha" == "$expected_manifest_sha" ]] \
  || fail "post-extraction manifest digest mismatch"
[[ "$actual_method_commit" == "$expected_method_commit" ]] \
  || fail "post-extraction method commit mismatch"

incoming_digest="$(tree_digest "$tmp_dir")" || fail "failed to digest extracted public pack"
policy_sha="$(sha256_file "${tmp_dir}/policy.toml")"
if [[ -e "$target" ]]; then
  [[ -d "$target" && ! -L "$target" ]] \
    || conflict "install target exists with different contents: $target"
  existing_digest="$(tree_digest "$target")" \
    || conflict "install target exists with different contents: $target"
  if [[ "$existing_digest" == "$incoming_digest" ]]; then
    install_receipt="$(emit_install_receipt)"
    print_install_result "already-installed" "$install_receipt"
    exit 0
  fi
  conflict "install target exists with different contents: $target"
fi

set +e
python3 - "$tmp_dir" "$target" <<'PY'
import os
import sys

try:
    os.rename(sys.argv[1], sys.argv[2])
except OSError:
    if os.path.exists(sys.argv[2]):
        raise SystemExit(2)
    raise
PY
rename_status=$?
set -e

if [[ "$rename_status" -eq 2 ]]; then
  existing_digest="$(tree_digest "$target")" \
    || conflict "concurrent install created different contents: $target"
  [[ "$existing_digest" == "$incoming_digest" ]] \
    || conflict "concurrent install created different contents: $target"
  install_receipt="$(emit_install_receipt)"
  print_install_result "already-installed" "$install_receipt"
  exit 0
fi
[[ "$rename_status" -eq 0 ]] || fail "atomic install rename failed"
tmp_dir=""

install_receipt="$(emit_install_receipt)"
print_install_result "installed" "$install_receipt"

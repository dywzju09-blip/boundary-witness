#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
create_tool="${repo_root}/tools/blind/create-public-archive.sh"
verify_tool="${repo_root}/tools/blind/verify-public-archive.sh"
install_tool="${repo_root}/tools/blind/install-public-archive.sh"
tmp_root="${repo_root}/target/tmp/blind-pack-policy"
pack="${tmp_root}/pack"
clean_worktree="${tmp_root}/clean-worktree"
dirty_sentinel="${repo_root}/.blind-pack-policy-dirty-${$}"
method_commit="$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}')"

fail() {
  printf 'blind-pack-policy: %s\n' "$*" >&2
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

sha256_stream() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

legacy_tree_digest() {
  python3 - "$1" <<'PY'
import hashlib
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
root_metadata = root.lstat()
root_mode = stat.S_IMODE(root_metadata.st_mode)
if not stat.S_ISDIR(root_metadata.st_mode):
    raise SystemExit(f"installed root is not a directory: {root}")
digest.update(b"D\0.\0" + f"{root_mode:04o}".encode() + b"\0")
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root).as_posix().encode()
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISDIR(metadata.st_mode):
        digest.update(b"D\0" + relative + b"\0" + f"{mode:04o}".encode() + b"\0")
    elif stat.S_ISREG(metadata.st_mode):
        digest.update(b"F\0" + relative + b"\0" + f"{mode:04o}".encode() + b"\0")
        digest.update(path.read_bytes())
    else:
        raise SystemExit(f"unsupported installed path: {path}")
print(digest.hexdigest())
PY
}

canonical_tree_digest() {
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

file_mode() {
  python3 - "$1" <<'PY'
import pathlib
import stat
import sys

print(f"{stat.S_IMODE(pathlib.Path(sys.argv[1]).stat().st_mode):04o}")
PY
}

make_mutant_archive() {
  local kind="$1"
  local destination="$2"
  mkdir -p "$destination"
  zstd -q -dc "$archive" > "${destination}/source.tar"
  python3 - "$kind" "${destination}/source.tar" "${destination}/blind-pack.tar" <<'PY'
import io
import pathlib
import sys
import tarfile

kind, source_path, output_path = sys.argv[1:]
source_bytes = pathlib.Path(source_path).read_bytes()
if kind == "appended-tar-bytes":
    pathlib.Path(output_path).write_bytes(source_bytes + b"hidden after tar eof\n")
    raise SystemExit(0)
if kind == "nonzero-member-padding":
    mutated = bytearray(source_bytes)
    offset = 0
    while offset + 512 <= len(mutated):
        header = mutated[offset:offset + 512]
        if not any(header):
            break
        size = int(bytes(header[124:136]).rstrip(b"\0 ") or b"0", 8)
        data_start = offset + 512
        if size % 512:
            mutated[data_start + size] = ord("X")
            pathlib.Path(output_path).write_bytes(mutated)
            raise SystemExit(0)
        offset = data_start + ((size + 511) // 512) * 512
    raise SystemExit("fixture has no member with tar padding")
if kind == "hidden-linkname":
    mutated = bytearray(source_bytes)
    offset = 0
    while offset + 512 <= len(mutated):
        header = mutated[offset:offset + 512]
        if not any(header):
            break
        size = int(bytes(header[124:136]).rstrip(b"\0 ") or b"0", 8)
        if header[156:157] == b"0":
            hidden = b"private/CVE-2099-secret"
            mutated[offset + 157:offset + 257] = hidden.ljust(100, b"\0")
            mutated[offset + 148:offset + 156] = b"        "
            checksum = sum(mutated[offset:offset + 512])
            mutated[offset + 148:offset + 156] = f"{checksum:06o}\0 ".encode("ascii")
            pathlib.Path(output_path).write_bytes(mutated)
            raise SystemExit(0)
        offset += 512 + ((size + 511) // 512) * 512
    raise SystemExit("fixture has no regular member for hidden linkname")

entries = []
with tarfile.open(source_path, "r:") as source:
    for member in source.getmembers():
        data = source.extractfile(member).read() if member.isfile() else None
        if kind == "noncanonical-mode" and member.name == "policy.toml":
            member.mode = 0o600
        entries.append((member, data))

if kind in {"traversal", "symlink", "hardlink", "duplicate-normalized"}:
    if kind == "traversal":
        member = tarfile.TarInfo("cases/../escape")
        member.type = tarfile.REGTYPE
        member.mode = 0o644
        data = b"escape\n"
    elif kind == "symlink":
        member = tarfile.TarInfo("cases/link")
        member.type = tarfile.SYMTYPE
        member.mode = 0o777
        member.linkname = "/tmp"
        data = None
    elif kind == "hardlink":
        member = tarfile.TarInfo("cases/hardlink")
        member.type = tarfile.LNKTYPE
        member.mode = 0o644
        member.linkname = "policy.toml"
        data = None
    else:
        member = tarfile.TarInfo("cases//duplicate")
        member.type = tarfile.REGTYPE
        member.mode = 0o644
        data = b"duplicate\n"
        second = tarfile.TarInfo("cases/duplicate")
        second.type = tarfile.REGTYPE
        second.mode = 0o644
        second.size = len(data)
        entries.append((second, data))
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""
    member.mtime = 0
    if data is not None:
        member.size = len(data)
    entries.append((member, data))

entries.sort(key=lambda entry: entry[0].name)
with tarfile.open(output_path, "w", format=tarfile.USTAR_FORMAT) as output:
    if kind == "gnu-longname-header":
        longname = b"cases\0"
        extension = tarfile.TarInfo("././@LongLink")
        extension.type = tarfile.GNUTYPE_LONGNAME
        extension.mode = 0o644
        extension.uid = 0
        extension.gid = 0
        extension.uname = ""
        extension.gname = ""
        extension.mtime = 0
        extension.size = len(longname)
        output.addfile(extension, io.BytesIO(longname))
    elif kind == "pax-global-header":
        extension = tarfile.TarInfo("GlobalPaxHeader")
        extension.type = tarfile.XGLTYPE
        extension.mode = 0o644
        extension.uid = 0
        extension.gid = 0
        extension.uname = ""
        extension.gname = ""
        extension.mtime = 0
        extension.size = 0
        output.addfile(extension)
    for member, data in entries:
        output.addfile(member, io.BytesIO(data) if data is not None else None)
PY
  zstd -q -19 -f "${destination}/blind-pack.tar" -o "${destination}/blind-pack.tar.zst"
  if [[ "$kind" == "zstd-skippable-frame" ]]; then
    python3 - "${destination}/blind-pack.tar.zst" <<'PY'
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
payload = b"hidden zstd skippable payload\n"
with path.open("ab") as output:
    output.write(bytes.fromhex("502a4d18"))
    output.write(struct.pack("<I", len(payload)))
    output.write(payload)
PY
  fi
  local mutant_sha
  mutant_sha="$(sha256_file "${destination}/blind-pack.tar.zst")"
  printf '%s  blind-pack.tar.zst\n' "$mutant_sha" > "${destination}/blind-pack.sha256"
  BW_MUTANT_SHA="$mutant_sha" python3 - "$deployment" "${destination}/blind-deployment.json" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    deployment = json.load(source)
deployment["archive_sha256"] = os.environ["BW_MUTANT_SHA"]
with open(sys.argv[2], "w", encoding="utf-8") as output:
    json.dump(deployment, output, indent=2, sort_keys=True)
    output.write("\n")
PY
}

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 && -d "$tmp_root" ]]; then
    find "$tmp_root" -maxdepth 1 -type f -name '*.err' -exec tail -n 20 {} \; >&2 || true
  fi
  git -C "$repo_root" reset -q -- "${dirty_sentinel#"${repo_root}/"}" >/dev/null 2>&1 || true
  rm -f "$dirty_sentinel" || true
  if [[ -e "${clean_worktree}/.git" ]]; then
    git -C "$repo_root" worktree remove --force "$clean_worktree" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_root" || true
  return "$status"
}
trap cleanup EXIT

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v git >/dev/null 2>&1 || fail "git is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v zstd >/dev/null 2>&1 || fail "zstd is required"

cleanup
trap cleanup EXIT
mkdir -p "${pack}/cases"

cat > "${pack}/policy.toml" <<'EOF'
schema_version = "boundary-witness.blind-policy/0.1"
minimum_replay_attempts = 2
gate_minimum_confirmed_cases = 1
forbidden_public_filename_tokens = ["ground-truth", "ground_truth", "cve-", "ghsa-", "advisory", "poc", "proof-of-concept", "proof_of_concept", "expected-result", "expected_result", "expected result", "private"]
EOF

policy_sha="$(sha256_file "${pack}/policy.toml")"
BW_POLICY_SHA="$policy_sha" BW_METHOD_COMMIT="$method_commit" python3 - "${pack}/manifest.json" <<'PY'
import json
import os
import sys

manifest = {
    "schema_version": "boundary-witness.blind-public/0.1",
    "suite_id": "archive-policy-suite",
    "split": "gate",
    "method_commit": os.environ["BW_METHOD_COMMIT"],
    "policy_sha256": os.environ["BW_POLICY_SHA"],
    "cases": [],
}
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(manifest, output, indent=2, sort_keys=True)
    output.write("\n")
PY

(
  cd "$pack"
  printf '%s  manifest.json\n' "$(sha256_file manifest.json)"
  printf '%s  policy.toml\n' "$(sha256_file policy.toml)"
) > "${pack}/checksums.sha256"

for tool in "$create_tool" "$verify_tool" "$install_tool"; do
  [[ -x "$tool" ]] || fail "missing executable blind deploy tool: $tool"
done

printf 'intentional dirty worktree sentinel\n' > "$dirty_sentinel"
if (
  cd "$repo_root"
  "$create_tool" "$pack" "${tmp_root}/dirty-out" "$method_commit"
) >"${tmp_root}/dirty.out" 2>"${tmp_root}/dirty.err"; then
  fail "dirty git worktree was accepted"
fi
grep -Fq 'dirty git worktree' "${tmp_root}/dirty.err" \
  || fail "dirty rejection did not mention dirty git worktree"
rm -f "$dirty_sentinel"

git -C "$repo_root" worktree add --detach "$clean_worktree" HEAD >/dev/null
git -C "$clean_worktree" config user.email "bw-test@example.invalid"
git -C "$clean_worktree" config user.name "BoundaryWitness Test"
cp "$create_tool" "$verify_tool" "$install_tool" "${clean_worktree}/tools/blind/"
git -C "$clean_worktree" add tools/blind
if ! git -C "$clean_worktree" diff --cached --quiet; then
  git -C "$clean_worktree" commit -q -m "test fixture: current blind archive tools"
fi
clean_method_commit="$(git -C "$clean_worktree" rev-parse --verify 'HEAD^{commit}')"
mkdir -p "${clean_worktree}/target/tmp/blind-pack-policy"
cp -R "$pack" "${clean_worktree}/target/tmp/blind-pack-policy/pack"

clean_pack="${clean_worktree}/target/tmp/blind-pack-policy/pack"
out="${clean_worktree}/target/tmp/blind-pack-policy/out"
repeat_out="${clean_worktree}/target/tmp/blind-pack-policy/out-repeat"
clean_create="${clean_worktree}/tools/blind/create-public-archive.sh"
clean_verify="${clean_worktree}/tools/blind/verify-public-archive.sh"
clean_install="${clean_worktree}/tools/blind/install-public-archive.sh"

BW_METHOD_COMMIT="$clean_method_commit" python3 - "$clean_pack/manifest.json" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)
manifest["method_commit"] = os.environ["BW_METHOD_COMMIT"]
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(manifest, output, indent=2, sort_keys=True)
    output.write("\n")
PY
(
  cd "$clean_pack"
  printf '%s  manifest.json\n' "$(sha256_file manifest.json)"
  printf '%s  policy.toml\n' "$(sha256_file policy.toml)"
) > "${clean_pack}/checksums.sha256"

inaccurate_pack="${clean_worktree}/target/tmp/blind-pack-policy/inaccurate-commit-pack"
cp -R "$clean_pack" "$inaccurate_pack"
inaccurate_commit="0123456789abcdef0123456789abcdef01234567"
BW_METHOD_COMMIT="$inaccurate_commit" python3 - "$inaccurate_pack/manifest.json" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)
manifest["method_commit"] = os.environ["BW_METHOD_COMMIT"]
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(manifest, output, indent=2, sort_keys=True)
    output.write("\n")
PY
(
  cd "$inaccurate_pack"
  printf '%s  manifest.json\n' "$(sha256_file manifest.json)"
  printf '%s  policy.toml\n' "$(sha256_file policy.toml)"
) > "${inaccurate_pack}/checksums.sha256"
if (
  cd "$clean_worktree"
  CARGO_TARGET_DIR="${repo_root}/target" "$clean_create" \
    "$inaccurate_pack" "${inaccurate_pack}-out" "$inaccurate_commit"
) >"${tmp_root}/inaccurate-commit.out" 2>"${tmp_root}/inaccurate-commit.err"; then
  fail "inaccurate method commit was accepted"
fi

nested_pack="${clean_worktree}/target/tmp/blind-pack-policy/nested-output-pack"
cp -R "$clean_pack" "$nested_pack"
if (
  cd "$clean_worktree"
  CARGO_TARGET_DIR="${repo_root}/target" "$clean_create" \
    "$nested_pack" "${nested_pack}/generated" "$clean_method_commit"
) >"${tmp_root}/nested-output.out" 2>"${tmp_root}/nested-output.err"; then
  fail "output directory inside public pack was accepted"
fi

(
  cd "$clean_worktree"
  CARGO_TARGET_DIR="${repo_root}/target" "$clean_create" "$clean_pack" "$out" "$clean_method_commit"
) >"${tmp_root}/create.out" 2>"${tmp_root}/create.err"

archive="${out}/blind-pack.tar.zst"
sha_file="${out}/blind-pack.sha256"
deployment="${out}/blind-deployment.json"
for output in "$archive" "$sha_file" "$deployment"; do
  [[ -f "$output" ]] || fail "expected output file: $output"
done

archive_sha="$(sha256_file "$archive")"
[[ "$(awk 'NR == 1 {print $1}' "$sha_file")" == "$archive_sha" ]] \
  || fail "blind-pack.sha256 does not match archive"

BW_EXPECTED_METHOD="$clean_method_commit" BW_EXPECTED_ARCHIVE="$archive_sha" python3 - "$deployment" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    deployment = json.load(source)
required = {
    "method_commit",
    "public_manifest_sha256",
    "archive_sha256",
    "created_at_utc",
    "source_git_status",
    "tool_version",
}
if set(deployment) != required:
    raise SystemExit(f"unexpected deployment fields: {sorted(deployment)}")
if deployment["method_commit"] != os.environ["BW_EXPECTED_METHOD"]:
    raise SystemExit("method_commit mismatch")
if deployment["archive_sha256"] != os.environ["BW_EXPECTED_ARCHIVE"]:
    raise SystemExit("archive_sha256 mismatch")
if deployment["source_git_status"] != "clean":
    raise SystemExit("source_git_status is not clean")
PY

listing="${tmp_root}/archive.list"
zstd -q -dc "$archive" | tar -tf - > "$listing"
for required in cases/ checksums.sha256 manifest.json policy.toml; do
  grep -Fxq "$required" "$listing" || fail "archive is missing $required"
done
while IFS= read -r member; do
  case "$member" in
    manifest.json|policy.toml|checksums.sha256|cases/|cases/*) ;;
    *) fail "archive contains disallowed member: $member" ;;
  esac
done < "$listing"

(
  cd "$clean_worktree"
  CARGO_TARGET_DIR="${repo_root}/target" "$clean_create" "$clean_pack" "$repeat_out" "$clean_method_commit"
) >"${tmp_root}/create-repeat.out" 2>"${tmp_root}/create-repeat.err"
[[ "$(sha256_file "${repeat_out}/blind-pack.tar.zst")" == "$archive_sha" ]] \
  || fail "repeated archive creation was not deterministic"

forbidden_index=0
for forbidden in private ground-truth ground_truth cve- ghsa- advisory poc .git; do
  forbidden_index=$((forbidden_index + 1))
  safe_name="$(printf '%s' "$forbidden" | tr -c '[:alnum:]' '_')"
  mutant="${clean_worktree}/target/tmp/blind-pack-policy/forbidden-${forbidden_index}-${safe_name}/pack"
  mkdir -p "$(dirname "$mutant")"
  cp -R "$clean_pack" "$mutant"
  mkdir -p "${mutant}/cases/${forbidden}"
  if (
    cd "$clean_worktree"
    CARGO_TARGET_DIR="${repo_root}/target" "$clean_create" \
      "$mutant" "${mutant}-out" "$clean_method_commit"
  ) >"${tmp_root}/forbidden-${safe_name}.out" 2>"${tmp_root}/forbidden-${safe_name}.err"; then
    fail "forbidden public path was accepted: $forbidden"
  fi
done

(
  cd "$clean_worktree"
  CARGO_TARGET_DIR="${repo_root}/target" "$clean_verify" "$archive" "$sha_file" "$deployment"
) >"${tmp_root}/verify.out" 2>"${tmp_root}/verify.err"

for binding in method_commit public_manifest_sha256 archive_sha256; do
  bad_deployment="${tmp_root}/bad-deployment-${binding}.json"
  BW_BAD_FIELD="$binding" python3 - "$deployment" "$bad_deployment" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    deployment = json.load(source)
field = os.environ["BW_BAD_FIELD"]
deployment[field] = "f" * (40 if field == "method_commit" else 64)
with open(sys.argv[2], "w", encoding="utf-8") as output:
    json.dump(deployment, output, indent=2, sort_keys=True)
    output.write("\n")
PY
  if (
    cd "$clean_worktree"
    CARGO_TARGET_DIR="${repo_root}/target" "$clean_verify" \
      "$archive" "$sha_file" "$bad_deployment"
  ) >"${tmp_root}/bad-deployment-${binding}.out" \
    2>"${tmp_root}/bad-deployment-${binding}.err"; then
    fail "deployment binding mismatch was accepted: $binding"
  fi
done

for mutation in extra-forbidden-field duplicate-key created-at source-git-status tool-version; do
  bad_deployment="${tmp_root}/bad-deployment-${mutation}.json"
  BW_DEPLOYMENT_MUTATION="$mutation" python3 - "$deployment" "$bad_deployment" <<'PY'
import json
import os
import pathlib
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    deployment = json.load(source)
mutation = os.environ["BW_DEPLOYMENT_MUTATION"]
if mutation == "extra-forbidden-field":
    deployment["poc"] = "hidden public-boundary payload"
elif mutation == "source-git-status":
    deployment["source_git_status"] = "dirty"
elif mutation == "created-at":
    deployment["created_at_utc"] = "not-a-utc-timestamp"
elif mutation == "tool-version":
    deployment["tool_version"] = "create-public-archive.sh/999.0"
elif mutation == "duplicate-key":
    canonical = json.dumps(deployment, indent=2, sort_keys=True)
    duplicate = f',\n  "tool_version": {json.dumps(deployment["tool_version"])}\n}}\n'
    pathlib.Path(sys.argv[2]).write_text(canonical[:-2] + duplicate, encoding="utf-8")
    raise SystemExit(0)
else:
    raise SystemExit(f"unknown deployment mutation: {mutation}")
with open(sys.argv[2], "w", encoding="utf-8") as output:
    json.dump(deployment, output, indent=2, sort_keys=True)
    output.write("\n")
PY
  if (
    cd "$clean_worktree"
    CARGO_TARGET_DIR="${repo_root}/target" "$clean_verify" \
      "$archive" "$sha_file" "$bad_deployment"
  ) >"${tmp_root}/bad-deployment-${mutation}.out" \
    2>"${tmp_root}/bad-deployment-${mutation}.err"; then
    fail "deployment metadata mutation was accepted: $mutation"
  fi
done

for mutation in \
  traversal symlink hardlink duplicate-normalized noncanonical-mode \
  appended-tar-bytes nonzero-member-padding zstd-skippable-frame \
  gnu-longname-header pax-global-header hidden-linkname; do
  mutant_root="${tmp_root}/archive-${mutation}"
  make_mutant_archive "$mutation" "$mutant_root"
  if (
    cd "$clean_worktree"
    CARGO_TARGET_DIR="${repo_root}/target" "$clean_verify" \
      "${mutant_root}/blind-pack.tar.zst" \
      "${mutant_root}/blind-pack.sha256" \
      "${mutant_root}/blind-deployment.json"
  ) >"${tmp_root}/archive-${mutation}.out" 2>"${tmp_root}/archive-${mutation}.err"; then
    fail "crafted $mutation archive passed verification"
  fi
done

tamper_root="${clean_worktree}/target/tmp/blind-pack-policy/tampered"
mkdir -p "${tamper_root}/pack"
zstd -q -dc "$archive" | tar -xf - -C "${tamper_root}/pack"
printf ' ' >> "${tamper_root}/pack/manifest.json"
COPYFILE_DISABLE=1 tar -cf "${tamper_root}/blind-pack.tar" \
  -C "${tamper_root}/pack" cases checksums.sha256 manifest.json policy.toml
zstd -q -19 -f "${tamper_root}/blind-pack.tar" -o "${tamper_root}/blind-pack.tar.zst"
if (
  cd "$clean_worktree"
  CARGO_TARGET_DIR="${repo_root}/target" "$clean_verify" \
    "${tamper_root}/blind-pack.tar.zst" "$sha_file" "$deployment"
) >"${tmp_root}/tamper.out" 2>"${tmp_root}/tamper.err"; then
  fail "tampered archive passed verification"
fi

install_root="${clean_worktree}/target/tmp/blind-pack-policy/install-root/blind-packs"
receipt_root="${clean_worktree}/target/tmp/blind-pack-policy/receipts"
export BW_BLIND_RECEIPTS_ROOT="$receipt_root"
export BW_BLIND_RECEIPT_KEY_ID="test-key"
export BW_BLIND_RECEIPT_KEY_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
export BW_BLIND_HOST_ID="linux-test-runner"

for invalid_key_case in invalid-hex odd-length-hex forbidden-key-id; do
  invalid_install_root="${clean_worktree}/target/tmp/blind-pack-policy/${invalid_key_case}/blind-packs"
  invalid_receipt_root="${clean_worktree}/target/tmp/blind-pack-policy/${invalid_key_case}/receipts"
  case "$invalid_key_case" in
    invalid-hex)
      invalid_key_id="test-key"
      invalid_key_hex="not-hex"
      ;;
    odd-length-hex)
      invalid_key_id="test-key"
      invalid_key_hex="abc"
      ;;
    forbidden-key-id)
      invalid_key_id="Private-test-key"
      invalid_key_hex="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ;;
  esac
  set +e
  (
    cd "$clean_worktree"
    BW_BLIND_PACKS_ROOT="$invalid_install_root" \
      BW_BLIND_RECEIPTS_ROOT="$invalid_receipt_root" \
      BW_BLIND_RECEIPT_KEY_ID="$invalid_key_id" \
      BW_BLIND_RECEIPT_KEY_HEX="$invalid_key_hex" \
      CARGO_TARGET_DIR="${repo_root}/target" \
      "$clean_install" "$archive" "$sha_file" "$deployment"
  ) >"${tmp_root}/${invalid_key_case}.out" 2>"${tmp_root}/${invalid_key_case}.err"
  invalid_key_status=$?
  set -e
  [[ "$invalid_key_status" -ne 0 ]] || fail "$invalid_key_case receipt key unexpectedly installed"
  rg -q 'invalid receipt key|receipt key hex|receipt key id' "${tmp_root}/${invalid_key_case}.err" \
    || fail "$invalid_key_case did not report an invalid receipt key"
  [[ ! -e "${invalid_install_root}/${archive_sha}" ]] \
    || fail "$invalid_key_case created an installed target"
  [[ ! -e "${invalid_receipt_root}/${archive_sha}.json" ]] \
    || fail "$invalid_key_case created an install receipt"
done

for invalid_receipt_field_case in forbidden-host-id forbidden-installed-path; do
  invalid_receipt_install_root="${clean_worktree}/target/tmp/blind-pack-policy/${invalid_receipt_field_case}/blind-packs"
  invalid_receipt_root="${clean_worktree}/target/tmp/blind-pack-policy/${invalid_receipt_field_case}/receipts"
  invalid_receipt_host_id="linux-test-runner"
  case "$invalid_receipt_field_case" in
    forbidden-host-id)
      invalid_receipt_host_id="Private-test-host"
      ;;
    forbidden-installed-path)
      invalid_receipt_install_root="${clean_worktree}/target/tmp/blind-pack-policy/${invalid_receipt_field_case}/private-blind-packs"
      ;;
  esac
  set +e
  (
    cd "$clean_worktree"
    BW_BLIND_PACKS_ROOT="$invalid_receipt_install_root" \
      BW_BLIND_RECEIPTS_ROOT="$invalid_receipt_root" \
      BW_BLIND_HOST_ID="$invalid_receipt_host_id" \
      CARGO_TARGET_DIR="${repo_root}/target" \
      "$clean_install" "$archive" "$sha_file" "$deployment"
  ) >"${tmp_root}/${invalid_receipt_field_case}.out" 2>"${tmp_root}/${invalid_receipt_field_case}.err"
  invalid_receipt_field_status=$?
  set -e
  [[ "$invalid_receipt_field_status" -ne 0 ]] \
    || fail "$invalid_receipt_field_case unexpectedly installed"
  rg -q 'invalid receipt host id|invalid receipt installed path' \
    "${tmp_root}/${invalid_receipt_field_case}.err" \
    || fail "$invalid_receipt_field_case did not report an invalid receipt field"
  [[ ! -e "${invalid_receipt_install_root}/${archive_sha}" ]] \
    || fail "$invalid_receipt_field_case created an installed target"
  [[ ! -e "${invalid_receipt_root}/${archive_sha}.json" ]] \
    || fail "$invalid_receipt_field_case created an install receipt"
done

empty_hostname_bin="${tmp_root}/empty-hostname-bin"
empty_hostname_install_root="${clean_worktree}/target/tmp/blind-pack-policy/empty-hostname/blind-packs"
empty_hostname_receipt_root="${clean_worktree}/target/tmp/blind-pack-policy/empty-hostname/receipts"
mkdir -p "$empty_hostname_bin"
cat > "${empty_hostname_bin}/hostname" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "${empty_hostname_bin}/hostname"
env -u BW_BLIND_HOST_ID \
  PATH="${empty_hostname_bin}:$PATH" \
  BW_BLIND_PACKS_ROOT="$empty_hostname_install_root" \
  BW_BLIND_RECEIPTS_ROOT="$empty_hostname_receipt_root" \
  BW_BLIND_RECEIPT_KEY_ID="test-key" \
  BW_BLIND_RECEIPT_KEY_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" \
  CARGO_TARGET_DIR="${repo_root}/target" \
  "$clean_install" "$archive" "$sha_file" "$deployment" \
  >"${tmp_root}/empty-hostname.out" 2>"${tmp_root}/empty-hostname.err"
empty_hostname_receipt="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["install_receipt"])' "${tmp_root}/empty-hostname.out")"
BW_EXPECTED_HOST_ID="unknown-host" python3 - "$empty_hostname_receipt" <<'PY'
import json
import os
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if receipt.get("host_id") != os.environ["BW_EXPECTED_HOST_ID"]:
    raise SystemExit("empty hostname did not use the receipt host fallback")
PY

internal_receipt_install_root="${clean_worktree}/target/tmp/blind-pack-policy/internal-receipt-root/blind-packs"
internal_receipt_target="${internal_receipt_install_root}/${archive_sha}"
internal_receipt_root="${internal_receipt_target}/receipts"
set +e
(
  cd "$clean_worktree"
  BW_BLIND_PACKS_ROOT="$internal_receipt_install_root" \
    BW_BLIND_RECEIPTS_ROOT="$internal_receipt_root" \
    CARGO_TARGET_DIR="${repo_root}/target" \
    "$clean_install" "$archive" "$sha_file" "$deployment"
) >"${tmp_root}/internal-receipt-root.out" 2>"${tmp_root}/internal-receipt-root.err"
internal_receipt_status=$?
set -e
[[ "$internal_receipt_status" -ne 0 ]] \
  || fail "receipt root inside the installed target unexpectedly installed"
rg -q 'install receipt root must not be inside installed pack' \
  "${tmp_root}/internal-receipt-root.err" \
  || fail "receipt root inside the installed target did not report the boundary violation"
[[ ! -e "$internal_receipt_target" ]] \
  || fail "receipt root inside the installed target polluted the installed target"
[[ ! -e "${internal_receipt_root}/${archive_sha}.json" ]] \
  || fail "receipt root inside the installed target created an install receipt"

symlink_target_install_root="${clean_worktree}/target/tmp/blind-pack-policy/symlink-target/blind-packs"
symlink_target_external_root="${clean_worktree}/target/tmp/blind-pack-policy/symlink-target/external-pack"
symlink_target_receipt_root="${clean_worktree}/target/tmp/blind-pack-policy/symlink-target/receipts"
symlink_target="${symlink_target_install_root}/${archive_sha}"
mkdir -p "$symlink_target_install_root" "$symlink_target_external_root"
cp -R "${clean_pack}/." "$symlink_target_external_root/"
symlink_target_external_before="$(canonical_tree_digest "$symlink_target_external_root")"
ln -s "$symlink_target_external_root" "$symlink_target"
set +e
(
  cd "$clean_worktree"
  BW_BLIND_PACKS_ROOT="$symlink_target_install_root" \
    BW_BLIND_RECEIPTS_ROOT="$symlink_target_receipt_root" \
    CARGO_TARGET_DIR="${repo_root}/target" \
    "$clean_install" "$archive" "$sha_file" "$deployment"
) >"${tmp_root}/symlink-target.out" 2>"${tmp_root}/symlink-target.err"
symlink_target_status=$?
set -e
[[ "$symlink_target_status" -ne 0 ]] \
  || fail "symlinked install target unexpectedly installed"
rg -q 'install target.*symlink' "${tmp_root}/symlink-target.err" \
  || fail "symlinked install target did not report the boundary violation"
[[ -L "$symlink_target" ]] \
  || fail "symlinked install target was replaced or followed"
[[ "$(readlink "$symlink_target")" == "$symlink_target_external_root" ]] \
  || fail "symlinked install target was retargeted"
[[ "$(canonical_tree_digest "$symlink_target_external_root")" == "$symlink_target_external_before" ]] \
  || fail "symlinked install target wrote into the external directory"
[[ ! -e "${symlink_target_receipt_root}/${archive_sha}.json" ]] \
  || fail "symlinked install target created an install receipt"

(
  cd "$clean_worktree"
  BW_BLIND_PACKS_ROOT="$install_root" CARGO_TARGET_DIR="${repo_root}/target" \
    "$clean_install" "$archive" "$sha_file" "$deployment"
) >"${tmp_root}/install.out" 2>"${tmp_root}/install.err"
installed="${install_root}/${archive_sha}"
[[ -f "${installed}/manifest.json" ]] || fail "installed pack is missing manifest.json"
install_receipt="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("install_receipt", ""))' "${tmp_root}/install.out")"
[[ -f "$install_receipt" ]] || fail "install receipt missing: $install_receipt"
[[ "$(file_mode "$install_receipt")" == "0600" ]] \
  || fail "install receipt mode is not 0600"
[[ "$install_receipt" != "$installed" && "$install_receipt" != "${installed}/"* ]] \
  || fail "install receipt is inside the installed target"
BW_EXPECTED_ARCHIVE="$archive_sha" \
BW_EXPECTED_DEPLOYMENT="$(sha256_file "$deployment")" \
BW_EXPECTED_MANIFEST="$(sha256_file "${installed}/manifest.json")" \
BW_EXPECTED_METHOD="$clean_method_commit" \
BW_EXPECTED_POLICY="$(sha256_file "${installed}/policy.toml")" \
BW_EXPECTED_TREE="$(canonical_tree_digest "$installed")" \
BW_EXPECTED_PATH="$installed" \
python3 - "$install_receipt" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "schema_version": "boundary-witness.blind-install-receipt/0.1",
    "archive_sha256": os.environ["BW_EXPECTED_ARCHIVE"],
    "deployment_json_sha256": os.environ["BW_EXPECTED_DEPLOYMENT"],
    "public_manifest_sha256": os.environ["BW_EXPECTED_MANIFEST"],
    "method_commit": os.environ["BW_EXPECTED_METHOD"],
    "policy_sha256": os.environ["BW_EXPECTED_POLICY"],
    "installed_pack_tree_sha256": os.environ["BW_EXPECTED_TREE"],
    "installed_path": os.environ["BW_EXPECTED_PATH"],
}
for field, value in expected.items():
    if receipt.get(field) != value:
        raise SystemExit(f"install receipt {field} mismatch")
if receipt.get("trust", {}).get("key_id") != "test-key":
    raise SystemExit("install receipt trust.key_id mismatch")

def signature(payload):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256()
    digest.update(b"boundary-witness.receipt-test-signature/0.1\0")
    digest.update(b"test-key\0")
    digest.update(canonical)
    digest.update(b"\0")
    digest.update(bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
    return digest.hexdigest()

payload = dict(receipt)
trust = payload.pop("trust")
if trust.get("signature_sha256") != signature(payload):
    raise SystemExit("install receipt signature did not verify")
payload["installed_path"] = "/tampered"
if trust.get("signature_sha256") == signature(payload):
    raise SystemExit("tampered install receipt signature was accepted")
PY
before="$(legacy_tree_digest "$installed")"

(
  cd "$clean_worktree"
  BW_BLIND_PACKS_ROOT="$install_root" CARGO_TARGET_DIR="${repo_root}/target" \
    "$clean_install" "$archive" "$sha_file" "$deployment"
) >"${tmp_root}/install-again.out" 2>"${tmp_root}/install-again.err"
BW_EXPECTED_RECEIPT="$install_receipt" python3 - \
  "${tmp_root}/install.out" "${tmp_root}/install-again.out" <<'PY'
import json
import os
import sys

installed, repeated = (json.loads(open(path, encoding="utf-8").read()) for path in sys.argv[1:])
for output, mode in ((installed, "installed"), (repeated, "already-installed")):
    if output.get("status") != "ok" or output.get("mode") != mode:
        raise SystemExit(f"unexpected installer status output: {output}")
    if output.get("install_receipt") != os.environ["BW_EXPECTED_RECEIPT"]:
        raise SystemExit("installer output does not bind the expected install receipt")
PY
after="$(legacy_tree_digest "$installed")"
[[ "$after" == "$before" ]] || fail "idempotent install modified the installed directory"

collision_pack="${clean_worktree}/target/tmp/blind-pack-policy/install-digest-collision-pack"
collision_out="${clean_worktree}/target/tmp/blind-pack-policy/install-digest-collision-out"
cp -R "$clean_pack" "$collision_pack"
BW_METHOD_COMMIT="$clean_method_commit" python3 - "$collision_pack" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
case_id = "blind-0123456789abcdef"
case_root = root / "cases" / case_id
case_root.mkdir()
(case_root / "COMPLETE").write_bytes(b"complete\n")
(case_root / "a").write_bytes(b"")
(case_root / "b").write_bytes(b"payload")

case_digest = hashlib.sha256()
for relative in ("COMPLETE", "a", "b"):
    case_digest.update(relative.encode("utf-8"))
    case_digest.update(b"\0")
    case_digest.update(hashlib.sha256((case_root / relative).read_bytes()).hexdigest().encode("ascii"))

manifest_path = root / "manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
manifest["method_commit"] = os.environ["BW_METHOD_COMMIT"]
manifest["cases"] = [{
    "case_id": case_id,
    "case_root": f"cases/{case_id}",
    "case_sha256": case_digest.hexdigest(),
    "command": {"program": "COMPLETE", "args": [], "env": {}},
    "timeout_seconds": 30,
}]
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

checksums = []
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    if path.is_file() and path.relative_to(root).as_posix() != "checksums.sha256":
        relative = path.relative_to(root).as_posix()
        checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n")
(root / "checksums.sha256").write_text("".join(checksums), encoding="utf-8")
PY
(
  cd "$clean_worktree"
  CARGO_TARGET_DIR="${repo_root}/target" "$clean_create" \
    "$collision_pack" "$collision_out" "$clean_method_commit"
) >"${tmp_root}/collision-create.out" 2>"${tmp_root}/collision-create.err"

collision_archive="${collision_out}/blind-pack.tar.zst"
collision_sha_file="${collision_out}/blind-pack.sha256"
collision_deployment="${collision_out}/blind-deployment.json"
collision_sha="$(sha256_file "$collision_archive")"
collision_install_root="${clean_worktree}/target/tmp/blind-pack-policy/install-digest-collision/blind-packs"
collision_target="${collision_install_root}/${collision_sha}"
mkdir -p "$collision_target"
cp -R "${collision_pack}/." "$collision_target/"
rm "${collision_target}/cases/blind-0123456789abcdef/b"
python3 - "${collision_target}/cases/blind-0123456789abcdef/a" <<'PY'
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_bytes(
    b"F\0cases/blind-0123456789abcdef/b\0" + b"0644\0payload"
)
PY
[[ "$(legacy_tree_digest "$collision_pack")" == "$(legacy_tree_digest "$collision_target")" ]] \
  || fail "install digest collision fixture does not reproduce the legacy encoding collision"
set +e
(
  cd "$clean_worktree"
  BW_BLIND_PACKS_ROOT="$collision_install_root" CARGO_TARGET_DIR="${repo_root}/target" \
    "$clean_install" "$collision_archive" "$collision_sha_file" "$collision_deployment"
) >"${tmp_root}/install-digest-collision.out" \
  2>"${tmp_root}/install-digest-collision.err"
collision_status=$?
set -e
[[ "$collision_status" -eq 2 ]] \
  || fail "structurally colliding installed target exited $collision_status instead of 2"

swap_source="${tmp_root}/archive-swap-source.tar.zst"
cp "$archive" "$swap_source"
swap_root="${clean_worktree}/target/tmp/blind-pack-policy/archive-swap-install"
wrapper_dir="${tmp_root}/archive-swap-bin"
mkdir -p "$wrapper_dir" "$swap_root"
real_zstd="$(command -v zstd)"
cat > "${wrapper_dir}/zstd" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
[[ ! -f "${BW_ZSTD_STATE}/count" ]] || count="$(cat "${BW_ZSTD_STATE}/count")"
count=$((count + 1))
printf '%s\n' "$count" > "${BW_ZSTD_STATE}/count"
if [[ "$count" -eq 2 ]]; then
  : > "${BW_ZSTD_STATE}/second.ready"
  while [[ ! -f "${BW_ZSTD_STATE}/continue" ]]; do sleep 0.01; done
fi
exec "$BW_REAL_ZSTD" "$@"
EOF
chmod +x "${wrapper_dir}/zstd"
set +e
(
  cd "$clean_worktree"
  PATH="${wrapper_dir}:$PATH" BW_REAL_ZSTD="$real_zstd" BW_ZSTD_STATE="$wrapper_dir" \
    BW_BLIND_PACKS_ROOT="$swap_root" CARGO_TARGET_DIR="${repo_root}/target" \
    "$clean_install" "$swap_source" "$sha_file" "$deployment"
) >"${tmp_root}/archive-swap.out" 2>"${tmp_root}/archive-swap.err" &
swap_pid=$!
set -e
for _ in $(seq 1 1000); do
  [[ ! -f "${wrapper_dir}/second.ready" ]] || break
  kill -0 "$swap_pid" >/dev/null 2>&1 || break
  sleep 0.01
done
[[ -f "${wrapper_dir}/second.ready" ]] || fail "archive swap test did not reach extraction"
cp "${tmp_root}/archive-noncanonical-mode/blind-pack.tar.zst" "$swap_source"
: > "${wrapper_dir}/continue"
set +e
wait "$swap_pid"
swap_status=$?
set -e
[[ "$swap_status" -eq 0 ]] || fail "archive snapshot install failed with status $swap_status"
swap_installed="${swap_root}/${archive_sha}"
[[ "$(file_mode "${swap_installed}/policy.toml")" == "0644" ]] \
  || fail "installer extracted caller-swapped archive instead of its private snapshot"

chmod 0600 "${installed}/policy.toml"
set +e
(
  cd "$clean_worktree"
  BW_BLIND_PACKS_ROOT="$install_root" CARGO_TARGET_DIR="${repo_root}/target" \
    "$clean_install" "$archive" "$sha_file" "$deployment"
) >"${tmp_root}/install-conflict.out" 2>"${tmp_root}/install-conflict.err"
conflict_status=$?
set -e
[[ "$conflict_status" -eq 2 ]] \
  || fail "permission-only conflicting install exited $conflict_status instead of 2"

chmod 0644 "${installed}/policy.toml"
chmod 0700 "$installed"
set +e
(
  cd "$clean_worktree"
  BW_BLIND_PACKS_ROOT="$install_root" CARGO_TARGET_DIR="${repo_root}/target" \
    "$clean_install" "$archive" "$sha_file" "$deployment"
) >"${tmp_root}/install-root-mode-conflict.out" \
  2>"${tmp_root}/install-root-mode-conflict.err"
root_conflict_status=$?
set -e
[[ "$root_conflict_status" -eq 2 ]] \
  || fail "root permission-only conflicting install exited $root_conflict_status instead of 2"

printf 'blind-pack-policy: ok\n'

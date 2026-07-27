#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage: create-public-archive.sh PUBLIC_PACK_ROOT OUTPUT_DIRECTORY METHOD_COMMIT

Creates:
  blind-pack.tar.zst
  blind-pack.sha256
  blind-deployment.json
EOF
}

fail() {
  printf 'create-public-archive: %s\n' "$*" >&2
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

worktree_is_clean() {
  [[ -z "$(git -C "$1" status --porcelain --untracked-files=all)" ]]
}

[[ $# -eq 3 ]] || {
  usage
  exit 1
}

pack_root="$1"
out_dir="$2"
method_commit="$3"

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v git >/dev/null 2>&1 || fail "git is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v zstd >/dev/null 2>&1 || fail "zstd is required"
[[ "$method_commit" =~ ^[0-9a-f]{40}$ ]] \
  || fail "method commit must be a full lowercase Git SHA-1"
[[ -d "$pack_root" && ! -L "$pack_root" ]] \
  || fail "public pack root not found or is a symlink: $pack_root"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null)" \
  || fail "tool is not inside a git worktree"
worktree_is_clean "$repo_root" || fail "dirty git worktree"
resolved_method_commit="$(git -C "$repo_root" rev-parse --verify "${method_commit}^{commit}" 2>/dev/null)" \
  || fail "method commit is not a Git commit object: $method_commit"
[[ "$resolved_method_commit" == "$method_commit" ]] \
  || fail "method commit does not resolve exactly: $method_commit"
head_commit="$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}')" \
  || fail "cannot resolve worktree HEAD commit"
[[ "$method_commit" == "$head_commit" ]] \
  || fail "method commit must match clean worktree HEAD: $method_commit != $head_commit"

pack_root="$(cd "$pack_root" && pwd -P)"
if ! python3 - "$pack_root" "$out_dir" <<'PY'
import os
import pathlib
import sys

pack = pathlib.Path(sys.argv[1])
output = pathlib.Path(os.path.realpath(sys.argv[2]))
try:
    output.relative_to(pack)
except ValueError:
    pass
else:
    raise SystemExit(1)
PY
then
  fail "output directory must not be inside public pack root"
fi

tmp_dir="$(mktemp -d -t bw-create-public-archive.XXXXXX)"
tmp_dir="$(cd "$tmp_dir" && pwd -P)"
chmod 700 "$tmp_dir"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

snapshot="${tmp_dir}/pack"
mkdir -m 700 "$snapshot"
python3 - "$pack_root" "$snapshot" <<'PY'
import os
import pathlib
import stat
import sys

source = sys.argv[1]
destination = pathlib.Path(sys.argv[2])
allowed_top_level = {"manifest.json", "policy.toml", "checksums.sha256", "cases"}
forbidden_tokens = (
    "private", "ground-truth", "ground_truth", "cve-", "ghsa-", "advisory", "poc",
)

def die(message: str) -> None:
    print(f"create-public-archive: {message}", file=sys.stderr)
    raise SystemExit(1)

def same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino

def copy_directory(source_fd: int, target: pathlib.Path, prefix: tuple[str, ...]) -> None:
    try:
        names = sorted(os.listdir(source_fd))
    except OSError as error:
        die(f"cannot list public pack: {error}")
    for name in names:
        if not name or name in {".", ".."} or "/" in name or "\0" in name:
            die(f"public pack contains unsafe path component: {name!r}")
        parts = prefix + (name,)
        relative = "/".join(parts)
        if parts[0] not in allowed_top_level:
            die(f"public pack contains disallowed path: {relative}")
        lowercase = relative.lower()
        if ".git" in parts or any(token in lowercase for token in forbidden_tokens):
            die(f"public pack contains forbidden path: {relative}")
        try:
            before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except OSError as error:
            die(f"cannot stat public pack path {relative}: {error}")
        target_path = target / name
        if stat.S_ISDIR(before.st_mode):
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                child_fd = os.open(name, flags, dir_fd=source_fd)
                opened = os.fstat(child_fd)
            except OSError as error:
                die(f"cannot snapshot directory {relative}: {error}")
            if not same_identity(before, opened):
                os.close(child_fd)
                die(f"public pack changed while snapshotting: {relative}")
            target_path.mkdir(mode=stat.S_IMODE(before.st_mode))
            try:
                copy_directory(child_fd, target_path, parts)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(before.st_mode):
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                file_fd = os.open(name, flags, dir_fd=source_fd)
                opened = os.fstat(file_fd)
            except OSError as error:
                die(f"cannot snapshot file {relative}: {error}")
            if not same_identity(before, opened):
                os.close(file_fd)
                die(f"public pack changed while snapshotting: {relative}")
            try:
                with os.fdopen(file_fd, "rb", closefd=True) as input_file, target_path.open("xb") as output_file:
                    while True:
                        chunk = input_file.read(1024 * 1024)
                        if not chunk:
                            break
                        output_file.write(chunk)
                    after = os.fstat(input_file.fileno())
            except OSError as error:
                die(f"cannot snapshot file {relative}: {error}")
            stable = (
                same_identity(opened, after)
                and opened.st_size == after.st_size
                and opened.st_mtime_ns == after.st_mtime_ns
                and opened.st_ctime_ns == after.st_ctime_ns
            )
            if not stable:
                die(f"public pack changed while snapshotting: {relative}")
            target_path.chmod(stat.S_IMODE(before.st_mode))
        elif stat.S_ISLNK(before.st_mode):
            die(f"public pack contains symlink: {relative}")
        else:
            die(f"public pack contains unsupported file type: {relative}")

root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
try:
    root_fd = os.open(source, root_flags)
except OSError as error:
    die(f"cannot open public pack root: {error}")
try:
    copy_directory(root_fd, destination, ())
finally:
    os.close(root_fd)

for required in ("manifest.json", "policy.toml", "checksums.sha256", "cases"):
    path = destination / required
    if required == "cases":
        if not path.is_dir() or path.is_symlink():
            die("public pack is missing cases directory")
    elif not path.is_file() or path.is_symlink():
        die(f"public pack is missing {required}")
PY

audit_json="$({
  cd "$repo_root"
  cargo run -p bw-blind-runner --bin bw-blind-audit --locked -- "$snapshot"
})"
public_manifest_sha="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["manifest_sha256"])' <<<"$audit_json")" \
  || fail "bw-blind-audit returned invalid JSON"
audit_method_commit="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["method_commit"])' <<<"$audit_json")" \
  || fail "bw-blind-audit returned invalid JSON"
[[ "$audit_method_commit" == "$method_commit" ]] \
  || fail "method commit does not match public manifest: $method_commit != $audit_method_commit"

tar_path="${tmp_dir}/blind-pack.tar"
archive_tmp="${tmp_dir}/blind-pack.tar.zst"
sha_tmp="${tmp_dir}/blind-pack.sha256"
deployment_tmp="${tmp_dir}/blind-deployment.json"
python3 - "$snapshot" "$tar_path" <<'PY'
import pathlib
import stat
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
tar_path = sys.argv[2]
paths = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())

with tarfile.open(tar_path, "w", format=tarfile.USTAR_FORMAT) as archive:
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
            raise SystemExit(f"unsupported public pack path: {relative}")
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

zstd -q -19 -f "$tar_path" -o "$archive_tmp"
archive_sha="$(sha256_file "$archive_tmp")"
printf '%s  blind-pack.tar.zst\n' "$archive_sha" > "$sha_tmp"

worktree_is_clean "$repo_root" || fail "dirty git worktree"
[[ "$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}')" == "$method_commit" ]] \
  || fail "worktree HEAD changed while creating archive"

BW_METHOD_COMMIT="$method_commit" \
BW_MANIFEST_SHA256="$public_manifest_sha" \
BW_ARCHIVE_SHA256="$archive_sha" \
python3 - "$deployment_tmp" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

deployment = {
    "method_commit": os.environ["BW_METHOD_COMMIT"],
    "public_manifest_sha256": os.environ["BW_MANIFEST_SHA256"],
    "archive_sha256": os.environ["BW_ARCHIVE_SHA256"],
    "created_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "source_git_status": "clean",
    "tool_version": "create-public-archive.sh/0.2",
}
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(deployment, output, indent=2, sort_keys=True)
    output.write("\n")
PY

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd -P)"
archive="${out_dir}/blind-pack.tar.zst"
sha_file="${out_dir}/blind-pack.sha256"
deployment="${out_dir}/blind-deployment.json"
for output in "$archive" "$sha_file" "$deployment"; do
  [[ ! -e "$output" ]] || fail "refusing to overwrite existing output: $output"
done
mv "$archive_tmp" "$archive"
mv "$sha_tmp" "$sha_file"
mv "$deployment_tmp" "$deployment"

BW_ARCHIVE_SHA256="$archive_sha" BW_OUTPUT_DIRECTORY="$out_dir" python3 - <<'PY'
import json
import os

print(json.dumps({
    "status": "ok",
    "archive_sha256": os.environ["BW_ARCHIVE_SHA256"],
    "out": os.environ["BW_OUTPUT_DIRECTORY"],
}, sort_keys=True))
PY

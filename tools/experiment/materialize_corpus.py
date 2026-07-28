"""Materialize a crates.io corpus manifest into on-disk sources.

The scanner never downloads anything: `build-precheck` resolves `source_ref` as a
filesystem path and refuses `crates_io` / `git_archive` records with
`source_not_materialized`. This tool bridges that gap. It reads a corpus manifest
whose records name crates.io releases, downloads and extracts each one, and
writes a second manifest whose records are `local_archive` and therefore
scannable.

The downloaded archive digest is recorded in `intake_notes` so a materialized
tree can be tied back to the exact bytes that produced it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import tarfile
import urllib.error
import urllib.request

CRATE_URL = "https://static.crates.io/crates/{name}/{name}-{version}.crate"
SCHEMA_VERSION = "v3.2.corpus_manifest.1"
MATERIALIZED_KIND = "local_archive"
DOWNLOADABLE_KINDS = {"crates_io"}


class MaterializeError(Exception):
    """A record could not be materialized."""


def read_manifest(path: pathlib.Path) -> list[dict]:
    records = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise MaterializeError(f"{path}:{number}: invalid JSON: {error}") from error
    if not records:
        raise MaterializeError(f"{path}: manifest has no records")
    return records


def download(url: str, destination: pathlib.Path, timeout: int) -> str:
    """Fetch `url` into `destination` and return its SHA-256."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        raise MaterializeError(f"{url}: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise MaterializeError(f"{url}: {error.reason}") from error
    destination.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def safe_extract(archive: pathlib.Path, target_root: pathlib.Path) -> pathlib.Path:
    """Extract a .crate archive, rejecting any member that escapes `target_root`."""
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        roots = set()
        for member in members:
            member_path = pathlib.PurePosixPath(member.name)
            if member.name.startswith("/") or ".." in member_path.parts:
                raise MaterializeError(f"{archive.name}: unsafe member path {member.name}")
            if member.issym() or member.islnk():
                link_path = pathlib.PurePosixPath(member.linkname)
                if member.linkname.startswith("/") or ".." in link_path.parts:
                    raise MaterializeError(
                        f"{archive.name}: escaping link {member.name} -> {member.linkname}"
                    )
            if member_path.parts:
                roots.add(member_path.parts[0])
        if len(roots) != 1:
            raise MaterializeError(
                f"{archive.name}: expected exactly one top-level directory, found {sorted(roots)}"
            )
        tar.extractall(target_root, filter="tar")
    return target_root / roots.pop()


def materialize(
    record: dict, corpus_root: pathlib.Path, timeout: int, force: bool
) -> tuple[pathlib.Path, str | None]:
    name = record["crate_name"]
    version = record["version"]
    source_kind = record["source_kind"]

    if source_kind == MATERIALIZED_KIND:
        existing = pathlib.Path(record["source_ref"])
        if not existing.is_absolute():
            existing = (corpus_root / existing).resolve()
        if not (existing / "Cargo.toml").is_file():
            raise MaterializeError(f"{name} {version}: {existing} has no Cargo.toml")
        return existing, None

    if source_kind not in DOWNLOADABLE_KINDS:
        raise MaterializeError(
            f"{name} {version}: source_kind {source_kind} cannot be downloaded"
        )

    extracted = corpus_root / f"{name}-{version}"
    if extracted.is_dir() and not force:
        if not (extracted / "Cargo.toml").is_file():
            raise MaterializeError(f"{name} {version}: {extracted} exists but has no Cargo.toml")
        return extracted, None

    archive = corpus_root / f"{name}-{version}.crate"
    digest = download(CRATE_URL.format(name=name, version=version), archive, timeout)
    unpacked = safe_extract(archive, corpus_root)
    archive.unlink()
    if unpacked != extracted:
        if extracted.exists():
            raise MaterializeError(f"{name} {version}: {extracted} already exists")
        unpacked.rename(extracted)
    if not (extracted / "Cargo.toml").is_file():
        raise MaterializeError(f"{name} {version}: extracted tree has no Cargo.toml")
    return extracted, digest


def materialized_record(
    record: dict, source_path: pathlib.Path, digest: str | None, relative_to: pathlib.Path | None
) -> dict:
    reference = source_path
    if relative_to is not None:
        try:
            reference = source_path.relative_to(relative_to)
        except ValueError:
            reference = source_path

    notes = list(record.get("intake_notes", []))
    origin = f"materialized_from={record['source_kind']}:{record['source_ref']}"
    if origin not in notes:
        notes.append(origin)
    if digest is not None:
        marker = f"archive_sha256={digest}"
        if marker not in notes:
            notes.append(marker)

    updated = dict(record)
    updated["schema_version"] = SCHEMA_VERSION
    updated["source_kind"] = MATERIALIZED_KIND
    updated["source_ref"] = reference.as_posix()
    updated["intake_notes"] = notes
    return updated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--corpus-root", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--relative-refs",
        action="store_true",
        help="write source_ref relative to the output manifest directory",
    )
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument(
        "--force", action="store_true", help="re-download crates that are already extracted"
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="skip records that fail instead of stopping; exit 1 if any were skipped",
    )
    args = parser.parse_args(argv)

    try:
        records = read_manifest(args.manifest)
    except MaterializeError as error:
        print(f"materialize-corpus: {error}", file=sys.stderr)
        return 2

    args.corpus_root.mkdir(parents=True, exist_ok=True)
    corpus_root = args.corpus_root.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    relative_to = args.output.parent.resolve() if args.relative_refs else None

    materialized: list[dict] = []
    skipped: list[str] = []
    for record in records:
        label = f"{record.get('crate_name')} {record.get('version')}"
        try:
            source_path, digest = materialize(
                record, corpus_root, args.timeout_seconds, args.force
            )
        except (MaterializeError, KeyError, OSError, tarfile.TarError) as error:
            if not args.keep_going:
                print(f"materialize-corpus: {label}: {error}", file=sys.stderr)
                return 1
            print(f"materialize-corpus: skipping {label}: {error}", file=sys.stderr)
            skipped.append(label)
            continue
        materialized.append(materialized_record(record, source_path, digest, relative_to))

    with args.output.open("w", encoding="utf-8") as handle:
        for record in materialized:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    print(
        json.dumps(
            {
                "kind": "v3-2-corpus-materialization",
                "materialized_count": len(materialized),
                "skipped_count": len(skipped),
                "corpus_root": str(corpus_root),
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 1 if skipped else 0


if __name__ == "__main__":
    raise SystemExit(main())

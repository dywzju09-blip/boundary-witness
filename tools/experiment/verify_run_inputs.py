#!/usr/bin/env python3
"""Verify that large-run inputs are frozen before a formal run starts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


RUN_INPUT_CONFIG_SCHEMA = "boundary-witness/run-input-config/v1"
RUN_INPUT_LOCK_SCHEMA = "boundary-witness/run-input-lock/v1"
DATASET_MANIFEST_SCHEMA = "boundary-witness/dataset-manifest/v1"


class VerificationError(Exception):
    pass


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def load_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise VerificationError(f"{path}: expected JSON object")
    return data


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return sha256_bytes(encoded)


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def run_git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repository,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise VerificationError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def repository_commit(repository: Path) -> str:
    return run_git(repository, "rev-parse", "HEAD")


def repository_dirty(repository: Path) -> bool:
    return bool(run_git(repository, "status", "--porcelain=v1", "--untracked-files=all"))


def rust_toolchain() -> str:
    result = subprocess.run(["rustc", "--version"], text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise VerificationError(f"rustc --version failed: {result.stderr.strip()}")
    return result.stdout.strip()


def file_tree_hash(root: Path) -> str:
    if not root.is_dir():
        raise VerificationError(f"{root}: expected directory")
    digest = hashlib.sha256()
    for path in sorted((candidate for candidate in root.rglob("*") if candidate.is_file()), key=sort_key):
        if path.is_symlink():
            raise VerificationError(f"{path}: symlink is not allowed in hashed input")
        relative = path.relative_to(root).as_posix()
        file_hash = sha256_bytes(path.read_bytes())
        digest.update(f"{file_hash}  {relative}\n".encode("utf-8"))
    return digest.hexdigest()


def sort_key(path: Path) -> bytes:
    return path.as_posix().encode("utf-8")


def collect_schema_versions(repository: Path) -> list[str]:
    versions: set[str] = set()
    for directory in [repository / "schemas", repository / "experiments" / "schemas"]:
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*.json"), key=sort_key):
            data = load_json(path)
            collect_schema_consts(data, versions)
    return sorted(versions)


def collect_schema_consts(value: object, versions: set[str]) -> None:
    if isinstance(value, dict):
        if value.get("const") and looks_like_schema_version(value["const"]):
            versions.add(str(value["const"]))
        for nested in value.values():
            collect_schema_consts(nested, versions)
    elif isinstance(value, list):
        for nested in value:
            collect_schema_consts(nested, versions)


def looks_like_schema_version(value: object) -> bool:
    return isinstance(value, str) and ("/" in value or value.startswith("v")) and "." in value


def require_field(data: dict[str, object], field: str, expected_type: type, label: str) -> object:
    if field not in data:
        raise VerificationError(f"{label}.{field}: missing required field")
    value = data[field]
    if not isinstance(value, expected_type):
        raise VerificationError(f"{label}.{field}: expected {expected_type.__name__}")
    return value


def verify_dataset_manifest(dataset: dict[str, object], config: dict[str, object]) -> dict[str, str]:
    if dataset.get("schema_version") != DATASET_MANIFEST_SCHEMA:
        raise VerificationError("dataset manifest schema version mismatch")
    dataset_id = str(require_field(dataset, "dataset_id", str, "dataset"))
    dataset_version = str(require_field(dataset, "dataset_version", str, "dataset"))
    dataset_hash = str(require_field(dataset, "tree_sha256", str, "dataset"))
    if not is_sha256(dataset_hash):
        raise VerificationError("dataset tree hash is not a lowercase SHA-256")
    if dataset_id != config.get("expected_dataset_id"):
        raise VerificationError("dataset id mismatch")
    if dataset_version != config.get("expected_dataset_version"):
        raise VerificationError("dataset version mismatch")
    if dataset_hash != config.get("expected_dataset_sha256"):
        raise VerificationError("dataset hash mismatch")
    return {
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "tree_sha256": dataset_hash,
        "inventory_sha256": str(dataset.get("inventory_sha256", "")),
    }


def verify_run_config(config: dict[str, object]) -> None:
    if config.get("schema_version") != RUN_INPUT_CONFIG_SCHEMA:
        raise VerificationError("run config schema version mismatch")
    required = [
        "run_id",
        "expected_toolchain",
        "expected_contract_snapshot_sha256",
        "expected_schema_versions",
        "expected_dataset_id",
        "expected_dataset_version",
        "expected_dataset_sha256",
        "expected_experiment_config_sha256",
        "experiment_config",
    ]
    for field in required:
        if field not in config:
            raise VerificationError(f"run config {field}: missing required field")
    for field in [
        "expected_contract_snapshot_sha256",
        "expected_dataset_sha256",
        "expected_experiment_config_sha256",
    ]:
        if not is_sha256(config[field]):
            raise VerificationError(f"run config {field}: expected lowercase SHA-256")
    if not isinstance(config["expected_schema_versions"], list) or not all(
        isinstance(item, str) for item in config["expected_schema_versions"]
    ):
        raise VerificationError("run config expected_schema_versions: expected string array")


def compare_or_fail(name: str, actual: object, expected: object) -> None:
    if actual != expected:
        raise VerificationError(f"{name} mismatch: actual={actual!r} expected={expected!r}")


def atomic_write_json(path: Path, value: dict[str, object]) -> None:
    partial = Path(str(path) + ".partial")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        partial.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(partial, path)
    except Exception:
        unlink_if_exists(partial)
        raise


def unlink_if_exists(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def verify(args: argparse.Namespace) -> dict[str, object]:
    repository = Path(args.repository).resolve()
    dataset_manifest_path = Path(args.dataset_manifest).resolve()
    run_config_path = Path(args.run_config).resolve()
    expected_commit = args.expected_commit

    actual_commit = repository_commit(repository)
    compare_or_fail("code commit", actual_commit, expected_commit)
    if repository_dirty(repository):
        raise VerificationError("repository is dirty")

    dataset = load_json(dataset_manifest_path)
    config = load_json(run_config_path)
    verify_run_config(config)

    actual_toolchain = rust_toolchain()
    compare_or_fail("toolchain", actual_toolchain, config["expected_toolchain"])

    actual_contract_hash = file_tree_hash(repository / "contracts")
    compare_or_fail("contract snapshot", actual_contract_hash, config["expected_contract_snapshot_sha256"])

    actual_schema_versions = collect_schema_versions(repository)
    expected_schema_versions = sorted(str(item) for item in config["expected_schema_versions"])
    compare_or_fail("schema versions", actual_schema_versions, expected_schema_versions)

    dataset_identity = verify_dataset_manifest(dataset, config)

    actual_config_hash = canonical_json_sha256(config["experiment_config"])
    compare_or_fail(
        "config hash",
        actual_config_hash,
        config["expected_experiment_config_sha256"],
    )

    return {
        "schema_version": RUN_INPUT_LOCK_SCHEMA,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repository": str(repository.name),
        "code_commit": actual_commit,
        "code_dirty": False,
        "toolchain": actual_toolchain,
        "contract_snapshot_sha256": actual_contract_hash,
        "schema_versions": actual_schema_versions,
        "dataset": dataset_identity,
        "experiment_config_sha256": actual_config_hash,
        "run_id": str(config["run_id"]),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--dataset-manifest", required=True)
    parser.add_argument("--run-config", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output-lock", required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    output_lock = Path(args.output_lock)
    unlink_if_exists(Path(str(output_lock) + ".partial"))
    try:
        lock = verify(args)
        atomic_write_json(output_lock, lock)
    except Exception as source:
        unlink_if_exists(output_lock)
        unlink_if_exists(Path(str(output_lock) + ".partial"))
        if isinstance(source, VerificationError):
            return fail(str(source))
        return fail(f"verification failed: {source}")
    print(json.dumps({"lock": str(output_lock), "verified": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

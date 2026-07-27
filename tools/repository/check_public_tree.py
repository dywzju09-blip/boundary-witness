#!/usr/bin/env python3
"""Validate that a public BoundaryWitness tree contains no private artifacts."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


FORBIDDEN_DIR_NAMES = {
    ".superpowers",
    ".worktrees",
    "boundary-witness-data",
    "holdout",
    "private",
    "private-results",
    "sealed-holdout",
    "security-candidates",
    "target",
}
FORBIDDEN_DIR_PREFIXES = ("sealed-" + "holdout-r",)
FORBIDDEN_FILE_NAMES = {".DS_Store"}
FORBIDDEN_TEXT_TOKENS = (
    "/" + "Users/",
    "private-" + "results/",
    "sealed-" + "holdout-r",
)
TEXT_SCAN_EXEMPT_FILES = {".git", ".gitignore"}


def rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def is_utf8_text(path: Path) -> bool:
    try:
        path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False
    except OSError:
        return False
    return True


def is_forbidden_dir_name(name: str) -> bool:
    return name in FORBIDDEN_DIR_NAMES or any(
        name.startswith(prefix) for prefix in FORBIDDEN_DIR_PREFIXES
    )


def scan(root: Path, max_bytes: int) -> list[str]:
    violations: list[str] = []
    root = root.resolve()

    for current, dirs, files in os.walk(root):
        current_path = Path(current)

        if current_path.name == ".git":
            dirs[:] = []
            continue

        kept_dirs: list[str] = []
        for name in dirs:
            child = current_path / name
            if name == ".git":
                continue
            if is_forbidden_dir_name(name):
                violations.append(f"{rel(child, root)}: forbidden directory")
                continue
            kept_dirs.append(name)
        dirs[:] = kept_dirs

        for name in files:
            path = current_path / name
            relative = rel(path, root)
            if name == ".git":
                continue
            if name in FORBIDDEN_FILE_NAMES:
                violations.append(f"{relative}: forbidden file")
                continue

            try:
                size = path.stat().st_size
            except OSError as error:
                violations.append(f"{relative}: cannot stat ({error})")
                continue

            if size > max_bytes:
                violations.append(f"{relative}: file exceeds {max_bytes} bytes")
                continue

            if name in TEXT_SCAN_EXEMPT_FILES:
                continue

            if is_utf8_text(path):
                text = path.read_text(encoding="utf-8")
                for token in FORBIDDEN_TEXT_TOKENS:
                    if token in text:
                        violations.append(f"{relative}: forbidden token {token}")
                        break

    return sorted(violations)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--max-bytes", required=True, type=int)
    args = parser.parse_args()

    violations = scan(args.root, args.max_bytes)
    for violation in violations:
        print(violation)
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())

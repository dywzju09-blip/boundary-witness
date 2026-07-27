#!/usr/bin/env python3
"""Check relative links and heading anchors in tracked Markdown files."""

from __future__ import annotations

import argparse
import re
import subprocess
import unicodedata
from pathlib import Path
from urllib.parse import unquote


LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def tracked_markdown(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    )
    return [root / line for line in result.stdout.splitlines() if line]


def strip_code_fences(lines: list[str]) -> list[tuple[int, str]]:
    output: list[tuple[int, str]] = []
    in_fence = False
    for index, line in enumerate(lines, start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            output.append((index, line))
    return output


def slugify(heading: str) -> str:
    value = heading.strip().lower()
    value = unicodedata.normalize("NFKC", value)
    chars: list[str] = []
    previous_dash = False
    for char in value:
        category = unicodedata.category(char)
        if char.isspace() or char == "-":
            if not previous_dash:
                chars.append("-")
                previous_dash = True
            continue
        if category[0] in {"L", "N"} or char == "_":
            chars.append(char)
            previous_dash = False
            continue
        if category.startswith("M"):
            chars.append(char)
            previous_dash = False
    return "".join(chars).strip("-")


def heading_anchors(path: Path) -> set[str]:
    anchors: set[str] = set()
    counts: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if not match:
            continue
        base = slugify(match.group(2))
        if not base:
            continue
        count = counts.get(base, 0)
        counts[base] = count + 1
        anchors.add(base if count == 0 else f"{base}-{count}")
    return anchors


def is_external(target: str) -> bool:
    lowered = target.lower()
    return lowered.startswith(("http://", "https://", "mailto:"))


def split_target(target: str) -> tuple[str, str]:
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    path, sep, anchor = target.partition("#")
    return unquote(path), unquote(anchor) if sep else ""


def check_file(path: Path, root: Path, anchor_cache: dict[Path, set[str]]) -> list[str]:
    errors: list[str] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for line_number, line in strip_code_fences(lines):
        for match in LINK_RE.finditer(line):
            raw_target = match.group(1)
            if is_external(raw_target):
                continue
            target_path, anchor = split_target(raw_target)
            destination = path if not target_path else (path.parent / target_path)
            destination = destination.resolve()
            relative_source = path.relative_to(root).as_posix()

            if not destination.exists():
                errors.append(f"{relative_source}:{line_number}: missing file {raw_target}")
                continue
            if anchor:
                anchors = anchor_cache.setdefault(destination, heading_anchors(destination))
                if anchor.lower() not in anchors:
                    errors.append(f"{relative_source}:{line_number}: missing anchor #{anchor}")
    return errors


def check(root: Path) -> list[str]:
    root = root.resolve()
    anchor_cache: dict[Path, set[str]] = {}
    errors: list[str] = []
    for path in tracked_markdown(root):
        errors.extend(check_file(path.resolve(), root, anchor_cache))
    return sorted(errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()

    errors = check(args.root)
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

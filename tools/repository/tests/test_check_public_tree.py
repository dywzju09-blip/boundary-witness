from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
CHECKER = REPO_ROOT / "tools" / "repository" / "check_public_tree.py"


class CheckPublicTreeTests(unittest.TestCase):
    def run_checker(self, root: Path, max_bytes: int = 1024) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--root",
                str(root),
                "--max-bytes",
                str(max_bytes),
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_clean_tree_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# Clean\n", encoding="utf-8")

            result = self.run_checker(root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_forbidden_paths_fail_with_relative_path(self) -> None:
        cases = [
            ("target/build.log", "target"),
            (".superpowers/state.json", ".superpowers"),
            (".DS_Store", ".DS_Store"),
            ("private-" + "results/run.json", "private-results"),
            ("sealed-" + "holdout-r42/clean.txt", "sealed-" + "holdout-r42"),
            ("security-candidates/candidate.md", "security-candidates"),
        ]
        for rel_path, expected in cases:
            with self.subTest(rel_path=rel_path), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                path = root / rel_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("blocked\n", encoding="utf-8")

                result = self.run_checker(root)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stdout)

    def test_large_file_fails_with_relative_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "fixtures" / "large.bin"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"x" * (10 * 1024 * 1024 + 1))

            result = self.run_checker(root, max_bytes=10 * 1024 * 1024)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fixtures/large.bin", result.stdout)

    def test_private_tokens_fail_with_relative_path(self) -> None:
        cases = [
            ("docs/path.md", "artifact stored at /" + "Users/example/private"),
            ("docs/private.md", "private-" + "results/run-1"),
            ("docs/holdout.md", "sealed-" + "holdout-r42"),
        ]
        for rel_path, content in cases:
            with self.subTest(rel_path=rel_path), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                path = root / rel_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

                result = self.run_checker(root)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(rel_path, result.stdout)


if __name__ == "__main__":
    unittest.main()

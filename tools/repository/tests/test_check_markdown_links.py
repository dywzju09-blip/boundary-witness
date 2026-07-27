from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
CHECKER = REPO_ROOT / "tools" / "repository" / "check_markdown_links.py"


class CheckMarkdownLinksTests(unittest.TestCase):
    def run_checker(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), "--root", str(root)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def make_repo(self, root: Path) -> None:
        subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)

    def track_all(self, root: Path) -> None:
        subprocess.run(["git", "add", "."], cwd=root, check=True)

    def test_valid_links_and_skips_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_repo(root)
            (root / "docs").mkdir()
            (root / "docs" / "guide.md").write_text(
                "# Guide\n\n## Details\n\nBody\n",
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                "\n".join(
                    [
                        "# Root",
                        "",
                        "## Local Section",
                        "",
                        "[guide](docs/guide.md)",
                        "[same](#local-section)",
                        "[cross](docs/guide.md#details)",
                        "[web](https://example.com/path)",
                        "[mail](mailto:test@example.invalid)",
                        "```",
                        "[missing](docs/missing.md)",
                        "```",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            self.track_all(root)

            result = self.run_checker(root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_file_and_anchor_fail_with_source_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_repo(root)
            (root / "docs").mkdir()
            (root / "docs" / "guide.md").write_text("# Guide\n", encoding="utf-8")
            (root / "README.md").write_text(
                "\n".join(
                    [
                        "# Root",
                        "",
                        "[missing](docs/missing.md)",
                        "[bad-anchor](docs/guide.md#missing-section)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            self.track_all(root)

            result = self.run_checker(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("README.md:3", result.stdout)
        self.assertIn("docs/missing.md", result.stdout)
        self.assertIn("README.md:4", result.stdout)
        self.assertIn("#missing-section", result.stdout)


if __name__ == "__main__":
    unittest.main()

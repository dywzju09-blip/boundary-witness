from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
TOOL = REPO_ROOT / "tools" / "experiment" / "verify_run_inputs.py"


class VerifyRunInputsTests(unittest.TestCase):
    def make_repo(self, root: Path) -> str:
        (root / "contracts" / "callback-retention").mkdir(parents=True)
        (root / "schemas" / "v1").mkdir(parents=True)
        (root / "experiments" / "schemas").mkdir(parents=True)
        (root / "contracts" / "callback-retention" / "contract.toml").write_text(
            'schema_version = "bw.contract/0.1"\n',
            encoding="utf-8",
        )
        (root / "schemas" / "v1" / "record.schema.json").write_text(
            json.dumps(
                {
                    "type": "object",
                    "properties": {"schema_version": {"const": "bw.test/0.1"}},
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "experiments" / "schemas" / "summary.schema.json").write_text(
            json.dumps(
                {
                    "type": "object",
                    "properties": {"schema_version": {"const": "bw.summary/0.1"}},
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=root, check=True, capture_output=True)
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()

    def write_fake_rustc(self, directory: Path, version: str) -> dict[str, str]:
        directory.mkdir(parents=True, exist_ok=True)
        rustc = directory / "rustc"
        rustc.write_text(f"#!/bin/sh\nprintf '%s\\n' '{version}'\n", encoding="utf-8")
        rustc.chmod(rustc.stat().st_mode | stat.S_IXUSR)
        env = os.environ.copy()
        env["PATH"] = str(directory) + os.pathsep + env.get("PATH", "")
        return env

    def sha256_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def tree_hash(self, root: Path, relative_root: str) -> str:
        base = root / relative_root
        digest = hashlib.sha256()
        for path in sorted(p for p in base.rglob("*") if p.is_file()):
            rel = path.relative_to(base).as_posix()
            file_hash = self.sha256_bytes(path.read_bytes())
            digest.update(f"{file_hash}  {rel}\n".encode("utf-8"))
        return digest.hexdigest()

    def schema_versions(self, root: Path) -> list[str]:
        versions = set()
        for directory in [root / "schemas", root / "experiments" / "schemas"]:
            for path in directory.rglob("*.json"):
                data = json.loads(path.read_text(encoding="utf-8"))
                versions.add(data["properties"]["schema_version"]["const"])
        return sorted(versions)

    def config_hash(self, config: object) -> str:
        encoded = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        return self.sha256_bytes(encoded)

    def write_inputs(
        self,
        root: Path,
        repository: Path,
        *,
        rustc_version: str = "rustc-test 1.0.0",
        contract_hash: str | None = None,
        schema_versions: list[str] | None = None,
        dataset_hash: str = "a" * 64,
        expected_dataset_hash: str | None = None,
        config_hash: str | None = None,
        dataset_id: str = "bw-sample",
        dataset_version: str = "v1",
    ) -> tuple[Path, Path, dict[str, object]]:
        experiment_config = {"campaign": "sample", "budget": 1}
        expected_config_hash = config_hash or self.config_hash(experiment_config)
        dataset_manifest = root / "dataset.json"
        dataset_manifest.write_text(
            json.dumps(
                {
                    "schema_version": "boundary-witness/dataset-manifest/v1",
                    "dataset_id": dataset_id,
                    "dataset_version": dataset_version,
                    "classification": "public",
                    "created_at": "2026-07-27T00:00:00Z",
                    "file_count": 1,
                    "total_bytes": 1,
                    "tree_sha256": dataset_hash,
                    "inventory_sha256": "b" * 64,
                    "inventory_record_count": 1,
                    "storage_replicas": ["local"],
                    "exclusions": [".bw-index/**"],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        run_config = root / "run-config.json"
        config_data: dict[str, object] = {
            "schema_version": "boundary-witness/run-input-config/v1",
            "run_id": "run-sample",
            "expected_toolchain": rustc_version,
            "expected_contract_snapshot_sha256": contract_hash
            or self.tree_hash(repository, "contracts"),
            "expected_schema_versions": schema_versions or self.schema_versions(repository),
            "expected_dataset_id": dataset_id,
            "expected_dataset_version": dataset_version,
            "expected_dataset_sha256": expected_dataset_hash or dataset_hash,
            "expected_experiment_config_sha256": expected_config_hash,
            "experiment_config": experiment_config,
        }
        run_config.write_text(json.dumps(config_data, sort_keys=True) + "\n", encoding="utf-8")
        return dataset_manifest, run_config, config_data

    def run_tool(
        self,
        repo: Path,
        dataset_manifest: Path,
        run_config: Path,
        expected_commit: str,
        output_lock: Path,
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--repository",
                str(repo),
                "--dataset-manifest",
                str(dataset_manifest),
                "--run-config",
                str(run_config),
                "--expected-commit",
                expected_commit,
                "--output-lock",
                str(output_lock),
            ],
            text=True,
            capture_output=True,
            env=env,
        )

    def test_verify_run_inputs_writes_lock_when_all_inputs_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            inputs = Path(tmp) / "inputs"
            inputs.mkdir()
            commit = self.make_repo(repo)
            env = self.write_fake_rustc(Path(tmp) / "bin", "rustc-test 1.0.0")
            dataset, config, _ = self.write_inputs(inputs, repo)
            lock = repo / "lock.json"

            result = self.run_tool(repo, dataset, config, commit, lock, env)

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            data = json.loads(lock.read_text(encoding="utf-8"))
        self.assertEqual(data["code_commit"], commit)
        self.assertFalse(data["code_dirty"])
        self.assertEqual(data["dataset"]["dataset_id"], "bw-sample")
        self.assertRegex(data["contract_snapshot_sha256"], r"^[0-9a-f]{64}$")

    def test_verify_run_inputs_rejects_each_mismatch_without_lock(self) -> None:
        cases = [
            ("commit", {"expected_commit": "0" * 40}, "code commit"),
            ("toolchain", {"rustc_version": "wrong-rustc"}, "toolchain"),
            ("contract", {"contract_hash": "c" * 64}, "contract"),
            ("schema", {"schema_versions": ["bw.test/0.1"]}, "schema versions"),
            ("dataset", {"expected_dataset_hash": "d" * 64}, "dataset"),
            ("config", {"config_hash": "e" * 64}, "config"),
        ]
        for name, overrides, message in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                repo = Path(tmp) / "repo"
                repo.mkdir()
                inputs = Path(tmp) / "inputs"
                inputs.mkdir()
                commit = self.make_repo(repo)
                env = self.write_fake_rustc(Path(tmp) / "bin", "rustc-test 1.0.0")
                expected_commit = str(overrides.pop("expected_commit", commit))
                dataset, config, _ = self.write_inputs(inputs, repo, **overrides)
                lock = repo / "lock.json"

                result = self.run_tool(repo, dataset, config, expected_commit, lock, env)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(lock.exists())

    def test_verify_run_inputs_rejects_dirty_tree_without_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            inputs = Path(tmp) / "inputs"
            inputs.mkdir()
            commit = self.make_repo(repo)
            env = self.write_fake_rustc(Path(tmp) / "bin", "rustc-test 1.0.0")
            dataset, config, _ = self.write_inputs(inputs, repo)
            (repo / "untracked.txt").write_text("dirty\n", encoding="utf-8")
            lock = repo / "lock.json"

            result = self.run_tool(repo, dataset, config, commit, lock, env)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dirty", result.stderr)
        self.assertFalse(lock.exists())

    def tearDown(self) -> None:
        shutil.rmtree("/tmp/bw-verify-run-inputs-test", ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
RUNNER = REPO_ROOT / "tools" / "remote" / "run"


class RemoteRunTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.log = self.root / "calls.log"
        self.local_marker = self.root / "local-command-ran"
        self._write_fake(
            "ssh",
            """
            printf 'ssh' >>"$BW_TEST_CALL_LOG"
            printf '\t%s' "$@" >>"$BW_TEST_CALL_LOG"
            printf '\n' >>"$BW_TEST_CALL_LOG"
            case " $* " in
              *" /mnt/hw/bw-agent/.agent-build-root "*)
                if [[ "${BW_TEST_FAIL_PREFLIGHT:-0}" == "1" ]]; then
                  exit 42
                fi
                ;;
            esac
            if [[ "$*" == *"remote-command-sentinel"* ]]; then
              printf 'remote-ok\n'
            fi
            """,
        )
        self._write_fake(
            "rsync",
            """
            printf 'rsync' >>"$BW_TEST_CALL_LOG"
            printf '\t%s' "$@" >>"$BW_TEST_CALL_LOG"
            for argument in "$@"; do
              case "$argument" in
                --exclude-from=*)
                  exclude_file="${argument#--exclude-from=}"
                  while IFS= read -r -d '' ignored_path; do
                    printf '\tignored=%s' "$ignored_path" >>"$BW_TEST_CALL_LOG"
                  done <"$exclude_file"
                  ;;
              esac
            done
            printf '\n' >>"$BW_TEST_CALL_LOG"
            """,
        )
        self._write_fake(
            "memory-hog",
            """
            : >"$BW_TEST_LOCAL_MARKER"
            """,
        )

    def _write_fake(self, name: str, body: str) -> None:
        path = self.bin_dir / name
        path.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            + textwrap.dedent(body).lstrip(),
            encoding="utf-8",
        )
        path.chmod(0o755)

    def run_runner(self, *args: str, fail_preflight: bool = False) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.bin_dir}:{env['PATH']}",
                "BW_TEST_CALL_LOG": str(self.log),
                "BW_TEST_LOCAL_MARKER": str(self.local_marker),
                "BW_TEST_FAIL_PREFLIGHT": "1" if fail_preflight else "0",
            }
        )
        return subprocess.run(
            ["bash", str(RUNNER), *args],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def calls(self) -> list[str]:
        if not self.log.exists():
            return []
        return self.log.read_text(encoding="utf-8").splitlines()

    def test_requires_separator_and_command(self) -> None:
        result = self.run_runner()
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_marker_failure_stops_before_sync_or_execution(self) -> None:
        result = self.run_runner("--", "memory-hog", fail_preflight=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("safety marker", result.stderr)
        self.assertEqual(len(self.calls()), 1)
        self.assertTrue(self.calls()[0].startswith("ssh\t"))
        self.assertIn("/mnt/hw/bw-agent/.agent-build-root", self.calls()[0])
        self.assertFalse(self.local_marker.exists())

    def test_syncs_worktree_then_runs_command_remotely(self) -> None:
        result = self.run_runner("--", "remote-command-sentinel", "argument")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("remote-ok", result.stdout)
        calls = self.calls()
        self.assertEqual(len(calls), 3)
        self.assertTrue(calls[0].startswith("ssh\t"))
        self.assertIn("test\t-f\t/mnt/hw/bw-agent/.agent-build-root", calls[0])
        self.assertIn("ConnectTimeout=10", calls[0])
        self.assertIn("ServerAliveInterval=15", calls[0])
        self.assertIn("ServerAliveCountMax=3", calls[0])
        self.assertTrue(calls[1].startswith("rsync\t"))
        self.assertIn("--delete-delay", calls[1])
        self.assertIn("--delete-excluded", calls[1])
        self.assertIn("--compress", calls[1])
        self.assertIn("--partial", calls[1])
        self.assertIn("--timeout=60", calls[1])
        self.assertIn("--from0", calls[1])
        self.assertIn("--exclude-from=", calls[1])
        self.assertIn("ignored=tools/remote/tests/__pycache__/", calls[1])
        self.assertIn("ConnectTimeout=10", calls[1])
        self.assertIn("--exclude=target/", calls[1])
        self.assertIn("server-b:/mnt/hw/bw-agent/worktree/", calls[1])
        self.assertTrue(calls[2].startswith("ssh\t"))
        self.assertIn("ServerAliveInterval=15", calls[2])
        self.assertIn("bash -c '", calls[2])
        self.assertNotIn("bash -lc", calls[2])
        self.assertIn("cd /mnt/hw/bw-agent/worktree", calls[2])
        self.assertIn("remote-command-sentinel argument", calls[2])

    def test_preserves_argument_boundaries_and_sets_remote_paths(self) -> None:
        result = self.run_runner("--", "printf", "%s", "a b", "$HOME", "semi;colon")
        self.assertEqual(result.returncode, 0, result.stderr)
        remote_call = self.calls()[-1]
        self.assertIn("CARGO_HOME=/mnt/hw/bw-agent/cargo-home", remote_call)
        self.assertIn(r"a\ b", remote_call)
        self.assertIn(r"\$HOME", remote_call)
        self.assertIn(r"semi\;colon", remote_call)

    def test_rebuildable_caches_are_local_while_task_data_stays_on_nfs(self) -> None:
        # /mnt/hw 是 NFS：小文件创建/删除比本地盘慢两个数量级，而 target 目录和构建期
        # 临时目录正是这种形态。只有可重建的缓存能搬到本地盘；语料、结果、worktree
        # 是任务数据和产物，必须留在 /mnt/hw/bw-agent。
        result = self.run_runner("--", "remote-command-sentinel")
        self.assertEqual(result.returncode, 0, result.stderr)
        remote_call = self.calls()[-1]
        self.assertIn("CARGO_TARGET_DIR=/var/lib/bw-agent/targets/workspace", remote_call)
        self.assertIn("TMPDIR=/var/lib/bw-agent/tmp", remote_call)
        self.assertIn("BW_CORPUS_DIR=/mnt/hw/bw-agent/corpus", remote_call)
        self.assertIn("BW_RESULTS_DIR=/mnt/hw/bw-agent/results", remote_call)
        self.assertIn("cd /mnt/hw/bw-agent/worktree", remote_call)

    def test_cache_option_selects_a_separate_target_dir_per_toolchain(self) -> None:
        # 仓库根用 1.97.0，compiler/bw-rustc 用 nightly-2026-07-08。共用一个 target
        # 目录会互相 invalidate，每次切换都全量重编——而且不报错，只是慢。
        for flag in (["--cache", "bw-rustc"], ["--cache=bw-rustc"]):
            with self.subTest(flag=flag):
                self.log.unlink(missing_ok=True)
                result = self.run_runner(*flag, "--", "remote-command-sentinel")
                self.assertEqual(result.returncode, 0, result.stderr)
                remote_call = self.calls()[-1]
                self.assertIn(
                    "CARGO_TARGET_DIR=/var/lib/bw-agent/targets/bw-rustc", remote_call
                )
                self.assertNotIn("targets/workspace", remote_call)

    def test_unknown_cache_name_is_rejected_before_touching_the_remote(self) -> None:
        # 拼错的名字必须当场失败。放任它拼出一个新目录等于在远端静默造了个一次性
        # 工作区，还会让人以为缓存命中了。
        result = self.run_runner("--cache", "workspce", "--", "memory-hog")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown --cache", result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.local_marker.exists())

    def test_never_executes_requested_command_locally(self) -> None:
        result = self.run_runner("--", "memory-hog")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.local_marker.exists())
        self.assertIn("memory-hog", self.calls()[-1])


if __name__ == "__main__":
    unittest.main()

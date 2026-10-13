from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_parallel_unittest.py"
sys.path.insert(0, str(ROOT / "scripts"))

import run_parallel_unittest as parallel_unittest  # noqa: E402


class ParallelUnittestTests(unittest.TestCase):
    def test_temporary_default_is_exactly_eight(self) -> None:
        self.assertEqual(parallel_unittest.DEFAULT_WORKERS, 8)

    def test_repository_observers_and_real_beads_timing_stay_serial(self) -> None:
        self.assertIn("test_continue_sprint.py", parallel_unittest.SERIAL_TEST_FILES)
        self.assertIn("test_native_precommit.py", parallel_unittest.SERIAL_TEST_FILES)
        self.assertIn("test_supervise_native_worker.py", parallel_unittest.SERIAL_TEST_FILES)

    def test_build_shards_is_deterministic_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths: list[Path] = []
            for index, size in enumerate((100, 80, 60, 40, 20)):
                path = root / f"test_{index}.py"
                path.write_text("x" * size, encoding="utf-8")
                paths.append(path.resolve())
            first = parallel_unittest.build_shards(paths, 3)
            second = parallel_unittest.build_shards(list(reversed(paths)), 3)
            self.assertEqual(
                [[path.name for path in shard.paths] for shard in first],
                [[path.name for path in shard.paths] for shard in second],
            )
            assigned = [path for shard in first for path in shard.paths]
            self.assertCountEqual(assigned, paths)
            self.assertEqual(len(first), 3)

    def test_cli_runs_isolated_shards_and_aggregates_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests = root / "tests"
            tests.mkdir()
            for index in range(3):
                (tests / f"test_case_{index}.py").write_text(
                    "import os\n"
                    "import unittest\n\n"
                    "class Case(unittest.TestCase):\n"
                    "    def test_has_private_temp_root(self):\n"
                    "        self.assertIn('worker-', os.environ['TMPDIR'])\n",
                    encoding="utf-8",
                )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--workers",
                    "2",
                    "--start-directory",
                    "tests",
                ],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("configured_workers=2", result.stdout)
            self.assertIn("parallel unittest: PASS workers=2 tests=3", result.stdout)

    def test_cli_returns_nonzero_and_prints_failed_shard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_failure.py").write_text(
                "import unittest\n\n"
                "class Case(unittest.TestCase):\n"
                "    def test_failure(self):\n"
                "        self.fail('expected failure')\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--workers", "8"],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("parallel unittest: FAIL workers=1 tests=1", result.stdout)
            self.assertIn("expected failure", result.stderr)

    def test_cli_rejects_nonpositive_worker_count(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--workers", "0"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("positive integer", result.stderr)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_parallel_unittest.py"
sys.path.insert(0, str(ROOT / "scripts"))

import run_parallel_unittest as parallel_unittest  # noqa: E402


class ParallelUnittestTests(unittest.TestCase):
    def _assert_method_packing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "test_registered_finite_tool_wiring.py"
            path.write_text("# EXAMPLE packing-only source\n", encoding="utf-8")
            methods = [f"tests.{path.stem}.Case.test_{index}" for index in range(7)]
            hints = {"case_seconds": dict(zip(methods, [30, 30, 30, 200, 0, 0, 0])),
                     "fixture_seconds": {path.name: 10}}
            for selected_hints in (hints, {"case_seconds": {}, "fixture_seconds": {}}):
                with self.subTest(contract="method coverage", weighted=bool(selected_hints["case_seconds"])):
                    units = parallel_unittest.build_work_units([path], 2, {path: methods}, selected_hints)
                    actual = [item for unit in units for item in unit.selectors]
                    self.assertCountEqual(actual, methods, "method omission or duplication")
                    self.assertEqual(len(actual), len(set(actual)), "duplicate selected method")
                    self.assertGreater(len(units), 2, "workunit count must exceed process capacity")
                    self.assertEqual(units, parallel_unittest.build_work_units(
                        [path], 2, {path: methods}, selected_hints))
            units = parallel_unittest.build_work_units([path], 2, {path: methods}, hints)
            self.assertTrue(all(unit.estimated_bytes <= 900_000 or len(unit.selectors) == 1
                                for unit in units),
                            "multi-method group exceeds the 90-second packing estimate")
            oversized = next(unit for unit in units if methods[3] in unit.selectors)
            self.assertEqual(oversized.selectors, [methods[3]], "oversized method must stay atomic")
            self.assertEqual(oversized.estimated_bytes, 2_100_000,
                             "packing must include repeated fixture cost")

    @staticmethod
    def _process_fixture(tests: Path, filename: str, methods: int) -> None:
        body = '''import json, os, tempfile, time, unittest
from pathlib import Path
def event(kind, **fields):
    with open(os.environ['CWO_EXAMPLE_EVENT_LOG'], 'a') as stream:
        stream.write(json.dumps(dict(kind=kind, pid=os.getpid(), **fields))+'\\n')
def setUpModule():
    event('start', tmp=os.environ['TMPDIR'], cached=tempfile.gettempdir(), home=os.environ['HOME'])
def tearDownModule():
    event('finish')
class Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls): event('class-setup')
    @classmethod
    def tearDownClass(cls): event('class-cleanup')
'''
        for index in range(methods):
            body += (f"    def test_{index}(self):\n"
                     "        print('EXAMPLE_WORKUNIT_STDOUT: lossless diagnostic')\n"
                     "        event('case', test_id=self.id())\n"
                     "        time.sleep(0.05)\n")
        (tests / filename).write_text(body, encoding="utf-8")

    def _assert_process_method_units(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests, artifacts = root / "tests", root / "artifacts"
            tests.mkdir()
            filename = "test_registered_finite_tool_wiring.py"
            self._process_fixture(tests, filename, 5)
            self._process_fixture(tests, "test_native_release.py", 1)
            events_file = root / "events.jsonl"
            environment = dict(os.environ, CWO_EXAMPLE_EVENT_LOG=str(events_file))
            environment.pop("PYTHONUNBUFFERED", None)
            baseline_events = root / "original-file-events.jsonl"
            baseline_temp = root / "original-file-temp"
            baseline_temp.mkdir()
            original = subprocess.run(
                [sys.executable, "-m", "unittest", "-v", str(tests / filename)],
                cwd=root, env=dict(environment, CWO_EXAMPLE_EVENT_LOG=str(baseline_events),
                                   TMPDIR=str(baseline_temp), TMP=str(baseline_temp),
                                   TEMP=str(baseline_temp)),
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(original.returncode, 0,
                             json.dumps({"stdout": original.stdout, "stderr": original.stderr}))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--workers", "2", "--verbose",
                 "--artifacts-dir", str(artifacts)],
                cwd=root, env=environment, text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0,
                             json.dumps({"stdout": result.stdout, "stderr": result.stderr}))
            events = [json.loads(line) for line in events_file.read_text().splitlines()]
            cases = [row["test_id"] for row in events if row["kind"] == "case"]
            expected = [f"tests.{Path(filename).stem}.Case.test_{index}" for index in range(5)]
            original_ids = [row["test_id"] for row in
                            map(json.loads, baseline_events.read_text().splitlines())
                            if row["kind"] == "case"]
            self.assertEqual(original_ids, expected, "original FILE case identity control drifted")
            expected.append("tests.test_native_release.Case.test_0")
            self.assertCountEqual(cases, expected, "FILE-to-selector case IDs changed")
            self.assertEqual(len(cases), len(set(cases)))
            self._assert_process_events(events, environment["HOME"])
            logs = list(artifacts.glob("worker-*/unittest.log"))
            self.assertEqual(len(logs), 5, "workunits must retain distinct logs")
            for log in logs:
                text = log.read_text()
                marker = "EXAMPLE_WORKUNIT_STDOUT: lossless diagnostic"
                self.assertEqual(text.count(marker), 1, "worker diagnostic bytes lost or duplicated")
                self.assertLess(text.index(marker), text.rindex("\nRan "),
                                "worker stdout must precede the real unittest footer")
            serial = (artifacts / "serial-worker-01" / "unittest.log").read_text()
            self.assertIn("tests.test_native_release.Case.test_0", serial)
            self.assertTrue(all("test_native_release" not in path.read_text() for path in logs),
                            "serial file entered parallel work")

    def _assert_process_events(self, events: list[dict], home: str) -> None:
        active, peak, roots = set(), 0, []
        for row in events:
            if row["kind"] == "start":
                active.add(row["pid"])
                peak = max(peak, len(active))
                roots.append(row["tmp"])
                self.assertEqual(row["tmp"], row["cached"], "fresh child tempfile cache changed")
                self.assertEqual(row["home"], home)
            elif row["kind"] == "finish":
                active.remove(row["pid"])
        self.assertFalse(active, "worker did not finish")
        self.assertLessEqual(peak, 2, "worker concurrency bound exceeded")
        self.assertEqual(len(roots), len(set(roots)), "workunit temporary root reused")
        for kind in ("start", "finish", "class-setup", "class-cleanup"):
            self.assertEqual(sum(row["kind"] == kind for row in events), 6,
                             f"ordinary repeated fixture semantics changed: {kind}")
        serial_index = next(index for index, row in enumerate(events)
                            if row["kind"] == "case" and "test_native_release" in row["test_id"])
        self.assertEqual(sum(row["kind"] == "finish" for row in events[:serial_index]), 5,
                         "serial tail began before all parallel work completed")

    def _assert_discovery_failures(self) -> None:
        sources = {
            "import-error": "raise RuntimeError('EXAMPLE discovery failure')\n",
            "duplicate-id": ("import unittest\nclass Case(unittest.TestCase):\n"
                             "    def test_one(self): pass\n"
                             "def load_tests(loader, suite, pattern):\n"
                             "    return unittest.TestSuite([Case('test_one'), Case('test_one')])\n"),
        }
        for name, source in sources.items():
            with self.subTest(contract="truthful discovery refusal", case=name):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    (root / "tests").mkdir()
                    (root / "tests/test_registered_finite_tool_wiring.py").write_text(source)
                    result = subprocess.run([sys.executable, str(SCRIPT)], cwd=root,
                                            text=True, capture_output=True, check=False)
                    self.assertEqual(result.returncode, 2,
                                     json.dumps({"stdout": result.stdout, "stderr": result.stderr}))
                    self.assertIn("discovery failed", result.stderr)

    def _assert_cost_hint_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "costs.json"
            for cost in (0, 12.5, -1, float("nan"), float("inf"), True):
                with self.subTest(contract="portable finite cost hints", cost=cost):
                    path.write_text(json.dumps({"case_seconds": {"EXAMPLE.Case.test_one": cost},
                                               "fixture_seconds": {}}))
                    with patch.object(parallel_unittest, "COST_FILE", path):
                        if type(cost) in (int, float) and 0 <= cost < float("inf"):
                            self.assertEqual(parallel_unittest._cost_hints()["case_seconds"]
                                             ["EXAMPLE.Case.test_one"], cost)
                        else:
                            with self.assertRaisesRegex(ValueError, "finite nonnegative"):
                                parallel_unittest._cost_hints()

    def _assert_partial_launch_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "test_example.py"
            path.write_text("import time,unittest\nclass Case(unittest.TestCase):\n"
                            "    def test_wait(self): time.sleep(30)\n")
            created, popen = [], subprocess.Popen

            def launch(*args, **kwargs):
                if created:
                    raise OSError("EXAMPLE second launch failure")
                child = popen(*args, **kwargs)
                created.append(child)
                return child

            with patch.object(parallel_unittest.subprocess, "Popen", side_effect=launch):
                summary = parallel_unittest.run_shards(
                    [parallel_unittest.Shard(0, [path]), parallel_unittest.Shard(1, [path])],
                    workers=2, working_directory=root, start_directory=root,
                    artifacts_directory=root / "artifacts", verbose=True,
                )
            self.assertEqual(summary.exit_code, 2)
            self.assertIsNotNone(created[0].poll(), "launch failure left an owned child running")

    def _assert_capacity_filled_before_wait(self) -> None:
        created, closed = [], []

        def launch(shard, **options):
            entry = Mock(shard=shard)

            def poll():
                self.assertEqual(len(created) - len(closed), 2,
                                 "scheduler failed to fill requested capacity before waiting")
                return 0

            entry.process.poll.side_effect = poll
            entry.log_file.close.side_effect = lambda: closed.append(entry)
            created.append(entry)
            return entry

        with patch.object(parallel_unittest, "_start_shard", side_effect=launch):
            units = [parallel_unittest.Shard(index, []) for index in range(6)]
            observed = []
            parallel_unittest._run_bounded(units, 2, observed)
        self.assertEqual(len(observed), 6)
        self.assertEqual(len(closed), 6)

    def test_temporary_default_is_exactly_eight(self) -> None:
        self._assert_cost_hint_values()
        self.assertEqual(parallel_unittest.DEFAULT_WORKERS, 8)

    def test_source_readers_are_parallel_and_other_observers_stay_serial(self) -> None:
        self.assertNotIn("test_supervise_native_worker.py", parallel_unittest.SERIAL_TEST_FILES)
        self.assertNotIn("test_native_retry_supervision.py", parallel_unittest.SERIAL_TEST_FILES)
        self.assertNotIn("test_native_worker_planning.py", parallel_unittest.SERIAL_TEST_FILES)
        self.assertEqual(parallel_unittest.SERIAL_TEST_FILES, frozenset({
            "test_native_pool_workspace.py",
            "test_native_precommit.py",
            "test_native_precommit_packet.py",
            "test_native_recovery.py",
            "test_native_release.py",
        }))

    def test_build_shards_is_deterministic_and_complete(self) -> None:
        self._assert_method_packing()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths: list[Path] = []
            for index, size in enumerate((100, 80, 60, 40, 20)):
                measured = {1: "test_registered_native_pool_host.py", 2: "test_outbound_screen.py"}
                path = root / measured.get(index, f"test_{index}.py")
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
            outbound = next(shard for shard in first
                            if any(path.name == "test_outbound_screen.py" for path in shard.paths))
            self.assertEqual([path.name for path in outbound.paths], ["test_outbound_screen.py"])
            host = next(shard for shard in first
                        if any(path.name == "test_registered_native_pool_host.py" for path in shard.paths))
            self.assertEqual([path.name for path in host.paths], ["test_registered_native_pool_host.py"])
            single = parallel_unittest.build_shards(paths, 1)
            self.assertEqual(len(single), 1)
            self.assertCountEqual(single[0].paths, paths)
            weighted_paths = []
            for index in range(4):
                path = root / f"test_runtime_weight_{index}.py"
                path.write_text("x" * 32, encoding="utf-8")
                weighted_paths.append(path.resolve())
            costs = {weighted_paths[0].name: 400.0, weighted_paths[2].name: 300.0}
            with patch.object(parallel_unittest, "MEASURED_TEST_SECONDS", costs):
                weighted = parallel_unittest.build_shards(weighted_paths, 2)
            groups = {path.name: shard.index for shard in weighted for path in shard.paths}
            self.assertNotEqual(groups[weighted_paths[0].name], groups[weighted_paths[2].name])
            self.assertCountEqual(groups, [path.name for path in weighted_paths])

            finite = root / "test_registered_finite_tool_wiring.py"
            finite.write_text("x" * 32, encoding="utf-8")
            measured_paths = paths + [finite.resolve()]
            for workers in (4, 16):
                measured = parallel_unittest.build_shards(measured_paths, workers)
                self.assertEqual(
                    measured,
                    parallel_unittest.build_shards(list(reversed(measured_paths)), workers),
                )
                self.assertEqual(
                    [shard.paths for shard in measured[:3]],
                    [[finite.resolve()], [paths[1]], [paths[2]]],
                )
                self.assertCountEqual(
                    [path for shard in measured for path in shard.paths], measured_paths,
                )

    def test_cli_runs_isolated_shards_and_aggregates_success(self) -> None:
        self._assert_capacity_filled_before_wait()
        self._assert_process_method_units()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests = root / "tests"
            tests.mkdir()
            names = ["test_native_retry_supervision", "test_native_worker_planning", "test_outbound_screen"]
            for name in names:
                (tests / f"{name}.py").write_text(
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
                    "--verbose",
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
            self.assertIn("parallel_files=3 serial_files=0", result.stdout)
            self.assertIn("parallel unittest: PASS workers=2 tests=3", result.stdout)
            for name in names:
                self.assertRegex(
                    result.stdout,
                    rf"family_case_seconds (?:tests\.)?{name} [0-9]+\.[0-9]+",
                )

    def test_cli_returns_nonzero_and_prints_failed_shard(self) -> None:
        self._assert_partial_launch_cleanup()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_native_worker_planning.py").write_text(
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
        self._assert_discovery_failures()
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--workers", "0"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("positive integer", result.stderr)

    @staticmethod
    def _run_fixture(root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--workers", "2", "--verbose",
             "--artifacts-dir", str(root / "artifacts")],
            cwd=root, text=True, capture_output=True, check=False,
        )

    def test_cli_method_workunit_failures_and_errors_expose_logs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests = root / "tests"
            tests.mkdir()
            filename = "test_registered_finite_tool_wiring.py"
            self.assertIn(filename, parallel_unittest.METHOD_SHARDED_TEST_FILES)
            (tests / filename).write_text(
                "import unittest\nclass Case(unittest.TestCase):\n"
                "    def test_failure(self): self.fail('EXAMPLE method failure')\n"
                "    def test_error(self): raise RuntimeError('EXAMPLE method error')\n",
                encoding="utf-8",
            )
            result = self._run_fixture(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("parallel unittest: FAIL workers=2 tests=2", result.stdout)
            logs = sorted((root / "artifacts").glob("worker-*/unittest.log"))
            self.assertGreaterEqual(len(logs), 2, "fixture must span multiple method workunits")
            self.assertEqual(result.stdout.count("] FAIL files=1 tests=1"), 2)
            for index, log in enumerate(logs, 1):
                self.assertIn(f"--- shard {index:02d} log ---", result.stderr)
                self.assertIn(log.read_text(), result.stderr)
            self.assertIn("AssertionError: EXAMPLE method failure", result.stderr)
            self.assertIn("RuntimeError: EXAMPLE method error", result.stderr)

    def test_cli_rejects_exit_zero_without_unittest_footer(self) -> None:
        for filename in ("test_example.py", "test_registered_finite_tool_wiring.py"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                tests = root / "tests"
                tests.mkdir()
                (tests / filename).write_text(
                    "import os, unittest\nclass Case(unittest.TestCase):\n"
                    "    def test_exit(self):\n"
                    "        print('EXAMPLE missing footer', flush=True)\n"
                    "        os._exit(0)\n",
                    encoding="utf-8",
                )
                result = self._run_fixture(root)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("] FAIL files=1 tests=unknown", result.stdout)
                self.assertIn("fixed-width unittest: FAIL", result.stdout)
                self.assertIn("tests=incomplete", result.stdout)
                self.assertIn("missing unittest footer", result.stderr)
                self.assertIn("--- shard 01 log ---", result.stderr)
                self.assertIn("EXAMPLE missing footer", result.stderr)

    def test_cli_method_workunit_requires_exact_case_count(self) -> None:
        for cases in (0, 1, 2, 3):
            with self.subTest(cases=cases), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                tests = root / "tests"
                tests.mkdir()
                filename = "test_registered_finite_input.py"
                self.assertIn(filename, parallel_unittest.METHOD_SHARDED_TEST_FILES)
                (tests / filename).write_text(
                    "import unittest\nclass Case(unittest.TestCase):\n"
                    "    def test_first(self): pass\n"
                    "    def test_second(self): pass\n"
                    "    def run(self, result=None):\n"
                    f"        if {cases} == 0 or ({cases} == 1 and "
                    "self._testMethodName == 'test_second'): return result\n"
                    "        super().run(result)\n"
                    f"        if {cases} == 3 and self._testMethodName == 'test_first':\n"
                    "            super().run(result)\n"
                    "        return result\n",
                    encoding="utf-8",
                )
                result = self._run_fixture(root)
                self.assertIn("parallel unittest workunits=1 capacity=1", result.stdout)
                self.assertEqual(result.returncode, int(cases != 2), result.stdout + result.stderr)
                self.assertIn(f"tests={cases}", result.stdout)
                if cases != 2:
                    self.assertIn(f"expected_tests=2 reported_tests={cases}", result.stderr)
                    self.assertIn("--- shard 01 log ---", result.stderr)
                else:
                    self.assertIn("fixed-width unittest: PASS", result.stdout)

    def test_cli_serial_fixture_intervals_never_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests = root / "tests"
            tests.mkdir()
            names = ("test_native_recovery.py", "test_native_release.py")
            for filename in names:
                self.assertIn(filename, parallel_unittest.SERIAL_TEST_FILES)
                (tests / filename).write_text(
                    "import json, time, unittest\nfrom pathlib import Path\n"
                    "def setUpModule():\n"
                    "    global started\n"
                    "    started = time.monotonic_ns()\n"
                    "def tearDownModule():\n"
                    "    finished = time.monotonic_ns()\n"
                    "    Path(__file__).with_suffix('.json').write_text(\n"
                    "        json.dumps([started, finished]))\n"
                    "class Case(unittest.TestCase):\n"
                    "    def test_wait(self): time.sleep(0.5)\n",
                    encoding="utf-8",
                )
            result = self._run_fixture(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            intervals = sorted(json.loads((tests / filename).with_suffix('.json').read_text())
                               for filename in names)
            for start, finish in intervals:
                self.assertLess(start, finish)
            self.assertLessEqual(intervals[0][1], intervals[1][0], "serial fixtures overlapped")
            self.assertIn("parallel_files=0 serial_files=2", result.stdout)
            self.assertIn("serial unittest: PASS workers=1 tests=2", result.stdout)


if __name__ == "__main__":
    unittest.main()

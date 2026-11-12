"""Extended code-health transitions; real Ruff and real fixed-fixture execution."""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_extended_code_health as gate  # noqa: E402

ANNOTATED = "def example(value: int) -> int:\n    return value\n"
DUPLICATE = "def first(value: int) -> int:\n    result = value + 1\n    return result\n"


class ExtendedGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        for name in (gate.SUBJECT, gate.DRIVER):
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        self.write("scripts/EXAMPLE.py", ANNOTATED)

    def write(self, name: str, source: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    def baseline(self) -> dict:
        return gate.refresh(None, gate.observe(self.root), {"moves": []},
                            "EXAMPLE reviewed executed staging measurement")

    def check(self, baseline: dict, document: dict | None = None) -> tuple[list[str], list[str]]:
        result = gate.compare(baseline, gate.observe(self.root), document or {"moves": []})
        return result[0], result[1]

    def test_real_named_annotation_diagnostics_unchanged_shift_and_reduction(self) -> None:
        baseline = self.baseline()
        self.write("scripts/EXAMPLE.py", "def example(value):\n    return value\n\ndef _private():\n    return 1\n")
        state = gate.observe(self.root)
        self.assertEqual({key.split("::")[2] for key in state["annotations"]}, {"ANN001", "ANN201", "ANN202"})
        self.assertEqual(len(gate.compare(baseline, state, {"moves": []})[0]), 3)
        with self.assertRaisesRegex(SystemExit, "admit"):
            gate.refresh(baseline, state, {"moves": []}, "EXAMPLE review")
        admitted = gate.refresh(baseline, state, {"moves": []}, "EXAMPLE annotation fixture",
                                "EXAMPLE intentionally missing annotations, not product debt")
        self.assertFalse(self.check(admitted)[0])
        path = self.root / "scripts/EXAMPLE.py"
        path.write_text("# EXAMPLE shifted lines\n\n" + path.read_text(), encoding="utf-8")
        self.assertFalse(self.check(admitted)[0])
        self.write("scripts/EXAMPLE.py", ANNOTATED)
        reduced = gate.refresh(admitted, gate.observe(self.root), {"moves": []}, "EXAMPLE annotate functions")
        self.assertEqual(reduced["annotations"], {})
        self.assertTrue(reduced["history"][-1]["reductions"])

    def test_annotation_reviewed_move_and_invalid_replayed_batch(self) -> None:
        self.write("scripts/EXAMPLE.py", "def example(value):\n    return value\n")
        baseline = self.baseline()
        (self.root / "scripts/EXAMPLE.py").unlink()
        self.write("scripts/EXAMPLE_moved.py", "def renamed(value):\n    return value\n")
        self.assertTrue(self.check(baseline)[0])
        move = {"from": "scripts/EXAMPLE.py::example", "to": "scripts/EXAMPLE_moved.py::renamed",
                "reason": "EXAMPLE reviewed mechanical move and rename"}
        document = {"batch": "EXAMPLE-review-1", "moves": [move]}
        self.assertFalse(self.check(baseline, document)[0])
        moved = gate.refresh(baseline, gate.observe(self.root), document, "EXAMPLE carry reviewed debt")
        self.assertFalse(self.check(moved, document)[0])  # Interrupted clear does not reapply a move.
        changed = copy.deepcopy(document)
        changed["moves"][0]["reason"] = "EXAMPLE changed consumed batch"
        with self.assertRaisesRegex(SystemExit, "already applied"):
            self.check(moved, changed)
        invalid = {"batch": "EXAMPLE-review-2", "moves": [{**move, "to": "scripts/EXAMPLE.py::absent"}]}
        with self.assertRaisesRegex(SystemExit, "invalid reviewed move"):
            self.check(baseline, invalid)

    def test_genuine_duplicate_shift_reviewed_move_and_removal(self) -> None:
        self.write("scripts/EXAMPLE.py", DUPLICATE)
        baseline = self.baseline()
        self.write("scripts/EXAMPLE_second.py", DUPLICATE.replace("first", "second"))
        state = gate.observe(self.root)
        self.assertEqual(len(state["duplicates"]), 2)
        self.assertTrue(gate.compare(baseline, state, {"moves": []})[0])
        baseline = gate.refresh(baseline, state, {"moves": []}, "EXAMPLE duplicate fixture",
                                "EXAMPLE deliberately duplicate body")
        self.write("scripts/EXAMPLE_second.py", "# EXAMPLE shift\n\n" + DUPLICATE.replace("first", "second"))
        self.assertFalse(self.check(baseline)[0])
        (self.root / "scripts/EXAMPLE_second.py").unlink()
        self.write("scripts/EXAMPLE_moved.py", DUPLICATE.replace("first", "renamed"))
        document = {"batch": "EXAMPLE-duplicate-move", "moves": [{
            "from": "scripts/EXAMPLE_second.py::second", "to": "scripts/EXAMPLE_moved.py::renamed",
            "reason": "EXAMPLE reviewed duplicate move"}]}
        self.assertFalse(self.check(baseline, document)[0])
        moved = gate.refresh(baseline, gate.observe(self.root), document, "EXAMPLE reviewed move")
        (self.root / "scripts/EXAMPLE_moved.py").unlink()
        reduced = gate.refresh(moved, gate.observe(self.root), {"moves": []}, "EXAMPLE remove duplicate")
        self.assertEqual(reduced["duplicates"], {})
        self.assertTrue(any("reduced duplicates" in note for note in reduced["history"][-1]["reductions"]))

    def test_duplicate_representation_preserves_literals_and_excludes_trivial_bodies(self) -> None:
        self.write("scripts/EXAMPLE.py", DUPLICATE + DUPLICATE.replace("first", "second").replace("+ 1", "+ 2")
                   + "\ndef trivial(value):\n    return value\n\ndef trivial2(value):\n    return value\n")
        self.assertFalse(gate.observe(self.root)["duplicates"])

    def test_real_covered_missed_lines_and_driver_change_detects_regression(self) -> None:
        self.write(gate.DRIVER, (self.root / gate.DRIVER).read_text() + '\nassert subject["example"](0) == 0\n')
        baseline = self.baseline()
        lane = gate.interpreter()
        measurement = baseline["coverage"][lane]
        function = measurement["functions"][f"{gate.SUBJECT}::example"]
        self.assertEqual(function["lines"], function["executed"])
        self.assertTrue(function["called"])
        self.assertEqual(measurement["sources"][gate.SUBJECT], gate.digest((self.root / gate.SUBJECT).read_bytes()))
        shutil.copyfile(ROOT / gate.DRIVER, self.root / gate.DRIVER)
        state = gate.observe(self.root)
        partial = state["coverage"][lane]["functions"][f"{gate.SUBJECT}::example"]
        self.assertTrue(set(partial["lines"]) - set(partial["executed"]))
        self.assertTrue(any("coverage regressed" in failure for failure in gate.compare(baseline, state, {"moves": []})[0]))
        with self.assertRaisesRegex(SystemExit, "admit"):
            gate.refresh(baseline, state, {"moves": []}, "EXAMPLE cannot silently lower measured floor")

    def test_measurement_line_shift_and_reviewed_rename_preserve_floor(self) -> None:
        baseline = self.baseline()
        self.write(gate.SUBJECT, "# EXAMPLE shift\n\n" + (self.root / gate.SUBJECT).read_text())
        self.assertFalse(self.check(baseline)[0])
        self.write(gate.SUBJECT, (self.root / gate.SUBJECT).read_text().replace("def example(", "def renamed("))
        self.write(gate.DRIVER, (self.root / gate.DRIVER).read_text().replace('["example"]', '["renamed"]'))
        document = {"batch": "EXAMPLE-coverage-rename", "moves": [{"from": f"{gate.SUBJECT}::example",
                    "to": f"{gate.SUBJECT}::renamed", "reason": "EXAMPLE reviewed rename"}]}
        self.assertTrue(self.check(baseline)[0])
        self.assertFalse(self.check(baseline, document)[0])
        self.write(gate.SUBJECT, (self.root / gate.SUBJECT).read_text().replace("return 0", "return -1"))
        self.assertTrue(any("stale measured source" in failure for failure in self.check(baseline, document)[0]))

    def test_missing_interpreter_measurement_is_not_success(self) -> None:
        baseline = self.baseline()
        baseline["coverage"] = {}
        self.assertIn("missing executed baseline interpreter", self.check(baseline)[0][0])
        with patch.object(gate.sys, "version_info", type("ExampleVersion", (), {"major": 3, "minor": 13})()):
            with self.assertRaisesRegex(SystemExit, "unsupported interpreter"):
                gate.observe(self.root)

    def test_missing_execution_driver_failure_and_source_drift_refuse(self) -> None:
        drivers = ["# EXAMPLE no execution\n", "raise SystemExit(0)\n", "raise RuntimeError('EXAMPLE driver failure')\n",
                   "from pathlib import Path\np = Path(__file__).with_name('EXAMPLE_subject.py')\np.write_text(p.read_text() + '\\n')\n"]
        for driver in drivers:
            with self.subTest(driver=drivers.index(driver)):
                self.write(gate.DRIVER, driver)
                with self.assertRaises((SystemExit, RuntimeError)):
                    gate.measure(self.root)
        (self.root / gate.DRIVER).unlink()
        with self.assertRaisesRegex(SystemExit, "missing or indirect"):
            gate.measure(self.root)

    def test_real_tool_error_and_wrong_pin_cannot_be_empty_success(self) -> None:
        with patch.object(gate.initial, "ruff_version", return_value="0.0.0"):
            with self.assertRaisesRegex(SystemExit, "pinned Ruff"):
                gate.observe(self.root)
        for exit_code, stdout in ((2, ""), (0, "")):
            with self.subTest(exit_code=exit_code), patch.object(gate.initial, "ruff_version", return_value=gate.RUFF):
                failed = subprocess.CompletedProcess([], exit_code, stdout, "EXAMPLE tool error")
                with patch.object(gate.subprocess, "run", return_value=failed) as check_process:
                    with self.assertRaisesRegex(SystemExit, "failed or lost"):
                        gate.annotation_diagnostics(self.root, ["scripts/EXAMPLE.py"])
                    check_process.assert_called_once()
                    self.assertEqual(check_process.call_args.args[0][1], "check")

    def test_equal_count_regrouping_refuses_real_hidden_coverage_loss(self) -> None:
        before = ("def example(value: int) -> int:\n"
                  "    result = 0; other = 1\n"
                  "    if value > 0:\n"
                  "        result += other\n"
                  "    if value < 0:\n"
                  "        result -= other\n"
                  "    return result\n")
        after = ("def example(value: int) -> int:\n"
                 "    result = 0\n"
                 "    other = 1\n"
                 "    if value > 0: result += other\n"
                 "    if value < 0:\n"
                 "        result -= other\n"
                 "    return result\n")
        self.write(gate.SUBJECT, before)
        driver = (self.root / gate.DRIVER).read_text().replace("!= 2", "!= 1")
        self.write(gate.DRIVER, driver)
        baseline = self.baseline()
        self.write(gate.SUBJECT, after)
        self.write(gate.DRIVER, driver.replace('(1) != 1', '(0) != 0'))
        state = gate.observe(self.root)
        lane, scope = gate.interpreter(), f"{gate.SUBJECT}::example"
        old, current = baseline["coverage"][lane]["functions"][scope], state["coverage"][lane]["functions"][scope]
        self.assertEqual(old["fingerprint"], current["fingerprint"])
        self.assertEqual(old["lines"], current["lines"])
        self.assertEqual(old["executed"], current["executed"])
        failures = gate.compare(baseline, state, {"moves": []})[0]
        self.assertTrue(any("stale measured source or line layout" in failure for failure in failures), failures)
        with self.assertRaisesRegex(SystemExit, "admit"):
            gate.refresh(baseline, state, {"moves": []}, "EXAMPLE regrouping cannot erase regression")
        reviewed = gate.refresh(baseline, state, {"moves": []}, "EXAMPLE reviewed remeasurement",
                                "EXAMPLE consciously accept changed line grouping and missed increment")
        self.assertTrue(reviewed["history"][-1]["failures"])
        self.assertEqual(reviewed["coverage"][lane]["sources"], state["coverage"][lane]["sources"])

    def test_inlined_comprehensions_refuse_before_first_refresh_execution_and_write(self) -> None:
        driver = (self.root / gate.DRIVER).read_text().replace("!= 2", "!= 1")
        self.write(gate.DRIVER, driver)
        expressions = ["[x + 1 for x in (value,)]", "{x + 1 for x in (value,)}", "{x: x + 1 for x in (value,)}"]
        for index, expression in enumerate(expressions):
            with self.subTest(kind=index):
                self.write(gate.SUBJECT, "def example(value: int) -> int:\n    result = " + expression + "\n    return len(result)\n")
                baseline = self.root / f"EXAMPLE-comprehension-{index}.json"
                with (patch.object(gate.initial, "_replace") as writer,
                      patch.object(gate.runpy, "run_path", wraps=gate.runpy.run_path) as execution,
                      contextlib.redirect_stdout(io.StringIO())):
                    with self.assertRaisesRegex(SystemExit, "does not support"):
                        gate.main(["refresh", "--baseline", str(baseline), "--reason", "EXAMPLE unsupported domain",
                                   "--admit", "EXAMPLE admission cannot waive exclusions"], root=self.root)
                    writer.assert_not_called()
                    execution.assert_not_called()
                self.assertFalse(baseline.exists())

    def test_initial_malformed_false_move_containers_refuse_without_persistence(self) -> None:
        baseline = self.root / "EXAMPLE-first.json"
        moves = self.root / "EXAMPLE-moves.json"
        for value in (None, False, {}):
            for admission in ([], ["--admit", "EXAMPLE no shape waiver"]):
                with self.subTest(value=value, admission=bool(admission)):
                    moves.write_text(json.dumps({"moves": value}), encoding="utf-8")
                    with patch.object(gate.initial, "_replace") as writer, contextlib.redirect_stdout(io.StringIO()):
                        with self.assertRaisesRegex(SystemExit, "invalid move"):
                            gate.main(["refresh", "--baseline", str(baseline), "--moves", str(moves),
                                       "--reason", "EXAMPLE malformed move document", *admission], root=self.root)
                        writer.assert_not_called()
                    self.assertFalse(baseline.exists())

    def test_cli_requires_reason_and_missing_baseline_refuses(self) -> None:
        baseline = self.root / "EXAMPLE-baseline.json"
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(SystemExit, "recorded --reason"):
                gate.main(["refresh", "--baseline", str(baseline)], root=self.root)
            with self.assertRaisesRegex(SystemExit, "missing staged baseline"):
                gate.main(["check", "--baseline", str(baseline)], root=self.root)
            self.assertEqual(gate.main(["refresh", "--baseline", str(baseline), "--reason", "EXAMPLE reviewed floor"], root=self.root), 0)
            self.assertEqual(gate.main(["check", "--baseline", str(baseline)], root=self.root), 0)
        self.assertEqual(json.loads(baseline.read_text())["history"][0]["reason"], "EXAMPLE reviewed floor")


if __name__ == "__main__":
    unittest.main()

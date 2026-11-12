"""Numeric baseline contracts through the private Tree CLI and direct consumers."""

from __future__ import annotations

import contextlib
import copy
import json
import unittest
from unittest.mock import patch

from tests.test_code_health import PolicySnapshot, TreeCase
from tests.test_code_health import COMPLEX, Tree, health, unused

DIAGNOSTIC = "scripts/a.py::<module>::F401::os"
FUNCTION = "scripts/a.py::busy"
FIELDS = (("complexity_threshold", None), ("f_e9", DIAGNOSTIC), ("complexity", FUNCTION))
INVALID = (True, False, 1.0, 5.9, "1000", -1, float("nan"), float("inf"), -float("inf"), None, [], {})
COMMANDS = ((), ("refresh",), ("refresh", "--admit", "reviewed debt"), ("init", "--reason", "fixture"))


class NumericPolicyTests(PolicySnapshot, TreeCase):


    def persist_refresh(self, tree: Tree, baseline: dict, state: dict, admit: str | None) -> dict:
        updated, _ = health.refresh(baseline, [], state, admit)
        health._write(tree.root, updated)
        return updated

    def recorded(self) -> tuple[Tree, dict]:
        tree = self.tree({"scripts/a.py": "import os\n" + COMPLEX}, diagnostics=[unused("scripts/a.py", 1)])
        tree.refresh()
        self.assertEqual(tree.baseline["f_e9"], {DIAGNOSTIC: 1})
        self.assertEqual(tree.baseline["complexity"], {FUNCTION: 5})
        tree.baseline["annotation"] = {"fraction": 0.25, "flags": [True, None]}
        tree.baseline["consumed_batches"] = {"historical-fixture": "retained-digest"}
        tree.save_baseline()
        self.assertEqual(tree.run()[0], 0)
        state = health.current_state(tree.root, tree.fake_ruff)
        self.assertEqual(health.compare(tree.baseline, [], state).failures, [])
        with patch.object(health, "_write", wraps=health._write) as write, \
                patch.object(health, "_replace", wraps=health._replace) as replace:
            updated = self.persist_refresh(tree, tree.baseline, state, None)
            write.assert_called_once()
            replace.assert_called_once()
        self.assertEqual(updated["annotation"], tree.baseline["annotation"])
        self.assertEqual(updated["consumed_batches"], tree.baseline["consumed_batches"])
        self.assertEqual(tree.run("refresh")[0], 0)
        tree.baseline = health.load_json(tree.root / health.BASELINE, {})
        return tree, state

    def assert_direct_refused(self, tree: Tree, baseline: object, state: dict) -> None:
        before = self.snapshot(tree)
        with patch.object(health, "_write", wraps=health._write) as write, \
                patch.object(health, "_replace", wraps=health._replace) as replace:
            report = health.compare(baseline, [], state)
            self.assertIsInstance(report, health.Report)
            self.assertTrue(report.failures)
            self.assertTrue(all(message.startswith("invalid baseline:") for message in report.failures))
            self.assertTrue(report.new_debt)
            self.assertEqual(report.notes, [])
            for admit in (None, "reviewed debt"):
                with self.assertRaisesRegex(SystemExit, "invalid baseline"):
                    self.persist_refresh(tree, baseline, state, admit)
            write.assert_not_called()
            replace.assert_not_called()
        self.assertEqual(self.snapshot(tree), before)

    def assert_cli_refused(self, tree: Tree, message: str, *, commands: tuple = COMMANDS) -> None:
        before = self.snapshot(tree)
        for argv in commands:
            for use_ruff in (False, True):
                with self.subTest(argv=argv, use_ruff=use_ruff), contextlib.ExitStack() as stack:
                    callback = stack.enter_context(patch.object(tree, "fake_ruff", wraps=tree.fake_ruff))
                    observers = [stack.enter_context(patch.object(health, name, wraps=getattr(health, name)))
                                 for name in ("current_state", "_python_files_in_tree", "_write", "_replace")]
                    observers.append(stack.enter_context(patch.object(health, "ruff_version", return_value="0.17.1")))
                    observers.append(stack.enter_context(patch.object(health, "ruff_diagnostics", side_effect=callback)))
                    with self.assertRaisesRegex(SystemExit, message):
                        health.main(list(argv), diagnostics=None if use_ruff else callback, root=tree.root)
                    for observer in [callback, *observers]:
                        observer.assert_not_called()
                self.assertEqual(self.snapshot(tree), before)

    def test_all_consumed_numbers_refuse_coercible_and_invalid_types(self) -> None:
        for field, identity in FIELDS:
            for value in INVALID:
                with self.subTest(field=field, value=repr(value)):
                    tree, state = self.recorded()
                    bad = copy.deepcopy(tree.baseline)
                    if identity is None:
                        bad[field] = value
                    else:
                        bad[field][identity] = value
                    self.assert_direct_refused(tree, bad, state)
                    tree.baseline = bad
                    tree.save_baseline()
                    self.assert_cli_refused(tree, "invalid baseline|cannot read JSON")

    def test_missing_fields_and_wrong_tables_refuse(self) -> None:
        for field, _ in FIELDS:
            tree, state = self.recorded()
            bad = copy.deepcopy(tree.baseline)
            del bad[field]
            self.assert_direct_refused(tree, bad, state)
            tree.baseline = bad
            tree.save_baseline()
            self.assert_cli_refused(tree, "invalid baseline")
        for field in ("f_e9", "complexity"):
            for table in (None, [], "", 1, True, 1.0):
                with self.subTest(field=field, table=repr(table)):
                    tree, state = self.recorded()
                    bad = copy.deepcopy(tree.baseline)
                    bad[field] = table
                    self.assert_direct_refused(tree, bad, state)
                    tree.baseline = bad
                    tree.save_baseline()
                    self.assert_cli_refused(tree, "invalid baseline")

    def test_direct_nonstring_identities_and_nonobject_baselines_refuse(self) -> None:
        for field in ("f_e9", "complexity"):
            tree, state = self.recorded()
            for key in (1, None, False, ("identity",)):
                bad = copy.deepcopy(tree.baseline)
                bad[field] = {key: 1}
                self.assert_direct_refused(tree, bad, state)
        tree, state = self.recorded()
        for bad in (None, [], True, 1, "baseline"):
            self.assert_direct_refused(tree, bad, state)

    def test_strict_reader_refuses_before_measurement_or_persistence(self) -> None:
        cases = (
            b'{"x": 1, "x": 2}', b'{"nested": {"x": 1, "x": 2}}',
            b'{"x": 1, "\\u0078": 2}', b'{"annotation": NaN}',
            b'{"annotation": Infinity}', b'{"annotation": -Infinity}',
            b'{"annotation": 1e400}', b'{"annotation": -1e400}',
            b'{"x": "\xff"}', b'{', b'[]', b'null', b'true', b'1', b'"object"',
        )
        for name in (health.BASELINE, health.MOVES):
            for raw in cases:
                with self.subTest(name=name, raw=raw):
                    tree, _ = self.recorded()
                    path = tree.root / name
                    path.write_bytes(raw)
                    with self.assertRaisesRegex(SystemExit, "cannot read JSON|must be a JSON object"):
                        health.load_json(path, {})
                    commands = COMMANDS[:-1] if name == health.MOVES else COMMANDS
                    self.assert_cli_refused(tree, "cannot read JSON|must be a JSON object", commands=commands)
                    if name == health.MOVES:
                        self.assert_fresh_init_moves_refused(raw)

    def assert_fresh_init_moves_refused(self, raw: bytes) -> None:
        tree = self.tree({"scripts/a.py": "value = 1\n"})
        baseline_path = tree.root / health.BASELINE
        initial_baseline = baseline_path.read_bytes()
        # A genuine init succeeds before the malformed-moves perturbation.
        self.assertEqual(tree.run("init", "--reason", "fixture")[0], 0)
        baseline_path.write_bytes(initial_baseline)
        (tree.root / health.MOVES).write_bytes(raw)
        self.assert_cli_refused(
            tree, "cannot read JSON|must be a JSON object", commands=(COMMANDS[-1],),
        )

    def test_threshold_mutations_cannot_hide_real_new_growth(self) -> None:
        for duplicate in (False, True):
            tree = self.tree({"scripts/a.py": "def small():\n    return 1\n"})
            tree.refresh()
            self.assertEqual(tree.run()[0], 0)
            tree.write({"scripts/b.py": COMPLEX})
            code, _, err = tree.run()
            self.assertEqual(code, 1)
            self.assertIn("new function over the complexity threshold 3:", err)
            path = tree.root / health.BASELINE
            raw = path.read_text(encoding="utf-8")
            needle = '"complexity_threshold": 3'
            self.assertEqual(raw.count(needle), 1)
            replacement = needle + ', "complexity_threshold": 1000' if duplicate else '"complexity_threshold": "1000"'
            path.write_text(raw.replace(needle, replacement), encoding="utf-8")
            self.assert_cli_refused(tree, "duplicate object key|invalid baseline")

    def test_legacy_empty_zero_and_unbounded_integer_baselines_still_work(self) -> None:
        for number in (0, 15, 10 ** 5000):
            tree = self.tree({"scripts/a.py": "value = 1\n"})
            self.assertNotIn("created", tree.baseline)
            self.assertNotIn("repeated", tree.baseline)
            self.assertNotIn("moved", tree.baseline)
            self.assertNotIn("consumed_batches", tree.baseline)
            self.assertEqual(tree.run()[0], 0)
            tree.baseline.update(complexity_threshold=number, f_e9={DIAGNOSTIC: number},
                                 complexity={FUNCTION: number}, annotation={"fraction": 0.25, "text": "\u00e9"})
            health._replace(tree.root / health.BASELINE, tree.baseline)
            loaded = health.load_json(tree.root / health.BASELINE, {})
            self.assertEqual(loaded, tree.baseline)
            self.assertIs(type(loaded["complexity_threshold"]), int)
            state = health.current_state(tree.root, tree.fake_ruff)
            self.assertEqual(health.compare(loaded, [], state).failures, [])
            self.assertEqual(tree.run()[0], 0)
            self.assertEqual(tree.run("refresh")[0], 0)
            refreshed = health.load_json(tree.root / health.BASELINE, {})
            self.assertEqual(refreshed["complexity_threshold"], number)
            self.assertEqual(refreshed["annotation"], loaded["annotation"])
            self.assertEqual((refreshed["f_e9"], refreshed["complexity"]), ({}, {}))
            self.assertEqual(tree.run()[0], 0)

    def test_normal_json_serialization_and_missing_file_defaults_are_retained(self) -> None:
        tree, _ = self.recorded()
        self.assertFalse((tree.root / health.MOVES).exists())
        self.assertEqual(health.load_json(tree.root / health.MOVES, {"moves": []}), {"moves": []})
        sample = {"s": "\u00e9", "n": [0, 15, 0.25, True, None, {}, []], "map": {2: "integer key"}}
        path = tree.root / "policy" / "roundtrip.json"
        health._replace(path, sample)
        self.assertEqual(path.read_text(encoding="utf-8"), json.dumps(sample, indent=2) + "\n")
        for raw in (None, b'{}'):
            baseline = tree.root / health.BASELINE
            if raw is None:
                baseline.unlink()
            else:
                baseline.write_bytes(raw)
            self.assert_cli_refused(tree, "missing baseline")

    def test_pending_moves_and_historical_metadata_survive_refusal(self) -> None:
        tree, _ = self.recorded()
        history = copy.deepcopy(tree.baseline)
        tree.write({"scripts/a.py": "import os\n" + COMPLEX.replace("def busy", "def renamed")})
        move = {"from": FUNCTION, "to": "scripts/a.py::renamed", "reason": "fixture rename"}
        tree.moves([move], batch="numeric-policy-fixture")
        self.assertEqual(tree.run()[0], 0)
        tree.baseline["complexity"][FUNCTION] = 5.9
        tree.save_baseline()
        self.assert_cli_refused(tree, "invalid baseline")
        tree.baseline = history
        tree.save_baseline()
        self.assertEqual(tree.run("refresh")[0], 0)
        updated = health.load_json(tree.root / health.BASELINE, {})
        self.assertEqual(updated["annotation"], history["annotation"])
        self.assertEqual(updated["consumed_batches"]["historical-fixture"], "retained-digest")
        self.assertEqual(updated["moved"], [*history["moved"], move])
        self.assertIn("numeric-policy-fixture", updated["consumed_batches"])
        self.assertEqual(health.load_json(tree.root / health.MOVES, {})["moves"], [])
        self.assertEqual(tree.run()[0], 0)

    def test_reviewed_actual_debt_admission_still_writes(self) -> None:
        tree, _ = self.recorded()
        grown = COMPLEX.replace("    return 0\n", "    if value == 5:\n        return 5\n    return 0\n")
        tree.write({"scripts/a.py": "import os\n" + grown})
        self.assertEqual(tree.run()[0], 1)
        before = self.snapshot(tree)
        with patch.object(health, "_write", wraps=health._write) as write, \
                patch.object(health, "_replace", wraps=health._replace) as replace:
            with self.assertRaisesRegex(SystemExit, "would admit new debt"):
                tree.run("refresh")
            write.assert_not_called()
            replace.assert_not_called()
        self.assertEqual(self.snapshot(tree), before)
        self.assertEqual(tree.run("refresh", "--admit", "reviewed growth")[0], 0)
        updated = health.load_json(tree.root / health.BASELINE, {})
        self.assertEqual(updated["complexity"][FUNCTION], 6)
        self.assertEqual(updated["admitted"][FUNCTION], "reviewed growth")
        self.assertEqual(tree.run()[0], 0)

    def test_valid_input_does_not_hide_unrelated_measurement_errors(self) -> None:
        tree, _ = self.recorded()
        with patch.object(health, "current_state", side_effect=ValueError("measurement bug")):
            with self.assertRaisesRegex(ValueError, "measurement bug"):
                tree.run()


if __name__ == "__main__":
    unittest.main()

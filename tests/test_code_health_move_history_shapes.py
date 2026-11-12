"""Reviewed moves and optional history shapes through private real-tree consumers."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import unittest
from unittest.mock import Mock, patch

from tests.test_code_health import PolicySnapshot
from tests.test_code_health import COMPLEX, Tree, health

BATCH = "cm-reviewed-fixture"
MOVE = {
    "from": "scripts/a.py::busy",
    "to": "scripts/a.py::renamed",
    "reason": "reviewed fixture rename",
    "annotation": {"z": [0.25, True, None], "a": {"text": "\u00e9"}},
}
COMMANDS = ((), ("refresh",), ("refresh", "--admit", "reviewed debt"))
INIT = ("init", "--reason", "fixture")
BAD_MOVES = (
    None, False, True, 0, 1, 1.0, "moves", {},
    [None], [True], [False], ["entry"], [1], [1.0], [[]],
    [[["from", MOVE["from"]], ["to", MOVE["to"]], ["reason", "pair list"]]],
)
BAD_CONSUMED = (
    None, False, True, 0, 1, "batch", [], [BATCH], [[BATCH, "digest"]],
    {BATCH: None}, {BATCH: False}, {BATCH: True}, {BATCH: 1}, {BATCH: 1.0},
    {BATCH: []}, {BATCH: {}},
)
BAD_MOVED = (
    None, False, True, 0, 1, "old", {},
    [None], [True], [False], ["old"], [1], [[]],
    [[["from", "old"], ["to", "gone"]]],
)


class MoveHistoryShapeTests(PolicySnapshot, unittest.TestCase):
    def tree(self, files: dict[str, str] | None = None) -> Tree:
        tree = Tree(files if files is not None else {"scripts/a.py": COMPLEX})
        self.addCleanup(tree.close)
        return tree


    def invoke(self, tree: Tree, argv: tuple, callback: Mock, default: bool) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(
                list(argv), diagnostics=None if default else callback, root=tree.root)
        return code, out.getvalue(), err.getvalue()

    @contextlib.contextmanager
    def observe(self, tree: Tree):
        with contextlib.ExitStack() as stack:
            observers = {"callback": Mock(wraps=tree.fake_ruff)}
            for name in ("current_state", "_python_files_in_tree", "_write", "_replace"):
                observers[name] = stack.enter_context(patch.object(health, name, wraps=getattr(health, name)))
            observers["ruff_version"] = stack.enter_context(patch.object(health, "ruff_version", return_value="0.17.1"))
            observers["ruff_diagnostics"] = stack.enter_context(
                patch.object(health, "ruff_diagnostics", side_effect=observers["callback"]))
            trace = Mock()
            for name, observer in observers.items():
                trace.attach_mock(observer, name)
            yield observers, trace

    def assert_zero(self, observers: dict) -> None:
        for observer in observers.values():
            observer.assert_not_called()

    def assert_cli_refused(self, tree: Tree, message: str, *,
                           commands: tuple = COMMANDS, baseline_error: bool = False) -> None:
        before = self.snapshot(tree)
        for argv in commands:
            for default in (False, True):
                with self.subTest(argv=argv, default=default), self.observe(tree) as (observers, _):
                    if not argv and not baseline_error:
                        code, _, err = self.invoke(tree, argv, observers["callback"], default)
                        self.assertEqual(code, 1)
                        self.assertIn(message, err)
                    else:
                        with self.assertRaisesRegex(SystemExit, message):
                            self.invoke(tree, argv, observers["callback"], default)
                    self.assert_zero(observers)
                    self.assertEqual(self.snapshot(tree), before)

    def persist(self, tree: Tree, baseline: dict, moves: object, state: dict, admit: str | None) -> dict:
        updated, _ = health.refresh(baseline, moves, state, admit, batch=BATCH)
        health._write(tree.root, updated)
        return updated

    def assert_direct_refused(self, tree: Tree, baseline: dict, moves: object, state: dict, *, history: bool = False) -> None:
        before = self.snapshot(tree)
        with patch.object(health, "_write", wraps=health._write) as write, \
                patch.object(health, "_replace", wraps=health._replace) as replace:
            report = health.compare(baseline, moves, state)
            self.assertIsInstance(report, health.Report)
            self.assertTrue(report.failures)
            self.assertTrue(report.new_debt)
            prefix = "invalid baseline:" if history else "invalid move:"
            self.assertTrue(all(item.startswith(prefix) for item in report.failures))
            self.assertEqual(report.notes, [])
            if not history:
                self.assertTrue(health.validate_moves(moves, baseline, state))
            _, pending, problems = health.pending_batch({"batch": BATCH, "moves": moves}, baseline)
            self.assertTrue(problems)
            self.assertEqual(pending, [])
            for admit in (None, "reviewed debt"):
                with self.assertRaisesRegex(SystemExit, "invalid baseline|fix the moves file"):
                    self.persist(tree, baseline, moves, state, admit)
            write.assert_not_called()
            replace.assert_not_called()
        self.assertEqual(self.snapshot(tree), before)

    def positive_refresh(self, tree: Tree, *, listed: bool) -> None:
        with self.observe(tree) as (observers, trace):
            self.assertEqual(self.invoke(tree, ("refresh",), observers["callback"], True)[0], 0)
            observers["callback"].assert_called_once()
            observers["current_state"].assert_called_once()
            observers["_python_files_in_tree"].assert_called_once()
            observers["ruff_version"].assert_called_once()
            observers["ruff_diagnostics"].assert_called_once()
            observers["_write"].assert_called_once()
            self.assertEqual(observers["_replace"].call_count, 2 if listed else 1)
            calls = [call[0] for call in trace.mock_calls]
            self.assertLess(calls.index("ruff_version"), calls.index("current_state"))
            self.assertLess(calls.index("current_state"), calls.index("callback"))
            self.assertLess(calls.index("callback"), calls.index("_write"))
            self.assertLess(calls.index("_write"), calls.index("_replace"))
            self.assertEqual([call.args[0] for call in observers["_replace"].call_args_list],
                             [tree.root / health.BASELINE, *([tree.root / health.MOVES] if listed else [])])

    def reviewed(self) -> tuple[Tree, list[dict]]:
        tree = self.tree()
        tree.refresh()
        self.assertEqual(tree.run()[0], 0)
        tree.write({"scripts/a.py": COMPLEX.replace("def busy", "def renamed")})
        moves = [copy.deepcopy(MOVE)]
        tree.moves(moves, batch=BATCH)
        document = health.load_json(tree.root / health.MOVES, {})
        raw = (tree.root / health.MOVES).read_bytes()
        state = health.current_state(tree.root, tree.fake_ruff)
        self.assertEqual(health.validate_moves(moves, tree.baseline, state), [])
        self.assertEqual(health.compare(tree.baseline, moves, state).failures, [])
        self.assertEqual(health.pending_batch(document, tree.baseline), (BATCH, moves, []))
        expected = hashlib.sha256(json.dumps(moves, sort_keys=True).encode("utf-8")).hexdigest()
        self.positive_refresh(tree, listed=True)
        baseline = health.load_json(tree.root / health.BASELINE, {})
        self.assertEqual(baseline["complexity"], {"scripts/a.py::renamed": 5})
        self.assertEqual(baseline["moved"], moves)
        self.assertEqual(baseline["consumed_batches"], {BATCH: expected})
        (tree.root / health.MOVES).write_bytes(raw)
        self.assertEqual(health.pending_batch(document, baseline), (BATCH, [], []))
        before = self.snapshot(tree)
        with self.observe(tree) as (observers, _):
            code, out, _ = self.invoke(tree, (), observers["callback"], True)
            self.assertEqual(code, 0)
            self.assertIn("refresh clears them", out)
            observers["callback"].assert_called_once()
            observers["current_state"].assert_called_once()
            observers["_write"].assert_not_called()
            observers["_replace"].assert_not_called()
            self.assertEqual(self.snapshot(tree), before)
        changed = copy.deepcopy(document)
        changed["moves"][0]["reason"] = "changed after consumption"
        (tree.root / health.MOVES).write_text(json.dumps(changed), encoding="utf-8")
        self.assertTrue(health.pending_batch(changed, baseline)[2])
        self.assert_cli_refused(tree, f"batch {BATCH} was already applied")
        (tree.root / health.MOVES).write_bytes(raw)
        self.positive_refresh(tree, listed=True)
        baseline = health.load_json(tree.root / health.BASELINE, {})
        baseline["moved"].extend([
            {"from": "retired.py::gone", "to": "retired.py::missing", "annotation": {"finite": [0.25, True, None]}},
            {},
        ])
        baseline["consumed_batches"].update({"old batch with spaces": "", "": "opaque digest"})
        tree.baseline = baseline
        tree.save_baseline()
        self.positive_refresh(tree, listed=False)
        self.assertEqual(health.load_json(tree.root / health.BASELINE, {})["moved"], baseline["moved"])
        self.assertEqual(health.load_json(tree.root / health.BASELINE, {})["consumed_batches"], baseline["consumed_batches"])
        self.assertEqual(tree.run()[0], 0)
        return tree, moves

    def test_moves_shapes_refuse_before_field_lookups_measurement_and_writes(self) -> None:
        tree, moves = self.reviewed()
        baseline = health.load_json(tree.root / health.BASELINE, {})
        state = health.current_state(tree.root, tree.fake_ruff)
        for bad in BAD_MOVES:
            with self.subTest(moves=bad):
                self.assert_direct_refused(tree, baseline, bad, state)
                tree.moves(moves, batch=BATCH)
                document = health.load_json(tree.root / health.MOVES, {})
                document["moves"] = bad
                (tree.root / health.MOVES).write_text(json.dumps(document), encoding="utf-8")
                self.assert_cli_refused(tree, "must be")
        tree.moves(moves, batch=BATCH)
        self.positive_refresh(tree, listed=True)
        for bad in ((), tuple(moves), {BATCH: MOVE}):
            self.assert_direct_refused(tree, baseline, bad, state)
        for document in (None, True, 1, "moves", [], ()):
            self.assertTrue(health.pending_batch(document, baseline)[2])

    def test_history_shapes_refuse_without_coercion_or_admission(self) -> None:
        tree, moves = self.reviewed()
        baseline = health.load_json(tree.root / health.BASELINE, {})
        state = health.current_state(tree.root, tree.fake_ruff)
        tree.moves(moves, batch=BATCH)
        for field, values in (("consumed_batches", BAD_CONSUMED), ("moved", BAD_MOVED)):
            for value in values:
                with self.subTest(field=field, value=value):
                    bad = copy.deepcopy(baseline)
                    bad[field] = value
                    self.assert_direct_refused(tree, bad, moves, state, history=True)
                    tree.baseline = bad
                    tree.save_baseline()
                    self.assert_cli_refused(tree, "invalid baseline", commands=COMMANDS + (INIT,),
                                            baseline_error=True)
                    tree.baseline = copy.deepcopy(baseline)
                    tree.save_baseline()
        for key in (1, False, None, ("batch",)):
            bad = copy.deepcopy(baseline)
            bad["consumed_batches"] = {key: "digest"}
            self.assert_direct_refused(tree, bad, moves, state, history=True)
        for value in ((), tuple(baseline["moved"])):
            bad = copy.deepcopy(baseline)
            bad["moved"] = value
            self.assert_direct_refused(tree, bad, moves, state, history=True)
        tree.moves(moves, batch=BATCH)
        self.positive_refresh(tree, listed=True)

    def test_optional_history_defaults_and_headerless_projections_remain_supported(self) -> None:
        tree, _ = self.reviewed()
        baseline = health.load_json(tree.root / health.BASELINE, {})
        for field in ("moved", "consumed_batches"):
            baseline.pop(field)
        state = health.current_state(tree.root, tree.fake_ruff)
        projection = {key: value for key, value in baseline.items() if key not in ("version", "tool")}
        self.assertEqual(health.compare(projection, [], state).failures, [])
        updated, _ = health.refresh(projection, [], state, None)
        self.assertEqual((updated["moved"], updated["consumed_batches"]), ([], {}))
        self.assertNotIn("version", updated)
        self.assertNotIn("tool", updated)
        self.assertEqual(health.pending_batch({"moves": []}, projection), (None, [], []))
        tree.baseline = baseline
        tree.save_baseline()
        (tree.root / health.MOVES).unlink()
        self.assertEqual(health.load_json(tree.root / health.MOVES, {"moves": []}), {"moves": []})
        self.positive_refresh(tree, listed=False)
        loaded = health.load_json(tree.root / health.BASELINE, {})
        self.assertEqual((loaded["moved"], loaded["consumed_batches"]), ([], {}))
        self.assertEqual(tree.run()[0], 0)

    def test_fresh_init_restores_uninitialized_bytes_and_preserves_guard_order(self) -> None:
        tree = self.tree({"scripts/a.py": "value = 1\n"})
        path = tree.root / health.BASELINE
        initial = path.read_bytes()
        self.assertFalse((tree.root / health.MOVES).exists())
        with self.observe(tree) as (observers, _):
            self.assertEqual(self.invoke(tree, INIT, observers["callback"], True)[0], 0)
            observers["callback"].assert_called_once()
            observers["_write"].assert_called_once()
            observers["_replace"].assert_called_once()
        self.assertEqual(health.load_json(path, {})["created"], "fixture")
        tree.moves([None], batch=BATCH)
        before = self.snapshot(tree)
        with self.observe(tree) as (observers, _):
            with self.assertRaisesRegex(SystemExit, "only once"):
                self.invoke(tree, INIT, observers["callback"], True)
            self.assert_zero(observers)
            self.assertEqual(self.snapshot(tree), before)
        path.write_bytes(initial)
        for bad in BAD_MOVES:
            tree.moves([], batch=BATCH)
            document = health.load_json(tree.root / health.MOVES, {})
            document["moves"] = bad
            (tree.root / health.MOVES).write_text(json.dumps(document), encoding="utf-8")
            self.assert_cli_refused(tree, "must be", commands=(INIT,))
            self.assertEqual(path.read_bytes(), initial)
        (tree.root / health.MOVES).unlink()
        with self.observe(tree) as (observers, _):
            self.assertEqual(self.invoke(tree, INIT, observers["callback"], True)[0], 0)
            observers["callback"].assert_called_once()
            observers["_write"].assert_called_once()
            observers["_replace"].assert_called_once()

    def test_valid_input_preserves_unrelated_measurement_failures(self) -> None:
        tree, _ = self.reviewed()
        before = self.snapshot(tree)
        with patch.object(health, "current_state", side_effect=ValueError("measurement bug")), \
                patch.object(health, "_write", wraps=health._write) as write, \
                patch.object(health, "_replace", wraps=health._replace) as replace:
            with self.assertRaisesRegex(ValueError, "measurement bug"):
                tree.run()
            write.assert_not_called()
            replace.assert_not_called()
        self.assertEqual(self.snapshot(tree), before)


if __name__ == "__main__":
    unittest.main()

"""Baseline envelope contracts through real producers and private consumer fixtures."""

from __future__ import annotations

import contextlib
import copy
import io
import shutil
import unittest
from unittest.mock import patch

from tests.test_code_health import PolicySnapshot
from tests.test_code_health import Tree, health

EDGE = "cwo_core.bridge -> utility"
COMMANDS = ((), ("refresh",), ("refresh", "--admit", "reviewed debt"),
            ("init", "--reason", "fixture"))
INVALID = (
    ("version", (True, False, 0, 2, -1, 1.0, "1", None, [], {})),
    ("tool", (None, [], False, "ruff", 1, {}, {"ruff": None}, {"ruff": 1},
              {"ruff": False}, {"ruff": []}, {"ruff": {}})),
    ("imports", ({}, "", EDGE, None, False, 1, [None], [1], [True], [[]], [{}])),
    ("admitted", ([], [[EDGE, "reason"]], False, True, None, "", 1,
                  {EDGE: None}, {EDGE: False}, {EDGE: 1}, {EDGE: []})),
)


class BaselineEnvelopeTests(PolicySnapshot, unittest.TestCase):
    def tree(self, *, threshold: int = 15) -> Tree:
        tree = Tree({"scripts/a.py": "value = 1\n"}, threshold=threshold)
        self.addCleanup(tree.close)
        self.assertIs(type(tree.baseline["version"]), int)
        self.assertEqual(tree.baseline["version"], 1)
        self.assertEqual(tree.baseline["tool"], {"ruff": "0.17.1"})
        tree.refresh()
        self.assertEqual(tree.run()[0], 0)
        return tree


    def invoke(self, tree: Tree, argv: tuple = (), *, diagnostics=None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(list(argv), diagnostics=diagnostics, root=tree.root)
        return code, out.getvalue(), err.getvalue()

    def persist(self, tree: Tree, baseline: dict, state: dict, admit: str | None) -> dict:
        updated, _ = health.refresh(baseline, [], state, admit)
        health._write(tree.root, updated)
        return updated

    def assert_direct_refused(self, tree: Tree, baseline: object, state: dict) -> None:
        before = self.snapshot(tree)
        with patch.object(health, "_write", wraps=health._write) as write, \
                patch.object(health, "_replace", wraps=health._replace) as replace:
            report = health.compare(baseline, [], state)
            self.assertIsInstance(report, health.Report)
            self.assertTrue(report.failures)
            self.assertTrue(all(item.startswith("invalid baseline:") for item in report.failures))
            self.assertTrue(report.new_debt)
            self.assertEqual(report.notes, [])
            for admit in (None, "reviewed debt"):
                with self.assertRaisesRegex(SystemExit, "invalid baseline"):
                    self.persist(tree, baseline, state, admit)
            write.assert_not_called()
            replace.assert_not_called()
        self.assertEqual(self.snapshot(tree), before)

    def assert_cli_refused(self, tree: Tree, message: str = "invalid baseline") -> None:
        before = self.snapshot(tree)
        for argv in COMMANDS:
            for default_route in (False, True):
                with self.subTest(argv=argv, default_route=default_route), contextlib.ExitStack() as stack:
                    callback = stack.enter_context(patch.object(tree, "fake_ruff", wraps=tree.fake_ruff))
                    observers = [stack.enter_context(patch.object(health, name, wraps=getattr(health, name)))
                                 for name in ("current_state", "_python_files_in_tree", "_write", "_replace")]
                    observers.append(stack.enter_context(patch.object(health, "ruff_version", return_value="0.17.1")))
                    observers.append(stack.enter_context(patch.object(health, "ruff_diagnostics", side_effect=callback)))
                    with self.assertRaisesRegex(SystemExit, message):
                        self.invoke(tree, argv, diagnostics=None if default_route else callback)
                    for observer in [callback, *observers]:
                        observer.assert_not_called()
                self.assertEqual(self.snapshot(tree), before)

    def assert_bad(self, tree: Tree, bad: dict, state: dict) -> None:
        self.assert_direct_refused(tree, bad, state)
        tree.baseline = bad
        tree.save_baseline()
        with self.assertRaisesRegex(SystemExit, "invalid baseline"):
            health._load(tree.root, "check", None)
        self.assert_cli_refused(tree)

    def test_invalid_envelopes_refuse_before_measurement_and_writes(self) -> None:
        for field, values in INVALID:
            for value in values:
                with self.subTest(field=field, value=repr(value)):
                    tree = self.tree()
                    state = health.current_state(tree.root, tree.fake_ruff)
                    bad = copy.deepcopy(tree.baseline)
                    bad[field] = value
                    self.assert_bad(tree, bad, state)

    def test_actual_import_edge_requires_array_elements_not_mapping_keys(self) -> None:
        tree = self.tree()
        tree.write({"scripts/utility.py": "value = 1\n", "scripts/cwo_core/__init__.py": "",
                    "scripts/cwo_core/bridge.py": "import utility\n"})
        self.assertEqual(health.import_edges(tree.root), {EDGE})
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("new core-to-CLI import: " + EDGE, err)
        with patch.object(health, "_write", wraps=health._write) as write, \
                patch.object(health, "_replace", wraps=health._replace) as replace:
            self.assertEqual(tree.run("refresh", "--admit", "reviewed fixture edge")[0], 0)
            write.assert_called_once()
            replace.assert_called_once()
        tree.baseline = health.load_json(tree.root / health.BASELINE, {})
        self.assertEqual(tree.baseline["imports"], [EDGE])
        self.assertEqual(tree.baseline["admitted"][EDGE], "reviewed fixture edge")
        self.assertEqual(tree.run()[0], 0)
        state = health.current_state(tree.root, tree.fake_ruff)
        self.assertEqual(health.compare(tree.baseline, [], state).failures, [])
        bad = copy.deepcopy(tree.baseline)
        bad["imports"] = {EDGE: "mapping keys are not allowance elements"}
        self.assert_bad(tree, bad, state)

    def test_malformed_admissions_cannot_be_waived_but_valid_admission_writes(self) -> None:
        tree = self.tree()
        tree.write({"scripts/utility.py": "value = 1\n", "scripts/cwo_core/bridge.py": "import utility\n"})
        self.assertEqual(tree.run()[0], 1)
        state = health.current_state(tree.root, tree.fake_ruff)
        valid = copy.deepcopy(tree.baseline)
        for value in ([], [[EDGE, "unreviewed"]], False):
            with self.subTest(admitted=value):
                bad = copy.deepcopy(valid)
                bad["admitted"] = value
                self.assert_bad(tree, bad, state)
        tree.baseline = valid
        tree.save_baseline()
        before = self.snapshot(tree)
        with patch.object(health, "_write", wraps=health._write) as write, \
                patch.object(health, "_replace", wraps=health._replace) as replace:
            with self.assertRaisesRegex(SystemExit, "would admit new debt"):
                tree.run("refresh")
            write.assert_not_called()
            replace.assert_not_called()
        self.assertEqual(self.snapshot(tree), before)
        with patch.object(health, "_write", wraps=health._write) as write, \
                patch.object(health, "_replace", wraps=health._replace) as replace:
            self.assertEqual(tree.run("refresh", "--admit", "reviewed actual edge")[0], 0)
            write.assert_called_once()
            replace.assert_called_once()
        loaded = health.load_json(tree.root / health.BASELINE, {})
        self.assertEqual(loaded["admitted"], {EDGE: "reviewed actual edge"})
        self.assertEqual(loaded["imports"], [EDGE])
        self.assertEqual(tree.run()[0], 0)

    def test_direct_consumers_reject_nonstring_admission_keys_and_nonarrays(self) -> None:
        tree = self.tree()
        state = health.current_state(tree.root, tree.fake_ruff)
        for identity in (1, False, None, ("identity",)):
            bad = copy.deepcopy(tree.baseline)
            bad["admitted"] = {identity: "reason"}
            self.assert_direct_refused(tree, bad, state)
        for imports in ((EDGE,), {EDGE}):
            bad = copy.deepcopy(tree.baseline)
            bad["imports"] = imports
            self.assert_direct_refused(tree, bad, state)

    def test_required_file_headers_and_imports_preserve_projection_compatibility(self) -> None:
        for field in ("version", "tool", "imports"):
            with self.subTest(field=field):
                tree = self.tree()
                state = health.current_state(tree.root, tree.fake_ruff)
                bad = copy.deepcopy(tree.baseline)
                del bad[field]
                if field == "imports":
                    self.assert_direct_refused(tree, bad, state)
                else:
                    self.assertEqual(health.compare(bad, [], state).failures, [])
                    updated, _ = health.refresh(bad, [], state, None)
                    self.assertNotIn(field, updated)
                tree.baseline = bad
                tree.save_baseline()
                self.assert_cli_refused(tree)

    def test_optional_fields_zero_default_and_huge_numbers_keep_existing_contracts(self) -> None:
        for number in (0, 15, 10 ** 5000):
            tree = self.tree()
            baseline = {key: value for key, value in tree.baseline.items()
                        if key not in ("admitted", "created", "repeated", "moved", "consumed_batches")}
            baseline.update(complexity_threshold=number, f_e9={"arbitrary identity": number},
                            complexity={"arbitrary function": number},
                            annotation={"finite": [0.25, True, None], "huge": number})
            health._replace(tree.root / health.BASELINE, baseline)
            loaded = health.load_json(tree.root / health.BASELINE, {})
            self.assertEqual(loaded, baseline)
            self.assertEqual(tree.run()[0], 0)
            self.assertEqual(tree.run("refresh")[0], 0)
            updated = health.load_json(tree.root / health.BASELINE, {})
            self.assertEqual(updated["admitted"], {})
            self.assertEqual(updated["complexity_threshold"], number)
            self.assertEqual(updated["annotation"], baseline["annotation"])
            self.assertEqual(updated["imports"], [])
            self.assertEqual((updated["f_e9"], updated["complexity"]), ({}, {}))
        tree = self.tree()
        tree.baseline["admitted"] = {"": "", "identity without a roster": "\u00e9"}
        tree.save_baseline()
        self.assertEqual(tree.run("refresh")[0], 0)
        self.assertEqual(health.load_json(tree.root / health.BASELINE, {})["admitted"], tree.baseline["admitted"])

    def test_numeric_missing_and_negative_controls_still_refuse(self) -> None:
        for field in ("complexity_threshold", "f_e9", "complexity"):
            tree = self.tree()
            state = health.current_state(tree.root, tree.fake_ruff)
            bad = copy.deepcopy(tree.baseline)
            del bad[field]
            self.assert_bad(tree, bad, state)
        tree = self.tree()
        bad = copy.deepcopy(tree.baseline)
        bad["complexity_threshold"] = -1
        self.assert_bad(tree, bad, health.current_state(tree.root, tree.fake_ruff))

    def test_default_ruff_route_checks_pin_before_measurement(self) -> None:
        if shutil.which("ruff") is None:
            self.skipTest("the pinned test-only ruff is not installed")
        tree = self.tree()
        self.assertEqual(health.ruff_version(), "0.17.1")
        self.assertEqual(self.invoke(tree)[0], 0)
        tree.baseline["tool"]["ruff"] = "different-fixture-pin"
        tree.save_baseline()
        before = self.snapshot(tree)
        with patch.object(health, "ruff_version", wraps=health.ruff_version) as version, \
                patch.object(health, "current_state", wraps=health.current_state) as measure, \
                patch.object(health, "_write", wraps=health._write) as write, \
                patch.object(health, "_replace", wraps=health._replace) as replace:
            with self.assertRaisesRegex(SystemExit, "is not the pinned different-fixture-pin"):
                self.invoke(tree)
            version.assert_called_once()
            measure.assert_not_called()
            write.assert_not_called()
            replace.assert_not_called()
        self.assertEqual(self.snapshot(tree), before)
        with patch.object(health, "ruff_version") as version, \
                patch.object(tree, "fake_ruff", wraps=tree.fake_ruff) as callback:
            self.assertEqual(self.invoke(tree, diagnostics=callback)[0], 0)
            callback.assert_called_once()
            version.assert_not_called()

    def test_missing_empty_and_fresh_init_guard_order_are_unchanged(self) -> None:
        for raw in (None, b"{}"):
            tree = self.tree()
            path = tree.root / health.BASELINE
            if raw is None:
                path.unlink()
            else:
                path.write_bytes(raw)
            self.assert_cli_refused(tree, "missing baseline")
        tree = Tree({"scripts/a.py": "value = 1\n"})
        self.addCleanup(tree.close)
        initial = (tree.root / health.BASELINE).read_bytes()
        self.assertFalse((tree.root / health.MOVES).exists())
        self.assertEqual(health.load_json(tree.root / health.MOVES, {"moves": []}), {"moves": []})
        self.assertEqual(tree.run("init", "--reason", "fixture")[0], 0)
        (tree.root / health.MOVES).write_bytes(b"{")
        with self.assertRaisesRegex(SystemExit, "only once"):
            tree.run("init", "--reason", "again")
        (tree.root / health.BASELINE).write_bytes(initial)
        with patch.object(health, "current_state", wraps=health.current_state) as measure, \
                patch.object(health, "_replace", wraps=health._replace) as replace:
            with self.assertRaisesRegex(SystemExit, "cannot read JSON"):
                tree.run("init", "--reason", "fixture")
            measure.assert_not_called()
            replace.assert_not_called()


if __name__ == "__main__":
    unittest.main()

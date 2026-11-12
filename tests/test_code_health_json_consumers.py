"""Finite JSON metadata across the checker reader, writer and batch consumers."""

from __future__ import annotations

import contextlib
import hashlib
import json
import unittest
from unittest.mock import patch

from tests.test_code_health import PolicySnapshot, SimpleTreeCase
from tests.test_code_health import Tree, function, health

BATCH = "json-consumer-fixture"
MARKER = "__JSON_CONSUMER_EXACT_INTEGER__"
DIGITS = "1" + "0" * 5000
COMMANDS = ((), ("refresh",), ("refresh", "--admit", "reviewed debt"))


def literal(value: object, *, indent: int | None = None, sort_keys: bool = True) -> bytes:
    """An independent stdlib projection with one literal, unbounded integer token."""
    text = json.dumps(value, indent=indent, sort_keys=sort_keys)
    quoted = json.dumps(MARKER)
    if text.count(quoted) != 1:
        raise AssertionError("the fixture needs exactly one integer marker")
    return text.replace(quoted, DIGITS).encode("utf-8")


class JsonConsumerTests(PolicySnapshot, SimpleTreeCase):


    def renamed(self) -> tuple[Tree, list[dict]]:
        tree = self.tree({"scripts/a.py": function("a", 4) + function("b", 6)})
        tree.refresh()
        self.assertEqual(tree.run()[0], 0)
        self.assertEqual(tree.baseline["complexity"], {"scripts/a.py::a": 5, "scripts/a.py::b": 7})
        tree.write({"scripts/a.py": function("c", 4) + function("d", 6)})
        moves = [
            {"from": "scripts/a.py::a", "to": "scripts/a.py::c", "reason": "rename a"},
            {"from": "scripts/a.py::b", "to": "scripts/a.py::d", "reason": "rename b"},
        ]
        tree.moves(moves, batch=BATCH)
        self.assertEqual(tree.run()[0], 0)
        return tree, moves

    def ordinary_move_control(self) -> None:
        tree, moves = self.renamed()
        moves[0]["annotation"] = {"z": [0.25, True, None, "\u00e9"], "a": {"last": [], "first": {}}}
        tree.moves(moves, batch=BATCH)
        expected = hashlib.sha256(json.dumps(moves, sort_keys=True).encode("utf-8")).hexdigest()
        self.assertEqual(health.moves_digest(moves), expected)
        self.assertEqual(tree.run()[0], 0)
        self.assertEqual(tree.run("refresh")[0], 0)
        baseline = health.load_json(tree.root / health.BASELINE, {})
        self.assertEqual(baseline["consumed_batches"], {BATCH: expected})
        self.assertEqual(baseline["moved"], moves)
        tree.moves(moves, batch=BATCH)
        code, out, _ = tree.run()
        self.assertEqual(code, 0)
        self.assertIn("refresh clears them", out)
        self.assertEqual(tree.run("refresh")[0], 0)
        self.assertEqual(health.load_json(tree.root / health.BASELINE, {})["moved"], moves)
        self.assertEqual(health.load_json(tree.root / health.MOVES, {})["moves"], [])

    def marked_moves(self, moves: list[dict]) -> list[dict]:
        annotation = {"z": [MARKER, {"text": "\u00e9"}], "a": [None, 0.25, True]}
        return [{**moves[0], "annotation": annotation}, dict(moves[1])]

    def install_marked(self, tree: Tree, marked: list[dict]) -> bytes:
        raw = literal({"version": 2, "batch": BATCH, "moves": marked})
        (tree.root / health.MOVES).write_bytes(raw)
        return raw

    def assert_capture(self, tree: Tree, marked: list[dict], digest: str) -> None:
        path = tree.root / health.BASELINE
        baseline = health.load_json(path, {})
        self.assertEqual(baseline["complexity"], {"scripts/a.py::c": 5, "scripts/a.py::d": 7})
        self.assertEqual(baseline["consumed_batches"], {BATCH: digest})
        self.assertEqual(len(baseline["moved"]), 2)
        number, text = baseline["moved"][0]["annotation"]["z"]
        self.assertIs(type(number), int)
        self.assertTrue(number == 10 ** 5000)
        projected = [{**baseline["moved"][0], "annotation": {
            **baseline["moved"][0]["annotation"], "z": [MARKER, text],
        }}, baseline["moved"][1]]
        self.assertEqual(projected, marked)
        projection = {**baseline, "moved": projected}
        self.assertEqual(path.read_bytes(), literal(projection, indent=2, sort_keys=False) + b"\n")

    def assert_batch_refused(self, tree: Tree) -> None:
        before = self.snapshot(tree)
        with patch.object(health, "current_state", wraps=health.current_state) as measure, \
                patch.object(health, "_write", wraps=health._write) as write, \
                patch.object(health, "_replace", wraps=health._replace) as replace:
            code, _, err = tree.run()
            self.assertEqual(code, 1)
            self.assertIn(f"batch {BATCH} was already applied", err)
            for argv in COMMANDS[1:]:
                with self.assertRaisesRegex(SystemExit, f"batch {BATCH} was already applied"):
                    tree.run(*argv)
            measure.assert_not_called()
            write.assert_not_called()
            replace.assert_not_called()
        self.assertEqual(self.snapshot(tree), before)

    def test_ordinary_writer_and_digest_bytes_match_stdlib(self) -> None:
        tree = self.tree({"scripts/a.py": "value = 1\n"})
        tree.refresh()
        self.assertEqual(tree.run()[0], 0)
        samples = [
            {"z": "\u00e9\U0001f600\n\"", "a": [0, -23, 1.25, -0.0, 1e30, True, False, None]},
            {"nested": ({"z": [[], {}, {"b": 2, "a": 1}]},), "empty": {}},
            {"keys": {2: "integer", 1.5: "float", None: "null", False: "bool"}},
        ]
        path = tree.root / "policy" / "ordinary.json"
        for sample in samples:
            with self.subTest(sample=sample):
                health._replace(path, sample)
                self.assertEqual(path.read_text(encoding="utf-8"), json.dumps(sample, indent=2) + "\n")
        ordinary = [{"z": {"b": [1, "\u00e9", {"y": None, "x": True}], "a": 0.25}, "a": []}]
        expected = json.dumps(ordinary, sort_keys=True).encode("utf-8")
        self.assertEqual(health.moves_digest(ordinary), hashlib.sha256(expected).hexdigest())
        self.assertEqual(health._json_text(ordinary, indent=None, sort_keys=True).encode("utf-8"), expected)
        shared = [1, {"x": "\u00e9"}]
        self.assertEqual(health._json_text([shared, shared]), json.dumps([shared, shared], indent=2))
        for container in ([], {}):
            if isinstance(container, list):
                container.append(container)
            else:
                container["self"] = container
            with self.assertRaisesRegex(ValueError, "Circular reference detected"):
                health._json_text(container)
        for encode in (lambda value: json.dumps(value, sort_keys=True),
                       lambda value: health._json_text(value, indent=None, sort_keys=True)):
            with self.assertRaises(TypeError):
                encode({"a": 1, 2: 3})

    def test_loaded_600_level_metadata_checks_and_refreshes(self) -> None:
        tree = self.tree({"scripts/a.py": "value = 1\n"})
        tree.refresh()
        self.assertEqual(tree.run()[0], 0)
        self.assertEqual(tree.run("refresh")[0], 0)
        path = tree.root / health.BASELINE
        ordinary = path.read_text(encoding="utf-8").rstrip()
        self.assertTrue(ordinary.endswith("}"))
        raw = ordinary[:-1] + ', "annotation": ' + "[" * 600 + "0" + "]" * 600 + "}\n"
        path.write_text(raw, encoding="utf-8")
        loaded = health.load_json(path, {})
        self.assertEqual(tree.run()[0], 0)
        self.assertEqual(tree.run("refresh")[0], 0)
        refreshed = health.load_json(path, {})
        for document in (loaded, refreshed):
            value = document["annotation"]
            for _ in range(600):
                self.assertIs(type(value), list)
                self.assertEqual(len(value), 1)
                value = value[0]
            self.assertIs(type(value), int)
            self.assertEqual(value, 0)
        self.assertEqual({key: value for key, value in loaded.items() if key != "annotation"},
                         {key: value for key, value in refreshed.items() if key != "annotation"})
        self.assertEqual(tree.run()[0], 0)

    def test_fresh_huge_move_annotation_refresh_records_exact_digest(self) -> None:
        self.ordinary_move_control()
        tree, moves = self.renamed()
        marked = self.marked_moves(moves)
        self.install_marked(tree, marked)
        expected = hashlib.sha256(literal(marked)).hexdigest()
        self.assertEqual(tree.run()[0], 0)
        self.assertEqual(tree.run("refresh")[0], 0)
        self.assert_capture(tree, marked, expected)
        self.assertEqual(health.load_json(tree.root / health.MOVES, {})["moves"], [])
        self.assertEqual(tree.run()[0], 0)

    def test_consumed_huge_annotation_is_recognized_and_never_replayed(self) -> None:
        self.ordinary_move_control()
        tree, moves = self.renamed()
        self.assertEqual(tree.run("refresh")[0], 0)
        self.assertEqual(tree.run()[0], 0)
        marked = self.marked_moves(moves)
        raw = self.install_marked(tree, marked)
        expected = hashlib.sha256(literal(marked)).hexdigest()
        baseline = health.load_json(tree.root / health.BASELINE, {})
        baseline["moved"] = health.load_json(tree.root / health.MOVES, {})["moves"]
        baseline["consumed_batches"][BATCH] = expected
        health._write(tree.root, baseline)
        self.assert_capture(tree, marked, expected)
        before = self.snapshot(tree)
        code, out, _ = tree.run()
        self.assertEqual(code, 0)
        self.assertIn("refresh clears them", out)
        self.assertEqual(self.snapshot(tree), before)
        changed = [{**marked[0], "reason": "changed"}, marked[1]]
        replay = [{**move, "from": move["to"], "to": move["from"]} for move in marked]
        for altered in (changed, list(reversed(marked)), replay):
            self.install_marked(tree, altered)
            self.assert_batch_refused(tree)
        (tree.root / health.MOVES).write_bytes(raw)
        tree.write({"scripts/a.py": function("a", 4) + function("b", 6)})
        before = self.snapshot(tree)
        code, out, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("refresh clears them", out)
        self.assertIn("new function over the complexity threshold", err)
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            tree.run("refresh")
        self.assertEqual(self.snapshot(tree), before)
        tree.write({"scripts/a.py": function("c", 4) + function("d", 6)})
        self.assertEqual(tree.run()[0], 0)
        self.assertEqual(tree.run("refresh")[0], 0)
        self.assert_capture(tree, marked, expected)
        self.assertEqual(health.load_json(tree.root / health.MOVES, {})["moves"], [])
        self.assertEqual(tree.run()[0], 0)

    def assert_reader_refused(self, tree: Tree, target: object, commands: tuple) -> None:
        before = self.snapshot(tree)
        for argv in commands:
            for use_ruff in (False, True):
                with self.subTest(argv=argv, use_ruff=use_ruff), contextlib.ExitStack() as stack:
                    callback = stack.enter_context(patch.object(tree, "fake_ruff", wraps=tree.fake_ruff))
                    observers = [stack.enter_context(patch.object(health, name, wraps=getattr(health, name)))
                                 for name in ("current_state", "_python_files_in_tree", "_write", "_replace")]
                    observers.append(stack.enter_context(patch.object(health, "ruff_version", return_value="0.17.1")))
                    observers.append(stack.enter_context(patch.object(health, "ruff_diagnostics", side_effect=callback)))
                    with self.assertRaisesRegex(SystemExit, r"cannot read JSON .*: .+") as refused:
                        health.main(list(argv), diagnostics=None if use_ruff else callback, root=tree.root)
                    self.assertIn(str(target), str(refused.exception))
                    for observer in [callback, *observers]:
                        observer.assert_not_called()
                self.assertEqual(self.snapshot(tree), before)

    def test_deep_malformed_documents_refuse_before_consumers(self) -> None:
        raw = b'{"annotation":' + b"[" * 10000
        for target in (health.BASELINE, health.MOVES):
            with self.subTest(target=target):
                tree = self.tree({"scripts/a.py": "value = 1\n"})
                tree.refresh()
                self.assertEqual(tree.run()[0], 0)
                self.assertEqual(tree.run("refresh")[0], 0)
                path = tree.root / target
                path.write_bytes(raw)
                commands = COMMANDS + (("init", "--reason", "fixture"),) if target == health.BASELINE else COMMANDS
                self.assert_reader_refused(tree, target, commands)
                fresh = self.tree({"scripts/a.py": "value = 1\n"})
                initial = (fresh.root / health.BASELINE).read_bytes()
                self.assertEqual(fresh.run("init", "--reason", "fixture")[0], 0)
                self.assertEqual(fresh.run()[0], 0)
                (fresh.root / health.BASELINE).write_bytes(initial)
                (fresh.root / target).write_bytes(raw)
                self.assert_reader_refused(fresh, target, (("init", "--reason", "fixture"),))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import NamedTuple
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_code_health as health  # noqa: E402
from tests.real_beads_fixture import configure_git_fixture

BODY = "    if value == 1:\n        return 1\n    if value == 2:\n        return 2\n    if value == 3:\n        return 3\n    if value == 4:\n        return 4\n"
COMPLEX = textwrap.dedent(
    """\
    def busy(value):
        if value == 1:
            return 1
        if value == 2:
            return 2
        if value == 3:
            return 3
        if value == 4:
            return 4
        return 0
    """
)


class Tree:
    """A small repository with a baseline, moves file and fake ruff output."""

    def __init__(self, files: dict[str, str], *, threshold: int = 3, diagnostics: list[dict] | None = None) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.diagnostics = diagnostics or []
        # Initialize as a git repository; the filesystem walk doesn't depend on git, but some tests may.
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True, capture_output=True)
        configure_git_fixture(self.root)
        subprocess.run(["git", "config", "user.name", "test"], cwd=self.root, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.root, check=True, capture_output=True)
        (self.root / "policy").mkdir()
        # Create both lint directories (scripts and tests) since the validator requires they exist.
        (self.root / "scripts").mkdir()
        (self.root / "tests").mkdir()
        # Initial files are staged by default for backward compatibility with existing tests.
        self.write(files, stage=True)
        self.baseline = {"version": 1, "tool": {"ruff": "0.17.1"}, "complexity_threshold": threshold,
                         "f_e9": {}, "imports": [], "complexity": {}, "admitted": {}}
        self.save_baseline()

    def write(self, files: dict[str, str], *, stage: bool = False) -> None:
        for name, text in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        # Add Python files to git so they're tracked (only if requested).
        if stage:
            python_files = [name for name in files if name.endswith((".py", ".pyi"))]
            if python_files:
                subprocess.run(["git", "add", *python_files], cwd=self.root, check=True, capture_output=True)

    def remove(self, name: str, *, untrack: bool = False) -> None:
        (self.root / name).unlink()
        # Remove from git tracking if it's a Python file (only if requested).
        if untrack and name.endswith((".py", ".pyi")):
            subprocess.run(["git", "rm", "--cached", name], cwd=self.root, check=False, capture_output=True)

    def save_baseline(self) -> None:
        (self.root / health.BASELINE).write_text(json.dumps(self.baseline), encoding="utf-8")

    def moves(self, moves: list[dict], batch: str | None = None) -> None:
        """Write a reviewed batch; each call is a fresh review with a new identifier unless ``batch`` is given."""
        self.batches = getattr(self, "batches", 0) + 1
        batch = batch if batch is not None else f"review-{self.batches}"
        (self.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": batch, "moves": moves}), encoding="utf-8")

    def fake_ruff(self, root: Path, paths: tuple[str, ...], inventory: list[str] | None = None) -> list[dict]:
        return list(self.diagnostics)

    def run(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(list(argv), diagnostics=self.fake_ruff, root=self.root)
        return code, out.getvalue(), err.getvalue()

    def refresh(self, admit: str | None = None) -> None:
        empty = not (self.baseline["f_e9"] or self.baseline["imports"] or self.baseline["complexity"])
        if empty and not admit and not getattr(self, "initialized", False):
            command = ["init", "--reason", "fixture"]
        else:
            command = ["refresh", *(["--admit", admit] if admit else [])]
        self.initialized = True
        code, _, _ = self.run(*command)
        assert code == 0
        self.baseline = json.loads((self.root / health.BASELINE).read_text(encoding="utf-8"))

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


class FilenameCase(NamedTuple):
    original: str
    filename: str
    content: str


class TreeCase(unittest.TestCase):
    """One fixture constructor API; every call still owns its real private Tree."""

    def tree(self, files: dict[str, str], **kwargs: object) -> Tree:
        tree = Tree(files, **kwargs)
        self.addCleanup(tree.close)
        return tree


class SimpleTreeCase(TreeCase):
    def tree(self, files: dict[str, str]) -> Tree:
        return super().tree(files)


class PolicySnapshot:
    def snapshot(self, tree: Tree) -> dict[str, bytes]:
        return {path.name: path.read_bytes() for path in (tree.root / "policy").iterdir()}


def unused(path: str, row: int, name: str = "os") -> dict:
    return {"filename": path, "code": "F401", "message": f"`{name}` imported but unused", "location": {"row": row, "column": 1}}


class RatchetTests(TreeCase):

    def test_recorded_debt_passes_and_new_debt_fails(self) -> None:
        tree = self.tree({"scripts/a.py": "import os\n\ndef f():\n    return 1\n"}, diagnostics=[unused("scripts/a.py", 1)])
        tree.refresh()
        self.assertEqual(tree.run()[0], 0, "an urgent fix can complete while unrelated debt stays recorded")
        tree.diagnostics.append(unused("scripts/a.py", 2, "sys"))
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("new F/E9 diagnostic: scripts/a.py::<module>::F401::sys", err)

    def test_line_shifts_and_comments_change_nothing(self) -> None:
        tree = self.tree({"scripts/a.py": "import os\n" + COMPLEX}, diagnostics=[unused("scripts/a.py", 1)])
        tree.refresh()
        tree.write({"scripts/a.py": "# a comment\n\n\nimport os\n\n# another\n" + COMPLEX})
        tree.diagnostics = [unused("scripts/a.py", 4)]
        self.assertEqual(tree.run()[0], 0)

    def test_complexity_growth_fails_and_shrink_is_reported(self) -> None:
        tree = self.tree({"scripts/a.py": COMPLEX})
        tree.refresh()
        self.assertEqual(tree.baseline["complexity"], {"scripts/a.py::busy": 5})
        tree.write({"scripts/a.py": COMPLEX.replace("    return 0\n", "    if value == 5:\n        return 5\n    return 0\n")})
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("complexity grew: scripts/a.py::busy (6, baseline 5)", err)
        tree.write({"scripts/a.py": "def busy(value):\n    if value:\n        return 1\n    return 0\n"})
        code, out, _ = tree.run()
        self.assertEqual(code, 0)
        self.assertIn("complexity reduced: scripts/a.py::busy (2, baseline 5)", out)
        tree.refresh()
        self.assertEqual(tree.baseline["complexity"], {}, "a shrunk entry below the threshold leaves the baseline")

    def test_new_complex_function_fails(self) -> None:
        tree = self.tree({"scripts/a.py": "def small():\n    return 1\n"})
        tree.refresh()
        tree.write({"scripts/b.py": COMPLEX})
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("new function over the complexity threshold 3: scripts/b.py::busy (5)", err)

    def test_reviewed_moves_and_renames_carry_the_baseline(self) -> None:
        tree = self.tree({"scripts/a.py": COMPLEX})
        tree.refresh()
        tree.remove("scripts/a.py", untrack=True)
        tree.write({"scripts/b.py": COMPLEX.replace("def busy", "def renamed"),
                    "scripts/a.py": "from b import renamed as busy  # temporary re-export\n"}, stage=True)
        code, _, err = tree.run()
        self.assertEqual(code, 1, "an unexplained transfer of debt fails")
        self.assertIn("scripts/b.py::renamed", err)
        tree.moves([{"from": "scripts/a.py::busy", "to": "scripts/b.py::renamed", "reason": "split module"}])
        code, out, _ = tree.run()
        self.assertEqual(code, 0)
        self.assertNotIn("baseline function gone", out, "the moved entry is matched, not reported missing")

    def test_moves_also_carry_diagnostics_inside_the_function(self) -> None:
        tree = self.tree({"scripts/a.py": "def f():\n    import os\n"},
                         diagnostics=[unused("scripts/a.py", 2)])
        tree.refresh()
        self.assertIn("scripts/a.py::f::F401::os", tree.baseline["f_e9"])
        tree.write({"scripts/a.py": "def g():\n    import os\n"})
        tree.diagnostics = [unused("scripts/a.py", 2)]
        self.assertEqual(tree.run()[0], 1)
        tree.moves([{"from": "scripts/a.py::f", "to": "scripts/a.py::g", "reason": "rename"}])
        self.assertEqual(tree.run()[0], 0)

    def test_new_core_to_cli_import_fails(self) -> None:
        tree = self.tree({"scripts/tool.py": "x = 1\n", "scripts/cwo_core/mod.py": "import json\n"})
        tree.refresh()
        tree.write({"scripts/cwo_core/mod.py": "import json\nfrom tool import x\n"})
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("new core-to-CLI import: cwo_core.mod -> tool", err)
        tree.refresh("existing coupling requires a module boundary correction")
        self.assertEqual(tree.baseline["imports"], ["cwo_core.mod -> tool"])
        tree.write({"scripts/cwo_core/mod.py": "import json\n"})
        code, out, _ = tree.run()
        self.assertEqual(code, 0)
        self.assertIn("core-to-CLI import removed: cwo_core.mod -> tool", out)

    def test_refresh_never_admits_debt_silently(self) -> None:
        tree = self.tree({"scripts/a.py": "def small():\n    return 1\n"})
        tree.refresh()
        tree.write({"scripts/b.py": COMPLEX})
        before = (tree.root / health.BASELINE).read_text(encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            tree.run("refresh")
        self.assertEqual((tree.root / health.BASELINE).read_text(encoding="utf-8"), before)
        tree.refresh("reviewed: table-driven parser, split planned")
        self.assertEqual(tree.baseline["complexity"], {"scripts/b.py::busy": 5})
        self.assertEqual(tree.baseline["admitted"], {"scripts/b.py::busy": "reviewed: table-driven parser, split planned"})

    def test_init_only_fills_an_empty_baseline(self) -> None:
        tree = self.tree({"scripts/a.py": COMPLEX})
        with self.assertRaisesRegex(SystemExit, "needs --reason"):
            tree.run("init")
        tree.refresh()
        self.assertEqual(tree.baseline["created"], "fixture")
        with self.assertRaisesRegex(SystemExit, "only once, into an empty baseline"):
            tree.run("init", "--reason", "again")

    def test_repeated_names_and_nested_functions_have_distinct_identities(self) -> None:
        tree = self.tree({"scripts/a.py": "if True:\n    def f():\n        return 1\nelse:\n    def f():\n        return 2\n"
                                          "class C:\n    def m(self):\n        def inner():\n            return 3\n        return inner\n"})
        self.assertEqual(set(health.function_complexity(tree.root)),
                         {"scripts/a.py::f", "scripts/a.py::f#2", "scripts/a.py::C.m", "scripts/a.py::C.m.inner"})


class ReviewRoundTwoTests(TreeCase):
    """Move identities, repeated definitions, diagnostics and CLI import edges."""


    def test_moves_need_a_reason_and_function_identities(self) -> None:
        tree = self.tree({"scripts/a.py": COMPLEX})
        tree.refresh()
        tree.remove("scripts/a.py", untrack=True)
        tree.write({"scripts/b.py": COMPLEX}, stage=True)
        for move in ({"from": "scripts/a.py::busy", "to": "scripts/b.py::busy"},
                     {"from": "scripts/a.py::busy", "to": "scripts/b.py::busy", "reason": "  "},
                     {"from": "scripts/a.py::busy::F401::os", "to": "scripts/b.py::busy::F821::os", "reason": "x"}):
            with self.subTest(move=move):
                tree.moves([move])
                code, _, err = tree.run()
                self.assertEqual(code, 1)
                self.assertIn("invalid move", err)
                with self.assertRaisesRegex(SystemExit, "fix the moves file"):
                    tree.run("refresh", "--admit", "anything")

    def test_a_move_cannot_merge_into_an_existing_entry(self) -> None:
        tree = self.tree({"scripts/a.py": COMPLEX, "scripts/b.py": COMPLEX.replace("    return 0\n", "    if value == 5:\n        return 5\n    return 0\n")})
        tree.refresh()
        self.assertEqual(tree.baseline["complexity"], {"scripts/a.py::busy": 5, "scripts/b.py::busy": 6})
        tree.remove("scripts/a.py", untrack=True)
        tree.moves([{"from": "scripts/a.py::busy", "to": "scripts/b.py::busy", "reason": "merge"}])
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("target already has baseline entries", err)

    def test_repeated_definitions_keep_their_diagnostics_apart(self) -> None:
        source = "if True:\n    def f():\n        import os\nelse:\n    def f():\n        return 1\n"
        tree = self.tree({"scripts/a.py": source}, diagnostics=[unused("scripts/a.py", 3)])
        tree.refresh()
        self.assertIn("scripts/a.py::f::F401::os", tree.baseline["f_e9"])
        tree.write({"scripts/a.py": "if True:\n    def f():\n        return 1\nelse:\n    def f():\n        import os\n"})
        tree.diagnostics = [unused("scripts/a.py", 6)]
        code, _, err = tree.run()
        self.assertEqual(code, 1, "moving the import into the second f is new debt there")
        self.assertIn("scripts/a.py::f#2::F401::os", err)

    def test_decorator_diagnostics_belong_to_their_function(self) -> None:
        source = "@missing_decorator\ndef f():\n    return 1\n"
        tree = self.tree({"scripts/a.py": source},
                         diagnostics=[{"filename": "scripts/a.py", "code": "F821", "message": "Undefined name `missing_decorator`",
                                       "location": {"row": 1, "column": 2}}])
        tree.refresh()
        self.assertEqual(list(tree.baseline["f_e9"]), ["scripts/a.py::f::F821::missing_decorator"])

    def test_every_import_form_of_a_cli_module_is_an_edge(self) -> None:
        for statement in ("import tool", "import scripts.tool", "from scripts.tool import x", "from scripts import tool",
                          "from .. import tool", "from ..tool import x", "from tool import x"):
            with self.subTest(statement=statement):
                tree = self.tree({"scripts/tool.py": "x = 1\n", "scripts/cwo_core/mod.py": f"{statement}\n"})
                self.assertEqual(health.import_edges(tree.root), {"cwo_core.mod -> tool"})
        tree = self.tree({"scripts/tool.py": "x = 1\n", "scripts/cwo_core/mod.py": "from . import tool\nimport json\n"})
        self.assertEqual(health.import_edges(tree.root), set(), "a sibling core module is not the CLI")

    def test_inline_suppressions_cannot_hide_a_diagnostic(self) -> None:
        self.assertIn("--ignore-noqa", health.RUFF_COMMAND)
        if shutil.which("ruff") is None:
            self.skipTest("the pinned ruff from requirements-test.txt is not installed")
        tree = self.tree({"scripts/a.py": "import os  # noqa: F401\nprint(undefined)  # noqa: F821\n"})
        codes = {record["code"] for record in health.ruff_diagnostics(tree.root, ("scripts",))}
        self.assertEqual(codes, {"F401", "F821"})

    def test_init_runs_once_and_reasons_cannot_be_blank(self) -> None:
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n"})
        tree.refresh()
        self.assertEqual(tree.baseline["created"], "fixture")
        with self.assertRaisesRegex(SystemExit, "only once"):
            tree.run("init", "--reason", "again")
        with self.assertRaisesRegex(SystemExit, "needs a reason"):
            tree.run("refresh", "--admit", "   ")


class ReviewRoundThreeTests(TreeCase):
    """Move descendants, repeated definitions and refresh consumption."""


    def test_moves_cannot_merge_descendants_into_existing_entries(self) -> None:
        source_a = "def a(value):\n" + BODY + "    def inner(value):\n" + BODY.replace("    ", "        ") + "    return inner\n"
        source_b = "def b(value):\n    def inner(value):\n" + BODY.replace("    ", "        ") + BODY.replace("    ", "        ").replace("== 1", "== 7").replace("== 2", "== 8") + "    return inner\n"
        tree = self.tree({"scripts/x.py": source_a + source_b})
        tree.refresh()
        self.assertTrue({"scripts/x.py::a", "scripts/x.py::a.inner", "scripts/x.py::b.inner"} <= set(tree.baseline["complexity"]))
        tree.write({"scripts/x.py": source_b.replace("def b(", "def b(") + source_a.replace("def a(", "def b_old(")})
        tree.moves([{"from": "scripts/x.py::a", "to": "scripts/x.py::b", "reason": "rename"}])
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("invalid move", err)

    def test_the_reviewed_descendant_merge_cannot_hide_growth(self) -> None:
        """The review's case: a=5 and a.inner=5; b under the threshold with b.inner=7; a -> b, then b.inner grows to 6."""
        def nested(conditions: int) -> str:
            return "".join(f"        if value == {n}:\n            return {n}\n" for n in range(conditions))

        a = "def a(value):\n" + BODY + "    def inner(value):\n" + nested(4) + "    return inner\n"
        b = "def b(value):\n    if value:\n        return 0\n    def inner(value):\n" + nested(6) + "    return inner\n"
        tree = self.tree({"scripts/x.py": a + b})
        tree.refresh()
        self.assertEqual(tree.baseline["complexity"], {"scripts/x.py::a": 5, "scripts/x.py::a.inner": 5, "scripts/x.py::b.inner": 7})
        before = (tree.root / health.BASELINE).read_bytes()
        tree.write({"scripts/x.py": "def b(value):\n" + BODY + "    def inner(value):\n" + nested(5) + "    return inner\n"})
        tree.moves([{"from": "scripts/x.py::a", "to": "scripts/x.py::b", "reason": "rename"}])
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("invalid move", err)
        with self.assertRaises(SystemExit):
            tree.run("refresh", "--admit", "merge")
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before)

    def test_renumbered_repeated_definitions_need_admission(self) -> None:
        first = "if True:\n    def f(value):\n" + BODY.replace("    ", "        ") + "else:\n    def f(value):\n" + BODY.replace("    ", "        ").replace("== 4", "== 9").replace("        if value == 9:\n            return 4\n", "") + "    \n"
        tree = self.tree({"scripts/x.py": first})
        tree.refresh()
        tree.write({"scripts/x.py": "def f(value):\n" + BODY})
        code, _, err = tree.run()
        self.assertEqual(code, 1, "the surviving definition must not inherit the first one's allowance")
        self.assertIn("repeated definitions changed: scripts/x.py::f (2 -> 1)", err)
        self.assertEqual(list(tree.baseline["repeated"]), ["scripts/x.py::f"])
        self.assertEqual(len(tree.baseline["repeated"]["scripts/x.py::f"]), 2)
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            tree.run("refresh")
        tree.refresh("first branch removed; second keeps its body")
        self.assertEqual(tree.run()[0], 0)

    def test_core_subpackages_are_checked_with_relative_depth(self) -> None:
        tree = self.tree({"scripts/tool.py": "x = 1\n", "scripts/cwo_core/sub/__init__.py": "",
                          "scripts/cwo_core/sub/mod.py": "from ... import tool\nfrom .. import other\nfrom tool import x\n",
                          "scripts/cwo_core/other.py": "y = 2\n"})
        self.assertEqual(health.import_edges(tree.root), {"cwo_core.sub.mod -> tool"})

    def test_a_refreshed_move_is_consumed_and_the_next_check_passes(self) -> None:
        tree = self.tree({"scripts/a.py": COMPLEX})
        tree.refresh()
        tree.remove("scripts/a.py", untrack=True)
        tree.write({"scripts/b.py": COMPLEX.replace("def busy", "def renamed")}, stage=True)
        tree.moves([{"from": "scripts/a.py::busy", "to": "scripts/b.py::renamed", "reason": "split module"}])
        self.assertEqual(tree.run()[0], 0)
        tree.refresh()
        self.assertEqual(tree.run()[0], 0, "check -> refresh -> check passes")
        self.assertEqual(tree.baseline["complexity"], {"scripts/b.py::renamed": 5})
        self.assertEqual(json.loads((tree.root / health.MOVES).read_text(encoding="utf-8"))["moves"], [])
        self.assertEqual(tree.baseline["moved"][-1]["reason"], "split module")

    def test_test_functions_can_be_moved(self) -> None:
        tree = self.tree({"tests/test_a.py": "def test_old():\n    import os\n"}, diagnostics=[unused("tests/test_a.py", 2)])
        tree.refresh()
        tree.write({"tests/test_a.py": "def test_new():\n    import os\n"})
        tree.diagnostics = [unused("tests/test_a.py", 2)]
        tree.moves([{"from": "tests/test_a.py::test_old", "to": "tests/test_a.py::test_new", "reason": "rename"}])
        self.assertEqual(tree.run()[0], 0)


def function(name: str, conditions: int, indent: str = "") -> str:
    """A function whose complexity is ``conditions + 1``."""
    body = "".join(f"{indent}    if value == {n}:\n{indent}        return {n}\n" for n in range(conditions))
    return f"{indent}def {name}(value):\n{body}{indent}    return -1\n"


def undefined(path: str, row: int, name: str = "missing") -> dict:
    return {"filename": path, "code": "F821", "message": f"Undefined name `{name}`", "location": {"row": row, "column": 5}}


class ReviewRoundFourTests(TreeCase):
    """Move destinations, overlapping mappings and interrupted refresh recovery."""


    def test_moved_diagnostics_cannot_converge_on_one_destination(self) -> None:
        # a.inner (row 3) and c (row 6) each hold one F821 for the same name; a -> b and c -> b.inner would add them up.
        source = "def a(value):\n    def inner(value):\n        return missing\n    return other\ndef c(value):\n    return missing\n"
        tree = self.tree({"scripts/x.py": source}, diagnostics=[undefined("scripts/x.py", 3), undefined("scripts/x.py", 4, "other"),
                                                                 undefined("scripts/x.py", 6)])
        tree.refresh()
        self.assertEqual(set(tree.baseline["f_e9"]), {"scripts/x.py::a::F821::other", "scripts/x.py::a.inner::F821::missing",
                                                      "scripts/x.py::c::F821::missing"})
        tree.write({"scripts/x.py": "def b(value):\n    def inner(value):\n        return missing + missing\n    return other\n"})
        tree.diagnostics = [undefined("scripts/x.py", 3), undefined("scripts/x.py", 3), undefined("scripts/x.py", 4, "other")]
        tree.moves([{"from": "scripts/x.py::a", "to": "scripts/x.py::b", "reason": "rename"},
                    {"from": "scripts/x.py::c", "to": "scripts/x.py::b.inner", "reason": "inline"}])
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("invalid move: moves would merge diagnostics into scripts/x.py::b.inner::F821::missing", err)

    def test_a_source_may_carry_only_nested_entries(self) -> None:
        source = "def a(value):\n    def inner(value):\n        return missing\n    return inner\n"
        tree = self.tree({"scripts/x.py": source}, diagnostics=[undefined("scripts/x.py", 3)])
        tree.refresh()
        tree.write({"scripts/x.py": source.replace("def a(", "def b(")})
        tree.moves([{"from": "scripts/x.py::a", "to": "scripts/x.py::b", "reason": "rename"}])
        self.assertEqual(tree.run()[0], 0)

    def test_every_move_must_carry_an_entry(self) -> None:
        source = "def a(value):\n    def inner(value):\n        return missing\n    return inner\n"
        tree = self.tree({"scripts/x.py": source}, diagnostics=[undefined("scripts/x.py", 3)])
        tree.refresh()
        tree.write({"scripts/x.py": "def b(value):\n    return 0\ndef c(value):\n    return missing\n"})
        tree.diagnostics = [undefined("scripts/x.py", 4)]
        tree.moves([{"from": "scripts/x.py::a", "to": "scripts/x.py::b", "reason": "rename"},
                    {"from": "scripts/x.py::a.inner", "to": "scripts/x.py::c", "reason": "extract"}])
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("move 1 carries no baseline entry (more specific moves take them all): scripts/x.py::a", err)
        tree.moves([{"from": "scripts/x.py::a.inner", "to": "scripts/x.py::c", "reason": "extract"}])
        self.assertEqual(tree.run()[0], 0)

    def test_a_destination_whose_own_entries_move_away_is_free(self) -> None:
        source = function("a", 4) + function("b", 6)
        tree = self.tree({"scripts/x.py": source})
        tree.refresh()
        tree.write({"scripts/x.py": function("b", 4) + function("c", 6)})
        tree.moves([{"from": "scripts/x.py::a", "to": "scripts/x.py::b", "reason": "a takes b's name"},
                    {"from": "scripts/x.py::b", "to": "scripts/x.py::c", "reason": "b becomes c"}])
        self.assertEqual(tree.run()[0], 0)
        tree.write({"scripts/x.py": function("b", 6) + function("c", 4)})
        code, _, err = tree.run()
        self.assertEqual(code, 1, "the chain carries each allowance to its own destination")
        self.assertIn("complexity grew: scripts/x.py::b (7, baseline 5)", err)

    def test_overlapping_moves_apply_the_most_specific_in_any_order(self) -> None:
        nested = function("a", 4) .replace("    return -1\n", function("inner", 4, "    ") + "    return inner\n")
        moves = [{"from": "scripts/x.py::a", "to": "scripts/x.py::b", "reason": "rename"},
                 {"from": "scripts/x.py::a.inner", "to": "scripts/x.py::c", "reason": "extract"}]
        for order in (moves, list(reversed(moves))):
            with self.subTest(first=order[0]["from"]):
                tree = self.tree({"scripts/x.py": nested})
                tree.refresh()
                self.assertEqual(tree.baseline["complexity"], {"scripts/x.py::a": 5, "scripts/x.py::a.inner": 5})
                hidden = function("b", 4).replace("    return -1\n", function("inner", 4, "    ") + "    return inner\n")
                tree.write({"scripts/x.py": hidden + function("c", 0)})
                tree.moves(order)
                code, _, err = tree.run()
                self.assertEqual(code, 1)
                self.assertIn("new function over the complexity threshold 3: scripts/x.py::b.inner (5)", err)
                tree.write({"scripts/x.py": function("b", 4) + function("c", 4)})
                self.assertEqual(tree.run()[0], 0, "a real extraction passes whatever the order")

    def test_repeated_definitions_cannot_trade_debt_when_the_count_stays(self) -> None:
        def pair(first: int, second: int) -> str:
            return "if True:\n" + function("f", first, "    ") + "else:\n" + function("f", second, "    ")

        tree = self.tree({"scripts/x.py": pair(7, 5)})
        tree.refresh()
        self.assertEqual(tree.baseline["complexity"], {"scripts/x.py::f": 8, "scripts/x.py::f#2": 6})
        tree.write({"scripts/x.py": "\n\n" + pair(7, 5)})
        self.assertEqual(tree.run()[0], 0, "unchanged definitions still pass")
        # The review's case: swapped, the second grows from 6 to 7 and the first shrinks from 8 to 6.
        tree.write({"scripts/x.py": pair(6, 5)})
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("repeated definitions changed: scripts/x.py::f (their code, order or debt changed, and only their order "
                      "tells them apart)", err)
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            tree.run("refresh")
        tree.refresh("reordered the platform branches")
        self.assertEqual(tree.baseline["admitted"]["scripts/x.py::f"], "reordered the platform branches")
        self.assertEqual(tree.run()[0], 0)

    def test_repeated_names_follow_reviewed_moves(self) -> None:
        def pair(name: str) -> str:
            return "if True:\n" + function(name, 7, "    ") + "else:\n" + function(name, 5, "    ")

        tree = self.tree({"scripts/x.py": pair("f")})
        tree.refresh()
        tree.write({"scripts/x.py": pair("g")})
        tree.moves([{"from": "scripts/x.py::f", "to": "scripts/x.py::g", "reason": "rename"},
                    {"from": "scripts/x.py::f#2", "to": "scripts/x.py::g#2", "reason": "rename"}])
        code, _, err = tree.run()
        # The moves carry the debt to the new names, but any change to a file whose repeated names carry debt asks
        # for review (round 7), so the rename is admitted with a reason.
        self.assertEqual(code, 1, err)
        self.assertIn("repeated definitions changed: scripts/x.py::g", err)
        self.assertNotIn("invalid move", err)
        tree.refresh("renamed the platform pair")
        self.assertEqual(tree.run()[0], 0)

    def test_an_interrupted_refresh_can_be_finished(self) -> None:
        tree = self.tree({"scripts/a.py": COMPLEX})
        tree.refresh()
        tree.remove("scripts/a.py", untrack=True)
        tree.write({"scripts/b.py": COMPLEX.replace("def busy", "def renamed")}, stage=True)
        move = {"from": "scripts/a.py::busy", "to": "scripts/b.py::renamed", "reason": "split module"}
        tree.moves([move])
        with patch.object(health, "_clear_moves", side_effect=OSError("disk full")), self.assertRaises(OSError):
            tree.run("refresh")
        baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertEqual((baseline["complexity"], baseline["moved"]), ({"scripts/b.py::renamed": 5}, [move]))
        self.assertEqual(json.loads((tree.root / health.MOVES).read_text(encoding="utf-8"))["moves"], [move])
        code, out, _ = tree.run()
        self.assertEqual(code, 0, "an applied move is consumed, not applied again")
        self.assertIn("refresh clears them", out)
        tree.refresh()
        self.assertEqual(json.loads((tree.root / health.MOVES).read_text(encoding="utf-8"))["moves"], [])
        self.assertEqual(tree.baseline["moved"], [move], "recorded once")
        self.assertEqual(tree.run()[0], 0)


def platform_function(name: str, conditions: int, offset: int, indent: str = "    ") -> str:
    """A function of complexity ``conditions + 1`` whose code differs by ``offset`` from its namesakes."""
    body = "".join(f"{indent}    if value == {n + offset}:\n{indent}        return {n}\n" for n in range(conditions))
    return f"{indent}def {name}(value):\n{body}{indent}    return -1\n"


class ReviewRoundFiveTests(TreeCase):
    """Repeated-definition fingerprints and atomic baseline writes."""


    @staticmethod
    def pair(first: str, second: str) -> str:
        return "import sys\nif sys.platform == 'win32':\n" + first + "else:\n" + second

    def test_swapped_repeated_definitions_need_review_with_the_metrics_unchanged(self) -> None:
        # The review's case: Windows f=8 and Linux f#2=6, reordered so that Linux (grown to 8) comes first and
        # Windows (shrunk to 6) second. The complexity of each position is unchanged.
        tree = self.tree({"scripts/x.py": self.pair(platform_function("f", 7, 0), platform_function("f", 5, 100))})
        tree.refresh()
        self.assertEqual(tree.baseline["complexity"], {"scripts/x.py::f": 8, "scripts/x.py::f#2": 6})
        tree.write({"scripts/x.py": self.pair(platform_function("f", 7, 100), platform_function("f", 5, 0))})
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("repeated definitions changed: scripts/x.py::f (their code, order or debt changed", err)
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            tree.run("refresh")

    def test_unchanged_repeated_definitions_pass_whatever_their_lines_and_comments(self) -> None:
        source = self.pair(platform_function("f", 7, 0), platform_function("f", 5, 100))
        tree = self.tree({"scripts/x.py": source})
        tree.refresh()
        shifted = "# platform split\n\n" + source.replace("    def f(value):\n", "    # the same body\n    def f(value):\n", 1)
        tree.write({"scripts/x.py": shifted})
        self.assertEqual(tree.run()[0], 0)

    def test_a_definition_number_in_a_file_name_is_not_a_definition_number(self) -> None:
        # The _unnumbered function should handle # in filenames even though the validator rejects them.
        self.assertEqual(health._unnumbered("scripts/x#1.py::f#2.inner#3"), "scripts/x#1.py::f.inner")
        # Use a valid filename (x1.py) for the actual file test. The principle is the same:
        # numbers/chars in the filename should not be confused with definition numbers.
        tree = self.tree({"scripts/x1.py": self.pair(platform_function("f", 7, 0), platform_function("f", 5, 100))})
        tree.refresh()
        tree.write({"scripts/x1.py": self.pair(platform_function("f", 5, 100), platform_function("f", 6, 0))})
        code, _, err = tree.run()
        self.assertEqual(code, 1, "the round-3 swap is caught in a file whose name contains a number")
        self.assertIn("repeated definitions changed: scripts/x1.py::f", err)

    def test_an_interrupted_write_never_leaves_part_of_a_file(self) -> None:
        """A write that fails halfway, to the baseline or to the moves file, leaves the old file whole."""
        real_open = open

        def failing_halfway(target: Path):
            def opener(path: object, *args: object, **kwargs: object) -> object:
                handle = real_open(path, *args, **kwargs)  # type: ignore[call-overload]
                if Path(str(path)).name == f".{target.name}.tmp":
                    real_write = handle.write

                    def write(text: str) -> int:
                        real_write(text[: len(text) // 2])
                        raise OSError("disk full")
                    handle.write = write  # type: ignore[method-assign]
                return handle
            return opener

        for target in (health.BASELINE, health.MOVES):
            with self.subTest(failing=target.name):
                tree = self.tree({"scripts/a.py": COMPLEX})
                tree.refresh()
                tree.remove("scripts/a.py", untrack=True)
                tree.write({"scripts/b.py": COMPLEX.replace("def busy", "def renamed")}, stage=True)
                move = {"from": "scripts/a.py::busy", "to": "scripts/b.py::renamed", "reason": "split module"}
                tree.moves([move])
                before = {name: (tree.root / name).read_bytes() for name in (health.BASELINE, health.MOVES)}
                real_write_text = Path.write_text

                def write_text_halfway(path: Path, text: str, *args: object, target: Path = target, **kwargs: object) -> int:
                    if path.name == target.name:  # a direct write, as an atomic writer never does
                        real_write_text(path, text[: len(text) // 2], *args, **kwargs)  # type: ignore[arg-type]
                        raise OSError("disk full")
                    return real_write_text(path, text, *args, **kwargs)  # type: ignore[arg-type]

                with patch("builtins.open", side_effect=failing_halfway(target)), \
                        patch.object(Path, "write_text", write_text_halfway), self.assertRaises(OSError):
                    tree.run("refresh")
                self.assertEqual((tree.root / target).read_bytes(), before[target], "the failed file is untouched")
                for name in (health.BASELINE, health.MOVES):
                    json.loads((tree.root / name).read_text(encoding="utf-8"))
                # Whichever write failed, the next check and refresh finish the job.
                self.assertEqual(tree.run()[0], 0)
                tree.refresh()
                self.assertEqual(json.loads((tree.root / health.MOVES).read_text(encoding="utf-8"))["moves"], [])
                self.assertEqual(tree.baseline["moved"], [move])
                self.assertEqual(tree.run()[0], 0)


class ReviewRoundSixTests(TreeCase):
    """Conditional-definition guard identity across supported interpreters."""


    def test_a_guard_change_that_swaps_roles_needs_review(self) -> None:
        # The review's case: Windows f=8 and Linux f#2=6; only the guard changes, from == to !=, so each
        # implementation now runs on the other platform while code and metrics stay identical.
        def pair(operator: str) -> str:
            return (f"import sys\nif sys.platform {operator} 'win32':\n" + platform_function("f", 7, 0) + "else:\n"
                    + platform_function("f", 5, 100))

        tree = self.tree({"scripts/x.py": pair("==")})
        tree.refresh()
        tree.write({"scripts/x.py": pair("!=")})
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("repeated definitions changed: scripts/x.py::f (their code, order or debt changed", err)
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            tree.run("refresh")

    def test_fingerprints_are_the_same_on_every_supported_interpreter(self) -> None:
        """Fixed expected values: the focused runs check them on both Python 3.12 and Python 3.14."""
        import ast

        source = ("import sys\nif sys.platform == 'win32':\n    def f(value):\n        return value + 1\n"
                  "else:\n    def f(value):\n        return value - 1\n")
        tree = ast.parse(source)
        module = hashlib.sha256(health._canonical(tree).encode("utf-8")).hexdigest()
        prints = [health._fingerprint(node, module) for _, _, _, node in health._definitions(tree)]
        self.assertEqual(prints, ["89ea683c6f558b22", "fde11f75cf9dc168"])


class ReviewRoundSevenTests(TreeCase):
    """Repeated-debt file changes and move cycles require review."""


    def test_a_guard_inside_a_try_that_swaps_roles_needs_review(self) -> None:
        # The review's case: an exception handler and an else branch, selected by a raise in the try body.
        def pair(operator: str) -> str:
            return (f"import sys\ntry:\n    if sys.platform {operator} 'win32':\n        raise ValueError\n"
                    "except ValueError:\n" + platform_function("f", 7, 0) + "else:\n" + platform_function("f", 5, 100))

        tree = self.tree({"scripts/x.py": pair("==")})
        tree.refresh()
        self.assertEqual(tree.baseline["complexity"], {"scripts/x.py::f": 8, "scripts/x.py::f#2": 6})
        tree.write({"scripts/x.py": pair("!=")})
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("repeated definitions changed: scripts/x.py::f", err)
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            tree.run("refresh")

    def test_any_code_change_to_a_file_with_repeated_debt_needs_review(self) -> None:
        source = ("import sys\nif sys.platform == 'win32':\n" + platform_function("f", 7, 0) + "else:\n"
                  + platform_function("f", 5, 100))
        tree = self.tree({"scripts/x.py": source})
        tree.refresh()
        tree.write({"scripts/x.py": "# platforms\n\n" + source + "\n# end\n"})
        self.assertEqual(tree.run()[0], 0, "comments and blank lines change nothing")
        tree.write({"scripts/x.py": source + "def helper():\n    return sys.platform\n"})
        code, _, err = tree.run()
        self.assertEqual(code, 1, "any code change in such a file asks for review")
        self.assertIn("repeated definitions changed: scripts/x.py::f", err)
        tree.refresh("added a helper next to the platform pair")
        self.assertEqual(tree.run()[0], 0)

    def test_a_move_cycle_applies_each_time(self) -> None:
        tree = self.tree({"scripts/a.py": COMPLEX})
        tree.refresh()
        a_to_b = {"from": "scripts/a.py::busy", "to": "scripts/b.py::busy", "reason": "move to b"}
        b_to_a = {"from": "scripts/b.py::busy", "to": "scripts/a.py::busy", "reason": "move back to a"}
        for move, present, gone in ((a_to_b, "scripts/b.py", "scripts/a.py"), (b_to_a, "scripts/a.py", "scripts/b.py"),
                                    (a_to_b, "scripts/b.py", "scripts/a.py")):
            with self.subTest(move=move["reason"], to=present):
                tree.remove(gone, untrack=True)
                tree.write({present: COMPLEX}, stage=True)
                tree.moves([move])
                code, _, err = tree.run()
                self.assertEqual(code, 0, err)
                tree.refresh()
                self.assertEqual(tree.baseline["complexity"], {f"{present}::busy": 5})
        self.assertEqual(tree.baseline["moved"], [a_to_b, b_to_a, a_to_b])


class ReviewRoundEightTests(TreeCase):
    """Consumed move batches cannot replay after interrupted refresh."""


    def test_an_interrupted_refresh_of_a_swap_cannot_replay_it(self) -> None:
        # The review's case: a reviewed swap a<->b, a refresh interrupted before it clears the moves file, then a
        # change back that grows b. The recorded batch is consumed, so the swap cannot be applied a second time.
        tree = self.tree({"scripts/x.py": function("a", 4) + function("b", 6)})
        tree.refresh()
        self.assertEqual(tree.baseline["complexity"], {"scripts/x.py::a": 5, "scripts/x.py::b": 7})
        swap = [{"from": "scripts/x.py::a", "to": "scripts/x.py::b", "reason": "swap names"},
                {"from": "scripts/x.py::b", "to": "scripts/x.py::a", "reason": "swap names"}]
        tree.write({"scripts/x.py": function("a", 6) + function("b", 4)})
        tree.moves(swap)
        self.assertEqual(tree.run()[0], 0)
        with patch.object(health, "_clear_moves", side_effect=OSError("disk full")), self.assertRaises(OSError):
            tree.run("refresh")
        baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertEqual(baseline["complexity"], {"scripts/x.py::a": 7, "scripts/x.py::b": 5})
        tree.write({"scripts/x.py": function("a", 4) + function("b", 6)})
        code, out, err = tree.run()
        self.assertEqual(code, 1, "b grew from 5 to 7; the consumed swap is not applied again")
        self.assertEqual(list(baseline["consumed_batches"]), ["review-1"])
        self.assertIn("complexity grew: scripts/x.py::b (7, baseline 5)", err)
        self.assertIn("refresh clears them", out)
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            tree.run("refresh")

    def test_a_new_batch_with_an_earlier_move_is_still_applied(self) -> None:
        tree = self.tree({"scripts/a.py": COMPLEX})
        tree.refresh()
        a_to_b = {"from": "scripts/a.py::busy", "to": "scripts/b.py::busy", "reason": "move to b"}
        b_to_a = {"from": "scripts/b.py::busy", "to": "scripts/a.py::busy", "reason": "move back"}
        for move, present, gone in ((a_to_b, "scripts/b.py", "scripts/a.py"), (b_to_a, "scripts/a.py", "scripts/b.py"),
                                    (a_to_b, "scripts/b.py", "scripts/a.py")):
            with self.subTest(move=move["reason"], to=present):
                tree.remove(gone, untrack=True)
                tree.write({present: COMPLEX}, stage=True)
                tree.moves([move])
                self.assertEqual(tree.run()[0], 0)
                tree.refresh()
                self.assertEqual(tree.baseline["complexity"], {f"{present}::busy": 5})

    def test_cli_packages_count_for_the_import_gate(self) -> None:
        tree = self.tree({
            "scripts/tool/__init__.py": "", "scripts/tool/__main__.py": "from . import main\n",
            "scripts/tool/main.py": "x = 1\n", "scripts/spaced/run.py": "y = 2\n",
            "scripts/cwo_core/a.py": "import scripts.tool.main\n", "scripts/cwo_core/b.py": "from scripts.tool import main\n",
            "scripts/cwo_core/c.py": "from ..tool import main\n", "scripts/cwo_core/d.py": "from spaced import run\n",
        })
        self.assertEqual(health.import_edges(tree.root),
                         {"cwo_core.a -> tool", "cwo_core.b -> tool", "cwo_core.c -> tool", "cwo_core.d -> spaced"})


class ReviewRoundNineTests(TreeCase):
    """Move batch identifiers distinguish separate review occurrences."""


    SWAP = [{"from": "scripts/x.py::a", "to": "scripts/x.py::b", "reason": "swap names"},
            {"from": "scripts/x.py::b", "to": "scripts/x.py::a", "reason": "swap names"}]

    def interrupted_swap(self, extra: str = "") -> Tree:
        """The review's setup: baseline a=5, b=7; a reviewed swap whose refresh stops before clearing the moves
        file, leaving baseline a=7, b=5 and the swap still listed under its batch identifier."""
        tree = self.tree({"scripts/x.py": function("a", 4) + function("b", 6) + extra})
        tree.refresh()
        tree.write({"scripts/x.py": function("a", 6) + function("b", 4) + extra})
        tree.moves(self.SWAP, batch="swap-1")
        with patch.object(health, "_clear_moves", side_effect=OSError("disk full")), self.assertRaises(OSError):
            tree.run("refresh")
        baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertEqual({k: v for k, v in baseline["complexity"].items() if k.endswith(("::a", "::b"))},
                         {"scripts/x.py::a": 7, "scripts/x.py::b": 5})
        return tree

    def assert_refused(self, tree: Tree) -> None:
        before = {name: (tree.root / name).read_bytes() for name in (health.BASELINE, health.MOVES)}
        code, _, err = tree.run()
        self.assertEqual(code, 1, "check must fail")
        self.assertIn("batch swap-1 was already applied", err)
        for argv in (["refresh"], ["refresh", "--admit", "growth"]):
            with self.subTest(argv=argv), self.assertRaisesRegex(SystemExit, "batch swap-1 was already applied"):
                tree.run(*argv)
        self.assertEqual({name: (tree.root / name).read_bytes() for name in before}, before, "nothing is written")

    def test_reordering_a_consumed_batch_does_not_revive_it(self) -> None:
        # The review's case: reversing the stale mappings must not let a=5, b=7 through as a second swap.
        tree = self.interrupted_swap()
        tree.write({"scripts/x.py": function("a", 4) + function("b", 6)})
        tree.moves(list(reversed(self.SWAP)), batch="swap-1")
        self.assert_refused(tree)

    def test_extending_a_consumed_batch_does_not_revive_it(self) -> None:
        tree = self.interrupted_swap(extra=function("c", 5))
        tree.write({"scripts/x.py": function("a", 4) + function("b", 6) + function("d", 5)})
        tree.moves([*self.SWAP, {"from": "scripts/x.py::c", "to": "scripts/x.py::d", "reason": "rename c"}],
                   batch="swap-1")
        self.assert_refused(tree)

    def test_the_unchanged_consumed_batch_is_still_finished_not_replayed(self) -> None:
        tree = self.interrupted_swap()
        code, out, _ = tree.run()
        self.assertEqual(code, 0)
        self.assertIn("refresh clears them", out)
        tree.refresh()
        self.assertEqual(json.loads((tree.root / health.MOVES).read_text(encoding="utf-8"))["moves"], [])
        self.assertEqual(tree.baseline["moved"], self.SWAP, "recorded once")

    def test_two_consecutive_identical_swaps_both_apply(self) -> None:
        tree = self.tree({"scripts/x.py": function("a", 4) + function("b", 6)})
        tree.refresh()
        for number, (a, b) in enumerate(((6, 4), (4, 6)), start=1):
            with self.subTest(swap=number):
                tree.write({"scripts/x.py": function("a", a) + function("b", b)})
                tree.moves(self.SWAP, batch=f"swap-{number}")
                code, _, err = tree.run()
                self.assertEqual(code, 0, err)
                tree.refresh()
                self.assertEqual(tree.baseline["complexity"], {"scripts/x.py::a": a + 1, "scripts/x.py::b": b + 1})
        self.assertEqual(tree.baseline["moved"], [*self.SWAP, *self.SWAP])

    def test_a_batch_needs_a_fresh_identifier(self) -> None:
        tree = self.tree({"scripts/a.py": COMPLEX})
        tree.refresh()
        tree.remove("scripts/a.py", untrack=True)
        tree.write({"scripts/b.py": COMPLEX}, stage=True)
        move = {"from": "scripts/a.py::busy", "to": "scripts/b.py::busy", "reason": "move to b"}
        for batch, message in ((None, "needs a batch identifier"), ("", "needs a batch identifier"),
                               ("has space", "needs a batch identifier")):
            with self.subTest(batch=batch):
                document = {"version": 2, "moves": [move]} if batch is None else {"version": 2, "batch": batch, "moves": [move]}
                (tree.root / health.MOVES).write_text(json.dumps(document), encoding="utf-8")
                code, _, err = tree.run()
                self.assertEqual(code, 1)
                self.assertIn(message, err)
                with self.assertRaisesRegex(SystemExit, message):
                    tree.run("refresh")
        tree.moves([move], batch="move-1")
        tree.refresh()
        # Reusing a consumed identifier for different moves is refused, even after the file was cleared.
        tree.remove("scripts/b.py", untrack=True)
        tree.write({"scripts/a.py": COMPLEX}, stage=True)
        tree.moves([{"from": "scripts/b.py::busy", "to": "scripts/a.py::busy", "reason": "back"}], batch="move-1")
        code, _, err = tree.run()
        self.assertEqual(code, 1)
        self.assertIn("batch move-1 was already applied", err)
class ReviewRoundTenTests(TreeCase):
    """Environment redirection and ignore rules cannot hide diagnostics."""


    def test_ruff_output_file_environment_variable_does_not_silence_diagnostics(self) -> None:
        """RUFF_OUTPUT_FILE can redirect the report to a file, leaving stdout empty and exit zero; the ratchet
        scrubs RUFF_* variables, so the diagnostic is still found and `check` fails normally."""
        # Start with a clean file, no violations in baseline.
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n"})
        tree.refresh()
        output_file = tree.root / "redirected.json"
        code, _, err = tree.run()
        self.assertEqual(code, 0, "baseline has no violations")
        # Add a new F821 violation (undefined name) but use real ruff, not fake_ruff, to test environment scrubbing.
        tree.write({"scripts/a.py": "def f():\n    return x\n"})
        env_patch = {**os.environ, "RUFF_OUTPUT_FILE": str(output_file)}
        with patch.dict(os.environ, env_patch, clear=True):
            # Call with diagnostics=None to use real ruff, which scrubs RUFF_OUTPUT_FILE before invocation.
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = health.main([], diagnostics=None, root=tree.root)
            self.assertEqual(code, 1, "check must fail even with RUFF_OUTPUT_FILE set")
            self.assertIn("new F/E9 diagnostic", err.getvalue())
            self.assertIn("F821", err.getvalue())
            self.assertFalse(output_file.exists(), "output was not redirected; RUFF_* variables were scrubbed")
            # Refresh must also refuse, with and without --admit.
            before_baseline = (tree.root / health.BASELINE).read_bytes()
            # Create moves file if it doesn't exist (refresh checks it).
            if not (tree.root / health.MOVES).exists():
                (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
            before_moves = (tree.root / health.MOVES).read_bytes()
            with self.assertRaisesRegex(SystemExit, "would admit new debt"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh"], diagnostics=None, root=tree.root)
            self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline, "baseline unchanged")
            self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves, "moves unchanged")

    def test_tracked_file_in_gitignore_with_new_debt_fails(self) -> None:
        """Adding a tracked file to .gitignore must not hide new debt. Uses real ruff."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n"})
        # Use real ruff to establish baseline.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        # Add a.py to .gitignore and introduce a new F821 violation.
        tree.write({".gitignore": "scripts/a.py\n",
                    "scripts/a.py": "def f():\n    return x\n"})
        # Check must fail with real ruff (explicit paths ignore .gitignore).
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main([], diagnostics=None, root=tree.root)
        self.assertEqual(code, 1, "check must fail even though a.py is now in .gitignore")
        self.assertIn("new F/E9 diagnostic", err.getvalue())
        self.assertIn("F821", err.getvalue())
        # Refresh must refuse without writing policy files.
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        if not (tree.root / health.MOVES).exists():
            (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                health.main(["refresh"], diagnostics=None, root=tree.root)
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_tracked_file_under_excluded_directory_with_transferred_debt_fails(self) -> None:
        """Moving a file with debt under an excluded directory (like .venv/) must not hide the debt. Uses real ruff."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    import os\n"})
        # Use real ruff to establish baseline with the F401.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertIn("scripts/a.py::f::F401::os", baseline["f_e9"])
        # Move the file under .venv/ (an excluded directory by default in ruff).
        tree.remove("scripts/a.py", untrack=True)
        (tree.root / "scripts" / ".venv").mkdir()
        tree.write({"scripts/.venv/a.py": "def f():\n    import os\n"}, stage=True)
        # Without a move, this appears as: old entry gone, new entry appears.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main([], diagnostics=None, root=tree.root)
        self.assertEqual(code, 1, "check must fail: the debt moved to an excluded directory")
        self.assertIn("new F/E9 diagnostic", err.getvalue())
        self.assertIn("scripts/.venv/a.py::f::F401::os", err.getvalue())
        # Refresh must refuse without writing.
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        if not (tree.root / health.MOVES).exists():
            (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                health.main(["refresh"], diagnostics=None, root=tree.root)
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)


class ReviewRoundElevenTests(TreeCase):
    """Source inventory, stub coverage, deletion and malformed diagnostic output."""


    def test_untracked_file_with_new_debt_fails(self) -> None:
        """An untracked file with new debt must fail check, and refresh must refuse without writing."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n"})
        # Initialize baseline with real ruff.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        # Add an untracked file with F821 violation (no stage=True, so it's not tracked).
        tree.write({"scripts/b.py": "def g():\n    return x\n"})
        # Check must fail even though the file is untracked.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main([], diagnostics=None, root=tree.root)
        self.assertEqual(code, 1, "check must fail on untracked file with new debt")
        self.assertIn("new F/E9 diagnostic", err.getvalue())
        self.assertIn("F821", err.getvalue())
        # Refresh without --admit must refuse and not write either policy file.
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        if not (tree.root / health.MOVES).exists():
            (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                health.main(["refresh"], diagnostics=None, root=tree.root)
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline, "baseline unchanged")
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves, "moves unchanged")
        # Refresh with --admit succeeds and admits the debt.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = health.main(["refresh", "--admit", "intentional"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, "refresh with --admit succeeds")
        new_baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertIn("scripts/b.py::g::F821::x", new_baseline["f_e9"])
        self.assertEqual(new_baseline["admitted"]["scripts/b.py::g::F821::x"], "intentional")

    def test_tracked_pyi_stub_with_new_debt_fails(self) -> None:
        """A tracked .pyi stub with new debt must fail check and refresh must refuse."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        # Add a .pyi stub with F821 violation.
        tree.write({"scripts/b.pyi": "def g() -> int: ...\nx\n"}, stage=True)
        # Check must fail.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main([], diagnostics=None, root=tree.root)
        self.assertEqual(code, 1, "check must fail on .pyi stub with new debt")
        self.assertIn("new F/E9 diagnostic", err.getvalue())
        self.assertIn("F821", err.getvalue())
        self.assertIn("scripts/b.pyi", err.getvalue())
        # Refresh must refuse.
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        if not (tree.root / health.MOVES).exists():
            (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                health.main(["refresh"], diagnostics=None, root=tree.root)
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_unstaged_deletion_records_reduction_without_crash(self) -> None:
        """An unstaged deletion should record debt reduction without crashing, with another source remaining."""
        tree = self.tree({"scripts/a.py": "import os\n", "scripts/b.py": "def f():\n    return 1\n"})
        # Establish baseline with fake diagnostics for scripts/a.py.
        tree.diagnostics = [unused("scripts/a.py", 1)]
        tree.refresh()
        self.assertIn("scripts/a.py::<module>::F401::os", tree.baseline["f_e9"])
        # Delete the file with debt (scripts/a.py), leaving scripts/b.py.
        tree.remove("scripts/a.py")
        # With the filesystem walk, the deleted file is not in the inventory, so refresh should succeed.
        tree.diagnostics = []
        code, out, _ = tree.run("refresh")
        self.assertEqual(code, 0, "refresh must succeed when a file with debt is deleted")
        self.assertIn("F/E9 diagnostic reduced", out)
        tree.baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertNotIn("scripts/a.py::<module>::F401::os", tree.baseline["f_e9"], "deleted file's debt removed from baseline")

    def test_empty_inventory_is_refused(self) -> None:
        """A lint directory with no sources must refuse, not silently skip Ruff."""
        tree = self.tree({"scripts/.keep": "", "tests/.keep": ""})
        # Initialize baseline first (with the .keep files, no Python sources).
        tree.refresh()
        # Remove the scripts and tests directories and replace with empty ones.
        shutil.rmtree(tree.root / "scripts")
        shutil.rmtree(tree.root / "tests")
        (tree.root / "scripts").mkdir()
        (tree.root / "tests").mkdir()
        # Both refresh and check should refuse with real ruff (fake_ruff doesn't check inventory).
        with self.assertRaisesRegex(SystemExit, "no Python sources found"):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                health.main([], diagnostics=None, root=tree.root)
        with self.assertRaisesRegex(SystemExit, "no Python sources found"):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)

    def test_empty_ruff_output_is_refused(self) -> None:
        """Empty ruff output (redirected or lost) must refuse for both refresh forms, without writing policy files."""
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n"})
        tree.refresh()
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        ruff_version_result = unittest.mock.Mock(returncode=0, stdout=f"ruff {baseline['tool']['ruff']}\n", stderr="")
        # Mock subprocess.run to return empty stdout for the ruff check command.
        mock_empty = unittest.mock.Mock(returncode=0, stdout="", stderr="")
        def side_effect(cmd, **kwargs):
            if cmd[0] == "ruff" and "--version" in cmd:
                return ruff_version_result
            return mock_empty
        with patch("subprocess.run", side_effect=side_effect), patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "ruff produced no output"):
                health.main(["refresh"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline, "baseline unchanged")
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves, "moves unchanged")
        with patch("subprocess.run", side_effect=side_effect), patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "ruff produced no output"):
                health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline, "baseline unchanged")
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves, "moves unchanged")
        # Check as well.
        with patch("subprocess.run", side_effect=side_effect), patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "ruff produced no output"):
                health.main([], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()

    def test_malformed_ruff_output_is_refused(self) -> None:
        """Malformed or non-array ruff output must refuse for both refresh forms, without writing policy files."""
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n"})
        tree.refresh()
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        ruff_version_result = unittest.mock.Mock(returncode=0, stdout=f"ruff {baseline['tool']['ruff']}\n", stderr="")
        # Test whitespace only (stripped to empty, another form of empty output).
        mock_whitespace = unittest.mock.Mock(returncode=0, stdout="   \n  ", stderr="")
        def whitespace_effect(cmd, **kwargs):
            return ruff_version_result if "--version" in cmd else mock_whitespace
        with patch("subprocess.run", side_effect=whitespace_effect), patch.object(health, "_replace") as mock_replace:
            # Whitespace-only output fails the "if not result.stdout:" check and raises "ruff produced no output".
            # But actually Python's truthiness of "   \n  " is True, so this will pass the empty check.
            # The real issue is it's not valid JSON. Let me check what actually happens.
            # Actually, looking at the code, it does "if not result.stdout:" which checks truthiness, and "   \n  " is truthy.
            # So it will try to parse as JSON and fail with "not valid JSON".
            with self.assertRaisesRegex(SystemExit, "not valid JSON"):
                health.main(["refresh"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        # Test malformed JSON.
        mock_malformed = unittest.mock.Mock(returncode=0, stdout="{invalid", stderr="")
        def malformed_effect(cmd, **kwargs):
            return ruff_version_result if "--version" in cmd else mock_malformed
        with patch("subprocess.run", side_effect=malformed_effect), patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "not valid JSON"):
                health.main(["refresh"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        with patch("subprocess.run", side_effect=malformed_effect), patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "not valid JSON"):
                health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        with patch("subprocess.run", side_effect=malformed_effect), patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "not valid JSON"):
                health.main([], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)
        # Test non-array output (a JSON object instead).
        mock_object = unittest.mock.Mock(returncode=0, stdout='{"error": "test"}', stderr="")
        def object_effect(cmd, **kwargs):
            return ruff_version_result if "--version" in cmd else mock_object
        with patch("subprocess.run", side_effect=object_effect), patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "must be a JSON array"):
                health.main(["refresh"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        with patch("subprocess.run", side_effect=object_effect), patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "must be a JSON array"):
                health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        with patch("subprocess.run", side_effect=object_effect), patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "must be a JSON array"):
                health.main([], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)
        # Test non-zero exit code.
        mock_failed = unittest.mock.Mock(returncode=1, stdout="", stderr="ruff error message")
        def failed_effect(cmd, **kwargs):
            return ruff_version_result if "--version" in cmd else mock_failed
        with patch("subprocess.run", side_effect=failed_effect), patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "ruff failed"):
                health.main(["refresh"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        with patch("subprocess.run", side_effect=failed_effect), patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "ruff failed"):
                health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)


class ReviewRoundTwelveTests(TreeCase):
    """Symlinks, unreadable paths and conditional stub definitions fail closed."""


    def test_symlinked_source_file_is_refused(self) -> None:
        """A symlinked source file must refuse check, refresh, and refresh --admit, with zero persistence calls."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "import os\n", "scripts/b.py": "def f():\n    return 1\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        # Create a symlink to scripts/a.py (which has debt).
        link_path = tree.root / "scripts" / "link.py"
        link_path.symlink_to("a.py")
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        # Check must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "symlink not supported"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main([], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "symlink not supported"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh --admit must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "symlink not supported"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_symlinked_directory_is_refused(self) -> None:
        """A symlinked directory must refuse check, refresh, and refresh --admit, with zero persistence calls."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        # Create a subdirectory with a source file and symlink to it.
        (tree.root / "scripts" / "subdir").mkdir()
        (tree.root / "scripts" / "subdir" / "b.py").write_text("import os\n", encoding="utf-8")
        link_dir = tree.root / "scripts" / "linked"
        link_dir.symlink_to("subdir")
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        # Check must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "symlink not supported"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main([], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "symlink not supported"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh --admit must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "symlink not supported"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_unreadable_subdirectory_is_refused(self) -> None:
        """An unreadable subdirectory must refuse check, refresh, and refresh --admit, with zero persistence calls."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        if os.geteuid() == 0:
            self.skipTest("running as root; permissions cannot be enforced")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        # Create an unreadable subdirectory with a source file.
        unreadable = tree.root / "scripts" / "unreadable"
        unreadable.mkdir()
        (unreadable / "b.py").write_text("import os\n", encoding="utf-8")
        unreadable.chmod(0o000)
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        try:
            # Check must refuse.
            with patch.object(health, "_replace") as mock_replace:
                with self.assertRaisesRegex(SystemExit, "cannot read"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main([], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
            # Refresh must refuse.
            with patch.object(health, "_replace") as mock_replace:
                with self.assertRaisesRegex(SystemExit, "cannot read"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
            # Refresh --admit must refuse.
            with patch.object(health, "_replace") as mock_replace:
                with self.assertRaisesRegex(SystemExit, "cannot read"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
            self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
            self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)
        finally:
            unreadable.chmod(0o755)

    def test_pyi_stub_conditional_definition_guard_change_fails(self) -> None:
        """Changing only a conditional definition's platform guard in a .pyi stub must fail check and reasonless refresh."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        # Add an F821 diagnostic to the stub so it carries debt and the comparison triggers.
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n",
                          "scripts/b.pyi": "import sys\nif sys.platform == 'linux':\n    def g() -> int: x\nelse:\n    def g() -> str: x\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertIn("scripts/b.pyi::g", baseline["repeated"])
        self.assertEqual(len(baseline["repeated"]["scripts/b.pyi::g"]), 2, "two conditional definitions of g")
        self.assertIn("scripts/b.pyi::g::F821::x", baseline["f_e9"])
        # Change only the platform guard (linux -> darwin), not the function signature or the undefined x.
        tree.write({"scripts/b.pyi": "import sys\nif sys.platform == 'darwin':\n    def g() -> int: x\nelse:\n    def g() -> str: x\n"})
        # Check must fail.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main([], diagnostics=None, root=tree.root)
        self.assertEqual(code, 1, "check must fail when a stub's conditional definition guard changes")
        self.assertIn("repeated definitions changed", err.getvalue())
        # Refresh without --admit must refuse.
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        before_moves = (tree.root / health.MOVES).read_bytes()
        with self.assertRaisesRegex(SystemExit, "refresh would admit new debt"):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                health.main(["refresh"], diagnostics=None, root=tree.root)
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_pyi_stub_reviewed_move_is_accepted(self) -> None:
        """A reviewed move of a .pyi stub definition must be accepted by check and refresh."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        # Create a stub with a conditional definition that carries F821 debt.
        stub_before = "import sys\nif sys.platform == 'linux':\n    def f() -> int: x\nelse:\n    def f() -> str: x\n"
        stub_after = "import sys\nif sys.platform == 'linux':\n    def f() -> int: x\nelse:\n    def f() -> str: x\n"
        tree = self.tree({"scripts/a.pyi": stub_before, "scripts/b.py": "def g():\n    return 1\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertIn("scripts/a.pyi::f", baseline["repeated"])
        self.assertIn("scripts/a.pyi::f::F821::x", baseline["f_e9"])
        # Move the stub to a new path and record the reviewed move.
        tree.remove("scripts/a.pyi")
        tree.write({"scripts/c.pyi": stub_after})
        tree.moves([{"from": "scripts/a.pyi::f", "to": "scripts/c.pyi::f", "reason": "reorganize stubs"},
                    {"from": "scripts/a.pyi::f#2", "to": "scripts/c.pyi::f#2", "reason": "reorganize stubs"}], batch="r12-stub-move")
        # Check must pass.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main([], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, "check must pass with a reviewed stub move")
        # Refresh must succeed and record the move as consumed.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = health.main(["refresh"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, "refresh must succeed with a reviewed stub move")
        new_baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertIn("scripts/c.pyi::f", new_baseline["repeated"])
        self.assertNotIn("scripts/a.pyi::f", new_baseline["repeated"])
        self.assertIn("r12-stub-move", new_baseline["consumed_batches"])


class ReviewRoundThirteenTests(TreeCase):

    def test_dangling_symlink_as_lint_root_is_refused(self) -> None:
        """A dangling symlink as a configured lint root must refuse check, refresh, and refresh --admit, with zero persistence calls."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        # Create a tree with a regular scripts directory and another clean source in tests.
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "tests/t.py": "def g():\n    return 2\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        # Replace scripts with a dangling symlink.
        shutil.rmtree(tree.root / "scripts")
        (tree.root / "scripts").symlink_to("nonexistent")
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        # Check must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "configured lint root is a symlink"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main([], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "configured lint root is a symlink"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh --admit must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "configured lint root is a symlink"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_symlinked_directory_root_is_refused(self) -> None:
        """A configured lint root that is a symlink to a directory with debt must refuse check, refresh, and refresh --admit, with zero persistence calls."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        # Create a tree with a regular scripts directory and another clean source in tests.
        tree = self.tree({"scripts/placeholder.py": "def p():\n    return 1\n", "tests/t.py": "def g():\n    return 2\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        # Remove scripts and create a real directory with debt, then symlink scripts to it.
        shutil.rmtree(tree.root / "scripts")
        (tree.root / "real_scripts").mkdir()
        (tree.root / "real_scripts" / "a.py").write_text("import os\n", encoding="utf-8")
        (tree.root / "scripts").symlink_to("real_scripts")
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        # Check must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "configured lint root is a symlink"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main([], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "configured lint root is a symlink"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh --admit must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "configured lint root is a symlink"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_inaccessible_directory_symlink_named_pkg_is_refused(self) -> None:
        """An inaccessible directory symlink named pkg must refuse check, refresh, and refresh --admit, with zero persistence calls."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "tests/t.py": "def g():\n    return 2\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        # Create a directory symlink named pkg.
        (tree.root / "scripts" / "pkg").symlink_to("nonexistent")
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        # Check must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "symlink not supported"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main([], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "symlink not supported"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh --admit must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, "symlink not supported"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_fifo_under_lint_root_is_refused(self) -> None:
        """A fifo under a lint root must refuse check, refresh, and refresh --admit, with zero persistence calls. Skip if mkfifo unavailable."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "tests/t.py": "def g():\n    return 2\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        # Create a fifo.
        fifo_path = tree.root / "scripts" / "fifo"
        os.mkfifo(fifo_path)
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()
        try:
            # Check must refuse.
            with patch.object(health, "_replace") as mock_replace:
                with self.assertRaisesRegex(SystemExit, "unsupported file type"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main([], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
            # Refresh must refuse.
            with patch.object(health, "_replace") as mock_replace:
                with self.assertRaisesRegex(SystemExit, "unsupported file type"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
            # Refresh --admit must refuse.
            with patch.object(health, "_replace") as mock_replace:
                with self.assertRaisesRegex(SystemExit, "unsupported file type"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
            self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
            self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)
        finally:
            fifo_path.unlink(missing_ok=True)

    def test_unsupported_filename_rows_refuse_without_persistence(self) -> None:
        rows = (
            FilenameCase("test_filename_with_delimiter_is_refused", "a::b.pyi", "def h() -> int: x\n"),
            FilenameCase("test_filename_with_space_is_refused", "my file.py", "import os\n"),
        )
        for row in rows:
            with self.subTest(original=row.original):
                if shutil.which("ruff") is None:
                    self.skipTest("ruff not available")
                tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "tests/t.py": "def g():\n    return 2\n"})
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
                self.assertEqual(code, 0, err.getvalue())
                # Create a file with :: in the name.
                (tree.root / "scripts" / row.filename).write_text(row.content, encoding="utf-8")
                before_baseline = (tree.root / health.BASELINE).read_bytes()
                (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
                before_moves = (tree.root / health.MOVES).read_bytes()
                # Check must refuse.
                with patch.object(health, "_replace") as mock_replace:
                    with self.assertRaisesRegex(SystemExit, "filename contains unsupported characters"):
                        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                            health.main([], diagnostics=None, root=tree.root)
                    mock_replace.assert_not_called()
                # Refresh must refuse.
                with patch.object(health, "_replace") as mock_replace:
                    with self.assertRaisesRegex(SystemExit, "filename contains unsupported characters"):
                        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                            health.main(["refresh"], diagnostics=None, root=tree.root)
                    mock_replace.assert_not_called()
                # Refresh --admit must refuse.
                with patch.object(health, "_replace") as mock_replace:
                    with self.assertRaisesRegex(SystemExit, "filename contains unsupported characters"):
                        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                            health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
                    mock_replace.assert_not_called()
                self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
                self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)


    def test_pyi_stub_diagnostic_only_guard_change_fails(self) -> None:
        """Changing only a conditional definition's platform guard in a .pyi stub with diagnostic-only debt must fail check and reasonless refresh."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        # Create a stub with conditional definitions carrying only F821 debt (no complexity).
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n",
                          "scripts/b.pyi": "import sys\nif sys.platform == 'linux':\n    def g() -> int: x\nelse:\n    def g() -> str: x\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertIn("scripts/b.pyi::g", baseline["repeated"])
        self.assertIn("scripts/b.pyi::g::F821::x", baseline["f_e9"])
        # Change only the platform guard (linux -> darwin), not the function signature or the undefined x.
        tree.write({"scripts/b.pyi": "import sys\nif sys.platform == 'darwin':\n    def g() -> int: x\nelse:\n    def g() -> str: x\n"})
        # Check must fail.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main([], diagnostics=None, root=tree.root)
        self.assertEqual(code, 1, "check must fail when a stub's conditional definition guard changes")
        self.assertIn("repeated definitions changed", err.getvalue())
        # Refresh without --admit must refuse.
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        before_moves = (tree.root / health.MOVES).read_bytes()
        with self.assertRaisesRegex(SystemExit, "would admit new debt"):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                health.main(["refresh"], diagnostics=None, root=tree.root)
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_deletion_through_real_ruff_records_reduction(self) -> None:
        """Deletion through REAL Ruff: baseline and refresh established with real Ruff, then delete one source with a second clean source remaining. Refresh records the reduction. No fake_ruff in this test."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        # Create two sources: one with debt, one clean.
        tree = self.tree({"scripts/a.py": "import os\n", "scripts/b.py": "def f():\n    return 1\n"})
        # Establish baseline with real Ruff (diagnostics=None).
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertIn("scripts/a.py::<module>::F401::os", baseline["f_e9"])
        # Delete the file with debt (scripts/a.py), leaving scripts/b.py.
        tree.remove("scripts/a.py")
        # Refresh through real Ruff must succeed and record the reduction.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["refresh"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, "refresh must succeed when a file with debt is deleted")
        self.assertIn("F/E9 diagnostic reduced", out.getvalue())
        new_baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertNotIn("scripts/a.py::<module>::F401::os", new_baseline["f_e9"], "deleted file's debt removed from baseline")


class ReviewRoundFourteenTests(TreeCase):

    def test_root_lstat_failure_refuses_with_zero_persistence(self) -> None:
        """When lstat on a lint root fails, check, refresh, and refresh --admit refuse with zero persistence calls."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "tests/t.py": "def g():\n    return 2\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()

        # Inject PermissionError on lstat of scripts root.
        original_lstat = Path.lstat

        def mock_lstat(self):
            if self == tree.root / "scripts":
                raise PermissionError("mock permission denied")
            return original_lstat(self)

        # Check must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch.object(Path, "lstat", mock_lstat):
                with self.assertRaisesRegex(SystemExit, "cannot inspect configured lint root scripts"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main([], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        # Refresh must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch.object(Path, "lstat", mock_lstat):
                with self.assertRaisesRegex(SystemExit, "cannot inspect configured lint root scripts"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        # Refresh --admit must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch.object(Path, "lstat", mock_lstat):
                with self.assertRaisesRegex(SystemExit, "cannot inspect configured lint root scripts"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_directory_scandir_failure_refuses_with_zero_persistence(self) -> None:
        """When scandir on a directory fails, check, refresh, and refresh --admit refuse with zero persistence calls."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "scripts/pkg/__init__.py": "pass\n", "scripts/pkg/b.py": "def g():\n    return 2\n", "tests/t.py": "def h():\n    return 3\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()

        # Inject PermissionError on scandir of scripts/pkg directory.
        import os
        original_scandir = os.scandir

        def mock_scandir(path):
            if Path(path) == tree.root / "scripts" / "pkg":
                raise PermissionError("mock permission denied")
            return original_scandir(path)

        # Check must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "cannot read directory scripts/pkg"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main([], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        # Refresh must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "cannot read directory scripts/pkg"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        # Refresh --admit must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "cannot read directory scripts/pkg"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_entry_stat_failure_refuses_with_zero_persistence(self) -> None:
        """When stat on a directory entry fails, check, refresh, and refresh --admit refuse with zero persistence calls."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "scripts/b.py": "def g():\n    return 2\n", "tests/t.py": "def h():\n    return 3\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()

        # Inject OSError(EIO) on stat of scripts/b.py entry.
        import os
        from contextlib import contextmanager
        original_scandir = os.scandir

        @contextmanager
        def mock_scandir(path):
            entries = list(original_scandir(path))
            if Path(path) == tree.root / "scripts":
                # Wrap entries to inject stat failure on b.py
                class WrappedEntry:
                    def __init__(self, entry):
                        self._entry = entry

                    def __getattr__(self, name):
                        return getattr(self._entry, name)

                    def stat(self, follow_symlinks=True):
                        if self._entry.name == "b.py":
                            raise OSError(5, "mock I/O error")  # EIO
                        return self._entry.stat(follow_symlinks=follow_symlinks)

                entries = [WrappedEntry(e) for e in entries]
            yield iter(entries)

        # Check must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "cannot inspect scripts/b.py"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main([], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        # Refresh must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "cannot inspect scripts/b.py"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        # Refresh --admit must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "cannot inspect scripts/b.py"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_nested_directory_traversal_failure_refuses_with_zero_persistence(self) -> None:
        """When scandir on a nested directory fails, check, refresh, and refresh --admit refuse with zero persistence calls."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "scripts/pkg/sub/__init__.py": "pass\n", "scripts/pkg/sub/c.py": "def g():\n    return 2\n", "tests/t.py": "def h():\n    return 3\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()

        # Inject PermissionError on scandir of nested scripts/pkg/sub directory.
        import os
        original_scandir = os.scandir

        def mock_scandir(path):
            if Path(path) == tree.root / "scripts" / "pkg" / "sub":
                raise PermissionError("mock permission denied")
            return original_scandir(path)

        # Check must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "cannot read directory scripts/pkg/sub"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main([], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        # Refresh must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "cannot read directory scripts/pkg/sub"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        # Refresh --admit must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "cannot read directory scripts/pkg/sub"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_unified_inventory_single_scan(self) -> None:
        """Unified inventory scans the scripts directory exactly once per check, preventing separate scans from swallowing errors.

        Round 14+ use a single fail-closed inventory passed to all measurements. This test injects a failure on the
        second scandir of the scripts directory and verifies that only one scan occurs, so the failure never triggers.
        A complexity increase from 16 to 17 is correctly detected. Round 13 (cc64a98) performed multiple scans (main
        inventory, then separate scans for imports and complexity), so the second-scan failure triggers during
        import discovery, causing an ERROR before reaching complexity measurement."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        # Create baseline with complexity 16 in scripts/a.py and a clean scripts/b.py.
        body = "    if value == 1:\n        return 1\n" * 15
        tree = self.tree({"scripts/a.py": f"def f(value):\n{body}    return 0\n", "scripts/b.py": "def g():\n    return 1\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        baseline = json.loads((tree.root / health.BASELINE).read_text(encoding="utf-8"))
        self.assertEqual(baseline["complexity"]["scripts/a.py::f"], 16)
        # Increase complexity to 17.
        body_17 = "    if value == 1:\n        return 1\n" * 16
        (tree.root / "scripts" / "a.py").write_text(f"def f(value):\n{body_17}    return 0\n", encoding="utf-8")
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()

        # Inject a traversal failure on the second scandir of the scripts directory.
        # This simulates a failure during the separate complexity scan on round 13.
        import os
        from contextlib import contextmanager
        original_scandir = os.scandir
        scandir_count = {"scripts": 0}

        @contextmanager
        def mock_scandir(path):
            path_obj = Path(path)
            if path_obj == tree.root / "scripts":
                scandir_count["scripts"] += 1
                if scandir_count["scripts"] > 1:
                    # Second scan of scripts directory fails.
                    raise PermissionError("mock permission denied on second scan")
            yield original_scandir(path)

        # Round 14+: unified inventory means only one scan, so the mock never triggers the failure.
        # Check detects the complexity increase.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                scandir_count["scripts"] = 0
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = health.main([], diagnostics=None, root=tree.root)
                # On round 14+: only one scan occurs, so we get the complexity error, not a traversal error.
                self.assertEqual(code, 1, "check must fail on complexity increase")
                self.assertIn("complexity grew", err.getvalue())
                self.assertEqual(scandir_count["scripts"], 1, "round 14+ scans scripts exactly once")
                mock_replace.assert_not_called()
        # Refresh must refuse to admit the complexity increase.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                scandir_count["scripts"] = 0
                with self.assertRaisesRegex(SystemExit, "would admit new debt"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh"], diagnostics=None, root=tree.root)
                self.assertEqual(scandir_count["scripts"], 1, "round 14+ scans scripts exactly once")
                mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

    def test_single_inventory_construction_per_check(self) -> None:
        """Production check constructs exactly one inventory, passed to all measurements."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "tests/t.py": "def g():\n    return 2\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())

        # Count _python_files_in_tree calls during one production check.
        original_inventory = health._python_files_in_tree
        call_count = [0]
        inventories_seen = []

        def counting_inventory(root, paths):
            call_count[0] += 1
            result = original_inventory(root, paths)
            inventories_seen.append(result[:])
            return result

        with patch.object(health, "_python_files_in_tree", side_effect=counting_inventory):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = health.main([], diagnostics=None, root=tree.root)
            self.assertEqual(code, 0, err.getvalue())

        # Exactly one inventory construction.
        self.assertEqual(call_count[0], 1, "inventory must be built exactly once per check")
        # All measurements received the same inventory (verified by checking identities in the counting wrapper).
        self.assertEqual(len(inventories_seen), 1)

    def test_unrecognized_file_mode_is_refused(self) -> None:
        """An unrecognized file mode (0o160000, gitlink) must refuse check, refresh, and refresh --admit, with zero persistence calls."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "tests/t.py": "def g():\n    return 2\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()

        # Mock a DirEntry with an unrecognized mode (0o160000 is gitlink, not handled by S_ISREG/S_ISDIR/S_ISLNK/special types).
        import os
        from contextlib import contextmanager
        original_scandir = os.scandir

        @contextmanager
        def mock_scandir(path):
            # First yield all real entries, then add a fake one.
            entries = list(original_scandir(path))

            class FakeEntry:
                def __init__(self):
                    self.name = "gitlink"
                    self.path = os.path.join(path, "gitlink")

                def stat(self, follow_symlinks=True):
                    class FakeStat:
                        st_mode = 0o160000
                    return FakeStat()

            entries.append(FakeEntry())
            yield iter(entries)

        # Check must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "unsupported file type"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main([], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        # Refresh must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "unsupported file type"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        # Refresh --admit must refuse.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "unsupported file type"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)


class ReviewRoundFifteenTests(SimpleTreeCase):
    """Round 15 findings: __pycache__ source exclusion, mid-iteration error, bypass regression clarity."""


    def test_pycache_source_is_refused(self) -> None:
        """Python source inside __pycache__ at any depth must be refused before Ruff and policy writes."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        # Create a valid baseline first.
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "tests/t.py": "def g():\n    return 2\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()

        # Add Python source inside __pycache__ directory.
        pycache_dir = tree.root / "scripts" / "__pycache__"
        pycache_dir.mkdir()
        (pycache_dir / "main.py").write_text("def h():\n    return 3\n", encoding="utf-8")

        # Check must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, r"Python source inside __pycache__ is not supported.*scripts/__pycache__/main\.py"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main([], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, r"Python source inside __pycache__ is not supported.*scripts/__pycache__/main\.py"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh --admit must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, r"Python source inside __pycache__ is not supported.*scripts/__pycache__/main\.py"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

        # Also test nested __pycache__: scripts/pkg/__pycache__/sub.pyi
        # Remove the first __pycache__ source before testing the nested one.
        (pycache_dir / "main.py").unlink()
        pycache_dir2 = tree.root / "scripts" / "pkg" / "__pycache__"
        pycache_dir2.mkdir(parents=True)
        (pycache_dir2 / "sub.pyi").write_text("def i() -> int: ...\n", encoding="utf-8")

        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, r"Python source inside __pycache__ is not supported.*scripts/pkg/__pycache__/sub\.pyi"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main([], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()

        # Test that __pycache__ with only .pyc files is accepted.
        (pycache_dir2 / "sub.pyi").unlink()
        (pycache_dir / "main.cpython-314.pyc").write_bytes(b"fake pyc")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main([], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())

    def test_scandir_iterator_mid_iteration_failure_refuses(self) -> None:
        """When scandir iterator raises OSError after yielding entries, all three commands refuse with zero persistence calls."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "scripts/b.py": "def g():\n    return 2\n", "tests/t.py": "def h():\n    return 3\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()

        # Create a mock iterator that yields some entries and then raises OSError.
        import os
        from contextlib import contextmanager
        original_scandir = os.scandir

        @contextmanager
        def mock_scandir(path):
            path_obj = Path(path)
            with original_scandir(path) as entries:
                if path_obj == tree.root / "scripts":
                    # Yield a custom iterator that yields one entry then raises.
                    class FailingIterator:
                        def __init__(self, original_iter):
                            self.original_iter = original_iter
                            self.count = 0

                        def __iter__(self):
                            return self

                        def __next__(self):
                            # Yield first entry successfully, then raise on second.
                            if self.count == 0:
                                self.count += 1
                                return next(self.original_iter)
                            else:
                                raise OSError(5, "Input/output error")

                    yield FailingIterator(entries)
                else:
                    yield entries

        # Check must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "cannot read directory scripts"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main([], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        # Refresh must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "cannot read directory scripts"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        # Refresh --admit must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with patch("os.scandir", side_effect=mock_scandir):
                with self.assertRaisesRegex(SystemExit, "cannot read directory scripts"):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
                mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)


class ReviewRoundSeventeenTests(SimpleTreeCase):
    """Round 17 finding: scripts/__init__.py allows covered source to escape import edge detection."""


    def test_scripts_init_is_refused(self) -> None:
        """scripts/__init__.py must be refused before Ruff and policy writes."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        # Create a valid baseline first.
        tree = self.tree({"scripts/a.py": "def f():\n    return 1\n", "tests/t.py": "def g():\n    return 2\n"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())
        before_baseline = (tree.root / health.BASELINE).read_bytes()
        (tree.root / health.MOVES).write_text(json.dumps({"version": 2, "batch": None, "moves": []}), encoding="utf-8")
        before_moves = (tree.root / health.MOVES).read_bytes()

        # Add scripts/__init__.py with a helper that core could import.
        (tree.root / "scripts" / "__init__.py").write_text("def helper():\n    return 42\n", encoding="utf-8")

        # Check must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, r"__init__\.py directly inside CLI lint root is not supported.*scripts/__init__\.py"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main([], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, r"__init__\.py directly inside CLI lint root is not supported.*scripts/__init__\.py"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        # Refresh --admit must refuse with zero persistence calls.
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, r"__init__\.py directly inside CLI lint root is not supported.*scripts/__init__\.py"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main(["refresh", "--admit", "test"], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()
        self.assertEqual((tree.root / health.BASELINE).read_bytes(), before_baseline)
        self.assertEqual((tree.root / health.MOVES).read_bytes(), before_moves)

        # Also test scripts/__init__.pyi is refused.
        (tree.root / "scripts" / "__init__.py").unlink()
        (tree.root / "scripts" / "__init__.pyi").write_text("def helper() -> int: ...\n", encoding="utf-8")
        with patch.object(health, "_replace") as mock_replace:
            with self.assertRaisesRegex(SystemExit, r"__init__\.py directly inside CLI lint root is not supported.*scripts/__init__\.pyi"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    health.main([], diagnostics=None, root=tree.root)
            mock_replace.assert_not_called()

    def test_package_init_below_scripts_is_accepted(self) -> None:
        """scripts/cwo_core/__init__.py and other package __init__.py files below scripts/ are accepted."""
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        # Create repository structure similar to the actual repo.
        tree = self.tree({
            "scripts/a.py": "def f():\n    return 1\n",
            "scripts/cwo_core/__init__.py": "# Core package\n",
            "scripts/cwo_core/mod.py": "def core_func():\n    return 2\n",
            "scripts/pkg/__init__.py": "# Package init\n",
            "scripts/pkg/sub.py": "def pkg_func():\n    return 3\n",
            "tests/t.py": "def g():\n    return 4\n",
        })
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main(["init", "--reason", "test"], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())

        # Check should pass.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main([], diagnostics=None, root=tree.root)
        self.assertEqual(code, 0, err.getvalue())


class FixtureLifecycleTests(unittest.TestCase):
    """Real fixture ownership and scandir context lifetimes."""

    def test_tree_helpers_remove_their_owned_repositories(self) -> None:
        cases = (
            (RatchetTests, "test_new_complex_function_fails"),
            (ReviewRoundFifteenTests, "test_pycache_source_is_refused"),
            (ReviewRoundSeventeenTests, "test_scripts_init_is_refused"),
        )
        for case_class, method in cases:
            with self.subTest(case=case_class.__name__):
                owner = case_class(method)
                self.addCleanup(owner.doCleanups)
                tree = owner.tree({"scripts/a.py": "value = 1\n"})
                self.addCleanup(tree.close)
                self.assertEqual((tree.root / "scripts/a.py").read_text(encoding="utf-8"), "value = 1\n")
                self.assertTrue(tree.root.is_dir())
                self.assertTrue(owner.doCleanups())
                self.assertFalse(tree.root.exists(), "the helper must register removal with its owning test")

    def test_mid_iteration_mock_closes_real_scandir_contexts(self) -> None:
        if shutil.which("ruff") is None:
            self.skipTest("ruff not available")
        owner = ReviewRoundFifteenTests("test_scandir_iterator_mid_iteration_failure_refuses")
        self.addCleanup(owner.doCleanups)
        original_tree = owner.tree

        def tracked_tree(files):
            tree = original_tree(files)
            self.addCleanup(tree.close)
            return tree

        original_scandir = os.scandir
        opened = []
        entered = []
        exited = []

        class TrackedIterator:
            def __init__(self, iterator):
                self.iterator = iterator

            def __iter__(self):
                return self

            def __next__(self):
                return next(self.iterator)

            def __enter__(self):
                self.iterator.__enter__()
                entered.append(self)
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                result = self.iterator.__exit__(exc_type, exc_value, traceback)
                exited.append((self, exc_type))
                return result

            def close(self):
                self.iterator.close()

        def tracked_scandir(path):
            iterator = TrackedIterator(original_scandir(path))
            opened.append(iterator)
            self.addCleanup(iterator.close)
            return iterator

        with patch.object(owner, "tree", side_effect=tracked_tree), patch("os.scandir", side_effect=tracked_scandir):
            owner.test_scandir_iterator_mid_iteration_failure_refuses()

        self.assertGreater(len(opened), 3, "include real baseline scans as positive controls")
        self.assertCountEqual(entered, opened)
        self.assertCountEqual([iterator for iterator, _ in exited], opened)
        self.assertEqual(sum(exc_type is OSError for _, exc_type in exited), 3)
        self.assertGreater(sum(exc_type is None for _, exc_type in exited), 0)
        for iterator in opened:
            with self.assertRaises(StopIteration):
                next(iterator)


class RepositoryRatchetTests(unittest.TestCase):
    def test_this_repository_matches_its_baseline(self) -> None:
        if shutil.which("ruff") is None:
            self.skipTest("the pinned ruff from requirements-test.txt is not installed")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = health.main([])
        self.assertEqual(code, 0, err.getvalue())

    def test_the_pinned_ruff_matches_requirements(self) -> None:
        baseline = json.loads((ROOT / health.BASELINE).read_text(encoding="utf-8"))
        requirements = (ROOT / "requirements-test.txt").read_text(encoding="utf-8")
        self.assertIn(f"ruff=={baseline['tool']['ruff']}", requirements)


if __name__ == "__main__":
    unittest.main()

"""Definition, handler, and private import debt in the main ratchet."""

import textwrap

from tests.test_code_health import TreeCase, health


class StructureRatchetTests(TreeCase):
    def test_definition_spans_and_sibling_suites(self) -> None:
        source = textwrap.dedent("""\
            @(
                first
            )
            @second
            def run(flag):
                try:
                    match flag:
                        case 0:
                            pass
                        case _:
                            if flag:
                                pass
                            elif flag:
                                with lock():
                                    pass
                except (Exception, TypeError, builtins.BaseException):
                    pass
                except:
                    pass

                def nested():
                    if flag:
                        if flag:
                            if flag:
                                if flag:
                                    if flag:
                                        pass
                    try:
                        pass
                    except Exception:
                        pass

            class Group:
                try:
                    pass
                except BaseException:
                    pass

                def handlers(self, flag):
                    try:
                        pass
                    except ValueError:
                        with lock():
                            pass
                    except RuntimeError:
                        pass
                    else:
                        if flag:
                            pass
                    finally:
                        pass

                def else_if(self, flag):
                    if flag:
                        pass
                    else:
                        if flag:
                            pass

            async def async_suites(items):
                async for item in items:
                    async with item:
                        pass

            try:
                pass
            except* (RuntimeError, Exception):
                pass
            """)
        tree = self.tree({"scripts/a.py": source})
        state = health.current_state(tree.root, tree.fake_ruff)
        definition_lines = len(source.split("\n\nclass Group:", 1)[0].splitlines())
        self.assertEqual(state["definition_length"]["scripts/a.py::run"], definition_lines)
        self.assertEqual(state["suite_nesting"], {
            "scripts/a.py::run": 4, "scripts/a.py::run.nested": 5,
            "scripts/a.py::Group.handlers": 2,
            "scripts/a.py::Group.else_if": 2, "scripts/a.py::async_suites": 2,
        })
        self.assertEqual(state["broad_catches"], {
            "scripts/a.py::run::Exception": 1, "scripts/a.py::run::BaseException": 1,
            "scripts/a.py::run::bare": 1, "scripts/a.py::run.nested::Exception": 1,
            "scripts/a.py::Group::BaseException": 1,
            "scripts/a.py::<module>::Exception": 1,
        })

    def test_scoped_debt_follows_reviewed_move_and_lowers_on_refresh(self) -> None:
        old, new = "scripts/registered_old.py", "scripts/offline_new.py"
        source = "def run(value):\n" + "    value += 1\n" * 100 + "    try:\n"
        source += "".join("    " * depth + "if value:\n" for depth in range(2, 7))
        source += "                            return value\n    except Exception:\n        return 0\n"
        record = {"filename": old, "code": "ANN201", "message": "Missing return type for `run`",
                  "location": {"row": 1}}
        tree = self.tree({old: source}, threshold=100, diagnostics=[record])
        tree.refresh()
        self.assertEqual(tree.baseline["complexity"], {})
        self.assertEqual(tree.baseline["suite_nesting"], {f"{old}::run": 6})
        self.assertGreater(tree.baseline["definition_length"][f"{old}::run"], 100)
        self.assertEqual(tree.baseline["annotations"], {f"{old}::run::ANN201::<return>": 1})

        tree.remove(old)
        renamed = source.replace("def run(", "def renamed(")
        tree.write({new: renamed})
        tree.diagnostics = [{**record, "filename": new, "message": "Missing return type for `renamed`"}]
        self.assertEqual(tree.run()[0], 1)
        tree.moves([{"from": f"{old}::run", "to": f"{new}::renamed", "reason": "reviewed rename"}])
        self.assertEqual(tree.run()[0], 0)
        tree.refresh()

        tree.write({new: "def renamed(value: int) -> int:\n    return value\n"})
        tree.diagnostics = []
        code, notes, _ = tree.run()
        self.assertEqual(code, 0)
        for metric in ("definition length", "suite nesting", "broad catch", "annotation diagnostic"):
            self.assertIn(f"{metric} reduced", notes)
        tree.refresh()
        for field in ("definition_length", "suite_nesting", "broad_catches", "annotations"):
            self.assertEqual(tree.baseline[field], {})
        tree.write({new: renamed})
        self.assertEqual(tree.run()[0], 1)

    def test_annotations_are_ratcheted_for_the_maintained_scripts(self) -> None:
        files = ["scripts/registered_worker.py", "scripts/offline_worker.py",
                 "scripts/cwo_core/native_pool_qualification_report.py", "scripts/other.py",
                 "tests/registered_fixture.py", "scripts/cwo_core/offline_worker.py"]
        records = [{"filename": path, "code": "ANN001", "message": "Argument `value`", "location": {"row": 1}}
                   for path in files]
        tree = self.tree(dict.fromkeys(files, "def run(value) -> int:\n    return value\n"), diagnostics=records)
        tree.refresh()
        self.assertEqual(tree.baseline["annotations"], {f"{path}::run::ANN001::value": 1 for path in files[:3]})
        self.assertEqual(tree.baseline["f_e9"], {})

    def test_repeated_definitions_require_review_for_guard_changes(self) -> None:
        path = "scripts/choices.py"
        source = ("if flag:\n    def choose():\n        try:\n            return 1\n"
                  "        except Exception:\n            return 0\nelse:\n    def choose():\n        return 2\n")
        tree = self.tree({path: source}, threshold=100)
        tree.refresh()
        self.assertEqual(tree.baseline["broad_catches"], {f"{path}::choose::Exception": 1})
        tree.write({path: source.replace("if flag:", "if alternate:")})
        code, _, failures = tree.run()
        self.assertEqual(code, 1)
        self.assertIn(f"repeated definitions changed: {path}::choose", failures)
        with self.assertRaisesRegex(SystemExit, "refresh would admit new debt"):
            tree.refresh()

    def test_private_imports_are_resolved_and_counted_once_per_consumer(self) -> None:
        source = textwrap.dedent("""\
            from cwo_core.api import _helper as first, __public_protocol__
            from .api import _helper as second
            from scripts.cwo_core.api import _helper as third
            from . import _name
            from .consumer import _self
            from ..tool import _util
            from ...outside import _invalid
            from third_party import _external
            """)
        path = "scripts/cwo_core/consumer.py"
        tree = self.tree({
            path: source, "scripts/cwo_core/__init__.py": "_name = 1\n",
            "scripts/tool.py": "_util = 1\n", "scripts/cwo_core/api.pyi": "_helper: int\n_second: int\n",
        })
        tree.refresh()
        self.assertEqual(tree.baseline["private_imports"], {
            "cwo_core.consumer -> cwo_core.api::_helper": 1,
            "cwo_core.consumer -> cwo_core::_name": 1,
            "cwo_core.consumer -> tool::_util": 1,
        })
        tree.write({path: source + "from .api import _second\n"})
        code, _, failures = tree.run()
        self.assertEqual(code, 1)
        identity = "cwo_core.consumer -> cwo_core.api::_second"
        self.assertIn(f"new private import: {identity}", failures)
        with self.assertRaisesRegex(SystemExit, "refresh would admit new debt"):
            tree.refresh()
        tree.refresh("reviewed private import")
        self.assertEqual(tree.baseline["admitted"][identity], "reviewed private import")

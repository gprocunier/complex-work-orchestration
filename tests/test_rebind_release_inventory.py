"""Mechanical release rebinding on disposable sources, without review decisions."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cwo_core import release_effect_routes as R

COMMAND = ROOT / "tools/rebind_release_inventory.py"
MANIFEST = "tests/fixtures/affected_contract_compatibility/EXAMPLE-manifest.json"


class RebindReleaseInventoryTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        sources = {
            "scripts/example.py": (
                "import subprocess\n\n"
                "def decorate(fn):\n    return fn\n\n"
                "@decorate\nasync def run(allowed, effects):\n"
                "    if not allowed:\n        raise ValueError('held')\n"
                "    note = 'before'\n"
                "    effects.append(\n        note\n    )\n"
                "    return note\n\n"
                "def primitive():\n    subprocess.run(['EXAMPLE'], check=True)\n"),
            "scripts/other.py": "def run():\n    return 'other'\n",
            "scripts/trace_only.py": "value = 1\n",
            "tests/test_example.py": (
                "def support():\n    return 1\n\n"
                "class ExampleTests:\n"
                "    def test_pair(self):\n"
                "        assert not []\n        assert [1]\n"),
            "references/example.txt": "prefix: safe suffix\n",
        }
        for name, text in sources.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        files, contents = R.source(root)
        manifest = {"files": {path: row["sha256"] for path, row in files.items()},
                    "current_file_modes": {path: row["mode"] for path, row in files.items()},
                    "historical_files": {"EXAMPLE-archived": {"archive.py": "0" * 64}}}
        path = root / MANIFEST
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        files[MANIFEST] = R.read_file(root, MANIFEST)[1]
        point_files = ["scripts/example.py", "scripts/other.py", "tests/test_example.py",
                       "references/example.txt"]
        points = {"guard": [0, 8, "if not allowed:"],
                  "effect": [0, 11, "effects.append(\n        note\n    )", 4, 13, 5],
                  "unused-span": [3, 1, "safe", 8, 1, 12]}
        for key, index, symbol in (("entry", 0, "run"), ("other", 1, "run"),
                                   ("test", 2, "ExampleTests.test_pair"),
                                   ("support", 2, "support"), ("unused-declaration", 0, "decorate")):
            declaration, _text = R.body(contents, {"path": point_files[index], "symbol": symbol})
            points[key] = [index, symbol, declaration["line"], declaration["sha256"]]
        witness = {"body": "test", "support": ["support"],
                   "test_id": "tests.test_example.ExampleTests.test_pair",
                   "kind": "operator-contract", "assertion": "assert not []", "positive": "assert [1]"}
        contract = {"entrypoint": "entry", "admission": "manual-program", "authority": "EXAMPLE only",
                    "effect": "disposable list append", "gates": ["guard"], "effect_points": ["effect"],
                    "witnesses": ["pair"], "manual_decisions": [], "ordering": "EXAMPLE direct call",
                    "limits": "EXAMPLE only", "trace_files": ["scripts/example.py"]}
        hits = [hit + [["exclude", "EXAMPLE-exclusion"]] for hit in R.primitive_hits(contents)]
        inventory = {"schema": "compact-release-routes-v1", "source_bindings": files,
                     "point_files": point_files, "points": points, "contracts": {"EXAMPLE": contract},
                     "witnesses": {"pair": witness}, "manual_decisions": {},
                     "routes": [{"id": "EXAMPLE-A", "contract": "EXAMPLE", "entrypoint": "entry"},
                                {"id": "EXAMPLE-B", "contract": "EXAMPLE", "entrypoint": "entry",
                                 "trace_files": ["scripts/example.py", "scripts/trace_only.py"]},
                                {"id": "EXAMPLE-C", "contract": "EXAMPLE", "entrypoint": "other",
                                 "gates": [], "effect_points": [], "trace_files": ["scripts/other.py"]}],
                     "primitive_coverage": {"schema": "bounded-primitives-v1", "hits": hits,
                                            "exclusions": {"EXAMPLE-exclusion": {
                                                "reason": "inert fixture", "conclusion": "never executed"}}}}
        (root / "policy").mkdir()
        (root / R.INVENTORY).write_bytes(R.encoded(inventory) + b"\n")
        R.trace(root)
        return root, inventory, manifest

    def run_rebind(self, root):
        return subprocess.run([sys.executable, "-B", str(COMMAND), "--root", str(root)],
                              cwd=root, capture_output=True, text=True, timeout=20)

    def bindings_snapshot(self, root):
        return {name: ((root / name).read_bytes(), (root / name).stat().st_mtime_ns)
                for name in (R.INVENTORY, MANIFEST)}

    def assert_refuses_untouched(self, root, *messages):
        before = self.bindings_snapshot(root)
        result = self.run_rebind(root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for message in messages:
            self.assertIn(message, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(self.bindings_snapshot(root), before)

    def test_refreshes_all_bindings_manifest_and_affected_routes_then_noops(self):
        root, original, old_manifest = self.fixture()
        source = root / "scripts/example.py"
        source.write_text(source.read_text().replace("note = 'before'", "note = 'after edit'"))
        source.chmod(0o755)
        result = self.run_rebind(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads((root / R.INVENTORY).read_bytes())
        manifest = json.loads((root / MANIFEST).read_bytes())
        self.assertNotEqual(manifest["files"]["scripts/example.py"], old_manifest["files"]["scripts/example.py"])
        self.assertEqual(manifest["historical_files"], old_manifest["historical_files"])
        self.assertEqual(manifest["current_file_modes"]["scripts/example.py"], 0o755)
        self.assertEqual(value["source_bindings"][MANIFEST], R.read_file(root, MANIFEST)[1])
        self.assertNotEqual(value["source_bindings"][MANIFEST], original["source_bindings"][MANIFEST])
        files, contents = R.source(root)
        self.assertEqual(value["source_bindings"], {name: files[name] for name in value["source_bindings"]})
        for key, row in value["points"].items():
            point = R._table_point(value, key)
            if isinstance(row[1], str):
                self.assertEqual(point, R.body(contents, point)[0])
        self.assertEqual(value["points"]["entry"][2], 6, "decorator belongs to the declaration")
        self.assertNotEqual(value["points"]["entry"], original["points"]["entry"])
        self.assertEqual(value["primitive_coverage"], original["primitive_coverage"])
        self.assertIn("source_bindings scripts/example.py", result.stdout)
        self.assertIn("source_bindings " + MANIFEST, result.stdout)
        self.assertIn("checkpoint files scripts/example.py", result.stdout)
        self.assertIn("checkpoint current_file_modes scripts/example.py", result.stdout)
        self.assertIn("declaration entry scripts/example.py:run", result.stdout)
        self.assertIn("affected route EXAMPLE-A: scripts/example.py", result.stdout)
        self.assertIn("affected route EXAMPLE-B: scripts/example.py", result.stdout)
        self.assertNotIn("affected route EXAMPLE-C", result.stdout)
        self.assertEqual((root / R.INVENTORY).read_bytes(), R.encoded(value) + b"\n")
        self.assertEqual((root / MANIFEST).read_text(), json.dumps(manifest, indent=2) + "\n")
        R.trace(root)
        before = self.bindings_snapshot(root)
        second = self.run_rebind(root)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(second.stdout, "No bindings changed.\n")
        self.assertEqual(self.bindings_snapshot(root), before)

    def test_moved_line_span_names_point_and_writes_neither_file(self):
        root, _value, _manifest = self.fixture()
        source = root / "scripts/example.py"
        source.write_text(source.read_text().replace(
            "    if not allowed:\n        raise ValueError('held')\n    note = 'before'\n",
            "    note = 'before'\n    if not allowed:\n        raise ValueError('held')\n"))
        self.assert_refuses_untouched(root, "guard", "scripts/example.py:8")

    def test_compact_hit_rebind_preserves_layout_decisions_and_idempotence(self):
        for indent in (None, 2):
            with self.subTest(indent=indent):
                root, value, _manifest = self.fixture()
                coverage = value["primitive_coverage"]
                coverage.update(schema="bounded-primitives-v2", paths=["scripts/example.py"])
                coverage["hits"] = [[0, *row[1:]] for row in coverage["hits"]]
                raw = json.dumps(value, indent=indent, separators=(",", ":") if indent is None else None) + "\n"
                (root / R.INVENTORY).write_text(raw)
                source = root / "scripts/other.py"
                source.write_text(source.read_text().replace("'other'", "'other edited'"))
                result = self.run_rebind(root)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                after = json.loads((root / R.INVENTORY).read_bytes())
                self.assertEqual(after["primitive_coverage"], coverage)
                rendered = json.dumps(after, indent=indent, separators=(",", ":") if indent is None else None) + "\n"
                self.assertEqual((root / R.INVENTORY).read_text(), rendered)
                self.assertEqual(R.trace(root)["primitive_hits"], [
                    [coverage["paths"][row[0]], *row[1:7]] for row in coverage["hits"]])
                before = self.bindings_snapshot(root)
                result = self.run_rebind(root)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout, "No bindings changed.\n")
                self.assertEqual(self.bindings_snapshot(root), before)

    def test_malformed_compact_hits_rebind_writes_neither_file(self):
        for malformed in ("bool-index", "duplicate-path", "duplicate-hit"):
            with self.subTest(malformed=malformed):
                root, value, _manifest = self.fixture()
                coverage = value["primitive_coverage"]
                coverage.update(schema="bounded-primitives-v2", paths=["scripts/example.py"])
                coverage["hits"] = [[0, *row[1:]] for row in coverage["hits"]]
                if malformed == "bool-index":
                    coverage["hits"][0][0] = False
                    message = "primitive path index"
                elif malformed == "duplicate-path":
                    coverage["paths"].append(coverage["paths"][0])
                    message = "duplicate primitive path"
                else:
                    coverage["hits"].append(coverage["hits"][0])
                    message = "primitive hit coverage mismatch"
                (root / R.INVENTORY).write_bytes(R.encoded(value) + b"\n")
                source = root / "scripts/other.py"
                source.write_text(source.read_text().replace("'other'", "'changed'"))
                self.assert_refuses_untouched(root, message)

    def test_moved_multiline_column_span_names_point_and_writes_neither_file(self):
        root, _value, _manifest = self.fixture()
        source = root / "scripts/example.py"
        source.write_text(source.read_text().replace("    effects.append(", "    (effects.append("))
        source.write_text(source.read_text().replace("    )\n", "    ))\n"))
        self.assert_refuses_untouched(root, "effect", "scripts/example.py:11:4")

    def test_even_unreferenced_column_spans_are_checked(self):
        root, _value, _manifest = self.fixture()
        (root / "references/example.txt").write_text("prefix:  safe suffix\n")
        self.assert_refuses_untouched(root, "unused-span", "references/example.txt:1:8")

    def test_missing_symbol_names_point_and_writes_neither_file(self):
        root, _value, _manifest = self.fixture()
        source = root / "scripts/example.py"
        source.write_text(source.read_text().replace("async def run(", "async def renamed("))
        self.assert_refuses_untouched(root, "entry", "scripts/example.py:6", "run")

    def test_new_or_changed_primitive_candidates_require_explicit_decisions(self):
        for old, new in (("return note", "return subprocess.run(['new'])"),
                         ("['EXAMPLE']", "['CHANGED']")):
            with self.subTest(new=new):
                root, _value, _manifest = self.fixture()
                source = root / "scripts/example.py"
                source.write_text(source.read_text().replace(old, new))
                self.assert_refuses_untouched(root, "primitive hit coverage mismatch")

    def test_refreshes_moved_declarations_and_unreferenced_declaration_hashes(self):
        root, original, _manifest = self.fixture()
        witness = root / "tests/test_example.py"
        witness.write_text("\n" + witness.read_text())
        source = root / "scripts/example.py"
        source.write_text(source.read_text().replace("return fn", "return (fn)"))
        result = self.run_rebind(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads((root / R.INVENTORY).read_bytes())
        for key in ("test", "support"):
            self.assertEqual(value["points"][key][2], original["points"][key][2] + 1)
            self.assertEqual(value["points"][key][3], original["points"][key][3])
            self.assertIn(f"declaration {key} tests/test_example.py:", result.stdout)
        self.assertNotEqual(value["points"]["unused-declaration"][3], original["points"]["unused-declaration"][3])
        self.assertIn("declaration unused-declaration scripts/example.py:decorate", result.stdout)
        R.trace(root)

    def test_routes_include_shared_witness_support_and_trace_only_files(self):
        for path, old, new, expected in (
            ("tests/test_example.py", "return 1", "return 2", {"EXAMPLE-A", "EXAMPLE-B", "EXAMPLE-C"}),
            ("scripts/trace_only.py", "value = 1", "value = 2", {"EXAMPLE-B"}),
        ):
            with self.subTest(path=path):
                root, _value, _manifest = self.fixture()
                source = root / path
                source.write_text(source.read_text().replace(old, new))
                result = self.run_rebind(root)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                affected = {line.split(":", 1)[0].removeprefix("affected route ")
                            for line in result.stdout.splitlines() if line.startswith("affected route ")}
                self.assertEqual(affected, expected)
                R.trace(root)


if __name__ == "__main__":
    unittest.main()

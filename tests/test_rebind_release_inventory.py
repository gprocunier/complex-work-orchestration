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
                    "registered_source_callers": {
                        path: files[path]["sha256"]
                        for path in ("scripts/example.py", "scripts/other.py",
                                     "tests/test_example.py", "references/example.txt")},
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
        (root / R.INVENTORY).write_bytes(R.inventory_bytes(inventory))
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

    def test_inventory_layout_is_record_per_line_and_refuses_other_layouts(self):
        root, value, _manifest = self.fixture()
        path = root / R.INVENTORY
        original = path.read_bytes()
        self.assertEqual(R.inventory(root)[0], value)
        for label, raw in (
            ("one-line", R.encoded(value) + b"\n"),
            ("indented", (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()),
            ("extra-newline", original + b"\n"),
            ("missing-newline", original.rstrip(b"\n")),
            ("crlf", original.replace(b"\n", b"\r\n")),
        ):
            with self.subTest(layout=label):
                path.write_bytes(raw)
                with self.assertRaisesRegex(R.Refused, "canonical inventory layout"):
                    R.inventory(root)
                self.assert_refuses_untouched(root, "canonical inventory layout")
        path.write_bytes(original)
        self.assertGreater(len(original.splitlines()), 20)
        self.assertTrue(all(not line.startswith(b" ") for line in original.splitlines()))
        R.trace(root)

    def test_compact_source_bindings_preserve_identity_and_rebind_noop(self):
        root, value, _manifest = self.fixture()
        legacy = R.inventory_bytes(value)
        expected = json.loads(json.dumps(value['source_bindings']))
        value['source_binding_columns'] = ['sha256', 'mode', 'size']
        compact = R.inventory_bytes(value)
        row = json.loads(compact)['source_bindings']['scripts/example.py']
        self.assertEqual(row, [expected['scripts/example.py'][key] for key in value['source_binding_columns']])
        self.assertLess(len(compact), len(legacy))
        (root / R.INVENTORY).write_bytes(compact)
        self.assertEqual(R.inventory(root)[0]['source_bindings'], expected)
        source = root / 'scripts/example.py'
        source.write_bytes(source.read_bytes() + b'\n# EXAMPLE binding layout control\n')
        result = self.run_rebind(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rebound = R.inventory(root)[0]
        files, _contents = R.source(root)
        self.assertEqual(rebound['source_bindings'], {path: files[path] for path in expected})
        before = self.bindings_snapshot(root)
        result = self.run_rebind(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'No bindings changed.\n')
        self.assertEqual(self.bindings_snapshot(root), before)
        R.trace(root)

    def test_compact_source_binding_columns_and_rows_refuse_malformed_identity(self):
        root, value, _manifest = self.fixture()
        columns = ['sha256', 'mode', 'size']
        row = value['source_bindings']['scripts/example.py']
        valid = [row[key] for key in columns]
        for declared, changed in ((None, valid), (list(reversed(columns)), valid),
                (columns, valid[:2]), (columns, valid + [0]),
                (columns, ['invalid', *valid[1:]]), (columns, [valid[0], True, valid[2]]),
                (columns, [*valid[:2], False]), (columns, [*valid[:2], -1])):
            with self.subTest(columns=declared, row=changed):
                bad = json.loads(json.dumps(value))
                bad['source_binding_columns'] = declared
                bad['source_bindings']['scripts/example.py'] = changed
                (root / R.INVENTORY).write_bytes(R._inventory_sections(bad) + b'\n')
                with self.assertRaisesRegex(R.Refused, 'source binding'):
                    R.inventory(root)
                self.assert_refuses_untouched(root, 'source binding')

    def test_independent_script_rebinds_merge_in_git_and_validate(self):
        root, value, manifest = self.fixture()
        # These scripts are independently bound, outside the checkpoint roster.
        # A shared checkpoint hash would be a genuinely overlapping record.
        paths = ("scripts/other.py", "scripts/trace_only.py")
        for path in paths:
            del manifest["files"][path]
            del manifest["current_file_modes"][path]
            manifest["registered_source_callers"].pop(path, None)
        (root / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        value["source_bindings"][MANIFEST] = R.read_file(root, MANIFEST)[1]
        (root / R.INVENTORY).write_bytes(R.inventory_bytes(value))
        self.git(root, "init", "--initial-branch=base")
        self.git(root, "config", "user.name", "Example Maintainer")
        self.git(root, "config", "user.email", "example@example.invalid")
        self.git(root, "config", "commit.gpgsign", "false")
        self.git(root, "add", ".")
        self.git(root, "commit", "-m", "Initial example")
        for branch, path in zip(("first", "second"), paths):
            self.git(root, "checkout", "-b", branch, "base")
            source = root / path
            source.write_text(source.read_text() + f"\n# independent edit to {path}\n")
            result = self.run_rebind(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", f"Edit {path}")
        self.git(root, "checkout", "base")
        self.git(root, "merge", "--no-edit", "first")
        self.git(root, "merge", "--no-edit", "second")
        self.assertEqual(self.git(root, "status", "--porcelain"), "")
        self.assertEqual(len(R.trace(root)["routes"]), 3)
        result = self.run_rebind(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "No bindings changed.\n")

    def test_independent_map_entries_and_route_rows_have_separate_lines(self):
        root, value, _manifest = self.fixture()
        lines = {line.removesuffix(b",") for line in (root / R.INVENTORY).read_bytes().splitlines()}
        for key in ("contracts", "points", "witnesses", "manual_decisions", "source_bindings"):
            for name, record in value[key].items():
                self.assertIn(R.encoded(name) + b":" + R.encoded(record), lines)
        coverage = value["primitive_coverage"]
        for name, record in coverage["exclusions"].items():
            self.assertIn(R.encoded(name) + b":" + R.encoded(record), lines)
        for record in value["routes"] + coverage["hits"] + value["point_files"]:
            self.assertIn(R.encoded(record), lines)

    def test_inventory_growth_over_cap_writes_neither_file(self):
        root, value, _manifest = self.fixture()
        value["capacity_example"] = ""
        value["capacity_example"] = "x" * (R.MAX_INVENTORY - len(R.inventory_bytes(value)))
        path = root / R.INVENTORY
        path.write_bytes(R.inventory_bytes(value))
        self.assertEqual(path.stat().st_size, R.MAX_INVENTORY)
        R.trace(root)
        source = root / "scripts/other.py"
        source.write_text("def run():\n    return " + repr("x" * 1000) + "\n")
        self.assert_refuses_untouched(root, "inventory byte limit exceeded")

    def test_reordered_sections_entries_and_keys_within_records_refuse(self):
        root, value, _manifest = self.fixture()
        path = root / R.INVENTORY
        original = path.read_bytes()
        section = b'"schema":"compact-release-routes-v1",\n\n'
        reordered = original.replace(section, b"").replace(b"{\n", b"{\n" + section, 1)
        entries = original.splitlines(keepends=True)
        first = next(i for i, line in enumerate(entries) if line.startswith(b'"scripts/example.py":'))
        second = next(i for i, line in enumerate(entries) if line.startswith(b'"scripts/other.py":'))
        entries[first], entries[second] = entries[second], entries[first]
        for raw in (reordered, b"".join(entries)):
            path.write_bytes(raw)
            self.assertEqual(json.loads(path.read_bytes()), value)
            self.assert_refuses_untouched(root, "canonical inventory layout")
        for record in (value["source_bindings"]["scripts/other.py"], value["routes"][0]):
            reordered = {key: record[key] for key in sorted(record, reverse=True)}
            raw = json.dumps(reordered, separators=(",", ":")).encode()
            changed = original.replace(R.encoded(record), raw)
            self.assertNotEqual(changed, original)
            path.write_bytes(changed)
            self.assertEqual(json.loads(changed), value)
            self.assert_refuses_untouched(root, "canonical inventory layout")
        path.write_bytes(original)
        self.assertEqual(R.inventory(root)[0], value)
        R.trace(root)

    def git(self, root, *arguments):
        result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *arguments],
                                cwd=root, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

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
        self.assertEqual(manifest["registered_source_callers"], {
            path: manifest["files"][path] for path in old_manifest["registered_source_callers"]})
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
        self.assertIn("checkpoint registered_source_callers scripts/example.py", result.stdout)
        self.assertIn("declaration entry scripts/example.py:run", result.stdout)
        self.assertIn("affected route EXAMPLE-A: scripts/example.py", result.stdout)
        self.assertIn("affected route EXAMPLE-B: scripts/example.py", result.stdout)
        self.assertNotIn("affected route EXAMPLE-C", result.stdout)
        self.assertEqual((root / R.INVENTORY).read_bytes(), R.inventory_bytes(value))
        self.assertEqual((root / MANIFEST).read_text(), json.dumps(manifest, indent=2) + "\n")
        R.trace(root)
        before = self.bindings_snapshot(root)
        second = self.run_rebind(root)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(second.stdout, "No bindings changed.\n")
        self.assertEqual(self.bindings_snapshot(root), before)

    def test_refreshes_only_declared_registered_caller_hashes_then_noops(self):
        root, _value, original = self.fixture()
        caller = "scripts/other.py"
        source = root / caller
        source.write_text(source.read_text().replace("'other'", "'other edited'"))
        unregistered = "scripts/trace_only.py"
        (root / unregistered).write_text("value = 2\n")
        result = self.run_rebind(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = json.loads((root / MANIFEST).read_bytes())
        observed = R.read_file(root, caller)[1]["sha256"]
        self.assertEqual(manifest["registered_source_callers"][caller], observed)
        self.assertEqual(manifest["files"][caller], observed)
        self.assertEqual(set(manifest["registered_source_callers"]),
                         set(original["registered_source_callers"]))
        self.assertNotIn(unregistered, manifest["registered_source_callers"])
        self.assertEqual(set(manifest["files"]), set(original["files"]))
        self.assertEqual(manifest["historical_files"], original["historical_files"])
        self.assertIn("checkpoint registered_source_callers " + caller, result.stdout)
        R.trace(root)
        before = self.bindings_snapshot(root)
        second = self.run_rebind(root)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(second.stdout, "No bindings changed.\n")
        self.assertEqual(self.bindings_snapshot(root), before)

    def test_caller_outside_checkpoint_dependencies_refuses_without_writes(self):
        root, _value, manifest = self.fixture()
        caller = "scripts/other.py"
        del manifest["files"][caller]
        del manifest["current_file_modes"][caller]
        (root / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
        self.assertTrue((root / caller).is_file())
        self.assert_refuses_untouched(
            root, "checkpoint registered caller outside dependency roster: " + caller)

    def test_registered_callers_require_a_mapping_without_writes(self):
        for callers in (None, [], "EXAMPLE"):
            with self.subTest(callers=callers):
                root, _value, manifest = self.fixture()
                manifest["registered_source_callers"] = callers
                (root / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
                self.assert_refuses_untouched(root, "checkpoint registered caller mapping required")

    def test_absent_registered_caller_table_stays_absent(self):
        root, _value, manifest = self.fixture()
        del manifest["registered_source_callers"]
        (root / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
        result = self.run_rebind(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = json.loads((root / MANIFEST).read_bytes())
        self.assertNotIn("registered_source_callers", after)
        self.assertEqual(after, manifest)
        R.trace(root)

    def test_refreshes_stale_registered_caller_with_current_dependency_binding(self):
        root, _inventory, manifest = self.fixture()
        source = root / "scripts/example.py"
        source.write_text(source.read_text().replace("note = 'before'", "note = 'current caller'"))
        current = R.read_file(root, "scripts/example.py")[1]["sha256"]
        manifest["files"]["scripts/example.py"] = current
        (root / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
        result = self.run_rebind(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        updated = json.loads((root / MANIFEST).read_bytes())
        self.assertEqual(updated["registered_source_callers"]["scripts/example.py"], current)
        self.assertEqual(set(updated["registered_source_callers"]), set(manifest["registered_source_callers"]))
        self.assertEqual(updated["historical_files"], manifest["historical_files"])
        self.assertIn("checkpoint registered_source_callers scripts/example.py", result.stdout)
        R.trace(root)
        before = self.bindings_snapshot(root)
        second = self.run_rebind(root)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(second.stdout, "No bindings changed.\n")
        self.assertEqual(self.bindings_snapshot(root), before)

    def test_unbound_registered_caller_refuses_without_writing_bindings(self):
        root, _inventory, manifest = self.fixture()
        manifest["registered_source_callers"]["EXAMPLE-unbound.py"] = "0" * 64
        (root / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
        self.assert_refuses_untouched(root, "checkpoint registered caller outside dependency roster: EXAMPLE-unbound.py")

    def test_missing_registered_caller_refuses_without_writing_bindings(self):
        root, _inventory, _manifest = self.fixture()
        (root / "scripts/example.py").unlink()
        self.assert_refuses_untouched(root, "checkpoint source missing: scripts/example.py")

    def test_moved_line_span_names_point_and_writes_neither_file(self):
        root, _value, _manifest = self.fixture()
        source = root / "scripts/example.py"
        source.write_text(source.read_text().replace(
            "    if not allowed:\n        raise ValueError('held')\n    note = 'before'\n",
            "    note = 'before'\n    if not allowed:\n        raise ValueError('held')\n"))
        self.assert_refuses_untouched(root, "guard", "scripts/example.py:8")

    def test_compact_hit_rebind_preserves_layout_decisions_and_idempotence(self):
        for schema in ("bounded-primitives-v1", "bounded-primitives-v2"):
            with self.subTest(schema=schema):
                root, value, _manifest = self.fixture()
                coverage = value["primitive_coverage"]
                if schema == "bounded-primitives-v2":
                    coverage.update(schema=schema, paths=["scripts/example.py"])
                    coverage["hits"] = [[0, *row[1:]] for row in coverage["hits"]]
                (root / R.INVENTORY).write_bytes(R.inventory_bytes(value))
                source = root / "scripts/other.py"
                source.write_text(source.read_text().replace("'other'", "'other edited'"))
                result = self.run_rebind(root)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                after = json.loads((root / R.INVENTORY).read_bytes())
                self.assertEqual(after["primitive_coverage"], coverage)
                self.assertEqual((root / R.INVENTORY).read_bytes(), R.inventory_bytes(after))
                expected = [row[:7] for row in coverage["hits"]]
                if schema == "bounded-primitives-v2":
                    expected = [[coverage["paths"][row[0]], *row[1:7]] for row in coverage["hits"]]
                self.assertEqual(R.trace(root)["primitive_hits"], expected)
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
                (root / R.INVENTORY).write_bytes(R.inventory_bytes(value))
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

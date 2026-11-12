"""Small functioning EXAMPLE release; no real candidate acceptance is authored."""
import ast
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cwo_core import release_effect_routes as R


class ReleaseEffectRoutesTests(unittest.TestCase):
    def example(self, compact=False, admission="guarded-effect"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name) / "evidence"
        root, output = directory / "EXAMPLE-source", directory / "EXAMPLE-evidence"
        for relative in ("scripts", "tests", "policy"):
            (root / relative).mkdir(parents=True)
        (root / "scripts/__init__.py").write_text("")
        (root / "tests/__init__.py").write_text("")
        (root / "scripts/example.py").write_text(
            "def run(allowed, effects):\n"
            "    if not allowed:\n"
            "        raise ValueError('EXAMPLE held')\n"
            "    effects.append('EXAMPLE send')\n")
        test_id = "tests.test_example.ExampleTests.test_zero_and_positive"
        (root / "tests/test_example.py").write_text(
            "import unittest\nfrom scripts.example import run\n"
            "class ExampleTests(unittest.TestCase):\n"
            "    def test_zero_and_positive(self):\n"
            "        \"\"\"EXAMPLE zero and matched positive.\"\"\"\n"
            "        effects = []\n"
            "        with self.assertRaises(ValueError):\n"
            "            run(False, effects)\n"
            "        self.assertEqual(effects, [])\n"
            "        run(True, effects)\n"
            "        self.assertEqual(effects, ['EXAMPLE send'])\n")
        files, contents = R.source(root)
        entry, _text = R.body(contents, {"path": "scripts/example.py", "symbol": "run"})
        witness, _text = R.body(contents, {"path": "tests/test_example.py", "symbol": "ExampleTests.test_zero_and_positive"})
        route = {"id": "EXAMPLE-send", "entrypoint": entry, "effect": "append to disposable list",
                 "gates": [{"path": "scripts/example.py", "line": 2, "text": "if not allowed:"}],
                 "authority": "EXAMPLE fixture Boolean only", "earlier_effects": "none",
                 "trace_files": ["scripts/example.py"],
                 "witnesses": [{"test_id": test_id, "body": witness,
                                "assertion": "self.assertEqual(effects, [])",
                                "positive": "self.assertEqual(effects, ['EXAMPLE send'])"}],
                 "manual_review": {"status": "external-review-required", "conclusion": "EXAMPLE explicit direct call",
                                   "limits": "EXAMPLE fixture only; no actual author approval"}}
        route["admission"] = admission
        if admission != "guarded-effect":
            route["gates"] = []
            route["witnesses"][0]["kind"] = "operator-contract"
        value = {"schema": "compact-release-routes-v1", "routes": [route], "source_bindings": files,
                 "primitive_coverage": {"schema": "bounded-primitives-v1", "hits": [], "exclusions": {}}}
        if compact:
            value = self.compact_example(value)
        (root / R.INVENTORY).write_bytes(R.encoded(value) + b"\n")
        index = R.write_trace(root, output)
        # A real harmless fixture method executes both its refusal and positive.
        result = subprocess.run([sys.executable, "-B", "-m", "unittest", "-v", test_id], cwd=root,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout.decode())
        (output / "EXAMPLE.log").write_bytes(result.stdout)
        receipt = {"status": "complete", "returncode": result.returncode, "log_sha256": R.digest(result.stdout)}
        (output / "EXAMPLE-receipt.json").write_bytes(R.encoded(receipt))
        artifact = lambda name: {"path": name, "sha256": R.digest((output / name).read_bytes())}
        observation = {"body_sha256": witness["sha256"], "source_sha256": index["source_sha256"],
                       "semantic_review": R.WITNESS_SEMANTICS[route["witnesses"][0].get("kind", "zero-effect-refusal")],
                       "receipt": artifact("EXAMPLE-receipt.json"), "log": artifact("EXAMPLE.log")}
        review = {"schema": "release-route-review-v1", "role": "independent-reviewer", "reviewer": "EXAMPLE-fixture",
                  "verdict": "ACCEPT", **{key: index[key] for key in ("source_sha256", "inventory_sha256", "trace_sha256")},
                  "decisions": {route["id"]: {"verdict": "ACCEPT", "conclusion": "EXAMPLE-only exercised both paths",
                      "decision_sha256": json.loads((output / "trace.json").read_bytes())["routes"][0]["decision_sha256"],
                      "observations": {test_id: observation}}}}
        return root, output, review

    def compact_example(self, value):
        route = copy.deepcopy(value["routes"][0])
        witness = route.pop("witnesses")[0]
        witness["body"] = "test"
        route.update(entrypoint="entry", gates=["gate"] if route["gates"] else [], witnesses=["pair"],
                     effect_points=["effect"], ordering="EXAMPLE direct call", limits="EXAMPLE only", manual_decisions=[])
        route.pop("id")
        return {**value, "point_files": ["scripts/example.py", "tests/test_example.py"],
                "points": {"entry": [0, "run", 1, value["routes"][0]["entrypoint"]["sha256"]],
                           "gate": [0, 2, "if not allowed:"], "effect": [0, 4, "effects.append('EXAMPLE send')"],
                           "test": [1, "ExampleTests.test_zero_and_positive", 4,
                                    value["routes"][0]["witnesses"][0]["body"]["sha256"]]},
                "contracts": {"EXAMPLE": route}, "witnesses": {"pair": witness}, "manual_decisions": {},
                "routes": [{"id": "EXAMPLE-send", "contract": "EXAMPLE", "entrypoint": "entry"}]}

    def select(self, root, output, review):
        raw = R.encoded(review)
        (output / "EXAMPLE-review.json").write_bytes(raw)
        return R.check(root, output, "EXAMPLE-review.json", R.digest(raw))

    def test_example_positive_and_missing_review_refuse_without_effects(self):
        root, output, review = self.example()
        result = self.select(root, output, review)
        self.assertTrue(result["complete_effect_trace"], "functioning selected EXAMPLE must complete")
        self.assertFalse(result["f8_complete"])
        with self.assertRaises(R.Refused, msg="missing independent selection must refuse"):
            R.check(root, output)
        command = [sys.executable, "-B", str(ROOT / "scripts/check_release_effect_routes.py"),
                   "--root", str(root), "--evidence-dir", str(output)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 1, "unselected CLI must refuse")
        self.assertFalse(json.loads(result.stdout)["complete_effect_trace"])
        raw = (output / "EXAMPLE-review.json").read_bytes()
        result = subprocess.run(command + ["--review", "EXAMPLE-review.json", "--review-sha256", R.digest(raw)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["complete_effect_trace"])
        self.assertEqual(sorted(path.name for path in root.iterdir()), ["policy", "scripts", "tests"])
        for admission in ("guarded-effect", "manual-program"):
            with self.subTest(compact_table_admission=admission):
                root, output, review = self.example(compact=True, admission=admission)
                self.assertTrue(self.select(root, output, review)["complete_effect_trace"],
                                "explicit EXAMPLE compact/manual contract must function")

    def test_stale_source_inventory_modes_and_trace_refuse(self):
        root, output, review = self.example()
        source = root / "scripts/example.py"
        original, mode = source.read_bytes(), source.stat().st_mode & 0o777
        self.assertTrue(self.select(root, output, review)["complete_effect_trace"])
        for row in ("bytes", "mode", "extra", "inventory", "trace", "index"):
            with self.subTest(row=row):
                path = {"inventory": root / R.INVENTORY, "trace": output / "trace.json",
                        "index": output / "index.json"}.get(row, source)
                before = path.read_bytes()
                if row == "mode":
                    source.chmod(mode ^ 0o100)
                elif row == "extra":
                    (root / "scripts/extra.py").write_text("call = lambda: None\n")
                else:
                    path.write_bytes(before + b"\n")
                with self.assertRaises(R.Refused, msg=f"{row} stale evidence admitted"):
                    self.select(root, output, review)
                if row == "mode":
                    with self.assertRaises(R.Refused, msg="stale inventory mode admitted by fresh generation"):
                        R.trace(root)
                path.write_bytes(before)
                source.chmod(mode)
                (root / "scripts/extra.py").unlink(missing_ok=True)
        self.assertEqual(source.read_bytes(), original)
        # Keep review/index coherent with a same-size incorrect lexical edge.
        # Only comparison with the freshly generated trace can reject this.
        current = json.loads((output / "trace.json").read_bytes())
        changed = copy.deepcopy(current)
        changed["sites"][0][-1] = "0" * 64
        raw = R.encoded(changed) + b"\n"
        (output / "trace.json").write_bytes(raw)
        (output / "index.json").write_bytes(R.encoded(R._index(current, raw)) + b"\n")
        review["trace_sha256"] = R.digest(raw)
        with self.assertRaises(R.Refused, msg="coherently indexed unrelated lexical edge admitted"):
            self.select(root, output, review)

    def test_unrelated_review_test_receipt_and_manual_decisions_refuse(self):
        root, output, review = self.example()
        route = review["decisions"]["EXAMPLE-send"]
        test_id = next(iter(route["observations"]))
        changes = {
            "rejected": lambda x: x.update(verdict="REJECT"),
            "author": lambda x: x.update(role="author"),
            "source": lambda x: x.update(source_sha256="0" * 64),
            "inventory": lambda x: x.update(inventory_sha256="0" * 64),
            "trace": lambda x: x.update(trace_sha256="0" * 64),
            "missing-route": lambda x: x["decisions"].clear(),
            "mismapped-route": lambda x: x["decisions"]["EXAMPLE-send"].update(decision_sha256="0" * 64),
            "unreviewed": lambda x: x["decisions"]["EXAMPLE-send"].update(verdict="PENDING"),
            "missing-observation": lambda x: x["decisions"]["EXAMPLE-send"]["observations"].clear(),
            "body": lambda x: x["decisions"]["EXAMPLE-send"]["observations"][test_id].update(body_sha256="0" * 64),
            "observed-source": lambda x: x["decisions"]["EXAMPLE-send"]["observations"][test_id].update(source_sha256="0" * 64),
            "extra-observation": lambda x: x["decisions"]["EXAMPLE-send"]["observations"].update({"tests.unrelated": {}}),
        }
        self.assertTrue(self.select(root, output, review)["complete_effect_trace"])
        for name, change in changes.items():
            with self.subTest(row=name):
                value = copy.deepcopy(review)
                change(value)
                with self.assertRaises(R.Refused, msg=f"{name} unrelated selection admitted"):
                    self.select(root, output, value)
        for name in ("EXAMPLE.log", "EXAMPLE-receipt.json"):
            with self.subTest(row=name):
                original = (output / name).read_bytes()
                (output / name).write_bytes(original + b"\n")
                with self.assertRaises(R.Refused, msg="changed raw evidence admitted"):
                    self.select(root, output, review)
                (output / name).write_bytes(original)
        log_before = (output / "EXAMPLE.log").read_bytes()
        receipt_before = (output / "EXAMPLE-receipt.json").read_bytes()
        for name in ("failed-receipt", "unrelated-pass-line"):
            with self.subTest(row=name):
                observed = copy.deepcopy(review)
                record = json.loads(receipt_before)
                if name == "failed-receipt":
                    record["returncode"] = 1
                else:
                    raw = log_before.replace(test_id.encode(), (test_id + "_unrelated").encode())
                    (output / "EXAMPLE.log").write_bytes(raw)
                    record["log_sha256"] = R.digest(raw)
                (output / "EXAMPLE-receipt.json").write_bytes(R.encoded(record))
                row = observed["decisions"]["EXAMPLE-send"]["observations"][test_id]
                for key, path in (("receipt", "EXAMPLE-receipt.json"), ("log", "EXAMPLE.log")):
                    row[key]["sha256"] = R.digest((output / path).read_bytes())
                with self.assertRaises(R.Refused, msg=f"{name} wrong execution evidence admitted"):
                    self.select(root, output, observed)
                (output / "EXAMPLE.log").write_bytes(log_before)
                (output / "EXAMPLE-receipt.json").write_bytes(receipt_before)

    def test_current_body_assertion_locations_and_custody_refuse(self):
        root, output, review = self.example()
        inventory = root / R.INVENTORY
        original = inventory.read_bytes()
        value = json.loads(original)
        changes = {
            "body": lambda x: x["routes"][0]["entrypoint"].update(sha256="0" * 64),
            "entry-is-test": lambda x: x["routes"][0].update(entrypoint=copy.deepcopy(x["routes"][0]["witnesses"][0]["body"])),
            "gate": lambda x: x["routes"][0]["gates"][0].update(line=3),
            "test": lambda x: x["routes"][0]["witnesses"][0].update(test_id="tests.unrelated.test_other"),
            "witness-body": lambda x: x["routes"][0]["witnesses"][0]["body"].update(sha256="0" * 64),
            "assertion": lambda x: x["routes"][0]["witnesses"][0].update(assertion="self.assertEqual(unrelated, 0)"),
            "empty-assertion": lambda x: x["routes"][0]["witnesses"][0].update(assertion=""),
            "empty-positive": lambda x: x["routes"][0]["witnesses"][0].update(positive=""),
            "manual": lambda x: x["routes"][0]["manual_review"].update(status="author-approved"),
            "binding": lambda x: x["source_bindings"].pop("scripts/example.py"),
            "duplicate": lambda x: x["routes"].append(copy.deepcopy(x["routes"][0])),
            "missing-gates": lambda x: x["routes"][0].update(gates=[]),
            "unknown-admission": lambda x: x["routes"][0].update(admission="invented"),
            "wrong-witness-kind": lambda x: x["routes"][0]["witnesses"][0].update(kind="operator-contract"),
            "unknown-witness-kind": lambda x: x["routes"][0]["witnesses"][0].update(kind="invented"),
            "helper-body": lambda x: x["routes"][0]["witnesses"][0].update(support=[{
                **x["routes"][0]["witnesses"][0]["body"], "sha256": "0" * 64}]),
        }
        for name, change in changes.items():
            with self.subTest(row=name):
                changed = copy.deepcopy(value)
                change(changed)
                inventory.write_bytes(R.encoded(changed))
                with self.assertRaises(R.Refused, msg=f"{name} invalid route admitted"):
                    R.trace(root)
        inventory.write_bytes(original)
        self.assertTrue(self.select(root, output, review)["complete_effect_trace"])
        table_root, table_output, table_review = self.example(compact=True)
        self.assertTrue(self.select(table_root, table_output, table_review)["complete_effect_trace"])
        table = json.loads((table_root / R.INVENTORY).read_bytes())
        for point_kind in ("gate", "manual-declaration"):
            invalid = copy.deepcopy(table)
            if point_kind == "gate":
                invalid["points"]["gate"][1] = 99
            else:
                invalid["points"]["manual-only"] = [0, "run", 1, "0" * 64]
            (table_root / R.INVENTORY).write_bytes(R.encoded(invalid))
            with self.assertRaises(R.Refused, msg="stale compact source point admitted"):
                R.trace(table_root)
        real_read = R.read_file
        for selected in ("EXAMPLE-review.json", "EXAMPLE.log"):
            with self.subTest(replaced_after_first_read=selected):
                changed = False
                def read_then_replace(directory, relative, limit=R.MAX_FILE):
                    nonlocal changed
                    result = real_read(directory, relative, limit)
                    if Path(directory) == output and relative == selected and not changed:
                        changed = True
                        (output / relative).write_bytes(result[0] + b"\n")
                    return result
                with patch.object(R, "read_file", side_effect=read_then_replace), self.assertRaises(R.Refused,
                        msg="custody input replaced after first read must refuse"):
                    self.select(root, output, review)

    def test_generated_data_stays_external_and_unsafe_reads_refuse(self):
        root, output, review = self.example()
        with self.assertRaises(R.Refused):
            R.write_trace(root, root / "evidence")
        with self.assertRaises(R.Refused):
            R.write_trace(root, output.parent.parent / "not-an-evidence-destination")
        path = root / "scripts/example.py"
        original = path.read_bytes()
        path.unlink()
        path.symlink_to(output / "EXAMPLE.log")
        with self.assertRaises((R.Refused, OSError), msg="symlink source must refuse"):
            R.trace(root)
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(R.Refused, msg="FIFO source must refuse without waiting"):
            R.trace(root)
        path.unlink()
        path.write_bytes(original)
        path.write_bytes(b"x" * (R.MAX_FILE + 1))
        with self.assertRaises(R.Refused, msg="unbounded source read must refuse"):
            R.trace(root)
        # Exercise the actual installer's selector, then a passive copy only.
        result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/check_installed_skill.py"),
                                 "--source-dir", str(ROOT), "--list-files"],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        selected = result.stdout.splitlines()
        self.assertIn(R.INVENTORY, selected)
        self.assertFalse(any("evidence" in Path(name).parts or "__pycache__" in Path(name).parts
                             or Path(name).name in {"trace.json", "index.json"} for name in selected),
                         "generated trace/intermediate/cache entered installed selection")
        projection = output / "passive-projection"
        for relative in selected:
            target = projection / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        self.assertEqual(sorted(str(path.relative_to(projection)) for path in projection.rglob("*") if path.is_file()),
                         sorted(selected), "passive projection differs from actual installer selection")
        self.assertLessEqual((projection / R.INVENTORY).stat().st_size, R.MAX_INVENTORY)


    def primitive_example(self, code, disposition=None, path="scripts/primitive.py"):
        """Rebind every source identity; classifier failures cannot hide behind drift."""
        root, _output, _review = self.example()
        selected = root / path
        prefix = selected.read_text() + "\n" if selected.exists() else ""
        selected.write_text(prefix + code)
        value = json.loads((root / R.INVENTORY).read_bytes())
        files, contents = R.source(root)
        value["source_bindings"].update({path: identity for path, identity in files.items()
                                         if path.startswith("scripts/")})
        hits = R.primitive_hits(contents)
        coverage = value["primitive_coverage"]
        if disposition:
            for index, hit in enumerate(hits):
                if disposition == "exclude":
                    key = f"EXAMPLE-inspection-{index}"
                    coverage["exclusions"][key] = {
                        "reason": "This exact EXAMPLE call is never executed by the tracer.",
                        "conclusion": "EXAMPLE inspection only, no authority for a real effect.",
                        "route": "EXAMPLE-send"}
                    selected = ["exclude", key]
                else:
                    path, line, col, end_line, end_col, _family, _sha = hit
                    lines = contents[path].splitlines(keepends=True)[line - 1:end_line]
                    lines[-1] = lines[-1][:end_col]
                    lines[0] = lines[0][col:]
                    point = {"path": path, "line": line, "text": b"".join(lines).decode(),
                             "col": col, "end_line": end_line, "end_col": end_col}
                    value["routes"][0].setdefault("effect_points", []).append(point)
                    selected = ["route", "EXAMPLE-send", point]
                coverage["hits"].append([*hit, selected])
        (root / R.INVENTORY).write_bytes(R.encoded(value))
        return root, value, hits

    def test_inventory_headroom_is_bounded(self):
        root, _output, _review = self.example()
        path = root / R.INVENTORY
        raw = path.read_bytes()
        path.write_bytes(raw + b" " * (200001 - len(raw)))
        try:
            loaded = R.inventory(root)[0]
        except R.Refused as error:
            self.fail(f"valid inventory over the former cap refused: {error}")
        self.assertEqual(loaded["schema"], "compact-release-routes-v1",
                         "valid inventory over the former cap must load")
        path.write_bytes(raw + b" " * (524288 - len(raw)))
        self.assertEqual(R.inventory(root)[0]["schema"], "compact-release-routes-v1")
        path.write_bytes(raw + b" " * (524289 - len(raw)))
        with self.assertRaisesRegex(R.Refused, "regular bounded file required"):
            R.inventory(root)

    def test_unmapped_primitives_refuse_after_coherent_rebinding(self):
        cases = [
            ("process", "import subprocess\nsubprocess.run(['bd', 'close', 'EXAMPLE'])\n"),
            ("process", "from subprocess import check_output as launch\nlaunch(['true'])\n"),
            ("process", "import subprocess as sp\nlaunch = sp.Popen\nlaunch(['true'])\n"),
            ("process", "import importlib as il\nmod = il.import_module('subprocess')\nmod.run(['true'])\n"),
            ("process", "import subprocess\nlaunch = getattr(subprocess, 'run')\nlaunch(['true'])\n"),
            ("process", "import os\nos.execve('EXAMPLE', [], {})\n"),
            ("network", "import socket as sk\nsk.create_connection(('EXAMPLE', 1))\n"),
            ("network", "from urllib.request import urlopen as open_url\nopen_url('EXAMPLE')\n"),
            ("network", "import http.client\nhttp.client.HTTPSConnection('EXAMPLE')\n"),
            ("network", "from http.server import ThreadingHTTPServer as Listener\nListener(('EXAMPLE', 0), Handler)\n"),
            ("browser", "from playwright.sync_api import sync_playwright as browser\nbrowser()\n"),
            ("browser", "page.goto('EXAMPLE')\n"),
            ("appserver", "RegisteredAppServer('EXAMPLE')\n"),
            ("appserver", "transport.send_request('EXAMPLE')\n"),
            ("beads", "run_bd(['close', 'EXAMPLE'])\n"),
            ("beads", "create_bead('EXAMPLE')\n"),
            ("install-copy", "from shutil import copytree as copy_skill\ncopy_skill('EXAMPLE', 'skills')\n"),
            ("dynamic", "import importlib\nimportlib.import_module(module_name)\n"),
            ("dynamic", "getattr(client, method_name)('EXAMPLE')\n"),
            ("dynamic", "import importlib\nimportlib.import_module('unknown.EXAMPLE').call()\n"),
            ("dynamic", "__import__('unknown.EXAMPLE')\n"),
        ]
        constructed = [
            ("browser", "page.locator('EXAMPLE').first.click()\n"),
            ("browser", "page.get_by_text('EXAMPLE').first.click()\n"),
            ("appserver", "super().request('EXAMPLE')\n"),
            ("browser", "pages[0].click('EXAMPLE')\n"),
            ("browser", "wrappers()[0].first.click()\n"),
            ("browser", "[page][0].click('EXAMPLE')\n"),
            ("appserver", "servers[0].send_request('EXAMPLE')\n"),
            ("browser", "invoke = page.locator('EXAMPLE').first.click\ninvoke()\n"),
            ("browser", "getattr(page.locator('EXAMPLE').first, 'click')()\n"),
            ("browser", "getattr(factory(), 'click')()\n"),
            ("process", "import subprocess\nsubprocess.registry()[0].run(['true'])\n"),
            ("process", "import os\nos.runners[0].execve('EXAMPLE', [], {})\n"),
            ("process", "import subprocess\nexecute = subprocess.registry()[0].run\nexecute(['true'])\n"),
            ("network", "import requests\nrequests.sessions()[0].get('EXAMPLE')\n"),
            ("network", "import urllib.request\nurllib.request.openers()[0].urlopen('EXAMPLE')\n"),
            ("network", "import socket\nsocket.factories()[0].socket()\n"),
            ("network", "import http.client\nhttp.client.factories()[0].HTTPConnection('EXAMPLE')\n"),
            ("network", "import socketserver\nmodule = socketserver\nmodule.servers()[0].TCPServer(('EXAMPLE', 0), Handler)\n"),
            ("browser", "import playwright.sync_api as api\napi.providers()[0].start()\n"),
            ("beads", "makers()[0].create_bead('EXAMPLE')\n"),
            ("install-copy", "import shutil\nshutil.handlers()[0].copytree('EXAMPLE', 'skills')\n"),
            ("process", "import subprocess\n[subprocess][0].run(['true'])\n"),
            ("process", "import subprocess\n(subprocess,)[0].run(['true'])\n"),
            ("process", "import subprocess\nmodules = {'p': subprocess}\nmodules['p'].run(['true'])\n"),
            ("install-copy", "import shutil\n{'s': shutil}['s'].copy2('EXAMPLE', 'skills')\n"),
            ("dynamic", "import importlib\ngetattr(importlib.import_module(module_name).factory()[0], method_name)()\n"),
        ]
        cases += constructed
        for family, code in cases:
            with self.subTest(family=family, code=code):
                root, _value, hits = self.primitive_example(code)
                with self.assertRaisesRegex(R.Refused, "primitive hit coverage mismatch",
                                            msg="coherently rebound unmapped primitive admitted"):
                    R.trace(root)
                self.assertIn(family, [hit[5] for hit in hits], "primitive family not surfaced")

        for code in (cases[0][1], cases[3][1]):
            with self.subTest(existing_script=code):
                root, _value, _hits = self.primitive_example(code, path="scripts/example.py")
                with self.assertRaisesRegex(R.Refused, "primitive hit coverage mismatch"):
                    R.trace(root)

        for code in (constructed[0][1], constructed[2][1], constructed[10][1]):
            for disposition in ("route", "exclude"):
                with self.subTest(constructed_positive=disposition, code=code):
                    root, _value, hits = self.primitive_example(code, disposition)
                    self.assertTrue(hits, "constructed primitive must have an exact disposition")
                    self.assertEqual(R.trace(root)["primitive_hits"], hits)

    def test_effect_points_and_named_manual_exclusions_cover_each_hit(self):
        code = "import subprocess\nresult = subprocess.run(\n    ['true']\n)\n"
        for disposition in ("route", "exclude"):
            with self.subTest(disposition=disposition):
                root, value, hits = self.primitive_example(code, disposition)
                self.assertEqual(R.trace(root)["primitive_hits"], hits, "explicit exact disposition must work")
                coverage = value["primitive_coverage"]
                changes = {
                    "missing": lambda x: x["hits"].clear(),
                    "extra": lambda x: x["hits"].append([*hits[0][:-1], "0" * 64, x["hits"][0][-1]]),
                    "duplicate": lambda x: x["hits"].append(copy.deepcopy(x["hits"][0])),
                    "stale-span": lambda x: x["hits"][0].__setitem__(4, hits[0][4] + 1),
                    "stale-bytes": lambda x: x["hits"][0].__setitem__(6, "0" * 64),
                    "unknown-disposition": lambda x: x["hits"][0].__setitem__(7, ["file-exempt", "scripts/primitive.py"]),
                    "unknown-family": lambda x: x["hits"][0].__setitem__(5, "invented"),
                    "malformed-row": lambda x: x["hits"][0].pop(),
                    "unknown-schema": lambda x: x.update(schema="invented"),
                    "orphan": lambda x: x["exclusions"].update({"EXAMPLE-orphan": {
                        "reason": "not selected by any source hit", "conclusion": "must refuse"}}),
                }
                if disposition == "exclude":
                    key = coverage["hits"][0][-1][1]
                    changes.update({
                        "unknown-exclusion": lambda x: x["hits"][0].__setitem__(7, ["exclude", "missing"]),
                        "extra-exclusion-argument": lambda x: x["hits"][0][-1].append("unrelated"),
                        "missing-reason": lambda x: x["exclusions"][key].update(reason=""),
                        "missing-conclusion": lambda x: x["exclusions"][key].update(conclusion=" "),
                        "unknown-exclusion-route": lambda x: x["exclusions"][key].update(route="missing"),
                    })
                else:
                    changes.update({
                        "unknown-route": lambda x: x["hits"][0].__setitem__(7, ["route", "missing", {}]),
                        "unrelated-effect": lambda x: x["hits"][0][-1].__setitem__(2, {
                            "path": "scripts/primitive.py", "line": 1, "text": "import subprocess"}),
                    })
                for name, change in changes.items():
                    with self.subTest(invalid=name):
                        changed = copy.deepcopy(coverage)
                        change(changed)
                        (root / R.INVENTORY).write_bytes(R.encoded({**value, "primitive_coverage": changed}))
                        with self.assertRaises(R.Refused, msg=f"{name} primitive disposition admitted"):
                            R.trace(root)
                if disposition == "route":
                    # This current, selected route point is valid source, but
                    # cannot stand in for the actual classified call.
                    wrong = copy.deepcopy(value)
                    wrong_point = {"path": "scripts/primitive.py", "line": 1, "text": "import subprocess"}
                    wrong["routes"][0]["effect_points"] = [wrong_point]
                    wrong["primitive_coverage"]["hits"][0][-1][2] = wrong_point
                    (root / R.INVENTORY).write_bytes(R.encoded(wrong))
                    with self.assertRaisesRegex(R.Refused, "primitive effect point must equal exact hit"):
                        R.trace(root)
                    # Exercise the actual compact table path with an assigned,
                    # multiline call; line-only points cannot select that span.
                    valid = copy.deepcopy(value)
                    point = valid["routes"][0]["effect_points"][0]
                    valid["point_files"] = [point["path"]]
                    valid["points"] = {"EXAMPLE-primitive": [0, point["line"], point["text"],
                                                             point["col"], point["end_line"], point["end_col"]]}
                    valid["primitive_coverage"]["hits"][0][-1][2] = "EXAMPLE-primitive"
                    (root / R.INVENTORY).write_bytes(R.encoded(valid))
                    self.assertEqual(R.trace(root)["primitive_hits"], hits)
                    for change in ("span-column", "span-end", "point-text", "point-not-selected"):
                        with self.subTest(compact_invalid=change):
                            invalid = copy.deepcopy(valid)
                            if change == "span-column":
                                invalid["points"]["EXAMPLE-primitive"][3] += 1
                            elif change == "span-end":
                                invalid["points"]["EXAMPLE-primitive"][4] = 999
                            elif change == "point-text":
                                invalid["points"]["EXAMPLE-primitive"][2] = "unrelated"
                            else:
                                invalid["routes"][0]["effect_points"] = []
                            (root / R.INVENTORY).write_bytes(R.encoded(invalid))
                            with self.assertRaises(R.Refused):
                                R.trace(root)
                if disposition == "exclude":
                    pair_root, pair, pair_hits = self.primitive_example(
                        "import subprocess\nsubprocess.run(['true'])\nsubprocess.check_call(['true'])\n", "exclude")
                    self.assertEqual(len(pair_hits), 2)
                    first, second = [row[-1][1] for row in pair["primitive_coverage"]["hits"]]
                    pair["primitive_coverage"]["hits"][1][-1][1] = first
                    pair["primitive_coverage"]["exclusions"].pop(second)
                    (pair_root / R.INVENTORY).write_bytes(R.encoded(pair))
                    with self.assertRaisesRegex(R.Refused, "duplicate primitive exclusion"):
                        R.trace(pair_root)
                # Change only excluded bytes and rebind all script identities. The
                # old per-hit hash must be the decisive refusal, not file drift.
                (root / "scripts/primitive.py").write_text(code.replace("true", "false"))
                files, _contents = R.source(root)
                value["source_bindings"].update({p: i for p, i in files.items() if p.startswith("scripts/")})
                (root / R.INVENTORY).write_bytes(R.encoded(value))
                with self.assertRaisesRegex(R.Refused, "primitive hit coverage mismatch"):
                    R.trace(root)

    def test_dynamic_candidates_require_individual_exclusions_and_aliases_are_bounded(self):
        root, _value, hits = self.primitive_example("getattr(client, method_name)('EXAMPLE')\n", "exclude")
        self.assertIn("dynamic", [hit[5] for hit in hits])
        self.assertEqual(R.trace(root)["primitive_hits"], hits)
        root, _value, _hits = self.primitive_example("getattr(client, method_name)('EXAMPLE')\n", "route")
        with self.assertRaisesRegex(R.Refused, "unresolved dynamic candidate requires exclusion"):
            R.trace(root)
        # A union preserves the effect-capable alias after a later reassignment;
        # conservative false positives receive individual manual dispositions.
        code = "import subprocess\nlaunch = subprocess.run\nlaunch = harmless\nlaunch(['true'])\n"
        root, _value, hits = self.primitive_example(code, "exclude")
        self.assertIn("process", [hit[5] for hit in hits])
        self.assertEqual(R.trace(root)["primitive_hits"], hits)
        chain = "import subprocess\n" + "\n".join(f"a{i} = a{i+1}" for i in range(10)) + "\na10 = subprocess.run\na0(['true'])\n"
        with self.assertRaisesRegex(R.Refused, "primitive alias resolution budget exceeded"):
            R.primitive_hits({"scripts/EXAMPLE.py": chain.encode()})

    def test_complete_scripts_binding_set_refuses_benign_drift(self):
        root, _output, _review = self.example()
        path = root / R.INVENTORY
        value = json.loads(path.read_bytes())
        (root / "scripts/benign.py").write_text("# EXAMPLE no primitive\n")
        with self.assertRaisesRegex(R.Refused, "complete scripts binding set required"):
            R.trace(root)
        files, _contents = R.source(root)
        value["source_bindings"]["scripts/benign.py"] = files["scripts/benign.py"]
        path.write_bytes(R.encoded(value))
        self.assertEqual(R.trace(root)["primitive_hits"], [])
        (root / "scripts/benign.py").unlink()
        with self.assertRaisesRegex(R.Refused, "complete scripts binding set required"):
            R.trace(root)
        (root / "scripts/benign.py").write_text("# EXAMPLE no primitive\n")
        value["source_bindings"].pop("scripts/benign.py")
        path.write_bytes(R.encoded(value))
        with self.assertRaisesRegex(R.Refused, "complete scripts binding set required"):
            R.trace(root)

    def gate_point(self, code, line=1, *, callee=None, predicate=False, shell=False):
        path = "scripts/gates.sh" if shell else "scripts/gates.py"
        point = {"path": path, "line": line, "text": code.splitlines()[line - 1].strip()}
        if callee is not None or predicate:
            tree = ast.parse(code)
            if predicate:
                node = next(n.test for n in ast.walk(tree) if isinstance(n, ast.If) and n.lineno == line)
            else:
                node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and
                            n.lineno == line and ast.unparse(n.func) == callee)
            point.update(line=node.lineno, col=node.col_offset, end_line=node.end_lineno,
                         end_col=node.end_col_offset, text=R._span(code.encode(), node).decode())
        return point

    def gate_example(self, code, gate, effects=(), *, compact=False, same_key=False):
        root, _output, _review = self.example()
        (root / gate["path"]).write_text(code)
        value = json.loads((root / R.INVENTORY).read_bytes())
        route = value["routes"][0]
        route["gates"] = [gate]
        route["effect_points"] = list(effects)
        route["trace_files"].append(gate["path"])
        files, contents = R.source(root)
        value["source_bindings"].update({p: identity for p, identity in files.items() if p.startswith("scripts/")})
        coverage = value["primitive_coverage"]
        for index, hit in enumerate(R.primitive_hits(contents)):
            key = f"EXAMPLE-unexecuted-guard-{index}"
            coverage["hits"].append([*hit, ["exclude", key]])
            coverage["exclusions"][key] = {"reason": "This exact syntax fixture is inspected, never imported.",
                                             "conclusion": "EXAMPLE classifier-only candidate; no runtime authority."}
        if compact:
            value = self.compact_example(value)
            value["point_files"].append(gate["path"])
            def entry(point):
                selected = [2, point["line"], point["text"]]
                if "col" in point:
                    selected += [point["col"], point["end_line"], point["end_col"]]
                return selected
            value["points"]["gate"] = entry(gate)
            value["points"]["effect"] = entry(effects[0])
            value["contracts"]["EXAMPLE"]["effect_points"] = ["gate" if same_key else "effect"]
        (root / R.INVENTORY).write_bytes(R.encoded(value))
        return root

    def assert_gate_accepts(self, root):
        failure, observed = None, None
        try:
            observed = R.trace(root)
        except R.Refused as error:
            failure = error
        self.assertIsNone(failure, f"current valid guard refused: {failure}")
        self.assertTrue(observed["routes"], "functioning EXAMPLE route must remain present")

    def test_gate_points_refuse_effects_and_non_guards(self):
        positives = [
            ("if not allowed:\n    pass\n", 1),
            ("if (\n    allowed\n):\n    pass\n", 1),
            ("raise ValueError(\n    'EXAMPLE held'\n)\n", 1),
            ("need(allowed, 'EXAMPLE held')\n", 1),
            ("result = normalize_command_spec(value)\n", 1),
            ("result: dict = normalize_command_spec(value)\n", 1),
        ]
        for code, line in positives:
            with self.subTest(valid_python=code):
                self.assert_gate_accepts(self.gate_example(code, self.gate_point(code, line)))
        code = "if (\n    allowed\n):\n    pass\n"
        self.assert_gate_accepts(self.gate_example(code, self.gate_point(code, predicate=True)))
        code = "if allowed and ready:\n    pass\n"
        fragment = self.gate_point(code, predicate=True)
        fragment.update(text="allowed", end_col=fragment["col"] + len("allowed"))
        root = self.gate_example(code, fragment)
        with self.assertRaisesRegex(R.Refused, "unsupported gate form"):
            R.trace(root)
        negatives = [
            ("result = {\n    'status': 'failed',\n}\n", 2),
            ("def guard_name():\n    pass\n", 1),
            ("'EXAMPLE message'\n", 1),
            ("changed = True\n", 1),
            ("target.write_text('EXAMPLE')\n", 1),
            ("import subprocess\nsubprocess.run(['true'])\n", 2),
            ("capability.claim()\n", 1),
            ("git_dir, common_dir = self._resolve_dirs()\n", 1),
            ("with capability._lock:\n    pass\n", 1),
            ("result = factory(\n    campaign_live_route=True,\n)\n", 2),
            ("evil.require_clean(allowed)\n", 1),
            ("result = custom_validator(allowed)\n", 1),
            ("if True:\n    pass\n", 1),
            ("if (\n    allowed\n):\n    pass\n", 2),
            ("raise ValueError(\n    'EXAMPLE message'\n)\n", 2),
            ("need(\n    allowed,\n    'EXAMPLE held',\n)\n", 2),
            ("need(allowed); value = 1\n", 1),
            ("if allowed: value = 1\n", 1),
            ("raise ValueError('held'); value = 1\n", 1),
        ]
        for code, line in negatives:
            with self.subTest(invalid_python=code, line=line):
                root = self.gate_example(code, self.gate_point(code, line))
                with self.assertRaisesRegex(R.Refused, "unsupported gate form"):
                    R.trace(root)
        shell_lines = [
            'if [ "$DRY_RUN" -eq 1 ]; then',
            'if [[ "$DRY_RUN" -eq 1 ]]; then',
            'if [[ "$DRY_RUN" -eq 0 ]]; then',
            'if [[ "$WRITE_CONFIG" -eq 1 && "$DRY_RUN" -eq 0 ]]; then',
            'if [[ "$REPLACE" -eq 1 && "$DRY_RUN" -eq 0 ]]; then',
            'if ! python3 -B "$CHECKER" --source-dir "$SOURCE_DIR" --installed-dir "$INSTALL_STAGE_DIR" --write-manifest --check; then',
            'entries="$(projection_list --list-entries)" || die "source does not satisfy the installed projection ($PROJECTION); nothing was installed"',
        ]
        for text in shell_lines:
            with self.subTest(valid_shell=text):
                code = text + "\n"
                self.assert_gate_accepts(self.gate_example(code, self.gate_point(code, shell=True)))
        guard = shell_lines[1]
        code = guard + "\n"
        col = guard.index('"$DRY_RUN"')
        fragment = {"path": "scripts/gates.sh", "line": 1, "col": col, "end_line": 1,
                    "end_col": col + len('"$DRY_RUN"'), "text": '"$DRY_RUN"'}
        with self.assertRaisesRegex(R.Refused, "unsupported gate form"):
            R.trace(self.gate_example(code, fragment))
        unknown_source = self.gate_point(code, shell=True)
        unknown_source["path"] = "scripts/gates.txt"
        with self.assertRaisesRegex(R.Refused, "unsupported gate form"):
            R.trace(self.gate_example(code, unknown_source))
        for prefix in ("cat <<'EOF'\n", "printf '\n", 'echo \\\n', 'printf "\n', "printf $'escaped\\'\n", "cat <<'EOF'\nignored\n"):
            with self.subTest(shell_nonstatement=prefix):
                code = prefix + guard + "\n"
                root = self.gate_example(code, self.gate_point(code, len(prefix.splitlines()) + 1, shell=True))
                with self.assertRaisesRegex(R.Refused, "unsupported gate form"):
                    R.trace(root)
        for prefix, line in (("cat <<$delimiter\n", 2), ("cat <<EOF <<SECOND\nSECOND\n", 3)):
            with self.subTest(unsupported_shell_context=prefix):
                code = prefix + guard + "\nEOF\nSECOND\n"
                root = self.gate_example(code, self.gate_point(code, line, shell=True))
                with self.assertRaisesRegex(R.Refused, "unsupported shell context"):
                    R.trace(root)
        for text in ('DRY_RUN=0', 'quote_cmd "${cmd[@]}"', 'if arbitrary; then'):
            with self.subTest(invalid_shell=text):
                code = text + "\n"
                root = self.gate_example(code, self.gate_point(code, shell=True))
                with self.assertRaisesRegex(R.Refused, "unsupported gate form"):
                    R.trace(root)
        for prefix in ("cat <<'EOF'\nignored\nEOF\n", 'cat <<-EOF\nignored\n\tEOF\n', "printf '\nignored'\n", "printf $'escaped\\' quote'\n", "printf 'literal\\'\n", 'echo \\\ncontinued\n', "# ignored ' <<EOF\n", 'printf "escaped\\" quote"\n'):
            with self.subTest(shell_context_ended=prefix):
                code = prefix + guard + "\n"
                point = self.gate_point(code, len(prefix.splitlines()) + 1, shell=True)
                self.assert_gate_accepts(self.gate_example(code, point))

    def test_gate_effect_overlap_refuses_after_coherent_rebinding(self):
        code = "need(allowed)\n"
        point = self.gate_point(code, callee="need")
        for compact, same_key in ((False, False), (True, False), (True, True)):
            with self.subTest(equal_span_compact=compact, same_key=same_key):
                root = self.gate_example(code, point, [point], compact=compact, same_key=same_key)
                with self.assertRaisesRegex(R.Refused, "gate overlaps effect"):
                    R.trace(root)
        for code in ("import subprocess\nif subprocess.run(['true']):\n    pass\n",
                     "if capability.claim():\n    pass\n"):
            with self.subTest(real_effect_in_predicate=code):
                line = 2 if code.startswith("import") else 1
                root = self.gate_example(code, self.gate_point(code, line))
                with self.assertRaisesRegex(R.Refused, "gate overlaps effect"):
                    R.trace(root)
        code = "if allowed:\n    need(allowed)\n    effects.append('EXAMPLE')\n"
        self.assert_gate_accepts(self.gate_example(code, self.gate_point(code),
                                                 [self.gate_point(code, 3, callee="effects.append")]))
        code = "label = 'é'; need(allowed); effects.append('EXAMPLE')\n"
        gate = self.gate_point(code, callee="need")
        effect = self.gate_point(code, callee="effects.append")
        self.assert_gate_accepts(self.gate_example(code, gate, [effect]))
        byte_start = len(code[:code.index("need")].encode())
        self.assertEqual(R.gate_span({gate["path"]: code.encode()}, gate),
                         (gate["path"], byte_start, byte_start + len("need(allowed)")))
        code = "if allowed: effects.append('EXAMPLE')\n"
        gate = {"path": "scripts/gates.py", "line": 1, "col": 0, "end_line": 1,
                "end_col": len("if allowed:"), "text": "if allowed:"}
        self.assert_gate_accepts(self.gate_example(code, gate,
                                                 [self.gate_point(code, callee="effects.append")]))
        code = "need(\n    allowed\n)\n"
        prefix = self.gate_point(code)
        self.assertEqual(R._effect_interval(code.encode(), prefix), (0, len(code.rstrip())))
        root = self.gate_example(code, self.gate_point(code, callee="need"), [prefix])
        with self.assertRaisesRegex(R.Refused, "gate overlaps effect"):
            R.trace(root)
        code = "need(wrapper(allowed))\n"
        inner = self.gate_point(code, callee="wrapper")
        start = code.index("wrapper")
        self.assertEqual(R._effect_interval(code.encode(), inner), (start, start + len("wrapper(allowed)")))

    def _probe_listener_pair(self):
        import check_codex_worker_surface as surface
        from cwo_core import native_live_availability as availability
        events, calls = [], []
        event_type = surface.threading.Event
        def event():
            value = event_type()
            events.append(value)
            return value
        listener = mock.Mock(server_address=("127.0.0.1", 12345))
        listener.handle_request.side_effect = lambda: (calls.append("serve"), events[1].set())
        listener.server_close.side_effect = lambda: calls.append("close")
        listener.socket.fileno.return_value = -1
        def construct(address, handler):
            self.assertEqual(address, ("127.0.0.1", 0))
            self.assertTrue(issubclass(handler, surface.BaseHTTPRequestHandler))
            calls.append("construct")
            return listener
        def thread(*, target, daemon):
            self.assertTrue(daemon)
            return mock.Mock(start=target, ident=123, is_alive=lambda: False)
        evidence = {}
        with mock.patch.object(surface, "ThreadingHTTPServer", side_effect=construct) as factory, \
             mock.patch.object(surface, "prepare_capture_binding", return_value={"lockdown_config_sha256": "mismatch"}) as prepare, \
             mock.patch.object(surface, "probe_thread_config", return_value={}), \
             mock.patch.object(surface.threading, "Thread", side_effect=thread), \
             mock.patch.object(surface.threading, "Event", side_effect=event):
            failure = None
            with mock.patch.object(availability, "N1_LIVE_AVAILABLE", False):
                try:
                    surface.capture_tool_request(codex_home=self.root, requested_model="EXAMPLE", timeout_seconds=1)
                except BaseException as error:
                    failure = error
            self.assertEqual((factory.call_count, prepare.call_count, calls), (0, 0, []))
            self.assertIsInstance(failure, availability.NativeLiveUnavailable)
            with mock.patch.object(availability, "N1_LIVE_AVAILABLE", True), \
                 self.assertRaisesRegex(surface.CodexToolSurfaceError, "configuration-binding-drift"):
                surface.capture_tool_request(codex_home=self.root, requested_model="EXAMPLE", timeout_seconds=1, evidence=evidence)
        self.assertEqual(calls, ["construct", "serve", "close"])
        self.assertEqual((evidence["probe_cleanup"]["serving_thread_stopped"],
                          evidence["probe_cleanup"]["listener_closed"]), (True, True))


    def _installer_pair(self):
        skills = self.root / "install/skills"
        marker = self.root / "validator-argv.json"
        validator = self.root / "validator.py"
        validator.write_text("import json,sys\nfrom pathlib import Path\n" +
                             f"Path({str(marker)!r}).write_text(json.dumps(sys.argv))\n")
        command = [str(ROOT / "scripts/install.sh"), "--skills-dir", str(skills), "--yes"]
        env = dict(os.environ, SKILL_VALIDATOR=str(validator))
        dry = subprocess.run([*command, "--dry-run"], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(dry.returncode, 0, dry.stdout + dry.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(skills.exists())
        installed = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        target = skills / "complex-work-orchestration"
        self.assertEqual(json.loads(marker.read_text()), [str(validator), str(target)])
        snapshot = {str(p.relative_to(target)): R.digest(p.read_bytes()) for p in target.rglob("*") if p.is_file()}
        dry = subprocess.run([*command, "--uninstall", "--dry-run"], env=env, capture_output=True, timeout=30)
        self.assertEqual(dry.returncode, 0, dry.stdout + dry.stderr)
        self.assertEqual({str(p.relative_to(target)): R.digest(p.read_bytes()) for p in target.rglob("*") if p.is_file()}, snapshot)
        removed = subprocess.run([*command, "--uninstall"], env=env, capture_output=True, timeout=30)
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assertFalse(target.exists())
        backups = list((skills.parent / "skill-backups").iterdir())
        self.assertEqual(len(backups), 1)
        self.assertEqual({str(p.relative_to(backups[0])): R.digest(p.read_bytes()) for p in backups[0].rglob("*") if p.is_file()}, snapshot)


    def _git_pair(self):
        from cwo_core import native_live_campaign_contracts as campaign
        patch = b"EXAMPLE harmless fake patch"
        manifest = {"candidate": {"commit": "EXAMPLE-commit", "tree": "EXAMPLE-before"},
                    "release": {"patch_file_sha256": R.digest(patch), "prospective_tree": "EXAMPLE-after"}}
        with mock.patch.object(campaign.subprocess, "run") as child, \
             mock.patch.object(campaign, "_run_git", side_effect=["EXAMPLE-before", "EXAMPLE-after"]):
            refused = campaign.validate_release_patch_result(self.root, None, manifest, patch_bytes=patch+b"!")
            child.assert_not_called()
            self.assertEqual(refused, ["release-patch-file-sha256-mismatch"])
            self.assertEqual(campaign.validate_release_patch_result(self.root, None, manifest, patch_bytes=patch), [])
        self.assertEqual(child.call_count, 4)
        commands = [c.args[0] for c in child.call_args_list]
        worktree = commands[0][4]
        self.assertEqual(commands, [["git", "worktree", "add", "--detach", worktree, "EXAMPLE-commit"],
                                   ["git", "apply", "--check", "-"], ["git", "apply", "--index", "-"],
                                   ["git", "worktree", "remove", "--force", worktree]])
        self.assertEqual([c.kwargs["cwd"] for c in child.call_args_list],
                         [self.root, Path(worktree), Path(worktree), self.root])
        self.assertEqual([c.kwargs.get("input") for c in child.call_args_list], [None, patch, patch, None])
        self.assertEqual([c.kwargs["check"] for c in child.call_args_list], [True, True, True, False])


    def _driver_pair(self):
        import check_extended_code_health as health
        for name in (health.SUBJECT, health.DRIVER):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        driver = self.root / health.DRIVER
        real = driver.with_suffix(".real.py")
        driver.rename(real)
        driver.symlink_to(real)
        with mock.patch.object(health.runpy, "run_path", wraps=health.runpy.run_path) as execute:
            failure = None
            try:
                health.measure(self.root)
            except BaseException as error:
                failure = error
            execute.assert_not_called()
            self.assertIsInstance(failure, SystemExit)
            self.assertIn("indirect approved", str(failure))
            driver.unlink()
            real.rename(driver)
            health.measure(self.root)
            self.assertEqual(execute.call_args_list[0], mock.call(str(driver), run_name="__w21_measurement__"))


    def _dns_pair(self):
        import dispatch_work as dispatch
        import socket
        records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.2.3.4", 443))]
        with mock.patch.object(dispatch.socket, "getaddrinfo", return_value=records) as dns:
            failure = None
            try:
                dispatch.validate_local_endpoint_base_url("https://example.invalid")
            except BaseException as error:
                failure = error
            dns.assert_not_called()
            self.assertIsInstance(failure, SystemExit)
            self.assertEqual(dispatch.validate_local_endpoint_base_url("https://10.2.3.4"), ["10.2.3.4"])
            dns.assert_not_called()
            self.assertEqual(dispatch.pinned_local_endpoint_address("https://example.invalid", allow_private_dns=True), "10.2.3.4")
            dns.assert_called_once_with("example.invalid", 0, type=socket.SOCK_STREAM)
        connection = dispatch.PinnedHTTPConnection("example.invalid", 443, pinned_address="10.2.3.4", timeout=2)
        with mock.patch.object(connection, "_create_connection", return_value=mock.Mock()) as connect:
            connection.connect()
            connect.assert_called_once_with(("10.2.3.4", 443), 2, None)


    def _expert_pair(self):
        import spawn_expert_reviews as experts
        text = "Add OIDC login to the OpenShift platform cluster networking and storage layer"
        route = experts.classify_work(text)
        reviews, unmet = experts.planned_expert_reviews("Expert review", route, 3)
        self.assertFalse(unmet)
        self.assertEqual(len(reviews), 4)
        missing = {**route, "ranked_experts": [e for e in route["ranked_experts"] if e["name"] != "security"]}
        for label, selected, dry, refused in (("admitted", route, False, False), ("missing", missing, False, True),
                                             ("dry-admitted", route, True, False), ("dry-missing", missing, True, True)):
            with self.subTest(experts=label), mock.patch.object(experts, "classify_work", return_value=selected), \
                 mock.patch.object(experts, "create_bead", side_effect=lambda title, **kw: {"id": "EXAMPLE", "title": title}) as creates, \
                 mock.patch.object(sys, "argv", ["spawn_expert_reviews.py", text, *(["--dry-run"] if dry else [])]), \
                 mock.patch("sys.stdout", io.StringIO()):
                failure = None
                try:
                    experts.main()
                except SystemExit as error:
                    failure = error
                self.assertEqual(creates.call_count, 0 if refused or dry else 4)
                self.assertEqual([c.args[0] for c in creates.call_args_list], [] if refused or dry else [r["title"] for r in reviews])
                if refused:
                    self.assertIsInstance(failure, SystemExit)
                    self.assertIn("required experts unmet: security", str(failure))
                else:
                    self.assertIsNone(failure)


    def test_remaining_boundary_pairs_at_actual_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            self.root = Path(directory)
            for row in (self._probe_listener_pair, self._installer_pair, self._git_pair, self._driver_pair, self._dns_pair, self._expert_pair):
                with self.subTest(row=row.__name__):
                    row()


if __name__ == "__main__":
    unittest.main()

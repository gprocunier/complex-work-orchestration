"""Historical ratchet data with sanitized metadata and focused controls for the real comparison API."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from scripts import check_code_health as health

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
DIAGNOSTIC = (
    "scripts/cwo_core/maintenance_native_runtime.py::<module>::"
    "F401::run_native_pool_live_canaries.AppServerError"
)
EDGE = "cwo_core.maintenance_qualification -> codex_tool_surface"
PROGRESS = "scripts/cwo_core/native_progress.py::evaluate_worker_progress"
BATCH = "transport-extraction-2026-10-23-local"
UNCHANGED = (
    "version", "tool", "complexity_threshold", "admitted", "created",
    "repeated", "moved", "consumed_batches",
)
ANCHORS = {
    "source_parent_commit": "fa7799be3e69e19dc315a9d395037f692cab82f3",
    "source_parent_tree": "7c13da41c7a9c791e2154140528af57dbfb4070d",
    "old_baseline_raw_sha256": "78085f594b7d3abe6fcb71ee0297f53e9d3a66de2acd957f42fd73832bca61ba",
    "old_baseline_canonical_sha256": "1857f6522d0f44a29a2c90550df590fdddeae125a7edfe439b8d58f369186dc0",
    "new_baseline_canonical_sha256": "123e4afbcac5aad37ab5d212e1e4ced421707d945ae597e59d27727e188cde03",
    "moves_sha256": "4d79a8c79b24821932ba10881f3bde683dabc80073b18adf1dbabb82c95fe54c",
    "checker_sha256": "8fec5ab975e095ea00a5fbc1d3bd97d8d379c0b01273c0e6345f12e07d1d7971",
    "ruff": "0.17.1",
}
SANITIZED_ANCHORS = {'sanitized_old_baseline_canonical_sha256': '084e498660694c3c13461724ae8155f13543a913029702ca0fd0ab924af59e33', 'sanitized_new_baseline_canonical_sha256': '76d5753278b3649b0111ef21c6908f21fb4b71113339250090d847906d625a0f'}
SNAPSHOT_SHA = (
    "e00eba4def4309ff1bdee0503c5dee09f115d56a7f7f31dfe48fc8946bd053bc"
)
REFUSALS = {
    "F401": f"new F/E9 diagnostic: {DIAGNOSTIC} (1 now, 0 in baseline)",
    "import": f"new core-to-CLI import: {EDGE}",
    "complexity": f"complexity grew: {PROGRESS} (42, baseline 41)",
}


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def reconstruct(after: dict, changes: dict) -> dict:
    before = copy.deepcopy(after)
    for field in ("f_e9", "complexity"):
        for identity, delta in changes[field].items():
            before[field][identity] = delta["before"]
    before["imports"] = sorted([*after["imports"], *changes["imports_removed"]])
    return before


def changed(document: dict, path: tuple, value: object) -> dict:
    result = copy.deepcopy(document)
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return result


class HistoricalLoweredRatchetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        raw = (FIXTURES / "w12_ratchet_snapshot_v1.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != SNAPSHOT_SHA:
            raise AssertionError("the frozen historical snapshot bytes changed")
        cls.snapshot = json.loads(raw)
        cls.manifest = json.loads(
            (FIXTURES / "w12_ratchet_reductions_v1.json").read_text(encoding="utf-8")
        )

    def same(self, actual: object, expected: object) -> None:
        self.assertEqual(canonical(actual), canonical(expected))

    def assert_counts(self, counts: dict) -> None:
        self.assertIs(type(counts), dict)
        for identity, count in counts.items():
            self.assertIs(type(identity), str)
            self.assertIs(type(count), int)
            self.assertGreater(count, 0)

    def assert_monotone(self, before: dict, after: dict) -> None:
        self.assertEqual(set(before), set(after))
        self.same(
            {key: value for key, value in before.items() if key not in ("f_e9", "imports", "complexity")},
            {key: value for key, value in after.items() if key not in ("f_e9", "imports", "complexity")},
        )
        for baseline in (before, after):
            for field in ("f_e9", "complexity"):
                self.assert_counts(baseline[field])
            edges = baseline["imports"]
            self.assertIs(type(edges), list)
            for edge in edges:
                self.assertIs(type(edge), str)
            self.same(edges, sorted(set(edges)))
        for field in ("f_e9", "complexity"):
            self.assertLessEqual(set(after[field]), set(before[field]))
            for identity, count in after[field].items():
                self.assertLessEqual(count, before[field][identity])
        self.assertEqual(set(before["complexity"]), set(after["complexity"]))
        self.assertLessEqual(set(after["imports"]), set(before["imports"]))

    def assert_history(self, snapshot: dict, manifest: dict) -> tuple[dict, dict]:
        self.same({key: manifest[key] for key in ANCHORS}, ANCHORS)
        self.same({key: manifest[key] for key in SANITIZED_ANCHORS}, SANITIZED_ANCHORS)
        self.same([manifest["fixture_type"], manifest["version"], manifest["effect_authority"]],
                  ["w12-monotone-ratchet-reductions", 1, False])
        self.same(manifest["unchanged_fields"], list(UNCHANGED))
        self.same([manifest["move_batch"], manifest["move_records_preserved"]], [BATCH, 8])
        self.same([snapshot["fixture_type"], snapshot["version"], snapshot["effect_authority"]],
                  ["w12-historical-monotone-ratchet-snapshot", 1, False])
        provenance = snapshot["provenance"]
        for field in ("source_parent_commit", "source_parent_tree", "ruff"):
            self.same(provenance[field], ANCHORS[field])
        for field in ("moves", "checker"):
            self.same(provenance[f"{field}_raw_sha256"], ANCHORS[f"{field}_sha256"])
        self.same(provenance["measured_report_sha256"],
                  "0861a0b924e8e31909c5f5c941b58d49c75dd85169f9b5d877a3a74a52ba724a")
        self.same(snapshot["measured_projection"], {
            "f_e9": {}, "imports": [],
            "complexity": {PROGRESS: 41}, "definitions": [PROGRESS], "repeated": {},
        })
        after = snapshot["baseline_after"]
        changes = manifest["changes"]
        self.same(changes["f_e9"], {DIAGNOSTIC: {"before": 1, "after": None}})
        self.same(changes["imports_removed"], [EDGE])
        self.assertEqual(len(changes["complexity"]), 13)
        self.assertNotIn(DIAGNOSTIC, after["f_e9"])
        self.assertNotIn(EDGE, after["imports"])
        for identity, delta in changes["complexity"].items():
            self.same(sorted(delta), ["after", "before"])
            self.assertIs(type(delta["before"]), int)
            self.assertIs(type(delta["after"]), int)
            self.assertGreater(delta["before"], delta["after"])
            self.same(after["complexity"][identity], delta["after"])
        before = reconstruct(after, changes)
        self.assert_monotone(before, after)
        for label, baseline in (("old", before), ("new", after)):
            self.same(hashlib.sha256(canonical(baseline)).hexdigest(),
                      SANITIZED_ANCHORS[f"sanitized_{label}_baseline_canonical_sha256"])
        totals = {
            "f_e9": [sum(before["f_e9"].values()), sum(after["f_e9"].values())],
            "imports": [len(before["imports"]), len(after["imports"])],
            "complexity_entries": [len(before["complexity"]), len(after["complexity"])],
        }
        self.same(totals, {"f_e9": [45, 44], "imports": [5, 4], "complexity_entries": [505, 505]})
        self.same(manifest["actual_before_after"], totals)
        self.assert_captured_moves(snapshot["moves_raw"], before, after)
        return before, after

    def assert_captured_moves(self, raw: str, before: dict, after: dict) -> None:
        self.assertIs(type(raw), str)
        self.same(hashlib.sha256(raw.encode("utf-8")).hexdigest(), ANCHORS["moves_sha256"])
        document = json.loads(raw)
        self.same([document["version"], document["batch"], len(document["moves"])], [2, BATCH, 8])
        for baseline in (before, after):
            self.same(baseline["moved"], [])
            self.same(baseline["consumed_batches"], {})
            batch, pending, problems = health.pending_batch(document, baseline)
            self.same([batch, pending, problems], [BATCH, document["moves"], []])
        for identity in (DIAGNOSTIC, PROGRESS):
            self.assertNotIn(identity.split("::", 1)[0], {move["from"].split("::", 1)[0] for move in document["moves"]})

    def projected_pair(self) -> tuple[dict, dict, dict]:
        before, after = self.assert_history(self.snapshot, self.manifest)
        state = copy.deepcopy(self.snapshot["measured_projection"])
        projected = []
        for baseline in (before, after):
            projected.append({
                "version": 1, "tool": {"ruff": ANCHORS["ruff"]}, "complexity_threshold": 15,
                "f_e9": {DIAGNOSTIC: baseline["f_e9"][DIAGNOSTIC]} if DIAGNOSTIC in baseline["f_e9"] else {},
                "imports": [EDGE] if EDGE in baseline["imports"] else [],
                "complexity": {PROGRESS: baseline["complexity"][PROGRESS]},
                "admitted": {}, "repeated": {}, "moved": [], "consumed_batches": {},
            })
        return projected[0], projected[1], state

    def assert_passes(self, baseline: dict, state: dict) -> None:
        report = health.compare(baseline, [], state)
        self.assertEqual(report.failures, [])
        self.assertEqual(report.new_debt, [])

    def test_historical_reconstruction_is_monotone(self) -> None:
        before, after = self.assert_history(self.snapshot, self.manifest)
        self.assertEqual(set(before) - set(UNCHANGED), {"f_e9", "imports", "complexity"})
        self.same([after["version"], after["tool"], after["complexity_threshold"]],
                  [1, {"ruff": "0.17.1"}, 15])

    def test_restored_debt_uses_real_compare(self) -> None:
        before, after, state = self.projected_pair()
        controls = self.manifest["controls"]
        self.same([control["kind"] for control in controls], ["F401", "import", "complexity"])
        for control in controls:
            kind = control["kind"]
            identity = {"F401": DIAGNOSTIC, "import": EDGE, "complexity": PROGRESS}[kind]
            with self.subTest(kind=kind):
                self.same(control, {"kind": kind, "identity": identity, "old_allowed": True,
                                    "new_refusal": [REFUSALS[kind]]})
                self.assert_passes(before, state)
                self.assert_passes(after, state)
                perturbed = copy.deepcopy(state)
                if kind == "F401":
                    perturbed["f_e9"][identity] = 1
                elif kind == "import":
                    perturbed["imports"].append(identity)
                else:
                    perturbed["complexity"][identity] = 42
                self.assert_passes(before, perturbed)
                report = health.compare(after, [], perturbed)
                self.assertEqual(report.failures, [REFUSALS[kind]])
                self.assertEqual(report.new_debt, [identity])

    def test_allowance_counts_require_positive_exact_integers(self) -> None:
        for identity in (DIAGNOSTIC, PROGRESS):
            for count in (True, False, 1.0, 0, -1):
                with self.subTest(identity=identity, count=repr(count)), self.assertRaises(AssertionError):
                    self.assert_counts({identity: count})

    def test_metadata_equality_retains_json_types(self) -> None:
        before, after = self.assert_history(self.snapshot, self.manifest)
        replacements = {
            "version": True,
            "complexity_threshold": 15.0,
            "admitted": {PROGRESS: "unreviewed"},
            "repeated": {PROGRESS: ["changed"]},
            "moved": [{"from": PROGRESS, "to": PROGRESS}],
            "consumed_batches": {BATCH: "changed"},
            "tool": {"ruff": "changed"},
            "created": "changed",
        }
        for field, value in replacements.items():
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self.assert_monotone(before, changed(after, (field,), value))

    def test_historical_tampering_is_rejected_in_memory(self) -> None:
        existing = next(iter(self.snapshot["baseline_after"]["f_e9"]))
        cases = [
            (("baseline_after", "complexity", PROGRESS), 42),
            (("baseline_after", "f_e9", existing), True),
            (("version",), True),
            (("effect_authority",), 0),
            (("moves_raw",), self.snapshot["moves_raw"] + "\n"),
            (("provenance", "checker_raw_sha256"), "0" * 64),
            (("measured_projection", "complexity", PROGRESS), 41.0),
        ]
        for path, value in cases:
            with self.subTest(path=path), self.assertRaises(AssertionError):
                self.assert_history(changed(self.snapshot, path, value), self.manifest)

    def test_reduction_manifest_tampering_is_rejected_in_memory(self) -> None:
        cases = [
            (("changes", "complexity", PROGRESS, "before"), True),
            (("changes", "complexity", PROGRESS, "after"), 41.0),
            (("changes", "f_e9", DIAGNOSTIC, "before"), True),
            (("source_parent_commit",), "0" * 40),
            (("new_baseline_canonical_sha256",), "0" * 64),
            (("effect_authority",), 0),
            (("move_records_preserved",), True),
        ]
        for path, value in cases:
            with self.subTest(path=path), self.assertRaises(AssertionError):
                self.assert_history(self.snapshot, changed(self.manifest, path, value))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import hashlib
import io
import json
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import prepare_route_feasibility as planner
from cwo_core import work_sizing

FIXTURE = ROOT / "tests" / "fixtures" / "route-feasibility-preparation.json"


def bind(payload):
    payload["bound_input_sha256"] = planner.input_sha256(payload)
    return payload


def record(*, tiny=False, alternatives=False):
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    policy = json.loads((ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8"))
    contract = fixture["tiny_contract" if tiny else "whole_contract"]
    specs = [("plan", "planning" if tiny else "author", [], None, "primary")]
    if not tiny:
        specs += [
            ("review", "review", ["plan"], "plan", "dependent"),
            ("synthesis", "synthesis", ["review"], "review", "dependent"),
            ("validation", "validation", ["synthesis"], "synthesis", "dependent"),
        ]
    if alternatives:
        contract["required_roles"].extend(fixture["alternative_roles"])
        specs += [
            ("retry", "retry", ["plan"], "plan", "retry"),
            ("fallback", "fallback", ["plan"], "plan", "fallback"),
            ("sibling", "sibling", ["plan"], "plan", "sibling"),
        ]
    payload = {
        "parent_id": "bead-preparation", "run_id": "run-offline", "aggregate_id": "aggregate-declared",
        "purpose": "Prepare a bounded offline note route.", "output": "Declared note and dependent reports.",
        "acceptance": ["Every separately declared role has its dependent inputs and allowance."],
        "task_contract": contract, "policy": policy,
        "policy_sha256": planner.canonical_authority_sha256(policy),
        "estimator_version": planner.ESTIMATOR_VERSION,
        "projection_policy": copy.deepcopy(fixture["projection_policy"]),
        "limits": {key: 1_000_000_000 for key in planner.RESOURCES}, "nodes": [],
    }
    for identity, role, dependencies, parent, kind in specs:
        source = copy.deepcopy(fixture["estimate_source"])
        source.update(work_unit_id=identity, bead_id=payload["parent_id"], primary_outcome=f"Offline {role} note.")
        unit = work_sizing.evaluate_work_estimate(source, policy=policy)
        node = {
            "id": identity, "role": role, "depends_on": dependencies, "lineage_parent": parent, "kind": kind,
            "execution": copy.deepcopy(fixture["execution"]), "prompt": f"Prepare the declared {role} note.",
            "wrappers": [{"id": "wrapper", "text": "Offline préparation only."}],
            "attachments": [{"id": "acceptance", "text": "Return the declared note."}],
            "sources": [{"id": "source-1", "text": "abc"}],
            "estimate_source": source, "source_sha256": work_sizing.canonical_work_estimate_sha256(source),
            "unit_estimate": unit, "unit_sha256": work_sizing.canonical_work_estimate_sha256(unit),
            "sizing_rationale": "Use the real per-unit computed allowance, plus the declared token/cost projection.",
            "uncertainty": {"status": "bounded", "detail": "Toy conservative assumptions, not measured billing."},
            "additional_input_tokens_upper": 2000,
        }
        node["rendered_request"] = planner.render_request(node)
        payload["nodes"].append(node)
    return bind(payload)


def cli(payload):
    stream = io.BytesIO(json.dumps(payload, ensure_ascii=True).encode("utf-8"))
    output = io.StringIO()
    code = planner.main(stream, output)
    return code, json.loads(output.getvalue())


class RoutePreparationTest(unittest.TestCase):
    def assert_inert(self, result):
        for field in ("operative", "qualified", "effect_authority", "external_completeness_authenticated",
                      "actual_quota_known", "actual_provider_billing_known"):
            self.assertIs(result[field], False)

    def test_whole_declared_route_uses_real_validated_allowances(self):
        payload = record()
        before = copy.deepcopy(payload)
        code, result = cli(payload)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "within-declared-limits")
        self.assertEqual(len(result["nodes"]), 4)
        for resource, unit_key in (("tool_calls", "tool_calls_hard"), ("runtime_seconds", "runtime_seconds_hard")):
            expected = sum(node["unit_estimate"]["aggregate_allowance"][unit_key] for node in payload["nodes"])
            self.assertEqual(result["totals"][resource], expected)
        for node in payload["nodes"]:
            self.assertEqual(work_sizing.validate_work_estimate(node["unit_estimate"], policy=payload["policy"]), [])
        measured = result["nodes"][0]["measurements"]["rendered_request"]
        self.assertEqual(measured, planner._measurement(payload["nodes"][0]["rendered_request"]))
        expected_input = sum(len(node["rendered_request"].encode("utf-8")) + 2000 for node in payload["nodes"])
        self.assertEqual(result["totals"]["tokens"], expected_input + 4 * 32)
        self.assertEqual(result["totals"]["cost_microunits"], expected_input * 3 + 4 * (32 * 7 + 11))
        self.assertGreater(measured["bytes"], len(payload["nodes"][0]["rendered_request"]))
        self.assert_inert(result)
        self.assertEqual(payload, before)

    def test_one_unit_planning_is_proportionate(self):
        result = planner.prepare(record(tiny=True))
        self.assertEqual(result["status"], "within-declared-limits")
        self.assertEqual([node["role"] for node in result["nodes"]], ["planning"])
        self.assert_inert(result)

    def test_all_alternatives_share_one_limit_and_are_counted_once(self):
        payload = record(alternatives=True)
        result = planner.prepare(payload)
        self.assertEqual(len(result["nodes"]), 7)
        self.assertEqual(len({node["id"] for node in result["nodes"]}), 7)
        for resource in planner.RESOURCES:
            self.assertEqual(result["totals"][resource], sum(node["amounts"][resource] for node in result["nodes"]))
        payload["limits"] = result["totals"].copy()
        self.assertEqual(planner.prepare(bind(payload))["status"], "within-declared-limits")
        for resource in planner.RESOURCES:
            bad = copy.deepcopy(payload)
            bad["limits"][resource] -= 1
            self.assertEqual(planner.prepare(bind(bad))["status"], "over-budget", resource)

    def test_contract_omission_missing_node_orphan_cycle_and_replay(self):
        cases = []
        omitted = record()
        omitted["nodes"].pop(1)
        cases.append((omitted, "role omission"))
        missing = record()
        missing["nodes"][1]["depends_on"] = ["missing"]
        missing["task_contract"]["required_roles"][1]["depends_on"] = ["missing"]
        cases.append((missing, "missing dependency"))
        orphan = record()
        orphan["nodes"][1]["lineage_parent"] = "missing"
        cases.append((orphan, "orphan"))
        cycle = record()
        cycle["nodes"][1].update(depends_on=["synthesis"], lineage_parent="synthesis")
        cycle["task_contract"]["required_roles"][1]["depends_on"] = ["synthesis"]
        cases.append((cycle, "cycle"))
        replay = record()
        replay["nodes"].append(copy.deepcopy(replay["nodes"][0]))
        cases.append((replay, "duplicate"))
        for payload, reason in cases:
            with self.subTest(reason=reason):
                result = planner.prepare(bind(payload))
                self.assertEqual(result["status"], "invalid")
                self.assertIn(reason, " ".join(result["reasons"]))

    def test_typed_identifiers_and_unit_identity_cannot_alias(self):
        for identity in (True, 1, ["plan"], ""):
            payload = record()
            payload["nodes"][0]["id"] = identity
            self.assertEqual(planner.prepare(bind(payload))["status"], "invalid")
        payload = record(alternatives=True)
        retry = payload["nodes"][4]
        retry["estimate_source"]["work_unit_id"] = "plan"
        retry["unit_estimate"] = work_sizing.evaluate_work_estimate(retry["estimate_source"], policy=payload["policy"])
        retry["source_sha256"] = work_sizing.canonical_work_estimate_sha256(retry["estimate_source"])
        retry["unit_sha256"] = work_sizing.canonical_work_estimate_sha256(retry["unit_estimate"])
        self.assertIn("scope identity", " ".join(planner.prepare(bind(payload))["reasons"]))

    def test_changed_inputs_rendering_policy_and_estimates_invalidate_bindings(self):
        for field in ("prompt", "wrappers", "attachments", "sources", "execution"):
            payload = record()
            node = payload["nodes"][0]
            if field == "prompt":
                node[field] += " changed"
            elif field == "execution":
                node[field]["options"]["temperature"] = 0.5
            else:
                node[field][0]["text"] += " changed"
            self.assertIn("bound input digest drift", " ".join(planner.prepare(payload)["reasons"]))
            self.assertIn("rendered request drift", " ".join(planner.prepare(bind(payload))["reasons"]))
        payload = record()
        payload["policy"]["work_sizing"]["version"] = 2
        self.assertIn("policy digest drift", " ".join(planner.prepare(payload)["reasons"]))
        for field in ("source_sha256", "unit_sha256"):
            payload = record()
            payload["nodes"][0][field] = "0" * 64
            self.assertEqual(planner.prepare(bind(payload))["status"], "invalid")
        payload = record()
        node = payload["nodes"][0]
        node["estimate_source"]["estimates"]["tool_calls_p90"] += 1
        node["source_sha256"] = work_sizing.canonical_work_estimate_sha256(node["estimate_source"])
        self.assertIn("stale unit", " ".join(planner.prepare(bind(payload))["reasons"]))
        fresh = record(tiny=True)
        previous = fresh["bound_input_sha256"]
        fresh["nodes"][0]["execution"]["effort"] = "new-declared-effort"
        fresh["nodes"][0]["rendered_request"] = planner.render_request(fresh["nodes"][0])
        self.assertEqual(planner.prepare(fresh)["status"], "invalid")
        result = planner.prepare(bind(fresh))
        self.assertEqual(result["status"], "within-declared-limits")
        self.assertNotEqual(result["bound_input_sha256"], previous)

    def test_changed_source_bytes_and_uncertainty_are_not_ignored(self):
        payload = record()
        node = payload["nodes"][0]
        node["sources"][0]["text"] = "abcd"
        node["rendered_request"] = planner.render_request(node)
        self.assertIn("context/source bytes", " ".join(planner.prepare(bind(payload))["reasons"]))
        payload = record()
        payload["nodes"][0]["uncertainty"]["status"] = "unresolved"
        self.assertEqual(planner.prepare(bind(payload))["status"], "unassessable")

    def test_unknown_measurement_billing_output_and_budget_stay_unknown(self):
        for unknown in ("measurement", "billing", "output", *planner.RESOURCES):
            payload = record()
            if unknown == "measurement":
                payload["projection_policy"].update(mode="unknown", tokens_per_utf8_byte_upper=None,
                                                    input_overhead_tokens=None, billing=None)
            elif unknown == "billing":
                payload["projection_policy"]["billing"] = None
            elif unknown == "output":
                payload["nodes"][0]["execution"]["output_tokens_upper"] = None
                payload["nodes"][0]["rendered_request"] = planner.render_request(payload["nodes"][0])
            else:
                payload["limits"][unknown] = None
            result = planner.prepare(bind(payload))
            self.assertEqual(result["status"], "unassessable", unknown)
            self.assertTrue(any(value == "unknown" for value in result["checks"].values()))
            if unknown in ("measurement", "billing", "output"):
                self.assertIsNone(result["totals"]["cost_microunits"])

    def test_real_old_validator_and_new_consumer_reject_controlled_bad_units(self):
        for mutation in ("allowance-bool", "derived-route", "estimate-bool"):
            payload = record()
            unit = payload["nodes"][0]["unit_estimate"]
            if mutation == "allowance-bool":
                unit["aggregate_allowance"]["tool_calls_hard"] = True
            elif mutation == "derived-route":
                unit["route"] = "architect"
            else:
                unit["estimates"]["tool_calls_p90"] = True
            self.assertTrue(work_sizing.validate_work_estimate(unit, policy=payload["policy"]), mutation)
            self.assertEqual(planner.prepare(bind(payload))["status"], "invalid", mutation)

    def test_refinement_remains_unsupported(self):
        payload = record()
        unit = payload["nodes"][0]["unit_estimate"]
        unit["parent_estimate_sha256"] = "0" * 64
        self.assertIn("requires validate_work_estimate_refinement",
                      " ".join(work_sizing.validate_work_estimate(unit, policy=payload["policy"])))
        result = planner.prepare(bind(payload))
        self.assertIn("refinement authority is unsupported", " ".join(result["reasons"]))
        self.assert_inert(result)

    def test_limits_json_utf8_and_arithmetic_fail_structurally(self):
        for value in (True, -1, 1.5):
            payload = record()
            payload["limits"]["tokens"] = value
            self.assertEqual(planner.prepare(bind(payload))["status"], "invalid")
        for value in (2**100, float("inf"), float("nan")):
            payload = record()
            payload["limits"]["tokens"] = value
            self.assertEqual(planner.prepare(payload)["status"], "invalid")
        payload = record()
        payload["projection_policy"]["tokens_per_utf8_byte_upper"] = planner.MAX_INTEGER
        self.assertIn("projected input", " ".join(planner.prepare(bind(payload))["reasons"]))
        payload = record()
        payload["nodes"][0]["prompt"] = "\ud800"
        self.assertEqual(planner.prepare(payload)["status"], "invalid")
        for raw in (b"\xff", b"{", b'{"x":1,"x":2}', b'{"x":NaN}', b"[" * 2000, b" " * (planner.MAX_BYTES + 1)):
            output = io.StringIO()
            self.assertEqual(planner.main(io.BytesIO(raw), output), 2)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "invalid")
            self.assert_inert(result)

    def test_cli_does_not_call_watched_effect_boundaries(self):
        payload = record()
        watched = (
            "dispatch_work.execute_local_envelope",
            "cwo_core.local_invocation.open_ledger",
            "cwo_core.invocation_ledger.InvocationLedger.reserve",
            "urllib.request.urlopen",
            "urllib.request.OpenerDirector.open",
            "subprocess.Popen",
            "cwo_core.work_sizing.load_policy",
            "cwo_core.work_sizing.build_policy_fit_commitment",
            "cwo_core.work_sizing.build_worker_commitment_from_receipt",
        )
        with ExitStack() as stack:
            spies = [stack.enter_context(patch(name, side_effect=AssertionError(name))) for name in watched]
            self.assertEqual(cli(payload)[0], 0)
            payload["limits"]["tool_calls"] = 0
            self.assertEqual(cli(bind(payload))[0], 1)
            for spy in spies:
                spy.assert_not_called()

    def test_context_source_coverage_is_exact_after_rebinding(self):
        def rebound(duplicate):
            payload = record(tiny=True)
            node = payload["nodes"][0]
            source = copy.deepcopy(node["estimate_source"])
            first = copy.deepcopy(source["context_manifest"][0])
            second = {**copy.deepcopy(first), "path": "source-2", "bytes": 3,
                      "sha256": hashlib.sha256(b"def").hexdigest()}
            source["context_manifest"] = [first, copy.deepcopy(first) if duplicate else second]
            node["sources"] = [{"id": "source-1", "text": "abc"}, {"id": "source-2", "text": "def"}]
            node["estimate_source"] = source
            node["source_sha256"] = work_sizing.canonical_work_estimate_sha256(source)
            node["unit_estimate"] = work_sizing.evaluate_work_estimate(source, policy=payload["policy"])
            self.assertEqual(work_sizing.validate_work_estimate(node["unit_estimate"], policy=payload["policy"]), [])
            node["unit_sha256"] = work_sizing.canonical_work_estimate_sha256(node["unit_estimate"])
            node["rendered_request"] = planner.render_request(node)
            return bind(payload)

        positive = planner.prepare(rebound(False))
        self.assertEqual(positive["status"], "within-declared-limits")
        self.assert_inert(positive)
        negative = planner.prepare(rebound(True))
        self.assertEqual(negative["status"], "invalid")
        self.assertIn("duplicate estimate context manifest path", negative["reasons"])
        self.assert_inert(negative)


if __name__ == "__main__":
    unittest.main()

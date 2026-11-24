"""Offline critic workflow through the recorded return and synthesis entry points."""
from __future__ import annotations

from contextlib import redirect_stdout
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.host_acceptance import record_received_evaluation
from cwo_core.host_records import HostRecordStore, using_test_store
from cwo_core.host_return_intake import record_manual_return, record_received_return
from cwo_core.model_identities import resolve_model
from cwo_core.peer_review import pending_evaluation_sha256
from cwo_core.returns import make_acceptance_decision
from build_contractor_packet import main as build_packet_main
from dispatch_work import main as dispatch_main
from evaluate_return import main as evaluate_main
from normalize_contractor_return import main as normalize_main
from route_work import main as route_main
from tests.test_zero_trust_consensus import claim


CANDIDATE = "retry-plan-revision-3"
SCOPE = "retry-plan-design"


class SynthesisWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = HostRecordStore.for_tests(self.root / "host")
        self.enterContext(using_test_store(self.store))

    def _run_json(self, command, main, *args):
        out = StringIO()
        with patch.object(sys, "argv", [command, *args]), redirect_stdout(out):
            main()
        return json.loads(out.getvalue())

    def _json_file(self, name, value):
        target = self.root / name
        target.write_text(json.dumps(value), encoding="utf-8")
        return str(target)

    def _review(self, dispatch_id, report, evaluator_args):
        pending = make_acceptance_decision(report, **evaluator_args, peer_review_status="pending")
        reviewer = dict(provider="openai", model_family="gpt", model_id=resolve_model("astra"),
                        reasoning_effort="max", dispatch_id=f"{dispatch_id}-peer")
        target = dict(dispatch_id=dispatch_id, return_sha256=sha256(report.encode()).hexdigest(),
                      evaluation_sha256=pending_evaluation_sha256(pending))
        self.store.write_dispatch(**reviewer, dispatch_role="peer-review", session_id="peer-session",
            request_sha256="c" * 64, review_target=target, executor="codex_architecture_critic")
        review = dict(record_type="cwo-peer-review", version=2, decision="passed", reviewer_identity=reviewer,
                      return_sha256=target["return_sha256"], evaluation_sha256=target["evaluation_sha256"])
        record_received_return(self.store, reviewer["dispatch_id"], json.dumps(review).encode())
        return dict(peer_review_record=review, peer_review_status="passed", peer_review_reviewer=reviewer)

    def _critic(self, executor, provider_key, identity, value, *, dispatch_id=None,
                manual=False, omit_peer_review=False, provider_conflicts=None):
        dispatch_id = dispatch_id or executor
        provider, family, model = identity
        report = (ROOT / "examples/sample-contractor-return.md").read_text(encoding="utf-8")
        report = report.replace("contract-jd-security-reasoning", "contract-jd-architecture-reasoning")
        report = report.replace("not required for this sample return", "independent review when required")
        report = report.replace("Risks or gaps:", f"Validation finding: Rotate the retry-log encryption key every {value} days.\nRisks or gaps:")
        mode = "manual_ui" if provider == "anthropic" else "native"
        context = dict(task="critic-task", scope=SCOPE, candidate=CANDIDATE, dispatch_id=dispatch_id,
                       packet_sha256=None, executor=executor)
        prepared = self.store.write_dispatch(dispatch_id=dispatch_id, dispatch_role="executor",
            provider=provider, model_family=None, model_id=None, reasoning_effort=None, session_id=None,
            request_sha256="b" * 64, bead_id="critic-task", executor=executor, provider_key=provider_key,
            evaluation_metadata=dict(dispatch_mode=mode, peer_review_required=provider == "anthropic",
                                     provider_conflict_domains=provider_conflicts or []))
        if manual:
            record_manual_return(self.store, dispatch_id, report.encode())
        else:
            self.store.write_observed_dispatch(dispatch_id, prepared_record_sha256=prepared,
                observation_sha256="d" * 64, provider=provider, model_family=family, model_id=model,
                reasoning_effort="high", session_id=f"{dispatch_id}-session",
                evaluation_metadata={"source_context": context})
            record_received_return(self.store, dispatch_id, report.encode())
        evaluator_args = dict(bead_id="critic-task", dispatch_id=dispatch_id, executor=executor,
            provider_key=provider_key, dispatch_mode=mode, share_boundary="redacted-packet",
            job_description_label="contract-jd-architecture-reasoning",
            peer_review_required=provider == "anthropic" and not omit_peer_review)
        review = self._review(dispatch_id, report, evaluator_args) if provider == "anthropic" and not manual else {}
        result = make_acceptance_decision(report, **evaluator_args, **review)
        self.assertEqual(result["accepted_for_use"], not manual or omit_peer_review, result["penalty_reasons"])
        record_received_evaluation(report, result)
        report_path = self.root / f"{dispatch_id}.md"
        report_path.write_text(report, encoding="utf-8")
        inputs = dict(evaluation=self._json_file(f"{dispatch_id}.json", result), **{"return": str(report_path)},
            zero_trust_claims=[{**claim("crypto", "key_rotation_days", value), "evidence": "Validation finding"}])
        record = dict(record_type="cwo-return-adjudication", version=1, adjudication_id=f"lead-{dispatch_id}",
            dispatch_id=dispatch_id, return_sha256=sha256(report.encode()).hexdigest(), candidate=CANDIDATE, scope=SCOPE,
            finding_ids=["finding:key-rotation"], decision="accepted", rationale="Lead reviewed this exact return.",
            supporting_evidence=[dict(artifact="validation.txt", artifact_type="validation-log",
                sha256=sha256(b"independent validation").hexdigest(), finding_ids=["finding:key-rotation"])],
            authority={"rule": "synthesis-input-adjudication"}, adjudicator="lead")
        return inputs, record

    def _panel(self, other_value="3", *, manual=False, omit_peer_review=False):
        route = self._run_json("route_work.py", route_main, "--json", "--external-ok", "--share-boundary",
            "redacted-packet", "--requested-role", "architecture",
            "Use Claude Opus 4.6 and Codex as architecture critics. Use model synthesis and zero-trust consensus.")
        self.assertTrue(route["model_synthesis"]["active"])
        self.assertIn("claude_architecture_critic",
                      {entry["executor"] for entry in route["architecture_critic_contracts"]})
        self.route_path = self._json_file("route.json", route)
        return zip(
            self._critic("codex_architecture_critic", "internal_codex", ("openai", "gpt", resolve_model("sol")), "3"),
            self._critic("claude_architecture_critic", "anthropic_manual",
                         ("anthropic", "claude", "claude-opus-4-6"), other_value, manual=manual,
                         omit_peer_review=omit_peer_review),
        )

    def _synthesize(self, inputs, decisions, *, candidate=CANDIDATE):
        from evaluate_synthesis import main

        return self._run_json("evaluate_synthesis.py", main,
            "--inputs", self._json_file("inputs.json", inputs), "--route", self.route_path,
            "--candidate", candidate, "--scope", SCOPE,
            "--adjudications", self._json_file("adjudications.json", decisions))

    def test_two_evaluated_critics_agree(self):
        inputs, decisions = self._panel()
        before = self.store.audit_events()
        result = self._synthesize(inputs, decisions)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["primary_input_count"], 2)
        self.assertEqual(result["zero_trust_consensus"]["independent_trust_domains"], ["anthropic", "openai"])
        self.assertEqual(result["zero_trust_consensus"]["consensus_status"], "informational")
        self.assertTrue(result["zero_trust_consensus"]["agreement_is_not_validation"])
        self.assertFalse(result["trusted_host_authority"])
        self.assertEqual(self.store.audit_events(), before)

    def test_material_disagreement_requires_architect_resolution(self):
        inputs, decisions = self._panel("4")
        result = self._synthesize(inputs, decisions)
        consensus = result["zero_trust_consensus"]
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(consensus["recommended_action"], "escalate")
        self.assertEqual(consensus["divergence_report"][0]["resolution_authority"], "architect")

    def test_manual_preparation_cannot_clear_missing_peer_review(self):
        inputs, decisions = self._panel(manual=True)
        result = self._synthesize(inputs, decisions)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["primary_input_count"], 1)
        self.assertIn("peer-review-pending", result["held_inputs"][0]["hold_reasons"])

    def test_original_dispatch_still_requires_peer_review_if_evaluation_omitted_it(self):
        inputs, decisions = self._panel(manual=True, omit_peer_review=True)
        result = self._synthesize(inputs, decisions)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["primary_input_count"], 1)
        self.assertIn("peer-review-pending", result["held_inputs"][0]["hold_reasons"])

    def test_manual_packet_entry_points_ingest_and_preserve_the_original_hold(self):
        inputs, decisions = self._panel()
        bead = self._json_file("manual-task.json", {
            "id": "manual-critic", "title": "Review the retry plan", "description": "Review the public plan.",
            "labels": ["contractor-only", "no-codex-exec", "contract-jd-architecture-reasoning"],
        })
        packet = self._run_json("build_contractor_packet.py", build_packet_main,
            "--bead", "manual-critic", "--bead-json-file", bead, "--executor", "claude_architecture_critic",
            "--external-ok", "--epic", "example-synthesis", "--share-boundary", "redacted-packet",
            "--format", "json", "--dispatch-id", "built-manual-critic")
        packet_path = self._json_file("manual-packet.json", packet)
        artifact = self._run_json("dispatch_work.py", dispatch_main, "--packet", packet_path, "--json")
        self.assertEqual(artifact["dispatch_mode"], "manual_ui")
        self.assertIn("Review the retry plan", artifact["manual_prompt"])
        report_path = inputs[1]["return"]
        normalized = self._run_json("normalize_contractor_return.py", normalize_main,
            "--contractor-packet", packet_path, "--file", report_path)
        self.assertEqual(normalized["dispatch_id"], packet["dispatch_id"])
        evaluation = self._run_json("evaluate_return.py", evaluate_main,
            "--contractor-packet", packet_path, "--file", report_path, "--json")
        self.assertTrue(evaluation["accepted_for_use"])
        inputs = (inputs[0], dict(inputs[1], evaluation=self._json_file("manual-evaluation.json", evaluation)))
        result = self._synthesize(inputs, [decisions[0]])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["primary_input_count"], 1)
        self.assertEqual(result["held_inputs"][0]["lane"], packet["dispatch_id"])
        self.assertIn("peer-review-pending", result["held_inputs"][0]["hold_reasons"])

    def test_recorded_provider_conflicts_still_require_independent_review(self):
        inputs, decisions = self._panel()
        review, adjudication = self._critic("codex_architecture_critic", "internal_codex",
            ("openai", "gpt", resolve_model("sol")), "3", dispatch_id="native-conflict-critic",
            provider_conflicts=["model-provider-competition"])
        result = self._synthesize([review, inputs[1]], [adjudication, decisions[1]])
        self.assertEqual(result["status"], "blocked")
        self.assertIn("provider-conflict-peer-review-pending", result["held_inputs"][0]["hold_reasons"])
        self.assertEqual(result["held_inputs"][0]["hold_classification"], "provider-conflict-pending")

    def test_altered_evaluation_does_not_match_ordinary_receipt(self):
        inputs, decisions = self._panel(manual=True)
        path = Path(inputs[1]["evaluation"])
        value = json.loads(path.read_text(encoding="utf-8"))
        value.update(implementation_blocked=False, accepted_for_use=True, hold_reasons=[])
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "recorded evaluation"):
            self._synthesize(inputs, decisions)

    def test_only_external_lane_quarantined_blocks_even_with_two_internal_inputs(self):
        inputs, decisions = self._panel()
        internal, accepted = self._critic("codex_architecture_critic", "internal_codex",
            ("openai", "gpt", resolve_model("sol")), "3", dispatch_id="another-native-review")
        quarantine = dict(decisions[1], decision="quarantined", supporting_evidence=[])
        result = self._synthesize([*inputs, internal], [decisions[0], quarantine, accepted])
        self.assertEqual(result["primary_input_count"], 2)
        self.assertIn("all external inputs are quarantined or boundary-tainted", result["blocked_reasons"])

    def test_changed_return_bytes_and_candidate_refuse(self):
        inputs, decisions = self._panel()
        with self.assertRaisesRegex(SystemExit, "candidate"):
            self._synthesize(inputs, decisions, candidate="retry-plan-revision-4")
        Path(inputs[0]["return"]).write_text("different return", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "return receipt"):
            self._synthesize(inputs, decisions)

    def test_duplicate_return_cannot_supply_two_primary_lanes(self):
        inputs, decisions = self._panel()
        result = self._synthesize([inputs[0], inputs[0]], [decisions[0]])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["primary_input_count"], 0)
        self.assertEqual(result["zero_trust_consensus"]["independent_trust_domain_count"], 0)
        self.assertTrue(all(lane["dispatch_binding"]["state"] == "failed" for lane in result["input_summaries"]))

    def test_recommended_primary_requires_existing_adjudication(self):
        inputs, _ = self._panel()
        result = self._synthesize(inputs, [])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["primary_input_count"], 0)


if __name__ == "__main__":
    unittest.main()

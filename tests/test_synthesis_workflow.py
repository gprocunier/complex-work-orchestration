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
from cwo_core.host_return_intake import MAX_RETURN_BYTES, record_manual_return, record_received_return
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
                manual=False, omit_peer_review=False, provider_conflicts=None, canonical_alias=False):
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
            if canonical_alias:
                self.store.write_return_received(dispatch_id, sha256(report.encode()).hexdigest(),
                    capture_provenance="host-capture-v1",
                    canonical_return_sha256=sha256(report.replace("\n", "\r\n").encode()).hexdigest())
            else:
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

    def _synthesize(self, inputs, decisions, *, candidate=CANDIDATE, scope=SCOPE):
        from evaluate_synthesis import main

        return self._run_json("evaluate_synthesis.py", main,
            "--inputs", self._json_file("inputs.json", inputs), "--route", self.route_path,
            "--candidate", candidate, "--scope", scope,
            "--adjudications", self._json_file("adjudications.json", decisions))

    def _record_input(self, item, dispatch_id):
        record, = self.store.find("evaluation", dispatch_id=dispatch_id)
        entry = dict(item, evaluation_record_sha256=record["_record_sha256"])
        del entry["evaluation"]
        return entry

    def test_host_evaluation_reference_matches_file_and_preserves_consensus(self):
        inputs, decisions = self._panel()
        expected = self._synthesize(inputs, decisions)
        referenced = self._record_input(inputs[1], decisions[1]["dispatch_id"])
        Path(inputs[1]["evaluation"]).unlink()
        before = self.store.audit_events()
        result = self._synthesize([inputs[0], referenced], decisions)
        self.assertEqual(result, expected)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(self.store.audit_events(), before)

    def test_requires_exactly_one_evaluation_source_and_a_return_file(self):
        inputs, decisions = self._panel()
        referenced = self._record_input(inputs[0], decisions[0]["dispatch_id"])
        return_file = {"return": referenced["return"]}
        for entry in (return_file, dict(referenced, evaluation=inputs[0]["evaluation"])):
            with self.subTest(entry=entry), self.assertRaisesRegex(SystemExit, "exactly one of evaluation"):
                self._synthesize([entry, inputs[1]], decisions)
        missing_return = dict(evaluation_record_sha256=referenced["evaluation_record_sha256"])
        with self.assertRaisesRegex(SystemExit, "name its return file"):
            self._synthesize([missing_return, inputs[1]], decisions)

    def test_evaluation_reference_rejects_invalid_missing_and_wrong_type_digests(self):
        inputs, decisions = self._panel()
        dispatch_id = decisions[0]["dispatch_id"]
        for record_id, error in (
            (None, "requires a SHA-256 id"),
            ("missing", "requires a SHA-256 id"),
            ("f" * 64, "host record unavailable"),
            (self.store.require_dispatch(dispatch_id)["_record_sha256"], "record type mismatch"),
        ):
            with self.subTest(record_id=record_id), self.assertRaisesRegex(SystemExit, error):
                entry = {"return": inputs[0]["return"], "evaluation_record_sha256": record_id}
                self._synthesize([entry, inputs[1]], decisions)

    def test_reference_requires_the_selected_record_itself_to_bind_current_evidence(self):
        inputs, decisions = self._panel()
        dispatch_id = decisions[0]["dispatch_id"]
        referenced = self._record_input(inputs[0], dispatch_id)
        record = self.store.get(referenced["evaluation_record_sha256"], record_type="evaluation")
        payload = {key: record[key] for key in (
            "dispatch_id", "bead_id", "return_sha256", "evaluation_sha256", "evaluation", "policy_sha256",
            "dispatch_record_sha256", "return_record_sha256",
        )}
        for field in ("dispatch_id", "return_sha256", "evaluation_sha256", "policy_sha256",
                      "dispatch_record_sha256", "return_record_sha256"):
            with self.subTest(field=field), self.assertRaisesRegex(SystemExit, "current recorded evaluation"):
                stale_record = self.store.write_record("evaluation", **dict(payload, **{field: "f" * 64}))
                self._synthesize([dict(referenced, evaluation_record_sha256=stale_record), inputs[1]], decisions)

        different_provider = dict(payload["evaluation"], provider_key="anthropic_manual")
        wrong_identity = self.store.write_record("evaluation", **dict(
            payload, evaluation=different_provider, evaluation_sha256=pending_evaluation_sha256(different_provider)))
        with self.assertRaisesRegex(SystemExit, "evaluation identity"):
            self._synthesize([dict(referenced, evaluation_record_sha256=wrong_identity), inputs[1]], decisions)

    def test_referenced_evaluation_requires_exact_bytes_and_recorded_scope(self):
        inputs, decisions = self._panel()
        critic, adjudication = self._critic("codex_architecture_critic", "internal_codex",
            ("openai", "gpt", resolve_model("sol")), "3", dispatch_id="critic-with-canonical-alias",
            canonical_alias=True)
        referenced = self._record_input(critic, adjudication["dispatch_id"])
        decisions = [adjudication, decisions[1]]
        with self.assertRaisesRegex(SystemExit, "candidate or scope"):
            self._synthesize([referenced, inputs[1]], decisions, scope="other-design")
        path = Path(referenced["return"])
        alias = path.read_bytes().replace(b"\n", b"\r\n")
        path.write_bytes(alias)
        legacy = self._synthesize([critic, inputs[1]], decisions)
        self.assertEqual(legacy["input_provenance"][0]["return_sha256"], sha256(alias).hexdigest())
        with self.assertRaisesRegex(SystemExit, "exact host return receipt"):
            self._synthesize([referenced, inputs[1]], decisions)

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
        referenced = self._record_input(inputs[1], decisions[1]["dispatch_id"])
        result = self._synthesize([inputs[0], referenced], decisions)
        self.assertEqual(result, self._synthesize(inputs, decisions))
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["primary_input_count"], 1)
        self.assertIn("peer-review-pending", result["held_inputs"][0]["hold_reasons"])

    def _manual_packet_input(self, report_path, *, peer_required=False):
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
        normalized = self._run_json("normalize_contractor_return.py", normalize_main,
            "--contractor-packet", packet_path, "--file", report_path)
        self.assertEqual(normalized["dispatch_id"], packet["dispatch_id"])
        peer_args = ["--peer-review-required", "--peer-review-status", "pending"] if peer_required else []
        evaluation = self._run_json("evaluate_return.py", evaluate_main,
            "--contractor-packet", packet_path, "--file", report_path, "--json", *peer_args)
        self.assertEqual(evaluation["accepted_for_use"], not peer_required)
        return {"return": report_path, "evaluation": self._json_file("manual-evaluation.json", evaluation)}

    def test_manual_packet_entry_points_ingest_and_preserve_the_original_hold(self):
        inputs, decisions = self._panel()
        packet_input = self._manual_packet_input(inputs[1]["return"])
        result = self._synthesize([inputs[0], packet_input], [decisions[0]])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["primary_input_count"], 1)
        self.assertEqual(result["held_inputs"][0]["lane"], "built-manual-critic")
        self.assertIn("peer-review-pending", result["held_inputs"][0]["hold_reasons"])

    def _operator_codex_input(self, report_path):
        captured = self.root / "operator-codex-return.md"
        captured.write_bytes(Path(report_path).read_bytes().replace(b"\n", b"\r\n"))
        origin = dict(capture_id="operator-codex", candidate=CANDIDATE, scope=SCOPE,
                      return_sha256=sha256(captured.read_bytes()).hexdigest())
        return {"return": str(captured), "operator_codex": origin,
                "zero_trust_claims": [claim("crypto", "key_rotation_days", "3")]}

    def test_operator_codex_input_appears_with_the_recorded_packet_and_keeps_both_holds(self):
        inputs, _ = self._panel()
        codex = self._operator_codex_input(inputs[0]["return"])
        packet = self._manual_packet_input(inputs[1]["return"], peer_required=True)
        packet["zero_trust_claims"] = inputs[1]["zero_trust_claims"]
        before = self.store.audit_events()
        result = self._synthesize([codex, packet], [])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["primary_input_count"], 0)
        self.assertFalse(result["execution_permitted"])
        self.assertFalse(result["trusted_host_authority"])
        self.assertEqual(result["zero_trust_consensus"]["comparable_claim_count"], 0)
        advisory, peer_pending = result["held_inputs"]
        self.assertEqual(advisory["synthesis_use"], "open-risk")
        self.assertIn("nonproduction-advisory: unqualified source", advisory["hold_reasons"])
        self.assertEqual(advisory["dispatch_binding"]["state"], "absent")
        self.assertFalse(advisory["dispatch_binding"]["attempted"])
        self.assertFalse(advisory["dispatch_binding"]["provenance_known"])
        self.assertEqual(peer_pending["dispatch_binding"]["state"], "bound")
        self.assertIn("peer-review-pending", peer_pending["hold_reasons"])
        origin, host = result["input_provenance"]
        self.assertEqual(origin["source"], "operator-supplied-codex")
        self.assertEqual(origin["candidate_scope_basis"], "operator-selected")
        self.assertEqual(origin["capture_id"], advisory["lane"])
        self.assertEqual(origin["executor"], "codex_architecture_critic")
        self.assertEqual(origin["return_sha256"], codex["operator_codex"]["return_sha256"])
        self.assertNotIn("dispatch_id", origin)
        self.assertNotIn("dispatch_record_sha256", origin)
        self.assertNotIn("return_record_sha256", origin)
        self.assertIn("return_record_sha256", host)
        self.assertEqual(host["return_sha256"], sha256(Path(packet["return"]).read_bytes()).hexdigest())
        self.assertEqual(self.store.audit_events(), before)

    def test_operator_codex_capture_id_cannot_target_adjudication(self):
        inputs, decisions = self._panel()
        codex = self._operator_codex_input(inputs[0]["return"])
        origin = codex["operator_codex"]
        hold = "nonproduction-advisory: unqualified source"
        decision = dict(decisions[0], dispatch_id=origin["capture_id"], return_sha256=origin["return_sha256"],
            finding_ids=[hold], supporting_evidence=[dict(decisions[0]["supporting_evidence"][0], finding_ids=[hold])])
        result = self._synthesize([codex, inputs[1]], [decision, decisions[1]])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["primary_input_count"], 1)
        advisory = result["held_inputs"][0]
        self.assertEqual(advisory["synthesis_use"], "open-risk")
        self.assertEqual(advisory["adjudication"]["state"], "none")
        self.assertIn(hold, advisory["hold_reasons"])
        self.assertIn("does not name the dispatch_id of any input", result["adjudication_errors"][0])
        self.assertEqual(self.store.find("dispatch", dispatch_id=origin["capture_id"]), [])
        self.assertEqual(self.store.find("evaluation", dispatch_id=origin["capture_id"]), [])

    def test_operator_codex_requires_exact_input_bytes_and_context(self):
        inputs, _ = self._panel()
        codex = self._operator_codex_input(inputs[0]["return"])
        for options in ({"candidate": "another-candidate"}, {"scope": "another-scope"}):
            with self.subTest(options=options), self.assertRaisesRegex(SystemExit, "candidate or scope differs"):
                self._synthesize([codex], [], **options)
        capture = Path(codex["return"])
        capture.write_bytes(capture.read_bytes().replace(b"\r\n", b"\n"))
        with self.assertRaisesRegex(SystemExit, "exact SHA-256 digest"):
            self._synthesize([codex], [])

    def test_operator_codex_refuses_invalid_and_oversized_return_files(self):
        inputs, _ = self._panel()
        codex = self._operator_codex_input(inputs[0]["return"])
        for raw, reason in ((b"\xff", "utf-8"), (b"x" * (MAX_RETURN_BYTES + 1), "input size limit")):
            with self.subTest(reason=reason), self.assertRaisesRegex(SystemExit, reason):
                Path(codex["return"]).write_bytes(raw)
                entry = dict(codex, operator_codex=dict(codex["operator_codex"], return_sha256=sha256(raw).hexdigest()))
                self._synthesize([entry], [])

    def test_operator_codex_refuses_alternate_metadata_sources(self):
        inputs, _ = self._panel()
        codex = self._operator_codex_input(inputs[0]["return"])
        origin = codex["operator_codex"]
        for entry, reason in (
            (dict(codex, evaluation=inputs[0]["evaluation"]), "accepts only"),
            (dict(codex, evaluation_record_sha256="f" * 64), "accepts only"),
            (dict(codex, synthesis_use="primary"), "accepts only"),
            (dict(codex, operator_codex=dict(origin, peer_review_status="passed")), "requires capture_id"),
            (dict(codex, operator_codex=dict(origin, provider_key="anthropic_manual")), "requires capture_id"),
            (dict(codex, operator_codex=dict(origin, dispatch_id="borrowed")), "requires capture_id"),
            (dict(codex, operator_codex=dict(origin, capture_id="other/path")), "bounded portable identifier"),
            (dict(codex, operator_codex=dict(origin, capture_id=" operator-codex ")), "bounded portable identifier"),
            (dict(codex, operator_codex=dict(origin, capture_id=23)), "bounded portable identifier"),
            (dict(codex, operator_codex=dict(origin, return_sha256="bad")), "lowercase SHA-256"),
        ):
            with self.subTest(entry=entry), self.assertRaisesRegex(SystemExit, reason):
                self._synthesize([entry], [])

    def test_operator_codex_capture_id_is_unique_in_panel(self):
        inputs, decisions = self._panel()
        codex = self._operator_codex_input(inputs[0]["return"])
        collision = dict(codex, operator_codex=dict(codex["operator_codex"], capture_id=decisions[0]["dispatch_id"]))
        for panel in ([collision, inputs[0]], [codex, codex]):
            with self.assertRaisesRegex(SystemExit, "capture_id must be unique"):
                self._synthesize(panel, [])

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

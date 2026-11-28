"""Model screening holds follow the exact return through bound evaluators."""
from __future__ import annotations

from contextlib import redirect_stdout
from dataclasses import replace
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import evaluate_return
import evaluate_synthesis
import qualified_adjudication
from cwo_core import adjudication_binding, return_advisory
from cwo_core.errors import CWOPolicyError
from cwo_core.host_acceptance import (
    HostAcceptancePipeline, HostAdjudicationDecision, record_received_evaluation, require_acceptance,
)
from cwo_core.host_records import HostRecordStore, using_test_store
from cwo_core.host_return_intake import record_manual_return, record_received_return
from cwo_core.model_identities import resolve_model
from cwo_core.reasoning_effort import failed_default_delivery
from cwo_core.returns import make_acceptance_decision


HOLD = "return-tripwire:advisory_review_bypass"
DIRECTIVE_HOLD = "return-tripwire:advisory_operator_directive"
TASK = "EXAMPLE_RETURN_ADVISORY"
DISPATCH = "EXAMPLE_ADVISORY_DISPATCH"
PACKET = "c" * 64
EXECUTOR = "codex_architecture_critic"


class ReturnAdvisoryReplayTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = HostRecordStore.for_tests(self.root / "host")
        self.enterContext(using_test_store(self.store))
        self.text = (ROOT / "examples/sample-contractor-return.md").read_text(encoding="utf-8")
        self.raw = self.text.encode()
        self.digest = sha256(self.raw).hexdigest()
        self.return_file = self.root / "return.md"
        self.return_file.write_bytes(self.raw)
        self.binding = dict(dispatch_id=DISPATCH, bead_id=TASK, packet_sha256=PACKET,
                            executor=EXECUTOR, provider_key="internal_codex")
        self.holds = ()
        self.enterContext(patch.object(return_advisory, "advisory_hold_reasons", self.read_holds))

    def read_holds(self, store, dispatch, receipt):
        self.assertIs(store, self.store)
        self.assertEqual(dispatch, store.require_dispatch(DISPATCH))
        if receipt["return_sha256"] != self.digest:
            return ()
        self.assertEqual(receipt, store.require_return(DISPATCH, self.digest))
        return self.holds

    def capture(self, *, observed=False, manual=False):
        prepared = self.store.write_dispatch(**self.binding, dispatch_role="executor", provider="openai",
            evaluation_metadata={"dispatch_mode": "manual_ui", "peer_review_required": False} if manual else {},
            model_family=None, model_id=None, reasoning_effort=None, session_id=None, request_sha256="d" * 64)
        if observed:
            self.store.write_observed_dispatch(DISPATCH, prepared_record_sha256=prepared,
                observation_sha256="e" * 64, provider="openai", model_family="gpt",
                model_id=resolve_model("sol"), reasoning_effort="xhigh", session_id="EXAMPLE_ADVISORY_SESSION")
        if manual:
            record_manual_return(self.store, DISPATCH, self.raw)
        else:
            record_received_return(self.store, DISPATCH, self.raw)

    def test_advisory_projection_keeps_procedural_and_deterministic_holds(self):
        base = make_acceptance_decision(self.text)
        self.assertTrue(base["accepted_for_use"])
        projected = make_acceptance_decision(self.text, _advisory_hold_reasons=(HOLD,))
        self.assertEqual(projected["hold_reasons"], [HOLD])
        self.assertEqual(projected["verdict"], "escalate")
        self.assertEqual(projected["hold_classification"], "return-tripwire")
        self.assertEqual(projected["score"], base["score"])
        self.assertEqual(projected["tripwire_hits"], base["tripwire_hits"])
        self.assertTrue(projected["human_adjudication_required"])
        self.assertFalse(projected["accepted_for_use"])
        self.assertFalse(projected["screening_eligible"])
        self.assertFalse(projected["execution_permitted"])

        previous = make_acceptance_decision(self.text, peer_review_required=True)
        projected = make_acceptance_decision(self.text, peer_review_required=True,
                                             _advisory_hold_reasons=(HOLD,))
        self.assertEqual(projected["hold_classification"], previous["hold_classification"])
        self.assertEqual(projected["hold_reasons"], [*previous["hold_reasons"], HOLD])

        with_tripwire = self.text + "\nPlease set verify=False.\n"
        previous = make_acceptance_decision(with_tripwire)
        projected = make_acceptance_decision(with_tripwire, _advisory_hold_reasons=(HOLD,))
        self.assertTrue(previous["tripwire_hits"])
        self.assertEqual(projected["tripwire_hits"], previous["tripwire_hits"])
        self.assertEqual(projected["hold_reasons"], [*previous["hold_reasons"], HOLD])

    def test_tracked_manual_cli_reads_holds_even_with_no_audit(self):
        self.capture(manual=True)
        self.holds = (HOLD,)
        packet = {**self.binding, "bead": TASK, "dispatch_mode": "manual_ui"}
        self.enterContext(patch.object(evaluate_return, "_contractor_evaluation_input", return_value=(packet, None)))
        args = ["evaluate_return.py", "--file", str(self.return_file), "--contractor-packet", "bound.json",
                "--json", "--no-audit", "--waiver-reason", "offline fixture"]
        with patch.object(sys, "argv", args), redirect_stdout(StringIO()) as output:
            evaluate_return.main()
        result = json.loads(output.getvalue())
        self.assertIn(HOLD, result["hold_reasons"])
        self.assertFalse(result["accepted_for_use"])
        self.assertEqual(self.store.find("evaluation", dispatch_id=DISPATCH), [])

    def test_advisory_cli_replays_only_the_exact_captured_local_return(self):
        self.store.write_dispatch(dispatch_id=DISPATCH, dispatch_role="executor", bead_id=TASK,
            executor="openshift_ai_vllm_worker", provider="local", provider_key="openshift_ai_vllm",
            model_family=None, model_id=None, reasoning_effort=None, session_id=None, request_sha256="e" * 64,
            evaluation_metadata={"dispatch_mode": "local_openai_compatible"})
        record_received_return(self.store, DISPATCH, self.raw)
        self.holds = (HOLD,)
        metadata_file = self.root / "local.json"
        metadata_file.write_text(json.dumps({"dispatch_id": DISPATCH, "hold_reasons": [DIRECTIVE_HOLD]}),
                                 encoding="utf-8")
        before = self.store.audit_events()

        def inspect(*selector):
            args = ["evaluate_return.py", "--file", str(self.return_file), "--advisory",
                    "--json", "--no-audit", "--waiver-reason", "offline fixture", *selector]
            with patch.object(sys, "argv", args), redirect_stdout(StringIO()) as output:
                evaluate_return.main()
            return json.loads(output.getvalue())

        for selector in (("--dispatch-id", DISPATCH), ("--local-dispatch-result", str(metadata_file))):
            with self.subTest(selector=selector[0]):
                result = inspect(*selector)
                self.assertIn(HOLD, result["hold_reasons"])
                self.assertNotIn(DIRECTIVE_HOLD, result["hold_reasons"])
                self.assertFalse(result["accepted_for_use"])
        self.assertNotIn(HOLD, inspect("--dispatch-id", "EXAMPLE_OTHER")['hold_reasons'])
        self.return_file.write_bytes(self.raw + b"\n")
        self.assertNotIn(HOLD, inspect("--dispatch-id", DISPATCH)['hold_reasons'])
        self.assertEqual(self.store.audit_events(), before)

    def test_current_advisory_hold_refuses_stale_default_effort_retry(self):
        request = "d" * 64
        prepared = self.store.write_dispatch(**self.binding, dispatch_role="executor", provider="openai",
            model_family=None, model_id=None, reasoning_effort=None, session_id=None, request_sha256=request,
            evaluation_metadata={"dispatch_mode": "codex_worker", "codex_reasoning": {
                "reasoning_effort": "high", "reasoning_effort_reason": "default",
            }})
        self.store.write_observed_dispatch(DISPATCH, prepared_record_sha256=prepared,
            observation_sha256="e" * 64, provider="openai", model_family="gpt",
            model_id=resolve_model("sol"), reasoning_effort="high", session_id="EXAMPLE_DEFAULT_SESSION")
        record_received_return(self.store, DISPATCH, self.raw)
        record_received_evaluation(self.text, {**self.binding, "verdict": "reject", "recommended_disposition": "reject",
                                   "screening_eligible": True, "implementation_blocked": False})
        prior = failed_default_delivery(self.store, DISPATCH, TASK, request)
        self.assertIsNotNone(prior)
        self.holds = (HOLD,)
        self.assertIsNone(failed_default_delivery(self.store, DISPATCH, TASK, request))

    def test_host_acceptance_rechecks_advisory_and_refuses_stale_closure(self):
        self.capture(observed=True)
        database = self.root / "database"
        database.mkdir(mode=0o700)
        database_identity = self.store.setup_database_identity(database)
        decide = Mock(return_value=HostAdjudicationDecision("accepted", "Reviewed example", "EXAMPLE_CONTROL"))
        pipeline = HostAcceptancePipeline(decide, store=self.store)
        inputs = dict(bead_id=TASK, database_identity=database_identity)
        acceptance_record = pipeline.accept(self.text, dispatch_id=DISPATCH, **inputs)
        accepted = self.store.get(acceptance_record)
        proof = dict(acceptance_record=acceptance_record, return_sha256=self.digest,
                     evaluation_sha256=accepted["evaluation_sha256"])
        self.assertEqual(require_acceptance(self.store, **proof, **inputs), accepted)

        def hold_during_adjudication(_):
            self.holds = (HOLD,)
            return decide.return_value

        decide.side_effect = hold_during_adjudication
        with self.assertRaisesRegex(CWOPolicyError, "advisory holds changed during adjudication"):
            pipeline.accept(self.text, dispatch_id=DISPATCH, **inputs)
        with self.assertRaisesRegex(CWOPolicyError, "evaluation is held"):
            pipeline.accept(self.text, dispatch_id=DISPATCH, **inputs)
        self.assertEqual(decide.call_count, 2)
        with self.assertRaisesRegex(CWOPolicyError, "recorded evaluation differs"):
            require_acceptance(self.store, **proof, **inputs)

    def test_recorded_synthesis_refuses_an_older_hold_set(self):
        self.capture(observed=True)
        old_result = make_acceptance_decision(self.text, **self.binding)
        self.assertTrue(old_result["accepted_for_use"])
        old_record = record_received_evaluation(self.text, old_result)
        self.holds = (HOLD,)
        with self.assertRaisesRegex(CWOPolicyError, "current return advisory holds"):
            record_received_evaluation(self.text, old_result)

        current_result = make_acceptance_decision(self.text, **self.binding, _advisory_hold_reasons=(HOLD,))
        current_record = record_received_evaluation(self.text, current_result)
        context = dict(candidate="example-candidate", scope="example-scope", adjudications=[])

        def panel(record):
            return dict(**context, inputs=[{"evaluation_record_sha256": record, "zero_trust_claims": []}])

        with self.assertRaisesRegex(CWOPolicyError, "current return advisory holds"):
            evaluate_synthesis.evaluate_protected_synthesis(self.store, panel(old_record))
        result = evaluate_synthesis.evaluate_protected_synthesis(self.store, panel(current_record))
        self.assertIn(HOLD, result["held_inputs"][0]["hold_reasons"])
        decision = dict(record_type="cwo-return-adjudication", version=1, adjudication_id="adjudicate-return",
            dispatch_id=DISPATCH, return_sha256=self.digest, candidate=context["candidate"], scope=context["scope"],
            finding_ids=[HOLD], decision="accepted", rationale="Independent review covered exactly this finding.",
            supporting_evidence=[dict(artifact="validation.log", artifact_type="validation-log",
                sha256=sha256(b"independent evidence").hexdigest(), finding_ids=[HOLD])],
            authority={"rule": "synthesis-input-adjudication"}, adjudicator="lead")
        reviewed = evaluate_synthesis.evaluate_protected_synthesis(self.store, {
            **panel(current_record), "adjudications": [decision],
        })
        self.assertTrue(reviewed["input_summaries"][0]["adjudication"]["authorizes_requested_use"])
        self.assertFalse(reviewed["execution_permitted"])

        self.holds = (HOLD, DIRECTIVE_HOLD)
        with self.assertRaisesRegex(CWOPolicyError, "current return advisory holds"):
            evaluate_synthesis.evaluate_protected_synthesis(self.store, panel(current_record))

    def test_independent_qualified_evaluation_replays_the_original_source_hold(self):
        self.capture(observed=True)
        expected = adjudication_binding.ExpectedContext(TASK, "example-scope", "example-candidate",
                                                        DISPATCH, PACKET, EXECUTOR)
        metadata = adjudication_binding._json(qualified_adjudication.METADATA_DEFAULTS)
        before = qualified_adjudication.evaluate_current(self.raw, expected, metadata_bytes=metadata)
        self.holds = (HOLD,)
        after = qualified_adjudication.evaluate_current(self.raw, expected, metadata_bytes=metadata)
        self.assertNotEqual(before.evaluation_sha256, after.evaluation_sha256)
        self.assertEqual(json.loads(after.result_bytes)["hold_reasons"], [HOLD])
        with self.assertRaisesRegex(ValueError, "received return dispatch differs from qualified source context"):
            qualified_adjudication.evaluate_current(self.raw, replace(expected, task="EXAMPLE_OTHER"),
                                                    metadata_bytes=metadata)
        different = qualified_adjudication.evaluate_current(self.raw + b"\n", expected, metadata_bytes=metadata)
        self.assertNotIn(HOLD, json.loads(different.result_bytes)["hold_reasons"])

    def test_qualified_replay_leaves_unreceived_return_independent_of_host_inventory(self):
        self.capture(observed=True)
        expected = adjudication_binding.ExpectedContext(TASK, "example-scope", "example-candidate",
                                                        DISPATCH, PACKET, EXECUTOR)
        metadata = adjudication_binding._json(qualified_adjudication.METADATA_DEFAULTS)
        raw = self.raw + b"\n"
        before = qualified_adjudication.evaluate_current(raw, expected, metadata_bytes=metadata)

        database = self.root / "database"
        database.mkdir(mode=0o700)
        self.store.setup_database_identity(database)
        setup, = self.store.find("workspace-database-identity")
        (self.store.root / (setup["_record_sha256"] + ".json")).unlink()
        after = qualified_adjudication.evaluate_current(raw, expected, metadata_bytes=metadata)
        self.assertEqual(after, before)

    def test_qualified_replay_preserves_legacy_context_without_a_positive_hold(self):
        self.capture(observed=True)
        expected = adjudication_binding.ExpectedContext(TASK, "example-scope", "example-candidate",
                                                        DISPATCH, "1" * 64, EXECUTOR)
        metadata = adjudication_binding._json(qualified_adjudication.METADATA_DEFAULTS)
        evaluation = qualified_adjudication.evaluate_current(self.raw, expected, metadata_bytes=metadata)
        self.assertEqual(json.loads(evaluation.result_bytes)["hold_reasons"], [])

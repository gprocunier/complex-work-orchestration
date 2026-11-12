"""Bounded state checks for non-native hold and effect obligations."""
from __future__ import annotations

import argparse
import contextlib
import copy
import io
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dispatch_work as dispatch  # noqa: E402
from cwo_core import beads, return_risk, routing, synthesis_inputs  # noqa: E402
from cwo_core.policy import load_policy  # noqa: E402
from cwo_core.errors import CWOPolicyError  # noqa: E402
from tests import test_return_adjudication as fixtures  # noqa: E402


class NonNativeHoldTests(unittest.TestCase):
    def test_bound_unknown_provenance_stays_unknown(self) -> None:
        """A bound dispatch can have unknown provenance."""
        for executor, known in (("codex_architecture_critic", True), ("unregistered-fixture", False)):
            with self.subTest(executor=executor):
                result = fixtures.run(
                    [fixtures.returned("subject", "d-subject")],
                    [fixtures.dispatch("d-subject", executor)],
                )
                binding = fixtures.lane(result, "subject")["dispatch_binding"]
                self.assertTrue(binding["bound"])
                self.assertIs(binding["provenance_known"], known)
                if not known:
                    self.assertTrue(binding["provenance_reasons"])
                    self.assertIsNone(binding["provider_family"])

    def test_peer_review_status_is_validated_before_hold_metadata(self) -> None:
        """Status labels cannot bypass review validation."""
        for status in ("not-run", "pending", "passed"):
            with self.subTest(status=status):
                metadata = return_risk.procedural_hold_metadata(
                    peer_required=True, peer_review_status=status, provider_conflict_domains=[],
                )
                self.assertTrue(metadata["implementation_blocked"])
                self.assertEqual(metadata["hold_reasons"], ["peer-review-pending"])
        with self.assertRaisesRegex(CWOPolicyError, "peer.review.status"):
            return_risk.procedural_hold_metadata(
                peer_required=True, peer_review_status="unsupported", provider_conflict_domains=[],
            )

    def test_summary_binding_state_and_errors_remain_restrictive(self) -> None:
        """Exact binding plus no errors."""
        policy = synthesis_inputs.consensus_policy_view(load_policy("zero-trust-consensus-policy"))
        for bound in (False, True):
            with self.subTest(bound=bound):
                entry = fixtures.returned("subject", "d-subject" if bound else None)
                records = [fixtures.dispatch("d-subject", "codex_architecture_critic")] if bound else []
                summary = fixtures.run([entry], records)["input_summaries"][0]
                clean = synthesis_inputs.consensus_lanes_from_summaries([entry], [summary], policy)[0]
                self.assertEqual(clean.summary_errors, ())
                self.assertIs(clean.bound, bound)
                self.assertIs(clean.provenance_known, bound)
                if bound:
                    changed = copy.deepcopy(summary)
                    changed["lane"] = "unrelated-lane"
                    refused = synthesis_inputs.consensus_lanes_from_summaries([entry], [changed], policy)[0]
                    self.assertTrue(refused.summary_errors)
                    self.assertFalse(refused.bound)
                    self.assertFalse(refused.provenance_known)

    def test_only_redacted_packet_boundary_downgrades_internal_sensitivity(self) -> None:
        """An actual redacted boundary is necessary."""
        for boundary in ("redacted-packet", "no-outside-sharing", "repo-readonly", "patch-branch"):
            with self.subTest(boundary=boundary):
                expected = "redacted" if boundary == "redacted-packet" else "internal"
                self.assertEqual(routing.dispatch_sensitivity_for_boundary("internal", boundary), expected)

    def test_internal_review_gate_suppresses_local_opt_in(self) -> None:
        """Local permission cannot clear an expert gate."""
        profile = load_policy("expert-registry")["experts"]["general_reasoning"]
        for gate_required in (False, True):
            with self.subTest(gate_required=gate_required):
                expert = dict(profile, validation_gate_required=gate_required)
                with mock.patch.object(routing, "score_executors", wraps=routing.score_executors) as score:
                    result = routing.select_executor_for_expert(
                        expert, text="Review internal example notes.", risk="low", sensitivity="internal",
                        share_boundary="no-outside-sharing", external_ok=False, local_ok=True, prefer_local=True,
                    )
                self.assertIs(score.call_args.kwargs["local_ok"], not gate_required)
                local = next(item for item in result["executor_candidates"]
                             if item["key"] == "local_openai_compatible_worker")
                if gate_required:
                    self.assertIn("local worker dispatch requires --local-ok", local["policy_violations"])
                else:
                    self.assertNotIn("local worker dispatch requires --local-ok", local["policy_violations"])

    def test_hard_stop_disables_actionable_blocking_review(self) -> None:
        """Stopped review metadata cannot claim dispatch readiness."""
        text = "Use ChatGPT Pro 5.5 Extended Reasoning as a master plan reviewer for the final execution plan and total work packet."
        for hard_stop in (False, True):
            with self.subTest(hard_stop=hard_stop):
                prompt = text + (" Do not use model synthesis." if hard_stop else "")
                result = routing.classify_work(
                    prompt, external_ok=True, share_boundary="redacted-packet", model_synthesis=hard_stop,
                )
                self.assertTrue(result["blocking_review_required"])
                self.assertEqual(result["route"], "external-contract")
                self.assertEqual(result["recommended_executor"], routing.CHATGPT_MASTER_REVIEW_EXECUTOR)
                self.assertIs(bool(result["hard_stops"]), hard_stop)
                self.assertIs(result["blocking_review_active"], not hard_stop)
                if hard_stop:
                    self.assertFalse(result["external_contract_allowed"])

    def test_option_names_must_be_nonempty_before_transport(self) -> None:
        """Validate both option-name lists."""
        for field in ("forbidden_request_options", "allowed_request_options"):
            with self.subTest(field=field):
                transport = {"request_options": {}, field: ["valid_option"]}
                args = argparse.Namespace(local_thinking="default")
                self.assertEqual(dispatch.local_request_options_override(transport, args), {})
                transport[field] = [""]
                with self.assertRaisesRegex(SystemExit, field + " must be a list of non-empty strings"):
                    dispatch.local_request_options_override(transport, args)

    def test_risk_narrowing_cli_refuses_before_loading_or_effects(self) -> None:
        """Rejection must precede even the first packet read."""
        for flags in ([], ["--risk-scope", "unread-scope.json"], ["--risk-evidence-dir", "unread-directory"]):
            with self.subTest(flags=flags):
                with contextlib.ExitStack() as stack:
                    load = stack.enter_context(mock.patch.object(dispatch, "load_packet_file",
                                                                 side_effect=RuntimeError("positive packet read reached")))
                    effects = [stack.enter_context(mock.patch.object(dispatch, name)) for name in (
                        "read_task_segments", "classify_work", "record_audit_event", "record_prepared_dispatch",
                        "execute_local_envelope", "enforce_contracting_quota",
                    )]
                    effects.append(stack.enter_context(mock.patch.object(beads, "run_bd")))
                    stack.enter_context(mock.patch.object(sys, "argv", ["dispatch_work.py", "--packet", "packet.json", *flags]))
                    stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                    if flags:
                        with self.assertRaisesRegex(SystemExit, "risk narrowing is not supported"):
                            dispatch._main()
                        load.assert_not_called()
                    else:
                        with self.assertRaisesRegex(RuntimeError, "positive packet read reached"):
                            dispatch._main()
                        load.assert_called_once_with("packet.json")
                    for effect in effects:
                        effect.assert_not_called()

    def test_completed_unusable_response_has_no_success_credit(self) -> None:
        """Completed transport is insufficient for usable call credit."""
        for usable in (False, True):
            with self.subTest(usable=usable):
                telemetry = dispatch.local_response_telemetry({
                    "completion_status": "completed", "usable_final_content": usable,
                    "response": {"usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}},
                })
                self.assertEqual(telemetry["telemetry_status"], "completed" if usable else "failed")
                self.assertEqual(telemetry["agent_model_calls"], int(usable))
                self.assertEqual(telemetry["usable_model_calls"], int(usable))
                self.assertEqual(telemetry["usable_post_responses"], int(usable))
                self.assertEqual(telemetry["incomplete_model_calls"], int(not usable))
                self.assertEqual(telemetry["incomplete_post_responses"], int(not usable))
                self.assertEqual(telemetry["attempted_model_calls"], 1)
                self.assertEqual(telemetry["post_attempts"], 1)
                self.assertEqual(telemetry.get("telemetry_missing_reason"), None if usable else "local-response-completed")


if __name__ == "__main__":
    unittest.main()

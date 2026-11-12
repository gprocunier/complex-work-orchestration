from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path
from typing import Iterator, NamedTuple

from tests.structural_assertions import Check, assert_checks

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.routing import classify_work  # noqa: E402
from cwo_core.synthesis import (  # noqa: E402
    evaluate_synthesis_inputs,
    recommend_model_synthesis,
    synthesis_lane_enabled,
)


CANDIDATE = "commit:" + "a" * 40 + " tree:" + "b" * 40
SCOPE = "bead:cwo-synthesis-fixture"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def bound_records(dispatches: dict[str, str], accepted: dict[str, list[str]]) -> dict:
    """Fake dispatch records and accepting adjudications for evaluate_synthesis_inputs."""

    records = [
        {
            "record_type": "cwo-dispatch-record", "version": 1, "dispatch_id": dispatch_id,
            "executor": executor, "return_sha256": _sha(dispatch_id), "candidate": CANDIDATE,
        }
        for dispatch_id, executor in dispatches.items()
    ]
    adjudications = [
        {
            "record_type": "cwo-return-adjudication", "version": 1,
            "adjudication_id": "adj-" + dispatch_id, "dispatch_id": dispatch_id,
            "return_sha256": _sha(dispatch_id), "candidate": CANDIDATE, "scope": SCOPE,
            "finding_ids": findings, "decision": "accepted",
            "rationale": "checked each finding against the candidate",
            "supporting_evidence": [{
                "artifact": "validation.txt", "artifact_type": "validation-log",
                "sha256": _sha("evidence " + dispatch_id), "finding_ids": findings,
            }],
            "authority": {"rule": "synthesis-input-adjudication"},
            "adjudicator": "lead",
        }
        for dispatch_id, findings in accepted.items()
    ]
    return {"dispatch_records": records, "adjudications": adjudications, "candidate": CANDIDATE, "scope": SCOPE}


def binding(dispatch_id: str) -> dict:
    return {"dispatch_id": dispatch_id, "return_sha256": _sha(dispatch_id)}


class SynthesisInputCase(NamedTuple):
    original: str
    inputs: list[dict]
    options: dict
    checks: tuple[Check, ...]
    override: dict | None = None


def _synthesis_input_rows() -> Iterator[SynthesisInputCase]:
    valid = {
        "lane": "glm-v2", "provider_camp": "local", "external": False,
        "executor": "rhoai_glm_compact_architecture_critic",
        "disposition": "accepted", "recommended_synthesis_use": "primary",
        **binding("d-glm-v2"),
        "local_expected_response_contract": "cwo-glm-critic-v2",
        "local_response_contract": "cwo-glm-critic-v2",
        "local_response_contract_status": "valid",
        "local_completion_status": "completed",
        "local_usable_final_content": True,
        "local_normalized_return_matches": True,
        "local_v2_frame_valid": True,
        "local_v2_identity_consistent": True,
        "local_response_model_status": "matched",
        "local_model_preflight_status": "passed",
        "local_http_status": 200,
    }
    legacy = {
        "lane": "glm-v1", "provider_camp": "local", "external": False,
        "executor": "rhoai_glm_compact_architecture_critic",
        "disposition": "accepted", "recommended_synthesis_use": "salvage-only",
        "local_expected_response_contract": "cwo-glm-critic-v1",
        "local_response_contract": "cwo-glm-critic-v1",
        "local_completion_status": "empty-final-content",
        "local_usable_final_content": False,
    }
    records = bound_records(
        {"d-glm-v2": "rhoai_glm_compact_architecture_critic"}, {"d-glm-v2": ["finding:critic-v2"]}
    )
    yield SynthesisInputCase('test_valid_v2_and_explicit_v1_keep_their_synthesis_lanes', [valid, legacy], {**records}, (
        Check(lambda result: result['primary_input_count'], 1),
        Check(lambda result: result['salvage_input_count'], 1),
        Check(lambda result: result['quarantined_input_count'], 0),
    ))


    yield SynthesisInputCase('test_two_accepted_synthesis_inputs_are_ready', [
            {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
            {
                "lane": "opus",
                "provider_camp": "anthropic",
                "disposition": "accepted-with-modification",
            },
        ], {}, (
        Check(lambda result: result['status'], 'ready'),
        Check(lambda result: result['blocked'], None, 'false'),
        Check(lambda result: result['usable_input_count'], 2),
        Check(lambda result: [item['synthesis_use'] for item in result['input_summaries']], ['primary', 'primary']),
    ))

    yield SynthesisInputCase('test_gemini_accepted_input_defaults_to_salvage_only', [
            {"lane": "gemini", "provider_camp": "google", "disposition": "accepted"},
            {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
        ], {}, (
        Check(lambda result: result['status'], 'blocked'),
        Check(lambda result: result['usable_input_count'], 1),
        Check(lambda result: result['salvage_input_count'], 1),
        Check(lambda result: result['input_summaries'][0]['synthesis_use'], 'salvage-only'),
        Check(lambda result: result['blocked_reasons'], 'salvage-only inputs do not satisfy minimum_usable_inputs', 'contains'),
    ))

    yield SynthesisInputCase('test_gemini_salvage_does_not_block_when_two_primary_inputs_remain', [
            {"lane": "gemini", "provider_camp": "google", "disposition": "accepted"},
            {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
            {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted-with-modification"},
        ], {}, (
        Check(lambda result: result['status'], 'ready'),
        Check(lambda result: result['blocked'], None, 'false'),
        Check(lambda result: result['usable_input_count'], 2),
        Check(lambda result: result['salvage_input_count'], 1),
    ))

    yield SynthesisInputCase('test_glm_local_input_is_primary_eligible_while_gemini_remains_salvage', [
            {"lane": "glm", "provider_camp": "local", "disposition": "accepted"},
            {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
            {"lane": "gemini", "provider_camp": "google", "disposition": "accepted"},
        ], {}, (
        Check(lambda result: result['status'], 'ready'),
        Check(lambda result: result['usable_input_count'], 2),
        Check(lambda result: result['salvage_input_count'], 1),
        Check(lambda result: result['input_summaries'][0]['synthesis_use'], 'primary'),
        Check(lambda result: result['input_summaries'][2]['synthesis_use'], 'salvage-only'),
    ))

    yield SynthesisInputCase('test_bound_adjudication_can_upgrade_gemini', [
            {
                "lane": "gemini",
                "provider_camp": "google",
                "disposition": "accepted",
                "synthesis_use": "primary",
                "reason": "architect upgraded one evaluated finding",
                **binding("d-gemini"),
            },
            {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
        ], {**bound_records({"d-gemini": "gemini_architecture_critic"}, {"d-gemini": ["finding:cipher-mode"]})}, (
        Check(lambda result: result['status'], 'ready'),
        Check(lambda result: result['usable_input_count'], 2),
        Check(lambda result: result['salvage_input_count'], 0),
        Check(lambda result: result['input_summaries'][0]['synthesis_use'], 'primary'),
    ))

    yield SynthesisInputCase('test_primary_override_without_architect_authority_cannot_upgrade_gemini', [
            {
                "lane": "gemini",
                "provider_camp": "google",
                "disposition": "accepted",
                "synthesis_use": "primary",
            },
            {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
        ], {}, (
        Check(lambda result: result['status'], 'blocked'),
        Check(lambda result: result['input_summaries'][0]['synthesis_use'], 'salvage-only'),
    ))


    yield SynthesisInputCase('test_all_salvage_only_inputs_do_not_make_synthesis_ready', [
            {"lane": "gemini", "provider_camp": "google", "disposition": "accepted"},
            {"lane": "manual", "provider_camp": "openai", "disposition": "accepted", "synthesis_use": "salvage-only"},
        ], {}, (
        Check(lambda result: result['status'], 'blocked'),
        Check(lambda result: result['usable_input_count'], 0),
        Check(lambda result: result['salvage_input_count'], 2),
        Check(lambda result: result['blocked_reasons'], 'salvage-only inputs do not satisfy minimum_usable_inputs', 'contains'),
    ))

    yield SynthesisInputCase('test_open_risk_differs_from_salvage_only', [
            {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
            {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
            {"lane": "risk", "provider_camp": "local", "disposition": "needs-investigation"},
        ], {}, (
        Check(lambda result: result['status'], 'partial'),
        Check(lambda result: result['usable_input_count'], 2),
        Check(lambda result: result['open_risk_input_count'], 1),
        Check(lambda result: result['salvage_input_count'], 0),
    ))

    yield SynthesisInputCase('test_recommended_synthesis_use_salvage_only_is_honored', [
            {
                "lane": "outside-critic",
                "provider_camp": "anthropic",
                "disposition": "accepted",
                "recommended_synthesis_use": "salvage-only",
            },
            {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
        ], {}, (
        Check(lambda result: result['status'], 'blocked'),
        Check(lambda result: result['usable_input_count'], 1),
        Check(lambda result: result['salvage_input_count'], 1),
    ))

    yield SynthesisInputCase('test_missing_empty_and_timeout_inputs_do_not_satisfy_minimum', [
            {"lane": "gemini", "disposition": "accepted"},
            {"lane": "opus", "disposition": "timed-out"},
            {"lane": "chatgpt", "disposition": "missing"},
            {"lane": "local", "disposition": "empty"},
        ], {}, (
        Check(lambda result: result['status'], 'blocked'),
        Check(lambda result: result['blocked'], None, 'true'),
        Check(lambda result: result['usable_input_count'], 1),
        Check(lambda result: result['partial_input_count'], 3),
        Check(lambda result: result['blocked_reasons'], 'fewer than minimum_usable_inputs accepted or accepted-with-modification inputs', 'contains'),
    ))

    yield SynthesisInputCase('test_partial_synthesis_is_ready_when_minimum_primary_inputs_remain', [
            {"lane": "gemini", "disposition": "accepted"},
            {"lane": "opus", "disposition": "accepted-with-modification"},
            {"lane": "chatgpt", "disposition": "timed-out"},
            {"lane": "local", "disposition": "needs-investigation"},
        ], {}, (
        Check(lambda result: result['status'], 'partial'),
        Check(lambda result: result['blocked'], None, 'false'),
        Check(lambda result: result['usable_input_count'], 2),
        Check(lambda result: result['partial_input_count'], 1),
        Check(lambda result: result['open_risk_input_count'], 1),
    ))

    policy = {
        "input_disposition_policy": {
            "use_as_synthesis_input": ["accepted", "accepted-with-modification"],
            "partial_only": ["timed-out"],
            "summarize_as_open_risk": ["needs-investigation"],
            "quarantine": ["quarantined", "boundary-tainted"],
            "exclude_as_rejected": ["rejected", "failed-evaluation"],
        },
        "partial_synthesis_policy": {
            "allow_partial": False,
            "minimum_usable_inputs": 2,
            "partial_status": "partial",
        },
        "salvage_only_provider_camps": [],
    }
    yield SynthesisInputCase('test_partial_synthesis_disabled_blocks_otherwise_ready_partial_result', [
            {"lane": "opus", "disposition": "accepted"},
            {"lane": "chatgpt", "disposition": "accepted-with-modification"},
            {"lane": "risk", "disposition": "needs-investigation"},
        ], {'policy': policy}, (
        Check(lambda result: result['status'], 'blocked'),
        Check(lambda result: result['blocked'], None, 'true'),
        Check(lambda result: result['allow_partial'], None, 'false'),
        Check(lambda result: result['blocked_reasons'], 'partial synthesis is disabled by policy', 'contains'),
    ))

    yield SynthesisInputCase('test_quarantined_and_boundary_tainted_external_inputs_block_synthesis', [
            {"lane": "gemini", "disposition": "quarantined", "external": True},
            {"lane": "opus", "disposition": "accepted", "boundary_taint_status": "boundary-tainted"},
        ], {}, (
        Check(lambda result: result['status'], 'blocked'),
        Check(lambda result: result['usable_input_count'], 0),
        Check(lambda result: result['quarantined_input_count'], 2),
        Check(lambda result: result['input_summaries'][1]['effective_disposition'], 'boundary-tainted'),
        Check(lambda result: result['blocked_reasons'], 'all external inputs are quarantined or boundary-tainted', 'contains'),
    ))

    yield SynthesisInputCase('test_boundary_taint_overrides_requested_primary_synthesis_use', [
            {
                "lane": "opus",
                "provider_camp": "anthropic",
                "disposition": "accepted",
                "boundary_taint_status": "boundary-tainted",
                "synthesis_use": "primary",
            },
            {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
        ], {}, (
        Check(lambda result: result['status'], 'blocked'),
        Check(lambda result: result['usable_input_count'], 1),
        Check(lambda result: result['quarantined_input_count'], 1),
        Check(lambda result: result['input_summaries'][0]['synthesis_use'], 'quarantine'),
        Check(lambda result: result['input_summaries'][0]['requested_synthesis_use'], 'primary'),
    ))

    yield SynthesisInputCase('test_process_hold_blocks_primary_synthesis_without_architect_override', [
            {
                "lane": "opus",
                "provider_camp": "anthropic",
                "disposition": "accepted",
                "recommended_synthesis_use": "primary",
                "implementation_blocked": True,
                "hold_classification": "provider-conflict-pending",
                "hold_reasons": ["provider-conflict-peer-review-pending"],
            },
            {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
        ], {}, (
        Check(lambda result: result['status'], 'blocked'),
        Check(lambda result: result['usable_input_count'], 1),
        Check(lambda result: result['open_risk_input_count'], 1),
        Check(lambda result: result['held_input_count'], 1),
        Check(lambda result: result['input_summaries'][0]['synthesis_use'], 'open-risk'),
        Check(lambda result: result['input_summaries'][0]['implementation_blocked'], None, 'true'),
        Check(lambda result: result['input_summaries'][0]['hold_classification'], 'provider-conflict-pending'),
    ))

    yield SynthesisInputCase('test_peer_review_hold_survives_labels_and_bound_adjudication', [
            {
                "lane": "opus",
                "provider_camp": "anthropic",
                "disposition": "accepted",
                "recommended_synthesis_use": "primary",
                "implementation_blocked": True,
                "hold_reasons": ["peer-review-pending"],
                "architect_adjudication_authorized": True,
                **binding("d-opus"),
            },
            {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
        ], {**bound_records({"d-opus": "claude_architecture_critic"}, {"d-opus": ["peer-review-pending"]})}, (
        Check(lambda result: result['status'], 'blocked'),
        Check(lambda result: result['usable_input_count'], 1),
        Check(lambda result: result['held_input_count'], 1),
        Check(lambda result: result['input_summaries'][0]['synthesis_use'], 'open-risk'),
        Check(lambda result: result['input_summaries'][0]['adjudication']['uncleared_hold_reasons'], ['peer-review-pending']),
        Check(lambda result: result['input_summaries'][0]['ignored_authority_claims'], ['architect_adjudication_authorized']),
    ))


    yield SynthesisInputCase('test_empty_synthesis_input_set_is_blocked', [], {}, (
        Check(lambda result: result['status'], 'blocked'),
        Check(lambda result: result['input_count'], 0),
        Check(lambda result: result['blocked_reasons'], 'fewer than minimum_usable_inputs accepted or accepted-with-modification inputs', 'contains'),
    ))

    controls = [
        {"lane": "control-a", "provider_camp": "openai", "disposition": "accepted"},
        {"lane": "control-b", "provider_camp": "anthropic", "disposition": "accepted"},
    ]
    invalid = {
        "lane": "glm-v2", "provider_camp": "local", "external": False,
        "executor": "rhoai_glm_compact_architecture_critic",
        "disposition": "accepted", "recommended_synthesis_use": "salvage-only",
        "local_expected_response_contract": "cwo-glm-critic-v2",
        "local_response_contract": "cwo-glm-critic-v2",
        "local_response_contract_status": "invalid",
        "local_completion_status": "contract-invalid",
        "local_usable_final_content": False,
        "local_normalized_return_matches": False,
    }
    for override in ({}, {"synthesis_use": "primary", "architect_adjudicated": True}):
        yield SynthesisInputCase('test_invalid_v2_local_evidence_cannot_be_salvaged_or_architect_upgraded', [*controls, {**invalid, **override}], {}, (
            Check(lambda result: result["primary_input_count"], 2),
            Check(lambda result: result["salvage_input_count"], 0),
            Check(lambda result: result["input_summaries"][2]["synthesis_use"], "quarantine"),
        ), override=override)


class SynthesisRouteCase(NamedTuple):
    original: str
    prompt: str
    options: dict
    checks: tuple[Check, ...]


def _synthesis_route_rows() -> Iterator[SynthesisRouteCase]:
    yield SynthesisRouteCase('test_route_result_carries_inactive_recommendation', "Refactor the orchestration control plane across routing, schema validation, docs, and CI.", {'requested_roles': ["architecture"]}, (
        Check(lambda result: result['model_synthesis']['recommended_mode'], 'recommended'),
        Check(lambda result: result['model_synthesis']['activation_state'], 'recommended'),
        Check(lambda result: result['model_synthesis']['active'], None, 'false'),
        Check(lambda result: result['model_synthesis']['requires_user_acceptance'], None, 'true'),
        Check(lambda result: synthesis_lane_enabled(result['model_synthesis']), None, 'false'),
        Check(lambda result: result['model_synthesis']['active_modes'], 'accepted', 'contains'),
    ))

    yield SynthesisRouteCase('test_explicit_synthesis_request_is_active', "Use model synthesis to combine Claude Opus, Gemini, and ChatGPT Pro findings.", {'external_ok': True, 'share_boundary': "redacted-packet", 'requested_roles': ["architecture"]}, (
        Check(lambda result: result['model_synthesis']['recommended_mode'], 'requested'),
        Check(lambda result: result['model_synthesis']['active'], None, 'true'),
        Check(lambda result: synthesis_lane_enabled(result['model_synthesis']), None, 'true'),
        Check(lambda result: result['model_synthesis']['artifact_contract'], 'input evaluator dispositions', 'contains'),
        Check(lambda result: result['model_synthesis']['artifact_contract'], 'partial or missing lane summary', 'contains'),
    ))

    yield SynthesisRouteCase('test_default_codex_synthesis_owner_uses_sol_label', "Use model synthesis with Codex 5.6 Sol, Claude Opus, and Gemini.", {'external_ok': True, 'share_boundary': "redacted-packet", 'requested_roles': ["architecture"]}, (
        Check(lambda result: {item['executor']: item for item in result['model_synthesis']['recommended_panel']}['frontier_architect']['role'], 'synthesis-owner'),
        Check(lambda result: {item['executor']: item for item in result['model_synthesis']['recommended_panel']}['frontier_architect']['effort'], 'codex-5.6-sol'),
    ))

    yield SynthesisRouteCase('test_explicit_critic_contracts_constrain_synthesis_panel', "Use Claude Opus and GLM as architecture critics. "
        "The critic panel is closed to those two providers. "
        "Do not add Gemini or ChatGPT Pro.", {'external_ok': True, 'local_ok': True, 'share_boundary': "redacted-packet", 'requested_roles': ["architecture"], 'model_synthesis': True}, (
        Check(lambda result: [item['executor'] for item in result['model_synthesis']['recommended_panel']], ['frontier_architect', 'claude_architecture_critic', 'rhoai_glm_hardened_architecture_critic']),
        Check(lambda result: result['model_synthesis']['mentioned_provider_camps'], ['anthropic', 'local']),
        Check(lambda result: result['model_synthesis']['active'], None, 'true'),
    ))

    yield SynthesisRouteCase('test_explicit_provider_exclusion_filters_generic_synthesis_panel', "Use model synthesis without Gemini.", {'requested_roles': ["architecture"]}, (
        Check(lambda result: result['model_synthesis']['recommended_mode'], 'requested'),
        Check(lambda result: result['model_synthesis']['active'], None, 'true'),
        Check(lambda result: [item['executor'] for item in result['model_synthesis']['recommended_panel']], 'gemini_architecture_critic', 'not-contains'),
        Check(lambda result: result['model_synthesis']['mentioned_provider_camps'], 'google', 'not-contains'),
    ))

    yield SynthesisRouteCase('test_conflicting_natural_language_synthesis_intent_disables_and_stops', "Use model synthesis. Do not use model synthesis.", {'requested_roles': ["architecture"]}, (
        Check(lambda result: result['model_synthesis']['recommended_mode'], 'disabled'),
        Check(lambda result: result['model_synthesis']['active'], None, 'false'),
        Check(lambda result: result['hard_stops'], 'conflicting model synthesis intent: synthesis is both requested and prohibited', 'contains'),
    ))

    yield SynthesisRouteCase('test_provider_conflict_and_partial_disposition_contracts_are_carried', "Review a Claude Mythos eval harness for a frontier model provider competitor.", {'external_ok': True, 'share_boundary': "redacted-packet", 'requested_roles': ["general-reasoning"]}, (
        Check(lambda result: result['model_synthesis']['recommended_mode'], 'recommended'),
        Check(lambda result: result['model_synthesis']['active'], None, 'false'),
        Check(lambda result: result['model_synthesis']['provider_conflict_flags'], None, 'true'),
        Check(lambda result: result['model_synthesis']['provider_conflict_flags'][0]['kind'], 'route-provider-conflict'),
        Check(lambda result: result['model_synthesis']['provider_conflict_flags'][0]['domains'], 'frontier-ai-development', 'contains'),
        Check(lambda result: result['model_synthesis']['input_disposition_policy']['quarantine'], 'quarantined', 'contains'),
        Check(lambda result: result['model_synthesis']['input_disposition_policy']['partial_only'], 'timed-out', 'contains'),
        Check(lambda result: result['model_synthesis']['partial_synthesis_policy']['allow_partial'], None, 'true'),
    ))


class ModelSynthesisTests(unittest.TestCase):

    def test_synthesis_input_disposition_rows(self) -> None:
        for row in _synthesis_input_rows():
            with self.subTest(original=row.original, override=row.override):
                result = evaluate_synthesis_inputs(row.inputs, **row.options)
                assert_checks(self, result, row.checks)

        primary = [
            {"lane": "chatgpt", "provider_camp": "openai", "disposition": "accepted"},
            {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
        ]
        self.assertEqual(evaluate_synthesis_inputs(primary)["status"], "ready")
        for label, fields, absent in (
            ("missing-disposition", {}, True),
            ("blank-disposition", {"disposition": " "}, False),
            ("nonstring-disposition", {"disposition": False}, False),
            ("nonstring-local-marker", {"disposition": "accepted", "local_response_contract": False}, False),
        ):
            with self.subTest(public_representation=label):
                entry = {"lane": "unresolved", **fields}
                try:
                    observed = evaluate_synthesis_inputs([*primary, entry])
                except (TypeError, AttributeError) as exc:
                    observed = exc
                self.assertIsInstance(observed, dict,
                                      f"Public malformed synthesis input needs a structured result: {label}")
                summary = observed["input_summaries"][2]
                self.assertNotEqual(summary["synthesis_use"], "primary")
                diagnostics = "\n".join(summary["unresolved_data"])
                if label == "nonstring-local-marker":
                    self.assertIn("local_response_contract is blank or not a string", diagnostics)
                elif absent:
                    self.assertIn("disposition is missing", diagnostics)
                    self.assertNotIn("disposition is null, blank or not a string", diagnostics)
                else:
                    self.assertIn("disposition is null, blank or not a string", diagnostics)

        records = bound_records({"d-contract": "codex_architecture_critic"}, {"d-contract": ["finding:contract"]})
        entry = {"lane": "bound", "external": False, "disposition": "accepted", **binding("d-contract")}
        good = evaluate_synthesis_inputs([*primary, entry], **records)
        self.assertEqual(good["adjudication_errors"], [])
        self.assertEqual(good["input_summaries"][2]["adjudication"]["state"], "applied")
        self.assertEqual(good["input_summaries"][2]["synthesis_use"], "primary")
        records["adjudications"][0]["finding_ids"] = None
        try:
            observed = evaluate_synthesis_inputs([*primary, entry], **records)
        except (TypeError, AttributeError) as exc:
            observed = exc
        self.assertIsInstance(observed, dict, "Invalid finding IDs need a structured public adjudication refusal")
        self.assertEqual(observed["input_summaries"][2]["adjudication"]["state"], "invalid")
        self.assertIn("finding_ids must be a non-empty list", "\n".join(
            observed["input_summaries"][2]["adjudication"]["errors"]))
        self.assertNotEqual(observed["input_summaries"][2]["synthesis_use"], "primary")


    def test_synthesis_route_projection_rows(self):
        for row in _synthesis_route_rows():
            with self.subTest(original=row.original):
                result = classify_work(row.prompt, **row.options)
                assert_checks(self, result, row.checks)


    def test_natural_language_synthesis_prohibitions_disable_the_lane(self) -> None:
        prompts = [
            "No model synthesis.",
            "Proceed without model synthesis.",
            "Do not use model synthesis; direct adjudication.",
        ]
        for text in prompts:
            with self.subTest(text=text):
                route = classify_work(text, requested_roles=["architecture"])
                synthesis = route["model_synthesis"]

                self.assertEqual(synthesis["recommended_mode"], "disabled")
                self.assertEqual(synthesis["activation_state"], "disabled")
                self.assertFalse(synthesis["active"])
                self.assertFalse(synthesis_lane_enabled(synthesis))
                self.assertFalse(synthesis["requires_user_acceptance"])
                self.assertFalse(synthesis["prompt_user_in_plan_mode"])
                self.assertEqual(synthesis["recommended_panel"], [])
                self.assertEqual(synthesis["mentioned_provider_camps"], [])
                self.assertEqual(synthesis["artifact_contract"], [])
                self.assertEqual(route["hard_stops"], [])


    def test_accepted_synthesis_opt_in_is_active(self) -> None:
        text = "Refactor a high-risk architecture policy route."
        route = classify_work(text, requested_roles=["architecture"])
        synthesis = recommend_model_synthesis(text, route, force_accepted=True)

        self.assertEqual(synthesis["recommended_mode"], "accepted")
        self.assertEqual(synthesis["activation_state"], "accepted")
        self.assertTrue(synthesis["active"])
        self.assertFalse(synthesis["prompt_user_in_plan_mode"])
        self.assertTrue(synthesis_lane_enabled(synthesis))

    def test_disabled_synthesis_takes_precedence_over_accepted_opt_in(self) -> None:
        text = "Use model synthesis for a high-risk architecture policy route."
        route = classify_work(text, requested_roles=["architecture"])
        synthesis = recommend_model_synthesis(text, route, force_accepted=True, disabled=True)

        self.assertEqual(synthesis["recommended_mode"], "disabled")
        self.assertFalse(synthesis["active"])
        self.assertFalse(synthesis_lane_enabled(synthesis))
        self.assertEqual(synthesis["trigger_reasons"], [])

    def test_high_risk_architecture_work_recommends_synthesis_without_explicit_request(self) -> None:
        synthesis = recommend_model_synthesis(
            "Redesign the architecture boundary for a high-risk release workflow.",
            {
                "risk_level": "high",
                "task_class": "architecture-review",
                "share_boundary": "redacted-packet",
            },
        )

        self.assertEqual(synthesis["recommended_mode"], "recommended")
        self.assertTrue(synthesis["requires_user_acceptance"])
        self.assertFalse(synthesis["active"])
        self.assertIn("high-risk architecture work", synthesis["trigger_reasons"])


    def test_rejected_and_failed_inputs_are_excluded_from_minimum(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {"lane": "gemini", "disposition": "accepted"},
                {"lane": "opus", "disposition": "rejected"},
                {"lane": "chatgpt", "disposition": "failed-evaluation"},
            ]
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["usable_input_count"], 1)
        self.assertEqual(result["rejected_input_count"], 2)
        self.assertIn(
            "fewer than minimum_usable_inputs accepted or accepted-with-modification inputs",
            result["blocked_reasons"],
        )


    def test_compact_critic_cannot_use_one_v1_marker_to_bypass_v2_guard(self) -> None:
        result = evaluate_synthesis_inputs([
            {"lane": "control", "provider_camp": "openai", "disposition": "accepted"},
            {
                "lane": "contradictory-glm", "provider_camp": "local", "external": False,
                "executor": "rhoai_glm_compact_architecture_critic",
                "disposition": "accepted", "synthesis_use": "primary", "architect_adjudicated": True,
                "local_expected_response_contract": "unknown-contract",
                "local_response_contract": "cwo-glm-critic-v1",
                "local_completion_status": "contract-invalid",
                "local_usable_final_content": False,
                "local_normalized_return_matches": False,
            },
        ])
        self.assertEqual(result["primary_input_count"], 1)
        self.assertEqual(result["salvage_input_count"], 0)
        self.assertEqual(result["input_summaries"][1]["synthesis_use"], "quarantine")

    def test_invalid_synthesis_use_cannot_upgrade_gemini(self) -> None:
        result = evaluate_synthesis_inputs(
            [
                {
                    "lane": "gemini",
                    "provider_camp": "google",
                    "disposition": "accepted",
                    "synthesis_use": "definitely-primary",
                },
                {"lane": "opus", "provider_camp": "anthropic", "disposition": "accepted"},
            ]
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["usable_input_count"], 1)
        self.assertEqual(result["salvage_input_count"], 1)
        self.assertEqual(result["input_summaries"][0]["synthesis_use"], "salvage-only")
        self.assertIsNone(result["input_summaries"][0]["requested_synthesis_use"])



if __name__ == "__main__":
    unittest.main()

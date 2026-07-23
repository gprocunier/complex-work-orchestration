from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import unittest
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo_core.native_replanning as native_replanning  # noqa: E402

from cwo_core.native_authority import (  # noqa: E402
    OPERATOR_APPROVAL_TYPE,
    OPERATOR_REQUIRED_CHANGE_TYPES,
    OperatorApprovalVerifier,
    VerifiedOperatorApproval,
    assess_operator_required_changes,
    canonical_authority_sha256,
    protected_change_identity,
    trusted_actor_authority,
    verify_operator_directive,
)
from cwo_core.native_replanning import (  # noqa: E402
    VerifiedReplanningState,
    build_replanning_state as _build_replanning_state,
    read_replanning_state,
    transition_replanning_state as _transition_replanning_state,
)

POLICY = json.loads((ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8"))
WORK_SIZING = POLICY["work_sizing"]["enforcement"]["foundation-canary"]["autonomous_replanning"]
_STATE_SEQUENCE = 0


def _sha(label: str) -> str:
    return canonical_authority_sha256({"label": label})


def _trusted_authority(level: str):
    source_type, actor_role = {
        "worker": ("worker-discovery", "operative-worker"),
        "pm": ("pm-observation", "project-manager"),
        "architect": ("architect-judgment", "architect"),
    }[level]
    return trusted_actor_authority(
        source_type=source_type,
        source_id=f"{level}-session",
        source_sha256=_sha(f"{level}-session"),
        actor_id=f"{level}-1",
        actor_role=actor_role,
        identity_source="trusted-session-jsonl",
    )


def _operator_authority(event: str):
    key = b"test-only-replanning-operator-key"
    body = {
        "version": 1,
        "directive_id": f"operator-{event}",
        "action_sha256": _sha(f"replanning:{event}"),
        "actor_id": "operator-1",
        "identity_source": "trusted-control-session",
        "authorized_scope": "complete-task",
        "parent_receipt_sha256": None,
        "issued_at": "2026-07-20T00:00:00Z",
        "nonce": f"nonce-{event}",
    }
    body["signature"] = hmac.new(
        key,
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return verify_operator_directive(
        body,
        verification_key=key,
        expected_actor_id="operator-1",
        expected_identity_source="trusted-control-session",
        expected_action_sha256=_sha(f"replanning:{event}"),
    )


def _authority_for_event(event: str):
    if event in {
        "model-mismatch",
        "control-loss",
        "security-or-authority-ambiguity",
        "out-of-scope-mutation",
        "tainted-mutation",
        "operator-trigger",
    }:
        return _operator_authority(event)
    if event in {"worker-compaction", "architect-refined"}:
        return _trusted_authority("architect")
    if event in {"exploration-limit", "clean-no-artifact", "pm-refined", "fresh-worker-assigned"}:
        return _trusted_authority("pm")
    return _trusted_authority("worker")


def build_replanning_state(state: dict, *, policy: dict | None = None) -> dict:
    return _build_replanning_state(
        state,
        caller_authority=_trusted_authority("worker"),
        policy=policy,
    )


def transition_replanning_state(
    state: dict,
    event: str,
    evidence,
    *,
    operator_approval_verifier: OperatorApprovalVerifier | None = None,
    operator_approval_receipts: dict | None = None,
    policy: dict | None = None,
) -> dict:
    return _transition_replanning_state(
        state,
        event,
        evidence,
        caller_authority=_authority_for_event(event),
        operator_approval_verifier=operator_approval_verifier,
        operator_approval_receipts=operator_approval_receipts,
        policy=policy,
    )


def _policy_with(overrides: dict[str, int] | None = None) -> dict:
    policy = copy.deepcopy(POLICY)
    replanning = policy["work_sizing"]["enforcement"]["foundation-canary"]["autonomous_replanning"]
    if overrides:
        replanning.update(overrides)
    return policy


def _base_state() -> dict:
    global _STATE_SEQUENCE
    _STATE_SEQUENCE += 1
    suffix = str(_STATE_SEQUENCE)
    return {
        "state": "planned",
        "work_unit_id": f"wu-native-replanning-{suffix}",
        "bead_id": f"bead-native-replanning-{suffix}",
        "packet_id": f"packet-native-replanning-{suffix}",
        "requested_model": "gpt-5.3-codex-spark",
        "objective": "native replanning validation",
        "security_context": "standard",
        "model_match": True,
        "control_healthy": True,
        "counters": {
            "dispatches": 0,
            "tool_calls_used": 0,
            "runtime_seconds_used": 0,
            "context_compactions": 0,
            "pm_replans_used": 0,
            "architect_cycles_used": 0,
        },
        "aggregate_allowance": {
            "tool_calls_hard": 100,
            "runtime_seconds_hard": 400,
            "dispatch_soft_cap": WORK_SIZING["dispatch_soft_cap"],
            "dispatch_soft_cap_action": WORK_SIZING["dispatch_soft_cap_action"],
            "max_pm_replans": WORK_SIZING["max_pm_replans"],
            "max_architect_cycles": WORK_SIZING["max_architect_cycles"],
            "max_compactions": WORK_SIZING["max_compactions"],
        },
        "mutation": {"out_of_scope": False, "tainted": False},
        "main_thread": {
            "model": "gpt-5.6-sol",
            "effort": "xhigh",
            "source": "user-declaration",
            "recommended_effort": "max",
            "recommendation_reason": "complex-repair",
            "advisory": True,
            "user_selected_effort_retained": True,
        },
    }


def _state_with_overrides(overrides: dict | None = None) -> dict:
    payload = _base_state()
    requested = copy.deepcopy(overrides or {})
    target_state = requested.pop("state", "executing")
    observed_mutation = requested.pop("mutation", None)
    payload.update(requested)
    state = build_replanning_state(payload)
    if target_state == "planned":
        return state
    state = transition_replanning_state(state, "accepted", {})
    if target_state == "dispatchable":
        return state
    state = transition_replanning_state(state, "dispatch-started", {})
    if observed_mutation is not None and any(observed_mutation.values()):
        return transition_replanning_state(
            state,
            "needs-replan",
            {"mutation": observed_mutation},
        )
    if target_state == "executing":
        return state
    if target_state == "pm-realignment":
        return transition_replanning_state(
            state,
            "needs-replan",
            _needs_replan_evidence(),
        )
    raise AssertionError(f"unsupported test lifecycle state: {target_state}")


def _protected_change_approval(
    key: bytes,
    before: dict,
    after: dict,
    *,
    change_type: str,
    nonce: str = "replanning-protected-change-nonce",
) -> dict:
    body = {
        "approval_type": OPERATOR_APPROVAL_TYPE,
        "version": 1,
        "approval_id": f"replanning-{change_type}",
        "change_type": change_type,
        "before_sha256": canonical_authority_sha256(before),
        "after_sha256": canonical_authority_sha256(after),
        "actor_id": "operator-1",
        "identity_source": "trusted-control-session",
        "authorized_scope": "complete-task",
        "parent_receipt_sha256": None,
        "issued_at": "2026-07-20T00:00:00Z",
        "expires_at": "2026-07-20T00:10:00Z",
        "nonce": nonce,
    }
    body["signature"] = hmac.new(
        key,
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return body


def _protected_refinement_assessment(
    state: dict,
    proposed_changes: dict,
):
    before = copy.deepcopy(state)
    before["authority_provenance"] = _trusted_authority("pm").serialize()
    after = copy.deepcopy(before)
    after.update(copy.deepcopy(proposed_changes))
    return assess_operator_required_changes(
        before,
        after,
        operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
        profile="native-replanning-refinement",
        identity=protected_change_identity(
            artifact_type="cwo-native-replanning-state",
            artifact_id=f"{before['result_type']}:{before['version']}",
            work_unit_id=before["work_unit_id"],
            bead_id=before["bead_id"],
            packet_id=before["packet_id"],
        ),
    )


def _needs_replan_evidence(*, decision: str = "pm-refine", uncertainty_class: str = "bounded") -> dict:
    return {
        "trusted_evidence": True,
        "exact_model": True,
        "control_healthy": True,
        "tool_calls_delta": 3,
        "runtime_seconds_delta": 12,
        "context_compactions_delta": 0,
        "mutation": {"out_of_scope": False, "tainted": False},
        "replan": {
            "reason_code": "unexpected-reasoning",
            "completed_evidence": "isolated the unexpected decision",
            "discovered_facts": ["the implementation depends on an authority decision"],
            "files_touched": [],
            "mutation_state": "clean",
            "mutation_stopped": True,
            "remaining_outcomes": ["apply the adjudicated decision"],
            "remaining_files": [],
            "remaining_tests": ["focused decision regression"],
            "uncertainty": {
                "class": uncertainty_class,
                "decision": decision,
                "detail": "the worker cannot choose the authority boundary",
            },
            "scope_delta": {
                "outcomes_added": 0,
                "files_added": 0,
                "tests_added": 1,
                "within_original_objective": True,
                "within_aggregate_allowance": True,
            },
            "bounded_options": [
                {
                    "option_id": "adjudicate",
                    "route": decision,
                    "description": "resolve the decision and redispatch a refined packet",
                    "tool_calls_p90": 4,
                    "runtime_seconds_p90": 60,
                }
            ],
            "recommendation": "adjudicate",
            "cumulative_usage": {
                "tool_calls": 3,
                "runtime_seconds": 12,
                "context_compactions": 0,
                "full_suite_runs": 0,
            },
        },
    }


class NativeReplanningTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.replay_store = Path(self._temporary.name) / "operator-replay.json"

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_successful_lifecycle_is_linear_and_stale_sources_cannot_dispatch(self) -> None:
        planned = build_replanning_state(_base_state())
        dispatchable = transition_replanning_state(planned, "accepted", {})
        with self.assertRaisesRegex(ValueError, "retired and stale"):
            transition_replanning_state(planned, "accepted", {})

        executing = transition_replanning_state(
            dispatchable,
            "dispatch-started",
            {},
        )
        self.assertEqual(executing["counters"]["dispatches"], 1)
        with self.assertRaisesRegex(ValueError, "retired and stale"):
            transition_replanning_state(dispatchable, "dispatch-started", {})

        completed = transition_replanning_state(
            executing,
            "completed",
            {"completed": True},
        )
        self.assertEqual(completed["state"], "completed")
        with self.assertRaisesRegex(ValueError, "retired and stale"):
            transition_replanning_state(
                executing,
                "completed",
                {"completed": True},
            )

    def test_concurrent_transition_claim_yields_exactly_one_successor(self) -> None:
        source = build_replanning_state(_base_state())
        entered = Event()
        release = Event()
        real_core = native_replanning._transition_replanning_state

        def blocked_core(*args, **kwargs):
            entered.set()
            if not release.wait(timeout=5):
                raise RuntimeError("test transition release timed out")
            return real_core(*args, **kwargs)

        with patch.object(
            native_replanning,
            "_transition_replanning_state",
            side_effect=blocked_core,
        ), ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(
                transition_replanning_state,
                source,
                "accepted",
                {},
            )
            if not entered.wait(timeout=5):
                release.set()
                self.fail("first transition did not enter the core")
            second = executor.submit(
                transition_replanning_state,
                source,
                "accepted",
                {},
            )
            second_error = second.exception(timeout=5)
            release.set()
            successor = first.result(timeout=5)

        self.assertIsInstance(second_error, ValueError)
        self.assertIn("already in-flight", str(second_error))
        self.assertIs(type(successor), VerifiedReplanningState)
        self.assertEqual(successor["state"], "dispatchable")

    def test_failed_core_or_sealing_releases_source_for_corrected_retry(self) -> None:
        malformed_source = build_replanning_state(_base_state())
        with self.assertRaisesRegex(ValueError, "unknown event"):
            transition_replanning_state(malformed_source, "not-an-event", {})
        corrected = transition_replanning_state(
            malformed_source,
            "accepted",
            {},
        )
        self.assertEqual(corrected["state"], "dispatchable")

        sealing_source = build_replanning_state(_base_state())
        with patch.object(
            native_replanning,
            "_mint_sealed_replanning_state",
            side_effect=ValueError("simulated sealing failure"),
        ), self.assertRaisesRegex(ValueError, "simulated sealing failure"):
            transition_replanning_state(sealing_source, "accepted", {})
        sealing_retry = transition_replanning_state(
            sealing_source,
            "accepted",
            {},
        )
        self.assertEqual(sealing_retry["state"], "dispatchable")

    def test_private_core_projection_is_nonoperative_and_does_not_consume_source(self) -> None:
        source = build_replanning_state(_base_state())
        projection = native_replanning._transition_replanning_state(
            source,
            "accepted",
            {},
            caller_authority=_trusted_authority("worker"),
        )
        self.assertIs(type(projection), dict)
        with self.assertRaisesRegex(ValueError, "inspection-only"):
            transition_replanning_state(projection, "dispatch-started", {})
        successor = transition_replanning_state(source, "accepted", {})
        self.assertEqual(successor["state"], "dispatchable")

    def test_terminal_transition_cannot_fork_from_preterminal_source(self) -> None:
        source = _state_with_overrides()
        contradictory = _needs_replan_evidence()
        contradictory["contradictory_validation"] = True
        stopped = transition_replanning_state(
            source,
            "needs-replan",
            contradictory,
        )
        self.assertEqual(stopped["state"], "protected-stop")
        self.assertTrue(
            stopped["terminal_latches"]["contradictory_validation"]
        )
        with self.assertRaisesRegex(ValueError, "retired and stale"):
            transition_replanning_state(
                source,
                "clean-no-artifact",
                {"trusted_evidence": True},
            )

    def test_typed_needs_replan_routes_to_pm_without_operator_approval(self) -> None:
        result = transition_replanning_state(
            _state_with_overrides(),
            "needs-replan",
            _needs_replan_evidence(),
        )
        self.assertEqual(result["state"], "pm-realignment")
        self.assertEqual(result["counters"]["pm_replans_used"], 1)
        self.assertEqual(result["next_action"], "request-pm-refinement")
        reassignment = transition_replanning_state(
            result,
            "pm-refined",
            {"requires_architect_cycle": False},
        )
        self.assertEqual(reassignment["state"], "reassignment-ready")

    def test_pm_refinement_rejects_protected_change_without_verified_approval(self) -> None:
        pm_state = transition_replanning_state(
            _state_with_overrides(),
            "needs-replan",
            _needs_replan_evidence(),
        )
        evidence = {
            "requires_architect_cycle": False,
            "proposed_changes": {"objective": "publish repaired CWO"},
        }
        with self.assertRaisesRegex(ValueError, "verified operator approval"):
            transition_replanning_state(pm_state, "pm-refined", evidence)
        with self.assertRaisesRegex(ValueError, "exact operator approval verifier"):
            _transition_replanning_state(
                pm_state,
                "pm-refined",
                evidence,
                caller_authority=_trusted_authority("pm"),
                operator_approval_verifier="operator",
                operator_approval_receipts={"objective-change": "approved"},
            )

    def test_pm_refinement_accepts_exact_operator_approval_and_records_audit(self) -> None:
        pm_state = transition_replanning_state(
            _state_with_overrides(),
            "needs-replan",
            _needs_replan_evidence(),
        )
        evidence = {
            "requires_architect_cycle": False,
            "proposed_changes": {"objective": "publish repaired CWO"},
        }
        assessment = _protected_refinement_assessment(
            pm_state, evidence["proposed_changes"]
        )
        key = b"test-only-replanning-protected-change-key"
        receipt = _protected_change_approval(
            key,
            assessment.before_subject,
            assessment.after_subject,
            change_type="objective-change",
        )
        verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            replay_store_path=self.replay_store,
            now="2026-07-20T00:05:00Z",
        )
        result = transition_replanning_state(
            pm_state,
            "pm-refined",
            evidence,
            operator_approval_verifier=verifier,
            operator_approval_receipts={"objective-change": receipt},
        )
        self.assertEqual(result["objective"], "publish repaired CWO")
        self.assertIn("operator-approved:objective-change", result["reason_codes"])
        self.assertEqual(
            [item["change_type"] for item in result["protected_change_authorizations"]],
            ["objective-change"],
        )
        self.assertEqual(
            result["cwo_native_replanning_receipt"][
                "protected_change_authorizations"
            ],
            result["protected_change_authorizations"],
        )
        self.assertEqual(
            verifier.consumed_nonces,
            frozenset({"replanning-protected-change-nonce"}),
        )

    def test_protected_replanning_approval_is_exact_and_nonreplayable(self) -> None:
        pm_state = transition_replanning_state(
            _state_with_overrides(),
            "needs-replan",
            _needs_replan_evidence(),
        )
        evidence = {
            "requires_architect_cycle": False,
            "proposed_changes": {"requested_model": "gpt-5.6-sol"},
        }
        assessment = _protected_refinement_assessment(
            pm_state, evidence["proposed_changes"]
        )
        key = b"test-only-replanning-protected-change-key"
        receipt = _protected_change_approval(
            key,
            assessment.before_subject,
            assessment.after_subject,
            change_type="model-substitution",
        )
        verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            replay_store_path=self.replay_store,
            now="2026-07-20T00:05:00Z",
        )
        result = transition_replanning_state(
            pm_state,
            "pm-refined",
            evidence,
            operator_approval_verifier=verifier,
            operator_approval_receipts={"model-substitution": receipt},
        )
        self.assertEqual(result["requested_model"], "gpt-5.6-sol")
        with self.assertRaisesRegex(ValueError, "retired and stale"):
            transition_replanning_state(
                pm_state,
                "pm-refined",
                evidence,
                operator_approval_verifier=verifier,
                operator_approval_receipts={"model-substitution": receipt},
            )

    def test_pm_can_narrow_budget_without_operator_but_cannot_use_wrong_event(self) -> None:
        pm_state = transition_replanning_state(
            _state_with_overrides(),
            "needs-replan",
            _needs_replan_evidence(),
        )
        result = transition_replanning_state(
            pm_state,
            "pm-refined",
            {
                "requires_architect_cycle": False,
                "proposed_changes": {
                    "aggregate_allowance": {
                        "tool_calls_hard": 90,
                        "runtime_seconds_hard": 350,
                    }
                },
            },
        )
        self.assertEqual(result["aggregate_allowance"]["tool_calls_hard"], 90)
        with self.assertRaisesRegex(ValueError, "only for refinement events"):
            transition_replanning_state(
                _state_with_overrides(),
                "completed",
                {
                    "completed": True,
                    "proposed_changes": {"objective": "different"},
                },
            )

    def test_typed_needs_replan_routes_material_reasoning_to_architect(self) -> None:
        result = transition_replanning_state(
            _state_with_overrides(),
            "needs-replan",
            _needs_replan_evidence(decision="architect-reasoning", uncertainty_class="architect"),
        )
        self.assertEqual(result["state"], "architect-realignment")
        self.assertEqual(result["counters"]["pm_replans_used"], 0)
        self.assertEqual(result["next_action"], "request-architect-refinement")

    def test_typed_needs_replan_fails_closed_on_invalid_evidence_or_scope(self) -> None:
        malformed = _needs_replan_evidence()
        malformed["replan"]["mutation_stopped"] = False
        stopped = transition_replanning_state(_state_with_overrides(), "needs-replan", malformed)
        self.assertEqual(stopped["state"], "protected-stop")
        self.assertIn("invalid-needs-replan-evidence", stopped["reason_codes"])

        changed = _needs_replan_evidence()
        changed["replan"]["scope_delta"]["within_original_objective"] = False
        stopped = transition_replanning_state(_state_with_overrides(), "needs-replan", changed)
        self.assertEqual(stopped["state"], "protected-stop")
        self.assertIn("objective-change", stopped["reason_codes"])

        oversized = _needs_replan_evidence()
        oversized["replan"]["bounded_options"][0]["tool_calls_p90"] = 98
        stopped = transition_replanning_state(_state_with_overrides(), "needs-replan", oversized)
        self.assertEqual(stopped["state"], "protected-stop")
        self.assertIn("invalid-needs-replan-evidence", stopped["reason_codes"])
    def test_oversized_read_only_exploration_realigns_to_pm_before_compaction(self) -> None:
        evidence = {
            "trusted_evidence": True,
            "exact_model": True,
            "control_healthy": True,
            "tool_calls_delta": 2,
            "runtime_seconds_delta": 10,
            "context_compactions_delta": 0,
            "mutation": {"out_of_scope": False, "tainted": False},
            "objective_changed": False,
            "security_changed": False,
            "authority_changed": False,
        }
        result = transition_replanning_state(_state_with_overrides(), "clean-no-artifact", evidence)
        self.assertEqual(result["state"], "pm-realignment")
        self.assertEqual(result["counters"]["pm_replans_used"], 1)
        self.assertEqual(result["cwo_native_replanning_receipt"]["state_after"], "pm-realignment")

    def test_clean_no_artifact_pm_refined_to_fresh_worker(self) -> None:
        evidence = {
            "trusted_evidence": True,
            "exact_model": True,
            "control_healthy": True,
            "mutation": {"out_of_scope": False, "tainted": False},
        }
        pm = transition_replanning_state(_state_with_overrides(), "clean-no-artifact", evidence)
        reassigned = transition_replanning_state(pm, "pm-refined", {"requires_architect_cycle": False})
        ready = transition_replanning_state(reassigned, "fresh-worker-assigned", {})
        self.assertEqual(ready["state"], "dispatchable")
        self.assertEqual(ready["reason_codes"], [WORK_SIZING["fresh-worker-reassignment"]["event"]])

    def test_one_pm_plus_one_architect_cycle_then_second_cycle_stops(self) -> None:
        evidence = {
            "trusted_evidence": True,
            "exact_model": True,
            "control_healthy": True,
            "mutation": {"out_of_scope": False, "tainted": False},
        }
        pm = transition_replanning_state(_state_with_overrides(), "clean-no-artifact", evidence)
        architect_ready = transition_replanning_state(pm, "pm-refined", {"requires_architect_cycle": True})
        reassignment = transition_replanning_state(architect_ready, "architect-refined", {})
        dispatchable = transition_replanning_state(reassignment, "fresh-worker-assigned", {})
        retry_running = transition_replanning_state(
            dispatchable, "dispatch-started", {}
        )
        second_pm = transition_replanning_state(retry_running, "clean-no-artifact", evidence)
        self.assertEqual(second_pm["state"], "protected-stop")
        self.assertIn("pm-replan-exhausted", second_pm["reason_codes"])

        expanded_policy = _policy_with({"max_pm_replans": 2})
        cycle = build_replanning_state(_base_state(), policy=expanded_policy)
        cycle = transition_replanning_state(
            cycle, "accepted", {}, policy=expanded_policy
        )
        cycle = transition_replanning_state(
            cycle, "dispatch-started", {}, policy=expanded_policy
        )
        cycle = transition_replanning_state(
            cycle, "clean-no-artifact", evidence, policy=expanded_policy
        )
        cycle = transition_replanning_state(
            cycle,
            "pm-refined",
            {"requires_architect_cycle": True},
            policy=expanded_policy,
        )
        cycle = transition_replanning_state(
            cycle, "architect-refined", {}, policy=expanded_policy
        )
        cycle = transition_replanning_state(
            cycle, "fresh-worker-assigned", {}, policy=expanded_policy
        )
        cycle = transition_replanning_state(
            cycle, "dispatch-started", {}, policy=expanded_policy
        )
        cycle = transition_replanning_state(
            cycle, "clean-no-artifact", evidence, policy=expanded_policy
        )
        cycle = transition_replanning_state(
            cycle,
            "pm-refined",
            {"requires_architect_cycle": True},
            policy=expanded_policy,
        )
        exhausted_architect = transition_replanning_state(
            cycle, "architect-refined", {}, policy=expanded_policy
        )
        self.assertEqual(exhausted_architect["state"], "protected-stop")
        self.assertIn("architect-cycle-exhausted", exhausted_architect["reason_codes"])

    def test_all_protected_boundaries_stop(self) -> None:
        base_execution = _state_with_overrides()
        stopped = transition_replanning_state(base_execution, "model-mismatch", {})
        self.assertEqual(stopped["state"], "protected-stop")
        self.assertEqual(stopped["reason_codes"], ["model-mismatch"])

        compaction = transition_replanning_state(
            _state_with_overrides(),
            "clean-no-artifact",
            {
                "trusted_evidence": True,
                "exact_model": True,
                "control_healthy": True,
                "mutation": {"out_of_scope": False, "tainted": False},
                "context_compactions_delta": 1,
            },
        )
        self.assertEqual(compaction["state"], "protected-stop")

        control = transition_replanning_state(
            _state_with_overrides(),
            "control-loss",
            {},
        )
        self.assertEqual(control["state"], "protected-stop")
        self.assertEqual(control["reason_codes"], ["control-loss"])

        security = transition_replanning_state(
            _state_with_overrides(),
            "clean-no-artifact",
            {
                "trusted_evidence": True,
                "exact_model": True,
                "control_healthy": True,
                "mutation": {"out_of_scope": False, "tainted": False},
                "security_changed": True,
            },
        )
        self.assertEqual(security["state"], "protected-stop")
        self.assertIn("security-or-authority-change", security["reason_codes"])

        invalid = transition_replanning_state(
            _state_with_overrides(),
            "clean-no-artifact",
            {
                "trusted_evidence": False,
                "exact_model": True,
                "control_healthy": True,
                "mutation": {"out_of_scope": False, "tainted": False},
            },
        )
        self.assertEqual(invalid["state"], "protected-stop")
        self.assertIn("invalid-trusted-evidence", invalid["reason_codes"])

    def test_aggregate_allowance_shared_across_reassignment(self) -> None:
        evidence = {
            "trusted_evidence": True,
            "exact_model": True,
            "control_healthy": True,
            "tool_calls_delta": 8,
            "runtime_seconds_delta": 16,
            "mutation": {"out_of_scope": False, "tainted": False},
        }
        initial = build_replanning_state(_base_state())
        initial = transition_replanning_state(initial, "accepted", {})
        with_dispatch = transition_replanning_state(
            initial,
            "dispatch-started",
            {"tool_calls_delta": 8, "runtime_seconds_delta": 16},
        )
        with_dispatch = transition_replanning_state(with_dispatch, "clean-no-artifact", evidence)
        with_dispatch = transition_replanning_state(with_dispatch, "pm-refined", {"requires_architect_cycle": False})
        reassign = transition_replanning_state(with_dispatch, "fresh-worker-assigned", {})
        self.assertEqual(reassign["state"], "dispatchable")
        self.assertEqual(reassign["counters"]["tool_calls_used"], 16)
        self.assertEqual(reassign["counters"]["runtime_seconds_used"], 32)

    def test_dispatch_soft_cap_is_warning_only(self) -> None:
        policy = _policy_with({"dispatch_soft_cap": 0, "dispatch_soft_cap_action": "pm-architect-review"})
        state = build_replanning_state(_base_state(), policy=policy)
        state = transition_replanning_state(
            state,
            "accepted",
            {},
            policy=policy,
        )
        dispatch = transition_replanning_state(state, "dispatch-started", {}, policy=policy)
        self.assertEqual(dispatch["state"], "executing")
        self.assertIn("dispatch-soft-cap-exceeded", dispatch["reason_codes"])
        self.assertNotEqual(dispatch["state"], "protected-stop")

    def test_invalid_state_event_evidence_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            build_replanning_state({"state": "executing", "work_unit_id": "wu", "bead_id": "bead", "packet_id": "pkt", "requested_model": "gpt-5.3-codex-spark", "objective": "x", "security_context": "x", "aggregate_allowance": {"tool_calls_hard": 1, "runtime_seconds_hard": 1}})
        with self.assertRaises(ValueError):
            transition_replanning_state(_state_with_overrides(), "no-such-event", {})
        with self.assertRaises(ValueError):
            transition_replanning_state(_state_with_overrides(), "accepted", 42)

    def test_event_name_and_authority_string_cannot_authorize_transition(self) -> None:
        state = _state_with_overrides({"state": "pm-realignment"})
        with self.assertRaisesRegex(ValueError, "insufficient-authority"):
            _transition_replanning_state(
                state,
                "pm-refined",
                {"requires_architect_cycle": False},
                caller_authority=_trusted_authority("worker"),
            )
        with self.assertRaisesRegex(ValueError, "verified-authority-required"):
            _transition_replanning_state(
                state,
                "pm-refined",
                {"requires_architect_cycle": False},
                caller_authority="pm",
            )

    def test_receipt_carries_verified_provenance_and_structured_reasons(self) -> None:
        result = transition_replanning_state(
            _state_with_overrides(),
            "needs-replan",
            _needs_replan_evidence(),
        )
        receipt = result["cwo_native_replanning_receipt"]
        self.assertNotIn("authority", receipt)
        self.assertEqual(
            receipt["authority_provenance"]["actor_role"],
            "operative-worker",
        )
        self.assertEqual(
            [record["reason"] for record in receipt["reason_records"]],
            receipt["reason_codes"],
        )
        self.assertTrue(
            all(record["detected_by"] == "native-replanning:needs-replan" for record in receipt["reason_records"])
        )

    def test_version_one_state_is_readable_but_cannot_create_new_write(self) -> None:
        legacy = copy.deepcopy(_state_with_overrides())
        legacy["version"] = 1
        legacy["authority"] = "operator"
        del legacy["authority_provenance"]
        legacy_receipt = legacy["cwo_native_replanning_receipt"]
        legacy_receipt["version"] = 1
        legacy_receipt["authority"] = "operator"
        del legacy_receipt["authority_provenance"]
        del legacy_receipt["reason_records"]
        self.assertEqual(read_replanning_state(legacy), legacy)
        with self.assertRaisesRegex(ValueError, "inspection-only"):
            _transition_replanning_state(
                legacy,
                "completed",
                {"completed": True},
                caller_authority=_operator_authority("operator-trigger"),
            )

    def test_refinement_rejects_unknown_proposed_fields_before_source_mutation(self) -> None:
        pm_state = transition_replanning_state(
            _state_with_overrides(),
            "needs-replan",
            _needs_replan_evidence(),
        )
        original = copy.deepcopy(pm_state)
        with self.assertRaisesRegex(ValueError, "unsupported field.*security_policy_bypass"):
            transition_replanning_state(
                pm_state,
                "pm-refined",
                {
                    "requires_architect_cycle": False,
                    "proposed_changes": {"security_policy_bypass": True},
                },
            )
        self.assertEqual(pm_state, original)

    def test_taint_and_contradictory_validation_are_sticky_terminal_stops(self) -> None:
        tainted = _state_with_overrides(
            {"mutation": {"out_of_scope": False, "tainted": True}}
        )
        taint_stop = transition_replanning_state(
            tainted,
            "needs-replan",
            _needs_replan_evidence(),
        )
        self.assertEqual(taint_stop["state"], "protected-stop")
        self.assertTrue(taint_stop["mutation"]["tainted"])
        self.assertTrue(taint_stop["terminal_latches"]["tainted"])
        self.assertIn("tainted-mutation", taint_stop["reason_codes"])
        taint_followup = transition_replanning_state(
            taint_stop,
            "pm-refined",
            {
                "requires_architect_cycle": False,
                "mutation": {"out_of_scope": False, "tainted": False},
            },
        )
        self.assertEqual(taint_followup["state"], "protected-stop")
        self.assertTrue(taint_followup["mutation"]["tainted"])
        self.assertTrue(taint_followup["terminal_latches"]["tainted"])

        contradiction_evidence = _needs_replan_evidence()
        contradiction_evidence["contradictory_validation"] = True
        contradiction_stop = transition_replanning_state(
            _state_with_overrides(),
            "needs-replan",
            contradiction_evidence,
        )
        self.assertEqual(contradiction_stop["state"], "protected-stop")
        self.assertIn(
            "contradictory-validation", contradiction_stop["reason_codes"]
        )
        self.assertTrue(
            contradiction_stop["terminal_latches"]["contradictory_validation"]
        )
        contradiction_followup = transition_replanning_state(
            contradiction_stop,
            "pm-refined",
            {
                "requires_architect_cycle": False,
                "contradictory_validation": False,
            },
        )
        self.assertEqual(contradiction_followup["state"], "protected-stop")
        self.assertIn(
            "contradictory-validation", contradiction_followup["reason_codes"]
        )
        self.assertTrue(
            contradiction_followup["terminal_latches"]["contradictory_validation"]
        )

    def test_serialized_v3_tampering_and_retargeting_are_never_operative(self) -> None:
        state = _state_with_overrides()
        self.assertIs(type(state), VerifiedReplanningState)
        attacks = []
        for field, value in (
            ("objective", "attacker objective"),
            ("requested_model", "attacker-model"),
            ("security_context", "bypassed"),
            ("work_unit_id", "retargeted-work"),
            ("bead_id", "retargeted-bead"),
            ("packet_id", "retargeted-packet"),
        ):
            tampered = state.serialize()
            tampered[field] = value
            attacks.append(tampered)
        budget = state.serialize()
        budget["aggregate_allowance"]["tool_calls_hard"] += 1000
        attacks.append(budget)
        receipt_mismatch = state.serialize()
        receipt_mismatch["cwo_native_replanning_receipt"]["packet_id"] = "other"
        attacks.append(receipt_mismatch)

        for tampered in attacks:
            with self.subTest(field=next(iter(set(tampered) - set(state)), "bound")):
                with self.assertRaisesRegex(ValueError, "integrity mismatch"):
                    read_replanning_state(tampered)
                with self.assertRaisesRegex(ValueError, "inspection-only"):
                    _transition_replanning_state(
                        tampered,
                        "completed",
                        42,
                        caller_authority="operator",  # type: ignore[arg-type]
                    )
        stripped_header = state.serialize()
        stripped_header.pop("result_type")
        with self.assertRaisesRegex(ValueError, "live verifier-minted"):
            _transition_replanning_state(
                stripped_header,
                "completed",
                42,
                caller_authority="operator",  # type: ignore[arg-type]
            )

    def test_transition_never_bootstraps_raw_or_projected_state(self) -> None:
        live = _state_with_overrides()
        projected = {
            field: live[field]
            for field in (
                "state",
                "work_unit_id",
                "bead_id",
                "packet_id",
                "requested_model",
                "objective",
                "security_context",
                "model_match",
                "control_healthy",
                "counters",
                "aggregate_allowance",
                "mutation",
                "terminal_latches",
                "main_thread",
                "reason_codes",
                "next_action",
            )
        }
        with self.assertRaisesRegex(ValueError, "live verifier-minted"):
            transition_replanning_state(projected, "completed", {"completed": True})

        projected.update(
            {
                "state": "planned",
                "model_match": True,
                "control_healthy": True,
                "counters": {key: 0 for key in live["counters"]},
                "mutation": {"out_of_scope": False, "tainted": False},
                "terminal_latches": {
                    "tainted": False,
                    "contradictory_validation": False,
                },
                "reason_codes": [],
                "next_action": "wait",
            }
        )
        with self.assertRaisesRegex(ValueError, "already-bootstrapped"):
            build_replanning_state(projected)

    def test_explicit_bootstrap_accepts_only_fresh_lifecycle_values(self) -> None:
        attacks = (
            ("state", "executing", "state must be planned"),
            (
                "counters",
                {
                    "dispatches": 1,
                    "tool_calls_used": 0,
                    "runtime_seconds_used": 0,
                    "context_compactions": 0,
                    "pm_replans_used": 0,
                    "architect_cycles_used": 0,
                },
                "counters must all be zero",
            ),
            (
                "terminal_latches",
                {"tainted": False, "contradictory_validation": True},
                "terminal latches must be false",
            ),
            ("reason_codes", ["prior-lineage"], "reason_codes must be empty"),
            ("next_action", "resume", "next_action must be wait"),
            (
                "protected_change_authorizations",
                [],
                "verifier-owned or unknown",
            ),
        )
        for field, value, error in attacks:
            payload = _base_state()
            payload[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, error
            ):
                build_replanning_state(payload)

    def test_live_state_capability_rejects_base_construction_and_slot_attacks(self) -> None:
        live = _state_with_overrides()
        self.assertNotIsInstance(live, dict)
        with self.assertRaises(TypeError):
            dict.__new__(VerifiedReplanningState)
        with self.assertRaises(TypeError):
            dict.__setitem__(live, "objective", "forged")

        forged = object.__new__(VerifiedReplanningState)
        with self.assertRaisesRegex(ValueError, "unregistered"):
            transition_replanning_state(forged, "completed", {"completed": True})
        payload_json = object.__getattribute__(
            live, "_VerifiedReplanningState__payload_json"
        )
        object.__setattr__(
            forged,
            "_VerifiedReplanningState__payload_json",
            payload_json,
        )
        with self.assertRaisesRegex(ValueError, "unregistered"):
            transition_replanning_state(forged, "completed", {"completed": True})

        tampered = json.loads(payload_json)
        tampered["objective"] = "slot mutation"
        object.__setattr__(
            live,
            "_VerifiedReplanningState__payload_json",
            json.dumps(tampered, sort_keys=True, separators=(",", ":")),
        )
        with self.assertRaisesRegex(ValueError, "capability integrity mismatch"):
            transition_replanning_state(live, "completed", {"completed": True})

        process_bound = _state_with_overrides()
        with patch(
            "cwo_core.native_replanning.os.getpid", return_value=-1
        ), self.assertRaisesRegex(ValueError, "capability integrity mismatch"):
            transition_replanning_state(
                process_bound,
                "completed",
                {"completed": True},
            )

    def test_copy_deepcopy_serialization_and_mapping_projection_are_audit_only(self) -> None:
        live = _state_with_overrides()
        projections = (
            copy.copy(live),
            copy.deepcopy(live),
            live.copy(),
            live.serialize(),
            dict(live),
        )
        for projection in projections:
            with self.subTest(projection=type(projection).__name__):
                self.assertIs(type(projection), dict)
                self.assertEqual(read_replanning_state(projection), projection)
                with self.assertRaisesRegex(ValueError, "inspection-only"):
                    transition_replanning_state(
                        projection,
                        "completed",
                        {"completed": True},
                    )

    def test_replanning_rejects_verifier_subclass_and_invalid_return_set(self) -> None:
        pm_state = transition_replanning_state(
            _state_with_overrides(),
            "needs-replan",
            _needs_replan_evidence(),
        )
        evidence = {
            "requires_architect_cycle": False,
            "proposed_changes": {"objective": "new exact objective"},
        }
        assessment = _protected_refinement_assessment(
            pm_state, evidence["proposed_changes"]
        )
        key = b"replanning-hostile-verifier-key"
        receipt = _protected_change_approval(
            key,
            assessment.before_subject,
            assessment.after_subject,
            change_type="objective-change",
        )

        class OverridingVerifier(OperatorApprovalVerifier):
            calls = 0

            def authorize_assessment(self, *args, **kwargs):
                type(self).calls += 1
                return []

        subclass = OverridingVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            replay_store_path=Path(self._temporary.name) / "subclass-replay.json",
            now="2026-07-20T00:05:00Z",
        )
        with self.assertRaisesRegex(ValueError, "exact operator approval verifier"):
            transition_replanning_state(
                pm_state,
                "pm-refined",
                evidence,
                operator_approval_verifier=subclass,
                operator_approval_receipts={"objective-change": receipt},
            )
        self.assertEqual(OverridingVerifier.calls, 0)

        verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            replay_store_path=Path(self._temporary.name) / "result-replay.json",
            now="2026-07-20T00:05:00Z",
        )
        forged_approval = object.__new__(VerifiedOperatorApproval)
        for returned, error in (
            ([], "result-set"),
            ([object()], "result-type"),
            ([forged_approval], "result-audit"),
        ):
            with self.subTest(error=error), patch.object(
                OperatorApprovalVerifier,
                "authorize_assessment",
                return_value=returned,
            ), self.assertRaisesRegex(ValueError, error):
                transition_replanning_state(
                    pm_state,
                    "pm-refined",
                    evidence,
                    operator_approval_verifier=verifier,
                    operator_approval_receipts={"objective-change": receipt},
                )
        self.assertEqual(pm_state["objective"], "native replanning validation")

    def test_serialized_terminal_stop_cannot_clear_latches_or_resume(self) -> None:
        contradictory = _needs_replan_evidence()
        contradictory["contradictory_validation"] = True
        contradiction_stop = transition_replanning_state(
            _state_with_overrides(), "needs-replan", contradictory
        )
        forged_contradiction = contradiction_stop.serialize()
        forged_contradiction["state"] = "pm-realignment"
        forged_contradiction["reason_codes"] = []
        forged_contradiction["terminal_latches"]["contradictory_validation"] = False
        with self.assertRaisesRegex(ValueError, "inspection-only"):
            transition_replanning_state(
                forged_contradiction,
                "pm-refined",
                {"requires_architect_cycle": False},
            )

        taint_stop = _state_with_overrides(
            {"mutation": {"out_of_scope": False, "tainted": True}}
        )
        forged_taint = taint_stop.serialize()
        forged_taint["mutation"]["tainted"] = False
        forged_taint["terminal_latches"]["tainted"] = False
        forged_taint["state"] = "pm-realignment"
        forged_taint["reason_codes"] = []
        with self.assertRaisesRegex(ValueError, "inspection-only"):
            transition_replanning_state(
                forged_taint,
                "pm-refined",
                {"requires_architect_cycle": False},
            )

    def test_mutation_flags_reject_bool_integer_aliases(self) -> None:
        with self.assertRaisesRegex(ValueError, "state.mutation.tainted must be a boolean"):
            build_replanning_state(
                {
                    **_base_state(),
                    "mutation": {"out_of_scope": False, "tainted": 1},
                }
            )

    def test_schema_and_policy_load_checks(self) -> None:
        policy = json.loads((ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8"))
        replanning = policy["work_sizing"]["enforcement"]["foundation-canary"]["autonomous_replanning"]
        self.assertIn("autonomous_replanning", str(policy))
        self.assertEqual(replanning["live_replay_enabled"], False)
        self.assertEqual(replanning["fresh-worker-reassignment"]["required"], True)

        schema = json.loads((ROOT / "schemas" / "native-replanning-state.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["title"], "Native Replanning State")
        required = set(schema["required"])
        self.assertIn("cwo_native_replanning_receipt", required)
        state = _state_with_overrides()
        self.assertEqual(state["version"], 3)
        self.assertIn("authority_provenance", state)
        self.assertEqual(state["schema"], "schemas/native-replanning-state.schema.json")

        weakened = copy.deepcopy(policy)
        weakened_replanning = weakened["work_sizing"]["enforcement"][
            "foundation-canary"
        ]["autonomous_replanning"]
        weakened_replanning["operator_required_for"].remove("objective-change")
        with self.assertRaisesRegex(ValueError, "every supported protected change"):
            build_replanning_state(_base_state(), policy=weakened)

        reversed_policy = copy.deepcopy(policy)
        reversed_policy["work_sizing"]["enforcement"]["foundation-canary"][
            "autonomous_replanning"
        ]["operator_required_for"] = list(reversed(OPERATOR_REQUIRED_CHANGE_TYPES))
        with self.assertRaisesRegex(ValueError, "every supported protected change"):
            build_replanning_state(_base_state(), policy=reversed_policy)

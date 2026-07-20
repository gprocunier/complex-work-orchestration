from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.beads_ready_set import (  # noqa: E402
    build_ready_set_evidence,
    candidate_conflicts,
    evaluate_ready_candidate,
)
from cwo_core.policy import load_policy  # noqa: E402
from cwo_core.work_sizing import (  # noqa: E402
    canonical_work_estimate_sha256,
    evaluate_work_estimate,
)


MODEL = "gpt-5.3-codex-spark"
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None
POOL_BUDGET = {
    "tool_calls": 12,
    "runtime_seconds": 30,
    "compactions": 3,
    "full_suite_runs": 3,
    "mutations": 6,
}


def work_plan(bead_id: str, write_paths: list[str]) -> dict:
    return evaluate_work_estimate(
        {
            "estimate_type": "cwo-native-work-estimate",
            "version": 1,
            "work_unit_id": f"work-{bead_id}",
            "bead_id": bead_id,
            "requested_model": MODEL,
            "primary_outcome": f"complete {bead_id}",
            "expected_artifacts": ["patch", "tests"],
            "expert_profiles": ["engineer"],
            "frozen_decisions": [],
            "unresolved_decisions": [],
            "subsystems": ["ready-set"],
            "write_paths": write_paths,
            "context_manifest": [],
            "acceptance_checks": ["focused tests pass"],
            "estimates": {
                "tool_calls_p50": 2,
                "tool_calls_p90": 4,
                "runtime_seconds_p50": 4,
                "runtime_seconds_p90": 9,
                "context_tokens_p90": 1000,
            },
            "scores": {
                "reasoning_uncertainty": 0,
                "subsystem_coupling": 1,
                "contract_risk": 1,
                "diagnostic_uncertainty": 0,
                "context_breadth": 1,
                "validation_breadth": 1,
            },
        }
    )


def worker_commitment(plan: dict) -> dict:
    return {
        "commitment_type": "cwo-native-worker-fit-commitment",
        "version": 1,
        "work_unit_id": plan["work_unit_id"],
        "bead_id": plan["bead_id"],
        "requested_model": MODEL,
        "session_id": f"session-{plan['bead_id']}",
        "attestation_source": "trusted-session-jsonl",
        "attested_model": MODEL,
        "work_estimate_sha256": canonical_work_estimate_sha256(plan),
        "decision": "accept",
        "confidence": 0.91,
        "estimates": {
            "tool_calls_p50": 2,
            "tool_calls_p90": 4,
            "runtime_seconds_p50": 4,
            "runtime_seconds_p90": 9,
        },
        "tool_calls_before_commitment": 0,
        "context_compactions_before_commitment": 0,
        "reason": "bounded ready-set test fixture",
    }


def ready_item(
    bead_id: str,
    *,
    write_paths: list[str] | None = None,
    read_paths: list[str] | None = None,
    labels: list[str] | None = None,
    aggregate_budget: dict | None = None,
    metadata_overrides: dict | None = None,
) -> dict:
    writes = list(write_paths or [])
    plan = work_plan(bead_id, writes)
    admission = {
        "version": 1,
        "work_plan": plan,
        "worker_commitment": worker_commitment(plan),
        "declared_read_paths": list(read_paths or []),
        "declared_write_paths": writes,
        "integration_target_paths": writes,
        "topology": "single-host-process-v1",
        "isolation_class": "mutable-isolated" if writes else "read-only-shared",
        "architecture_authority": "architect",
        "execution_authority": "workerbee",
        "share_boundary": "no-outside-sharing",
        "required_tools": ["apply_patch"] if writes else ["read"],
        "tool_surface_id": "surface-mutable" if writes else "surface-read-only",
        "hard_budget": {
            "tool_calls": 4,
            "runtime_seconds": 9,
            "compactions": 0,
            "full_suite_runs": 1,
            "mutations": 2 if writes else 0,
        },
        "aggregate_hard_budget": dict(aggregate_budget or POOL_BUDGET),
    }
    admission.update(metadata_overrides or {})
    return {
        "id": bead_id,
        "title": bead_id,
        "type": "task",
        "status": "open",
        "priority": 1,
        "labels": labels or ["implementation"],
        "dependencies": [],
        "raw": {
            "id": bead_id,
            "title": bead_id,
            "issue_type": "task",
            "status": "open",
            "priority": 1,
            "labels": labels or ["implementation"],
            "updated_at": "2026-07-20T20:00:00Z",
            "metadata": {"cwo_ready_set_admission": admission},
            "_cwo_executable_leaf": True,
        },
    }


def released_three_policy() -> dict:
    policy = deepcopy(load_policy("native-worker-execution"))
    policy["native_supervision_pool"]["capacity"]["released_max_active_workers"] = 3
    return policy


class BeadsReadySetTests(unittest.TestCase):
    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_nonempty_candidate_and_snapshot_match_continuation_schema(self) -> None:
        from jsonschema import Draft202012Validator

        result = build_ready_set_evidence(
            [ready_item("bead-a", write_paths=["scripts/a.py"])],
            epic_id="epic",
            policy_document=released_three_policy(),
        )
        schema = json.loads(
            (ROOT / "schemas" / "sprint-continuation.schema.json").read_text(
                encoding="utf-8"
            )
        )
        candidate_schema = {
            "$schema": schema["$schema"],
            "$ref": "#/$defs/ready_candidate",
            "$defs": schema["$defs"],
        }
        snapshot_schema = {
            "$schema": schema["$schema"],
            "$ref": "#/$defs/readiness_snapshot",
            "$defs": schema["$defs"],
        }

        Draft202012Validator(candidate_schema).validate(
            result["recommended_ready_set"][0]
        )
        Draft202012Validator(snapshot_schema).validate(
            result["beads_readiness_snapshot"]
        )

    def test_actual_released_n2_policy_produces_offline_n3_candidate(self) -> None:
        items = [
            ready_item("bead-a", write_paths=["scripts/a.py"]),
            ready_item("bead-b", write_paths=["scripts/b.py"]),
            ready_item("bead-c", write_paths=["scripts/c.py"]),
        ]

        result = build_ready_set_evidence(
            items,
            epic_id="epic",
            requested_workers=3,
            policy_document=load_policy("native-worker-execution"),
        )

        self.assertEqual(result["fanout_decision"], "pool")
        self.assertEqual(
            [item["id"] for item in result["recommended_ready_set"]],
            ["bead-a", "bead-b", "bead-c"],
        )
        self.assertFalse(result["dispatch_authorized"])
        self.assertEqual(result["ready_set_authority"], "candidate-evidence-only")
        self.assertEqual(
            result["candidate_capacity_evidence"]["bounded_candidate_capacity"],
            3,
        )
        self.assertEqual(
            result["candidate_capacity_evidence"]["released_max_active_workers"],
            2,
        )
        self.assertTrue(
            result["candidate_capacity_evidence"][
                "selected_exceeds_released_capacity"
            ]
        )
        self.assertFalse(
            result["candidate_capacity_evidence"]["selected_released_for_dispatch"]
        )
        self.assertIn(
            "offline-unreleased-capacity-candidate",
            {reason["code"] for reason in result["fanout_reasons"]},
        )

    def test_n_four_request_is_capped_and_rejected_as_phase1_candidate(self) -> None:
        items = [
            ready_item("bead-a", write_paths=["scripts/a.py"]),
            ready_item("bead-b", write_paths=["scripts/b.py"]),
            ready_item("bead-c", write_paths=["scripts/c.py"]),
            ready_item("bead-d", write_paths=["scripts/d.py"]),
        ]

        result = build_ready_set_evidence(
            items,
            epic_id="epic",
            requested_workers=4,
            policy_document=load_policy("native-worker-execution"),
        )

        self.assertEqual(
            [item["id"] for item in result["recommended_ready_set"]],
            ["bead-a", "bead-b", "bead-c"],
        )
        self.assertEqual(
            result["candidate_capacity_evidence"]["bounded_candidate_capacity"],
            3,
        )
        self.assertIn(
            "phase1-candidate-ceiling-applied",
            {reason["code"] for reason in result["fanout_reasons"]},
        )

    def test_capacity_is_a_ceiling_for_one_and_two(self) -> None:
        items = [
            ready_item("bead-a", write_paths=["a.py"]),
            ready_item("bead-b", write_paths=["b.py"]),
            ready_item("bead-c", write_paths=["c.py"]),
        ]
        policy = released_three_policy()

        one = build_ready_set_evidence(
            items,
            epic_id="epic",
            requested_workers=1,
            policy_document=policy,
        )
        two = build_ready_set_evidence(
            items,
            epic_id="epic",
            requested_workers=2,
            policy_document=policy,
        )

        self.assertEqual([item["id"] for item in one["recommended_ready_set"]], ["bead-a"])
        self.assertEqual([item["id"] for item in two["recommended_ready_set"]], ["bead-a", "bead-b"])

    def test_mutable_path_conflict_keeps_independent_leaf(self) -> None:
        items = [
            ready_item("bead-a", write_paths=["scripts/shared.py"]),
            ready_item("bead-b", write_paths=["scripts/shared.py/helpers"]),
            ready_item("bead-c", write_paths=["scripts/other.py"]),
        ]

        result = build_ready_set_evidence(
            items,
            epic_id="epic",
            requested_workers=3,
            policy_document=released_three_policy(),
        )

        self.assertEqual(
            [item["id"] for item in result["recommended_ready_set"]],
            ["bead-a", "bead-c"],
        )
        excluded = {item["id"]: item["reasons"] for item in result["excluded_ready_issues"]}
        self.assertIn("mutable-path-conflict", {reason["code"] for reason in excluded["bead-b"]})

    def test_shared_read_only_work_is_compatible(self) -> None:
        items = [
            ready_item("bead-a", read_paths=["schemas/shared.json"]),
            ready_item("bead-b", read_paths=["schemas/shared.json"]),
        ]
        result = build_ready_set_evidence(
            items,
            epic_id="epic",
            requested_workers=2,
            policy_document=released_three_policy(),
        )

        self.assertEqual(
            [item["id"] for item in result["recommended_ready_set"]],
            ["bead-a", "bead-b"],
        )

    def test_aggregate_budget_prevents_oversubscribed_subset(self) -> None:
        aggregate = {**POOL_BUDGET, "tool_calls": 7}
        items = [
            ready_item("bead-a", write_paths=["a.py"], aggregate_budget=aggregate),
            ready_item("bead-b", write_paths=["b.py"], aggregate_budget=aggregate),
        ]

        result = build_ready_set_evidence(
            items,
            epic_id="epic",
            requested_workers=2,
            policy_document=released_three_policy(),
        )

        self.assertEqual([item["id"] for item in result["recommended_ready_set"]], ["bead-a"])
        excluded = {item["id"]: item["reasons"] for item in result["excluded_ready_issues"]}
        self.assertIn(
            "aggregate-budget-conflict",
            {reason["code"] for reason in excluded["bead-b"]},
        )

    def test_protected_domain_model_tool_authority_and_budget_conflicts_are_explicit(self) -> None:
        left_item = ready_item("bead-a", write_paths=["schemas/a.json"])
        right_item = ready_item(
            "bead-b",
            write_paths=["schemas/b.json"],
            aggregate_budget={**POOL_BUDGET, "tool_calls": 11},
            metadata_overrides={
                "architecture_authority": "operator",
                "tool_surface_id": "other-surface",
            },
        )
        right_admission = right_item["raw"]["metadata"]["cwo_ready_set_admission"]
        right_admission["work_plan"]["requested_model"] = "other-model"
        right_admission["worker_commitment"]["requested_model"] = "other-model"
        right_admission["worker_commitment"]["attested_model"] = "other-model"
        right_admission["worker_commitment"]["work_estimate_sha256"] = canonical_work_estimate_sha256(
            right_admission["work_plan"]
        )

        left, left_reasons = evaluate_ready_candidate(left_item, rank=0)
        right, right_reasons = evaluate_ready_candidate(right_item, rank=1)
        self.assertEqual(left_reasons, [])
        self.assertEqual(right_reasons, [])
        assert left is not None and right is not None

        codes = {reason["code"] for reason in candidate_conflicts(left, right)}
        self.assertIn("protected-domain-conflict", codes)
        self.assertIn("architecture-authority-conflict", codes)
        self.assertIn("model-conflict", codes)
        self.assertIn("tool-surface-conflict", codes)
        self.assertIn("aggregate-budget-contract-conflict", codes)

    def test_missing_metadata_and_restricted_labels_are_excluded(self) -> None:
        missing = ready_item("bead-missing", write_paths=["missing.py"])
        missing["raw"]["metadata"] = {}
        restricted = ready_item(
            "bead-restricted",
            write_paths=["restricted.py"],
            labels=["implementation", "no-codex-exec"],
        )

        result = build_ready_set_evidence(
            [missing, restricted],
            epic_id="epic",
            policy_document=released_three_policy(),
        )
        excluded = {item["id"]: item["reasons"] for item in result["excluded_ready_issues"]}

        self.assertIn(
            "missing-admission-metadata",
            {reason["code"] for reason in excluded["bead-missing"]},
        )
        self.assertIn(
            "restricted-label",
            {reason["code"] for reason in excluded["bead-restricted"]},
        )

    def test_snapshot_is_deterministic_and_changes_on_issue_drift(self) -> None:
        first = ready_item("bead-a", write_paths=["a.py"])
        second = ready_item("bead-b", write_paths=["b.py"])
        policy = released_three_policy()

        forward = build_ready_set_evidence(
            [first, second],
            epic_id="epic",
            policy_document=policy,
        )
        reverse = build_ready_set_evidence(
            [second, first],
            epic_id="epic",
            policy_document=policy,
        )
        self.assertEqual(
            forward["beads_readiness_snapshot_sha256"],
            reverse["beads_readiness_snapshot_sha256"],
        )

        changed = deepcopy(second)
        changed["raw"]["updated_at"] = "2026-07-20T20:01:00Z"
        drifted = build_ready_set_evidence(
            [first, changed],
            epic_id="epic",
            policy_document=policy,
        )
        self.assertNotEqual(
            forward["beads_readiness_snapshot_sha256"],
            drifted["beads_readiness_snapshot_sha256"],
        )


if __name__ == "__main__":
    unittest.main()

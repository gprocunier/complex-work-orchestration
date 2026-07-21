from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import hmac
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.beads_ready_set import (  # noqa: E402
    LEASE_SCOPE_TYPE,
    LEASE_SCOPE_VERSION,
    authority_after_artifact,
    build_ready_set_evidence,
    candidate_conflicts,
    canonical_json_sha256,
    evaluate_ready_candidate,
)
from cwo_core.native_authority import (  # noqa: E402
    OPERATOR_APPROVAL_TYPE,
    OperatorApprovalVerifier,
    canonical_authority_sha256,
    trusted_actor_authority,
)
from cwo_core.native_capability import (  # noqa: E402
    build_native_capability_receipt,
    canonical_capability_evidence_sha256,
)
from cwo_core.native_tool_isolation import (  # noqa: E402
    build_tool_surface_snapshot,
    default_tool_policy,
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
    tool_policy = default_tool_policy(mutable=bool(writes))
    tool_surface = build_tool_surface_snapshot(
        tool_policy,
        source="ready-set-test",
        server_allowlist_supported=True,
        allowlist_parameter="tools",
        effective_allowlist=list(tool_policy["permitted_tools"]),
    )
    capability_evidence = {
        "requested_model": MODEL,
        "configured_model": MODEL,
        "advertised": True,
        "advertised_models": [MODEL],
        "spawn_accepted": True,
        "canary_session_id": f"capability-{bead_id}",
        "attestation_source": "trusted-session-jsonl",
        "attested_model": MODEL,
        "tool_calls": 0,
        "context_compactions": 0,
        "runtime_seconds": 1.25,
        "closure_receipt": True,
        "tool_surface_id": tool_surface["surface_sha256"],
    }
    capability_authority = trusted_actor_authority(
        source_type="worker-discovery",
        source_id=capability_evidence["canary_session_id"],
        source_sha256=canonical_capability_evidence_sha256(capability_evidence),
        actor_id=f"worker-{bead_id}",
        actor_role="operative-worker",
        identity_source=capability_evidence["attestation_source"],
    )
    capability_receipt = build_native_capability_receipt(
        capability_evidence,
        [MODEL],
        "2026-07-20T20:00:00Z",
        "2026-07-20T20:30:00Z",
        session_authority=capability_authority,
    )
    lease_scope = {
        "lease_scope_type": LEASE_SCOPE_TYPE,
        "version": LEASE_SCOPE_VERSION,
        "issue_id": bead_id,
        "integration_root_identity_sha256": canonical_json_sha256(
            {"integration_root": "ready-set-test-root"}
        ),
        "workspace_scope_sha256": canonical_json_sha256(
            {"workspace_scope": bead_id}
        ),
        "target_paths": writes,
    }
    lease_scope["lease_scope_sha256"] = canonical_json_sha256(lease_scope)
    admission = {
        "version": 2,
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
        "required_tools": list(tool_policy["permitted_tools"]),
        "tool_surface_id": tool_surface["surface_sha256"],
        "tool_policy": tool_policy,
        "tool_surface": tool_surface,
        "capability_receipt": capability_receipt,
        "capability_assessed_at": "2026-07-20T20:15:00Z",
        "lease_scope": lease_scope,
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


def signed_operator_approval(
    key: bytes,
    before: dict,
    after: dict,
    *,
    authorized_scope: str = "complete-task",
    nonce: str = "ready-set-approval-nonce",
) -> dict:
    body = {
        "approval_type": OPERATOR_APPROVAL_TYPE,
        "version": 1,
        "approval_id": "ready-set-approval",
        "change_type": "security-or-authority-change",
        "before_sha256": canonical_authority_sha256(before),
        "after_sha256": canonical_authority_sha256(after),
        "actor_id": "operator-1",
        "identity_source": "trusted-control-session",
        "authorized_scope": authorized_scope,
        "parent_receipt_sha256": None,
        "issued_at": "2026-07-20T20:00:00Z",
        "expires_at": "2026-07-20T20:30:00Z",
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


def authority_approved_item() -> tuple[dict, OperatorApprovalVerifier]:
    key = b"ready-set-test-operator-key"
    item = ready_item(
        "bead-authority",
        write_paths=["scripts/authority.py"],
        labels=["implementation", "authority-change"],
    )
    admission = item["raw"]["metadata"]["cwo_ready_set_admission"]
    before = {
        "artifact_type": "cwo-ready-set-authority-scope",
        "version": 1,
        "issue_id": "bead-authority",
        "state": "before",
    }
    after = authority_after_artifact(
        issue_id="bead-authority",
        change_labels=["authority-change"],
        architecture_authority=admission["architecture_authority"],
        execution_authority=admission["execution_authority"],
        share_boundary=admission["share_boundary"],
        work_estimate_sha256=canonical_work_estimate_sha256(
            admission["work_plan"]
        ),
        worker_commitment_sha256=canonical_json_sha256(
            admission["worker_commitment"]
        ),
        read_paths=admission["declared_read_paths"],
        write_paths=admission["declared_write_paths"],
        integration_target_paths=admission["integration_target_paths"],
        topology=admission["topology"],
        isolation_class=admission["isolation_class"],
        lease_scope_sha256=admission["lease_scope"]["lease_scope_sha256"],
        requested_model=admission["work_plan"]["requested_model"],
        required_tools=admission["required_tools"],
        tool_surface_id=admission["tool_surface_id"],
        capability_receipt_sha256=admission["capability_receipt"][
            "receipt_sha256"
        ],
        hard_budget=admission["hard_budget"],
        aggregate_hard_budget=admission["aggregate_hard_budget"],
    )
    receipt = signed_operator_approval(key, before, after)
    builder = OperatorApprovalVerifier(
        verification_key=key,
        expected_actor_id="operator-1",
        expected_identity_source="trusted-control-session",
        now="2026-07-20T20:15:00Z",
    )
    audit = builder.verify(
        receipt,
        expected_change_type="security-or-authority-change",
        before_artifact=before,
        after_artifact=after,
    ).audit_record()
    admission["authority_change_before"] = before
    admission["authority_provenance"] = audit["authority_provenance"]
    admission["operator_approval_audit"] = audit
    verifier = OperatorApprovalVerifier(
        verification_key=key,
        expected_actor_id="operator-1",
        expected_identity_source="trusted-control-session",
        now="2026-07-20T20:15:00Z",
    )
    return item, verifier


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
            result["candidate_capacity_evidence"]["selected_within_released_capacity"]
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

    def test_all_safe_subsets_through_capacity_are_returned_deterministically(self) -> None:
        items = [
            ready_item("bead-a", write_paths=["scripts/a.py"]),
            ready_item("bead-b", write_paths=["scripts/b.py"]),
            ready_item("bead-c", write_paths=["scripts/c.py"]),
            ready_item("bead-d", write_paths=["scripts/d.py"]),
        ]

        result = build_ready_set_evidence(
            items,
            epic_id="epic",
            requested_workers=3,
            policy_document=released_three_policy(),
        )
        cohorts = [
            tuple(cohort["issue_ids"])
            for cohort in result["compatible_ready_sets"]
        ]

        self.assertEqual(len(cohorts), 14)
        self.assertEqual(
            cohorts[:4],
            [
                ("bead-a", "bead-b", "bead-c"),
                ("bead-a", "bead-b", "bead-d"),
                ("bead-a", "bead-c", "bead-d"),
                ("bead-b", "bead-c", "bead-d"),
            ],
        )
        self.assertEqual(
            [item["id"] for item in result["recommended_ready_set"]],
            list(cohorts[0]),
        )
        self.assertTrue(
            all(
                cohort["dispatch_authorized"] is False
                and cohort["authority"] == "candidate-evidence-only"
                for cohort in result["compatible_ready_sets"]
            )
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
        cohorts = {
            tuple(item["issue_ids"]) for item in result["compatible_ready_sets"]
        }
        self.assertNotIn(("bead-a", "bead-b"), cohorts)
        self.assertIn(("bead-a", "bead-c"), cohorts)
        self.assertIn(("bead-b", "bead-c"), cohorts)
        self.assertIn(
            "mutable-path-conflict",
            {reason["code"] for reason in result["fanout_reasons"]},
        )

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
        cohorts = {
            tuple(item["issue_ids"]) for item in result["compatible_ready_sets"]
        }
        self.assertNotIn(("bead-a", "bead-b"), cohorts)
        self.assertIn(
            "aggregate-budget-conflict",
            {reason["code"] for reason in result["fanout_reasons"]},
        )

    def test_protected_domain_model_tool_authority_and_budget_conflicts_are_explicit(self) -> None:
        left_item = ready_item("bead-a", write_paths=["schemas/a.json"])
        right_item = ready_item("bead-b", write_paths=["schemas/b.json"])

        left, left_reasons = evaluate_ready_candidate(left_item, rank=0)
        right, right_reasons = evaluate_ready_candidate(right_item, rank=1)
        self.assertEqual(left_reasons, [])
        self.assertEqual(right_reasons, [])
        assert left is not None and right is not None
        left = replace(left, protected_domains=("schema",))
        right = replace(
            right,
            protected_domains=("schema",),
            architecture_authority="operator",
            requested_model="other-model",
            tool_surface_id="other-surface",
            aggregate_hard_budget=tuple(
                sorted({**POOL_BUDGET, "tool_calls": 11}.items())
            ),
        )

        codes = {reason["code"] for reason in candidate_conflicts(left, right)}
        self.assertIn("protected-domain-conflict", codes)
        self.assertIn("architecture-authority-conflict", codes)
        self.assertIn("model-conflict", codes)
        self.assertIn("tool-surface-conflict", codes)
        self.assertIn("aggregate-budget-contract-conflict", codes)

    def test_topology_share_model_tool_capability_and_lease_evidence_fail_closed(self) -> None:
        cases: list[tuple[str, str, object]] = [
            ("topology", "unsupported-topology", "other-topology"),
            ("share_boundary", "unknown-share-boundary", "unknown-boundary"),
            ("tool_surface_id", "tool-surface-id-mismatch", "f" * 64),
        ]
        for field, expected_code, value in cases:
            with self.subTest(field=field):
                item = ready_item("bead-invalid", write_paths=["invalid.py"])
                admission = item["raw"]["metadata"]["cwo_ready_set_admission"]
                admission[field] = value
                candidate, reasons = evaluate_ready_candidate(item, rank=0)
                self.assertIsNone(candidate)
                self.assertIn(expected_code, {reason["code"] for reason in reasons})

        unauthorized = ready_item("bead-model", write_paths=["model.py"])
        unauthorized_admission = unauthorized["raw"]["metadata"][
            "cwo_ready_set_admission"
        ]
        unauthorized_admission["work_plan"]["requested_model"] = "other-model"
        candidate, reasons = evaluate_ready_candidate(unauthorized, rank=0)
        self.assertIsNone(candidate)
        self.assertIn("unauthorized-model", {reason["code"] for reason in reasons})

        tampered_receipt = ready_item("bead-receipt", write_paths=["receipt.py"])
        tampered_receipt["raw"]["metadata"]["cwo_ready_set_admission"][
            "capability_receipt"
        ]["attested_model"] = "other-model"
        candidate, reasons = evaluate_ready_candidate(tampered_receipt, rank=0)
        self.assertIsNone(candidate)
        self.assertIn(
            "invalid-capability-receipt",
            {reason["code"] for reason in reasons},
        )

        malformed_lease = ready_item("bead-lease", write_paths=["lease.py"])
        malformed_lease["raw"]["metadata"]["cwo_ready_set_admission"][
            "lease_scope"
        ]["lease_scope_sha256"] = "0" * 64
        candidate, reasons = evaluate_ready_candidate(malformed_lease, rank=0)
        self.assertIsNone(candidate)
        self.assertIn(
            "invalid-lease-scope-intent", {reason["code"] for reason in reasons}
        )

    def test_lease_identity_conflicts_are_explicit_and_hash_bound(self) -> None:
        left_item = ready_item("bead-a", write_paths=["a.py"])
        right_item = ready_item("bead-b", write_paths=["b.py"])
        left, left_reasons = evaluate_ready_candidate(left_item, rank=0)
        right, right_reasons = evaluate_ready_candidate(right_item, rank=1)
        self.assertEqual(left_reasons, [])
        self.assertEqual(right_reasons, [])
        assert left is not None and right is not None

        different_root = replace(
            right,
            integration_root_identity_sha256="a" * 64,
        )
        same_workspace = replace(
            right,
            workspace_scope_sha256=left.workspace_scope_sha256,
        )
        self.assertIn(
            "lease-integration-root-conflict",
            {reason["code"] for reason in candidate_conflicts(left, different_root)},
        )
        self.assertIn(
            "lease-workspace-identity-conflict",
            {reason["code"] for reason in candidate_conflicts(left, same_workspace)},
        )

    def test_authority_change_requires_trusted_exact_scope_verification(self) -> None:
        item, verifier = authority_approved_item()

        candidate, reasons = evaluate_ready_candidate(item, rank=0)
        self.assertIsNone(candidate)
        self.assertIn(
            "operator-approval-verifier-unavailable",
            {reason["code"] for reason in reasons},
        )

        candidate, reasons = evaluate_ready_candidate(
            item,
            rank=0,
            operator_approval_verifier=verifier,
        )
        self.assertEqual(reasons, [])
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertIsNotNone(candidate.authority_approval_audit_sha256)

        tampered, tampered_verifier = authority_approved_item()
        tampered["raw"]["metadata"]["cwo_ready_set_admission"][
            "declared_read_paths"
        ] = ["different/scope"]
        candidate, reasons = evaluate_ready_candidate(
            tampered,
            rank=0,
            operator_approval_verifier=tampered_verifier,
        )
        self.assertIsNone(candidate)
        self.assertIn(
            "operator-approval-candidate-scope-mismatch",
            {reason["code"] for reason in reasons},
        )

    def test_legacy_bool_and_hex_cannot_self_attest_authority(self) -> None:
        item = ready_item(
            "bead-authority",
            write_paths=["authority.py"],
            labels=["implementation", "authority-change"],
            metadata_overrides={
                "authority_change_approved": True,
                "authority_approval_sha256": "a" * 64,
            },
        )

        candidate, reasons = evaluate_ready_candidate(item, rank=0)

        self.assertIsNone(candidate)
        codes = {reason["code"] for reason in reasons}
        self.assertIn("invalid-admission-metadata", codes)
        self.assertIn("unapproved-authority-change", codes)

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

    def test_snapshot_seals_rank_graph_labels_estimate_ownership_and_scope(self) -> None:
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
        repeated = build_ready_set_evidence(
            [deepcopy(first), deepcopy(second)],
            epic_id="epic",
            policy_document=policy,
        )
        self.assertEqual(
            forward["beads_readiness_snapshot_sha256"],
            repeated["beads_readiness_snapshot_sha256"],
        )
        self.assertNotEqual(
            forward["beads_readiness_snapshot_sha256"],
            reverse["beads_readiness_snapshot_sha256"],
        )

        mutations: dict[str, object] = {
            "updated": lambda item: item["raw"].__setitem__(
                "updated_at", "2026-07-20T20:01:00Z"
            ),
            "dependency": lambda item: item["raw"].__setitem__(
                "dependencies",
                [{"depends_on_id": "bead-a", "type": "blocks"}],
            ),
            "labels": lambda item: (
                item.__setitem__("labels", ["implementation", "validation"]),
                item["raw"].__setitem__(
                    "labels", ["implementation", "validation"]
                ),
            ),
            "estimate": lambda item: item["raw"]["metadata"][
                "cwo_ready_set_admission"
            ]["work_plan"].__setitem__("primary_outcome", "drifted outcome"),
            "ownership": lambda item: item["raw"]["metadata"][
                "cwo_ready_set_admission"
            ].__setitem__("architecture_authority", "different-architect"),
            "scope": lambda item: item["raw"]["metadata"][
                "cwo_ready_set_admission"
            ].__setitem__("declared_read_paths", ["new/read/scope"]),
            "issue-owner": lambda item: item["raw"].__setitem__(
                "owner", "different-owner"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(drift=label):
                changed = deepcopy(second)
                mutate(changed)  # type: ignore[operator]
                drifted = build_ready_set_evidence(
                    [first, changed],
                    epic_id="epic",
                    policy_document=policy,
                )
                self.assertNotEqual(
                    forward["beads_readiness_snapshot_sha256"],
                    drifted["beads_readiness_snapshot_sha256"],
                )

        canonical_order_drift = [deepcopy(first), deepcopy(second)]
        canonical_order_drift[0]["raw"]["_cwo_canonical_ready_rank"] = 1
        canonical_order_drift[1]["raw"]["_cwo_canonical_ready_rank"] = 0
        canonical = build_ready_set_evidence(
            canonical_order_drift,
            epic_id="epic",
            policy_document=policy,
        )
        self.assertNotEqual(
            forward["beads_readiness_snapshot_sha256"],
            canonical["beads_readiness_snapshot_sha256"],
        )

        extra_scope = ready_item("bead-nonready", write_paths=["nonready.py"])
        scoped = build_ready_set_evidence(
            [first, second],
            scope_items=[first, second, extra_scope],
            epic_id="epic",
            policy_document=policy,
        )
        self.assertNotEqual(
            forward["beads_readiness_snapshot_sha256"],
            scoped["beads_readiness_snapshot_sha256"],
        )
        excluded = {
            item["id"]: item["reasons"] for item in scoped["excluded_ready_issues"]
        }
        self.assertIn(
            "not-canonical-ready",
            {reason["code"] for reason in excluded["bead-nonready"]},
        )


if __name__ == "__main__":
    unittest.main()

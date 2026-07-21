from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.beads_ready_set import build_ready_set_evidence  # noqa: E402
from cwo_core.native_authority import (  # noqa: E402
    OPERATOR_APPROVAL_TYPE,
    OperatorApprovalVerifier,
    canonical_authority_sha256,
)
from cwo_core.native_pool_proportionality import (  # noqa: E402
    PoolProportionalityError,
    canonical_proportionality_sha256,
    load_pool_proportionality_policy,
    pool_proportionality_check,
    proportionality_override_assessment,
    proportionality_override_artifacts,
    validate_pool_proportionality_assessment,
    verify_proportionality_override,
)
from cwo_core.policy import load_policy  # noqa: E402
from cwo_core.work_sizing import evaluate_work_estimate  # noqa: E402
from tests.test_beads_ready_set import ready_item, worker_commitment  # noqa: E402
from tests.test_native_work_sizing import _literal_command_payload  # noqa: E402


HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None
AGGREGATE_BUDGET = {
    "tool_calls": 1000,
    "runtime_seconds": 10000,
    "compactions": 10,
    "full_suite_runs": 10,
    "mutations": 100,
}


def _set_runtime(
    item: dict,
    runtime_p90_seconds: int,
    *,
    policy: dict,
) -> dict:
    admission = item["raw"]["metadata"]["cwo_ready_set_admission"]
    source = deepcopy(admission["work_plan"])
    source["estimates"]["runtime_seconds_p50"] = max(1, runtime_p90_seconds * 4 // 5)
    source["estimates"]["runtime_seconds_p90"] = runtime_p90_seconds
    plan = evaluate_work_estimate(source, policy=policy)
    commitment = worker_commitment(plan)
    commitment["estimates"]["runtime_seconds_p50"] = source["estimates"][
        "runtime_seconds_p50"
    ]
    commitment["estimates"]["runtime_seconds_p90"] = runtime_p90_seconds
    admission["work_plan"] = plan
    admission["worker_commitment"] = commitment
    admission["hard_budget"]["runtime_seconds"] = runtime_p90_seconds
    admission["aggregate_hard_budget"] = dict(AGGREGATE_BUDGET)
    return item


def _literal_item(bead_id: str, *, policy: dict) -> dict:
    item = ready_item(bead_id, write_paths=[])
    admission = item["raw"]["metadata"]["cwo_ready_set_admission"]
    source = _literal_command_payload()
    source["bead_id"] = bead_id
    source["work_unit_id"] = f"work-{bead_id}"
    plan = evaluate_work_estimate(source, policy=policy)
    admission["work_plan"] = plan
    admission["worker_commitment"] = worker_commitment(plan)
    admission["aggregate_hard_budget"] = dict(AGGREGATE_BUDGET)
    return item


def _fixture(
    runtimes: list[int],
    *,
    writes: bool = False,
    policy: dict | None = None,
) -> tuple[dict, dict[str, dict], list[dict], dict]:
    document = deepcopy(policy or load_policy("native-worker-execution"))
    items: list[dict] = []
    for index, runtime in enumerate(runtimes):
        bead_id = f"bead-{chr(ord('a') + index)}"
        paths = [f"src/{bead_id}.py"] if writes else []
        item = ready_item(bead_id, write_paths=paths)
        items.append(_set_runtime(item, runtime, policy=document))
    readiness = build_ready_set_evidence(
        items,
        epic_id="epic-proportionality",
        requested_workers=3,
        policy_document=document,
    )
    estimates = {
        item["id"]: item["raw"]["metadata"]["cwo_ready_set_admission"]["work_plan"]
        for item in items
    }
    return readiness, estimates, items, document


def _signed_approval(
    key: bytes,
    before: dict,
    after: dict,
    *,
    nonce: str = "proportionality-override-nonce",
) -> dict:
    body = {
        "approval_type": OPERATOR_APPROVAL_TYPE,
        "version": 1,
        "approval_id": "proportionality-override-approval",
        "change_type": "security-or-authority-change",
        "before_sha256": canonical_authority_sha256(before),
        "after_sha256": canonical_authority_sha256(after),
        "actor_id": "operator-1",
        "identity_source": "trusted-control-session",
        "authorized_scope": "complete-task",
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


def _evaluation(result: dict, issue_ids: list[str]) -> dict:
    return next(
        item for item in result["cohort_evaluations"] if item["issue_ids"] == issue_ids
    )


def _reseal_assessment(value: dict) -> dict:
    for evaluation in value["cohort_evaluations"]:
        unsigned_evaluation = dict(evaluation)
        unsigned_evaluation.pop("evaluation_sha256", None)
        evaluation["evaluation_sha256"] = canonical_proportionality_sha256(
            unsigned_evaluation
        )
    selected = value.get("selected_cohort")
    if selected is not None:
        value["selected_cohort"] = deepcopy(
            next(
                evaluation
                for evaluation in value["cohort_evaluations"]
                if evaluation["cohort_sha256"] == selected["cohort_sha256"]
            )
        )
    unsigned_assessment = dict(value)
    unsigned_assessment.pop("assessment_sha256", None)
    value["assessment_sha256"] = canonical_proportionality_sha256(unsigned_assessment)
    return value


class NativePoolProportionalityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.replay_root = Path(self._temporary.name)
        self._replay_index = 0

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def replay_store(self) -> Path:
        self._replay_index += 1
        return self.replay_root / f"operator-replay-{self._replay_index}.json"

    def test_policy_defaults_are_provisional_and_capacity_remains_n2(self) -> None:
        document = load_policy("native-worker-execution")
        policy = load_pool_proportionality_policy(document)
        self.assertEqual(policy.minimum_child_runtime_p90_ms, 300_000)
        self.assertEqual(policy.minimum_gross_savings_overhead_multiple_milli, 2_000)
        self.assertIn("literal-command", policy.forbidden_task_classes)
        self.assertEqual(
            document["native_supervision_pool"]["capacity"][
                "released_max_active_workers"
            ],
            2,
        )

    def test_incident_sized_lanes_are_rejected(self) -> None:
        readiness, estimates, _, policy = _fixture([90, 120, 120])
        result = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=3,
            policy_document=policy,
        )
        self.assertFalse(result["accepted"])
        self.assertEqual(result["decision"], "single")
        self.assertIsNone(result["selected_cohort"])
        self.assertTrue(
            all(
                any(
                    reason["code"] == "child-runtime-below-provisional-minimum"
                    for reason in evaluation["reasons"]
                )
                for evaluation in result["cohort_evaluations"]
                if evaluation["worker_count"] >= 2
            )
        )

    def test_zero_and_one_ready_lane_never_become_a_pool(self) -> None:
        one_ready, one_estimate, _, one_policy = _fixture([480])
        one = pool_proportionality_check(
            one_ready,
            one_estimate,
            requested_workers=1,
            policy_document=one_policy,
        )
        self.assertEqual(one["decision"], "single")
        self.assertFalse(one["accepted"])
        self.assertIn(
            "pool-requires-multiple-workers",
            {reason["code"] for reason in one["cohort_evaluations"][0]["reasons"]},
        )

        empty_policy = deepcopy(load_policy("native-worker-execution"))
        empty_ready = build_ready_set_evidence(
            [],
            epic_id="epic-proportionality",
            requested_workers=3,
            policy_document=empty_policy,
        )
        empty = pool_proportionality_check(
            empty_ready,
            {},
            requested_workers=3,
            policy_document=empty_policy,
        )
        self.assertEqual(empty["decision"], "blocked")
        self.assertFalse(empty["accepted"])
        self.assertIsNone(empty["fallback_issue_id"])

    def test_adequate_n3_is_offline_candidate_only(self) -> None:
        readiness, estimates, _, policy = _fixture([480, 480, 480])
        result = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=3,
            policy_document=policy,
        )
        self.assertTrue(result["accepted"])
        self.assertEqual(result["selected_cohort"]["worker_count"], 3)
        self.assertEqual(result["candidate_mode"], "offline-unreleased-candidate")
        self.assertFalse(result["dispatch_authorized"])
        self.assertFalse(result["selected_cohort"]["within_released_capacity"])

    def test_capacity_is_ceiling_when_only_two_lanes_are_economical(self) -> None:
        readiness, estimates, _, policy = _fixture([480, 480, 120])
        result = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=3,
            policy_document=policy,
        )
        self.assertEqual(result["selected_cohort"]["issue_ids"], ["bead-a", "bead-b"])
        self.assertEqual(result["selected_cohort"]["worker_count"], 2)
        self.assertEqual(result["candidate_mode"], "released-capacity")

    def test_forged_compatible_cohort_is_not_authorized_by_singleton_hashes(
        self,
    ) -> None:
        policy = deepcopy(load_policy("native-worker-execution"))
        items = [
            _set_runtime(
                ready_item(bead_id, write_paths=["src/shared.py"]),
                480,
                policy=policy,
            )
            for bead_id in ("bead-a", "bead-b")
        ]
        readiness = build_ready_set_evidence(
            items,
            epic_id="epic-proportionality",
            requested_workers=2,
            policy_document=policy,
        )
        self.assertEqual(
            [cohort["issue_ids"] for cohort in readiness["compatible_ready_sets"]],
            [["bead-a"], ["bead-b"]],
        )
        estimates = {
            item["id"]: item["raw"]["metadata"]["cwo_ready_set_admission"]["work_plan"]
            for item in items
        }
        candidate_hash_by_id = {
            cohort["issue_ids"][0]: cohort["candidate_sha256s"][0]
            for cohort in readiness["compatible_ready_sets"]
        }
        snapshot_sha256 = readiness["beads_readiness_snapshot_sha256"]
        forged = {
            "cohort_type": "cwo-compatible-ready-set",
            "version": 1,
            "snapshot_sha256": snapshot_sha256,
            "issue_ids": ["bead-a", "bead-b"],
            "candidate_sha256s": [
                candidate_hash_by_id["bead-a"],
                candidate_hash_by_id["bead-b"],
            ],
            "worker_count": 2,
            "within_released_capacity": True,
            "authority": "candidate-evidence-only",
            "dispatch_authorized": False,
        }
        forged["cohort_sha256"] = canonical_proportionality_sha256(forged)
        readiness["compatible_ready_sets"].insert(0, forged)
        with self.assertRaisesRegex(
            PoolProportionalityError,
            "compatible-ready-set-commitment-mismatch",
        ):
            pool_proportionality_check(
                readiness,
                estimates,
                requested_workers=2,
                policy_document=policy,
            )

    def test_highest_net_savings_precedes_ready_rank(self) -> None:
        readiness, estimates, _, policy = _fixture([300, 400, 500, 1000])
        result = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=3,
            policy_document=policy,
        )
        self.assertEqual(
            result["selected_cohort"]["issue_ids"],
            ["bead-b", "bead-c", "bead-d"],
        )

    def test_ready_rank_and_bead_id_break_equal_economic_ties(self) -> None:
        readiness, estimates, _, policy = _fixture([480, 480, 480, 480])
        one = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=3,
            policy_document=policy,
        )
        two = pool_proportionality_check(
            deepcopy(readiness),
            deepcopy(estimates),
            requested_workers=3,
            policy_document=deepcopy(policy),
        )
        self.assertEqual(
            one["selected_cohort"]["issue_ids"],
            ["bead-a", "bead-b", "bead-c"],
        )
        self.assertEqual(one, two)

    def test_requested_n2_ceiling_selects_best_pair(self) -> None:
        readiness, estimates, _, policy = _fixture([300, 400, 500, 1000])
        result = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=2,
            policy_document=policy,
        )
        self.assertEqual(result["candidate_capacity_ceiling"], 2)
        self.assertEqual(result["selected_cohort"]["issue_ids"], ["bead-c", "bead-d"])
        n3 = _evaluation(result, ["bead-b", "bead-c", "bead-d"])
        self.assertIn(
            "candidate-capacity-ceiling-exceeded",
            {reason["code"] for reason in n3["reasons"]},
        )

    def test_modeled_overhead_increases_with_n(self) -> None:
        readiness, estimates, _, policy = _fixture([480, 480, 480])
        result = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=3,
            policy_document=policy,
        )
        n2 = _evaluation(result, ["bead-a", "bead-b"])
        n3 = _evaluation(result, ["bead-a", "bead-b", "bead-c"])
        self.assertGreater(
            n3["economics"]["total_orchestration_overhead_ms"],
            n2["economics"]["total_orchestration_overhead_ms"],
        )
        self.assertEqual(n3["economics"]["overhead"]["schedulability_ms"], 950)
        self.assertEqual(n2["economics"]["overhead"]["schedulability_ms"], 750)

    def test_measured_overhead_never_undercuts_conservative_floor(self) -> None:
        readiness, estimates, _, policy = _fixture([480, 480])
        conservative = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=2,
            measured_fixed_overhead_ms=1,
            policy_document=policy,
        )
        measured = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=2,
            measured_fixed_overhead_ms=500_000,
            policy_document=policy,
        )
        self.assertEqual(conservative["effective_fixed_overhead_ms"], 60_000)
        self.assertEqual(conservative["fixed_overhead_source"], "conservative-policy")
        self.assertEqual(measured["effective_fixed_overhead_ms"], 500_000)
        self.assertEqual(measured["fixed_overhead_source"], "measured")
        self.assertFalse(measured["accepted"])

    def test_resealed_policy_bypasses_fail_semantic_validation(self) -> None:
        rejected_readiness, rejected_estimates, _, policy = _fixture([120, 120])
        rejected = pool_proportionality_check(
            rejected_readiness,
            rejected_estimates,
            requested_workers=2,
            policy_document=policy,
        )
        laundered = deepcopy(rejected)
        pair = _evaluation(laundered, ["bead-a", "bead-b"])
        pair["reasons"] = []
        pair["eligible_without_override"] = True
        pair["overridden"] = False
        pair["overridden_rule_ids"] = []
        pair["accepted"] = True
        laundered["selected_cohort"] = deepcopy(pair)
        laundered["decision"] = "pool"
        laundered["accepted"] = True
        laundered["candidate_mode"] = "released-capacity"
        _reseal_assessment(laundered)
        errors = validate_pool_proportionality_assessment(
            laundered,
            policy_document=policy,
        )
        self.assertIn("assessment-cohort[0]-reasons-policy-mismatch", errors)

        literal_items = [
            _literal_item("bead-a", policy=policy),
            _literal_item("bead-b", policy=policy),
        ]
        literal_readiness = build_ready_set_evidence(
            literal_items,
            epic_id="epic-proportionality",
            requested_workers=2,
            policy_document=policy,
        )
        literal_estimates = {
            item["id"]: item["raw"]["metadata"]["cwo_ready_set_admission"]["work_plan"]
            for item in literal_items
        }
        literal = pool_proportionality_check(
            literal_readiness,
            literal_estimates,
            requested_workers=2,
            policy_document=policy,
        )
        literal_laundered = deepcopy(literal)
        literal_pair = _evaluation(literal_laundered, ["bead-a", "bead-b"])
        literal_pair["reasons"] = []
        literal_pair["eligible_without_override"] = True
        literal_pair["accepted"] = True
        literal_laundered["selected_cohort"] = deepcopy(literal_pair)
        literal_laundered["decision"] = "pool"
        literal_laundered["accepted"] = True
        literal_laundered["candidate_mode"] = "released-capacity"
        _reseal_assessment(literal_laundered)
        errors = validate_pool_proportionality_assessment(
            literal_laundered,
            policy_document=policy,
        )
        self.assertIn("assessment-cohort[0]-reasons-policy-mismatch", errors)

        adequate_readiness, adequate_estimates, _, adequate_policy = _fixture(
            [480, 480]
        )
        adequate = pool_proportionality_check(
            adequate_readiness,
            adequate_estimates,
            requested_workers=2,
            policy_document=adequate_policy,
        )
        fixed_overhead_contradictions = []
        effective_below_floor = deepcopy(adequate)
        effective_below_floor["effective_fixed_overhead_ms"] = 1
        fixed_overhead_contradictions.append(_reseal_assessment(effective_below_floor))
        false_measured_source = deepcopy(adequate)
        false_measured_source["fixed_overhead_source"] = "measured"
        fixed_overhead_contradictions.append(_reseal_assessment(false_measured_source))
        ignored_measurement = deepcopy(adequate)
        ignored_measurement["measured_fixed_overhead_ms"] = 999_999
        fixed_overhead_contradictions.append(_reseal_assessment(ignored_measurement))
        for contradiction in fixed_overhead_contradictions:
            errors = validate_pool_proportionality_assessment(
                contradiction,
                policy_document=adequate_policy,
            )
            self.assertTrue(
                any("fixed-overhead" in error for error in errors),
                errors,
            )

        if HAS_JSONSCHEMA:
            from jsonschema import Draft202012Validator

            schema = json.loads(
                (
                    ROOT
                    / "schemas"
                    / "native-pool-proportionality-assessment.schema.json"
                ).read_text(encoding="utf-8")
            )
            validator = Draft202012Validator(schema)
            for contradiction in (
                laundered,
                literal_laundered,
                *fixed_overhead_contradictions,
            ):
                self.assertTrue(list(validator.iter_errors(contradiction)))

    def test_savings_equality_is_rejected_and_strict_excess_is_accepted(self) -> None:
        policy = deepcopy(load_policy("native-worker-execution"))
        policy["native_supervision_pool"]["proportionality"][
            "minimum_child_runtime_p90_ms"
        ] = 1_000
        equal_ready, equal_estimates, _, equal_policy = _fixture(
            [222, 222], policy=policy
        )
        equal = pool_proportionality_check(
            equal_ready,
            equal_estimates,
            requested_workers=2,
            measured_fixed_overhead_ms=60_250,
            policy_document=equal_policy,
        )
        self.assertFalse(equal["accepted"])
        above_ready, above_estimates, _, above_policy = _fixture(
            [223, 223], policy=policy
        )
        above = pool_proportionality_check(
            above_ready,
            above_estimates,
            requested_workers=2,
            measured_fixed_overhead_ms=60_250,
            policy_document=above_policy,
        )
        self.assertTrue(above["accepted"])

    def test_mutation_and_integration_costs_are_modeled(self) -> None:
        read_ready, read_estimates, _, read_policy = _fixture([480, 480])
        mutable_ready, mutable_estimates, _, mutable_policy = _fixture(
            [480, 480], writes=True
        )
        read_only = pool_proportionality_check(
            read_ready,
            read_estimates,
            requested_workers=2,
            policy_document=read_policy,
        )["selected_cohort"]
        mutable = pool_proportionality_check(
            mutable_ready,
            mutable_estimates,
            requested_workers=2,
            policy_document=mutable_policy,
        )["selected_cohort"]
        self.assertEqual(read_only["economics"]["overhead"]["mutation_ms"], 0)
        self.assertEqual(read_only["economics"]["overhead"]["integration_ms"], 0)
        self.assertGreater(mutable["economics"]["overhead"]["mutation_ms"], 0)
        self.assertGreater(mutable["economics"]["overhead"]["integration_ms"], 0)

    def test_literal_command_is_nonwaivable(self) -> None:
        policy = deepcopy(load_policy("native-worker-execution"))
        items = [
            _literal_item("bead-a", policy=policy),
            _literal_item("bead-b", policy=policy),
        ]
        readiness = build_ready_set_evidence(
            items,
            epic_id="epic-proportionality",
            requested_workers=2,
            policy_document=policy,
        )
        estimates = {
            item["id"]: item["raw"]["metadata"]["cwo_ready_set_admission"]["work_plan"]
            for item in items
        }
        result = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=2,
            policy_document=policy,
        )
        cohort = _evaluation(result, ["bead-a", "bead-b"])
        forbidden = next(
            reason
            for reason in cohort["reasons"]
            if reason["code"] == "forbidden-task-class"
        )
        self.assertFalse(forbidden["waivable"])
        with self.assertRaisesRegex(PoolProportionalityError, "nonwaivable-findings"):
            proportionality_override_artifacts(
                result,
                cohort_sha256=cohort["cohort_sha256"],
                reason="Do not permit this command lane.",
            )

    def test_override_requires_exact_fresh_operator_approval(self) -> None:
        readiness, estimates, _, policy = _fixture([120, 120])
        baseline = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=2,
            policy_document=policy,
        )
        cohort = _evaluation(baseline, ["bead-a", "bead-b"])
        reason = "Operator accepts the exact provisional economic exception."
        artifacts = proportionality_override_artifacts(
            baseline,
            cohort_sha256=cohort["cohort_sha256"],
            reason=reason,
        )
        assessment = proportionality_override_assessment(
            baseline,
            artifacts,
            cohort_sha256=cohort["cohort_sha256"],
        )
        key = b"test-only-proportionality-override-key"
        receipt = _signed_approval(
            key,
            assessment.before_subject,
            assessment.after_subject,
        )
        verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            replay_store_path=self.replay_store(),
            now=datetime(2026, 7, 20, 20, 15, tzinfo=timezone.utc),
        )
        authorization = verify_proportionality_override(
            baseline,
            cohort_sha256=cohort["cohort_sha256"],
            reason=reason,
            approval_receipt=receipt,
            operator_approval_verifier=verifier,
            policy_document=policy,
        )
        overridden = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=2,
            policy_document=policy,
            override_authorization=authorization,
        )
        self.assertTrue(overridden["accepted"])
        self.assertTrue(overridden["selected_cohort"]["overridden"])
        self.assertEqual(
            overridden["override_authorization"]["action_sha256"],
            artifacts["action_sha256"],
        )
        for path in (
            ("source_type",),
            ("actor_role",),
            ("authorized_scope",),
            ("verification", "method"),
        ):
            malformed = deepcopy(overridden)
            target = malformed["override_authorization"]["operator_approval_audit"][
                "authority_provenance"
            ]
            for component in path[:-1]:
                target = target[component]
            target[path[-1]] = []
            errors = validate_pool_proportionality_assessment(
                malformed,
                policy_document=policy,
            )
            self.assertTrue(
                any(error.startswith("assessment-override-audit:") for error in errors)
            )
        with self.assertRaisesRegex(
            PoolProportionalityError, "override-authorization-replayed"
        ):
            pool_proportionality_check(
                readiness,
                estimates,
                requested_workers=2,
                policy_document=policy,
                override_authorization=authorization,
            )
        with self.assertRaisesRegex(PoolProportionalityError, "replayed"):
            verify_proportionality_override(
                baseline,
                cohort_sha256=cohort["cohort_sha256"],
                reason=reason,
                approval_receipt=receipt,
                operator_approval_verifier=verifier,
                policy_document=policy,
            )
        with self.assertRaisesRegex(PoolProportionalityError, "baseline-mismatch"):
            pool_proportionality_check(
                readiness,
                estimates,
                requested_workers=2,
                measured_fixed_overhead_ms=500_000,
                policy_document=policy,
                override_authorization=authorization,
            )
        with self.assertRaisesRegex(
            PoolProportionalityError, "verified-proportionality-override-required"
        ):
            pool_proportionality_check(
                readiness,
                estimates,
                requested_workers=2,
                policy_document=policy,
                override_authorization={  # type: ignore[arg-type]
                    "action_sha256": artifacts["action_sha256"]
                },
            )

    def test_verified_override_is_atomically_single_use(self) -> None:
        readiness, estimates, _, policy = _fixture([120, 120])
        baseline = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=2,
            policy_document=policy,
        )
        cohort = _evaluation(baseline, ["bead-a", "bead-b"])
        reason = "Operator accepts one exact concurrent application attempt."
        artifacts = proportionality_override_artifacts(
            baseline,
            cohort_sha256=cohort["cohort_sha256"],
            reason=reason,
        )
        assessment = proportionality_override_assessment(
            baseline,
            artifacts,
            cohort_sha256=cohort["cohort_sha256"],
        )
        key = b"test-only-atomic-proportionality-key"
        verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            replay_store_path=self.replay_store(),
            now=datetime(2026, 7, 20, 20, 15, tzinfo=timezone.utc),
        )
        authorization = verify_proportionality_override(
            baseline,
            cohort_sha256=cohort["cohort_sha256"],
            reason=reason,
            approval_receipt=_signed_approval(
                key,
                assessment.before_subject,
                assessment.after_subject,
                nonce="atomic-proportionality-override-nonce",
            ),
            operator_approval_verifier=verifier,
            policy_document=policy,
        )
        barrier = Barrier(2)

        def apply_once() -> str:
            barrier.wait()
            try:
                result = pool_proportionality_check(
                    readiness,
                    estimates,
                    requested_workers=2,
                    policy_document=policy,
                    override_authorization=authorization,
                )
            except PoolProportionalityError as error:
                return str(error)
            return "accepted" if result["accepted"] else "rejected"

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: apply_once(), range(2)))
        self.assertEqual(outcomes.count("accepted"), 1)
        self.assertEqual(
            sum("override-authorization-replayed" in item for item in outcomes),
            1,
        )

    def test_serialized_override_is_one_exact_coherent_authority_artifact(
        self,
    ) -> None:
        readiness, estimates, _, policy = _fixture([120, 120, 120])
        baseline = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=3,
            policy_document=policy,
        )
        n2_cohort = _evaluation(baseline, ["bead-a", "bead-b"])
        reason = "Operator accepts this exact N2 economic exception."
        n2_artifacts = proportionality_override_artifacts(
            baseline,
            cohort_sha256=n2_cohort["cohort_sha256"],
            reason=reason,
            policy_document=policy,
        )
        n2_assessment = proportionality_override_assessment(
            baseline,
            n2_artifacts,
            cohort_sha256=n2_cohort["cohort_sha256"],
        )
        key = b"test-only-serialized-override-binding-key"
        authorization = verify_proportionality_override(
            baseline,
            cohort_sha256=n2_cohort["cohort_sha256"],
            reason=reason,
            approval_receipt=_signed_approval(
                key,
                n2_assessment.before_subject,
                n2_assessment.after_subject,
                nonce="serialized-override-binding-nonce",
            ),
            operator_approval_verifier=OperatorApprovalVerifier(
                verification_key=key,
                expected_actor_id="operator-1",
                expected_identity_source="trusted-control-session",
                replay_store_path=self.replay_store(),
                now=datetime(2026, 7, 20, 20, 15, tzinfo=timezone.utc),
            ),
            policy_document=policy,
        )
        overridden = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=3,
            policy_document=policy,
            override_authorization=authorization,
        )
        self.assertEqual(
            validate_pool_proportionality_assessment(
                overridden,
                policy_document=policy,
            ),
            [],
        )

        action_tamper = deepcopy(overridden)
        action_tamper["override_authorization"]["action_sha256"] = "0" * 64
        self.assertIn(
            "assessment-override-action-sha256-mismatch",
            validate_pool_proportionality_assessment(
                _reseal_assessment(action_tamper),
                policy_document=policy,
            ),
        )

        baseline_tamper = deepcopy(overridden)
        baseline_tamper["override_authorization"]["baseline_assessment_sha256"] = (
            "0" * 64
        )
        self.assertIn(
            "assessment-override-baseline-sha256-mismatch",
            validate_pool_proportionality_assessment(
                _reseal_assessment(baseline_tamper),
                policy_document=policy,
            ),
        )

        reason_tamper = deepcopy(overridden)
        changed_reason = "Resealed but not operator-approved reason."
        reason_tamper["override_authorization"]["reason"] = changed_reason
        reason_tamper["override_authorization"]["reason_sha256"] = (
            canonical_proportionality_sha256(changed_reason)
        )
        self.assertIn(
            "assessment-override-action-sha256-mismatch",
            validate_pool_proportionality_assessment(
                _reseal_assessment(reason_tamper),
                policy_document=policy,
            ),
        )

        n3_cohort = _evaluation(baseline, ["bead-a", "bead-b", "bead-c"])
        n3_artifacts = proportionality_override_artifacts(
            baseline,
            cohort_sha256=n3_cohort["cohort_sha256"],
            reason=reason,
            policy_document=policy,
        )
        retargeted = deepcopy(baseline)
        retargeted_n3 = _evaluation(
            retargeted,
            ["bead-a", "bead-b", "bead-c"],
        )
        retargeted_n3["overridden"] = True
        retargeted_n3["overridden_rule_ids"] = sorted(
            {item["code"] for item in retargeted_n3["reasons"]}
        )
        retargeted_n3["accepted"] = True
        retargeted["selected_cohort"] = deepcopy(retargeted_n3)
        retargeted["decision"] = "pool"
        retargeted["accepted"] = True
        retargeted["candidate_mode"] = "offline-unreleased-candidate"
        retargeted["override_authorization"] = deepcopy(
            overridden["override_authorization"]
        )
        retargeted["override_authorization"].update(
            {
                "action_sha256": n3_artifacts["action_sha256"],
                "cohort_sha256": n3_cohort["cohort_sha256"],
            }
        )
        retarget_errors = validate_pool_proportionality_assessment(
            _reseal_assessment(retargeted),
            policy_document=policy,
        )
        self.assertTrue(
            {
                "assessment-override-audit-before-sha256-mismatch",
                "assessment-override-audit-after-sha256-mismatch",
            }.issubset(retarget_errors)
        )

        for audit_field in ("before_sha256", "after_sha256"):
            audit_tamper = deepcopy(overridden)
            audit = audit_tamper["override_authorization"]["operator_approval_audit"]
            replacement = "0" * 64
            audit[audit_field] = replacement
            audit["signed_receipt"][audit_field] = replacement
            audit["receipt_sha256"] = canonical_authority_sha256(
                audit["signed_receipt"]
            )
            errors = validate_pool_proportionality_assessment(
                _reseal_assessment(audit_tamper),
                policy_document=policy,
            )
            self.assertIn(
                f"assessment-override-audit-{audit_field.replace('_', '-')}-mismatch",
                errors,
            )

        change_type_tamper = deepcopy(overridden)
        audit = change_type_tamper["override_authorization"]["operator_approval_audit"]
        audit["change_type"] = "objective-change"
        audit["signed_receipt"]["change_type"] = "objective-change"
        audit["receipt_sha256"] = canonical_authority_sha256(audit["signed_receipt"])
        self.assertIn(
            "assessment-override-audit-change-type-mismatch",
            validate_pool_proportionality_assessment(
                _reseal_assessment(change_type_tamper),
                policy_document=policy,
            ),
        )

    def test_snapshot_estimate_and_cohort_drift_fail_closed(self) -> None:
        readiness, estimates, _, policy = _fixture([480, 480])
        snapshot_drift = deepcopy(readiness)
        snapshot_drift["beads_readiness_snapshot"]["epic_id"] = "changed"
        with self.assertRaisesRegex(
            PoolProportionalityError, "snapshot-sha256-mismatch"
        ):
            pool_proportionality_check(
                snapshot_drift,
                estimates,
                requested_workers=2,
                policy_document=policy,
            )

        estimate_drift = deepcopy(estimates)
        source = deepcopy(estimate_drift["bead-a"])
        source["estimates"]["runtime_seconds_p50"] = 481
        source["estimates"]["runtime_seconds_p90"] = 481
        estimate_drift["bead-a"] = evaluate_work_estimate(source, policy=policy)
        with self.assertRaisesRegex(
            PoolProportionalityError, "snapshot-binding-mismatch"
        ):
            pool_proportionality_check(
                readiness,
                estimate_drift,
                requested_workers=2,
                policy_document=policy,
            )

        cohort_drift = deepcopy(readiness)
        cohort_drift["compatible_ready_sets"][0]["issue_ids"].reverse()
        with self.assertRaises(PoolProportionalityError):
            pool_proportionality_check(
                cohort_drift,
                estimates,
                requested_workers=2,
                policy_document=policy,
            )

    def test_n4_and_malformed_policy_are_rejected(self) -> None:
        readiness, estimates, _, policy = _fixture([480, 480, 480])
        with self.assertRaisesRegex(
            PoolProportionalityError, "exceed-hard-candidate-capacity"
        ):
            pool_proportionality_check(
                readiness,
                estimates,
                requested_workers=4,
                policy_document=policy,
            )
        malformed = deepcopy(policy)
        malformed["native_supervision_pool"]["proportionality"].pop(
            "minimum_child_runtime_p90_ms"
        )
        with self.assertRaisesRegex(PoolProportionalityError, "fields-invalid"):
            load_pool_proportionality_policy(malformed)

    def test_assessment_hash_and_schema_are_strict(self) -> None:
        readiness, estimates, _, policy = _fixture([480, 480])
        result = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=2,
            policy_document=policy,
        )
        self.assertEqual(validate_pool_proportionality_assessment(result), [])
        unsigned = deepcopy(result)
        observed = unsigned.pop("assessment_sha256")
        self.assertEqual(observed, canonical_proportionality_sha256(unsigned))
        tampered = deepcopy(result)
        tampered["selected_cohort"]["economics"]["net_parallel_savings_ms"] += 1
        self.assertIn(
            "assessment-selected-cohort-mismatch",
            validate_pool_proportionality_assessment(tampered),
        )
        if HAS_JSONSCHEMA:
            from jsonschema import Draft202012Validator

            schema = json.loads(
                (
                    ROOT
                    / "schemas"
                    / "native-pool-proportionality-assessment.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(result)

    def test_assessment_validator_enforces_capacity_relationships(self) -> None:
        n2_readiness, n2_estimates, _, n2_policy = _fixture([480, 480])
        n2 = pool_proportionality_check(
            n2_readiness,
            n2_estimates,
            requested_workers=2,
            policy_document=n2_policy,
        )
        n2_contradiction = deepcopy(n2)
        n2_contradiction["cohort_evaluations"][0]["within_released_capacity"] = False
        errors = validate_pool_proportionality_assessment(
            _reseal_assessment(n2_contradiction),
            policy_document=n2_policy,
        )
        self.assertIn("assessment-cohort[0]-release-classification-mismatch", errors)

        n3_readiness, n3_estimates, _, n3_policy = _fixture([480, 480, 480])
        n3 = pool_proportionality_check(
            n3_readiness,
            n3_estimates,
            requested_workers=3,
            policy_document=n3_policy,
        )
        n3_release_contradiction = deepcopy(n3)
        n3_release_contradiction["cohort_evaluations"][0][
            "within_released_capacity"
        ] = True
        errors = validate_pool_proportionality_assessment(
            _reseal_assessment(n3_release_contradiction),
            policy_document=n3_policy,
        )
        self.assertIn("assessment-cohort[0]-release-classification-mismatch", errors)

        n3_ceiling_contradiction = deepcopy(n3)
        n3_ceiling_contradiction["candidate_capacity_ceiling"] = 2
        errors = validate_pool_proportionality_assessment(
            _reseal_assessment(n3_ceiling_contradiction),
            policy_document=n3_policy,
        )
        self.assertIn("assessment-cohort[0]-accepted-above-capacity-ceiling", errors)

        n3_request_contradiction = deepcopy(n3)
        n3_request_contradiction["requested_workers"] = 2
        errors = validate_pool_proportionality_assessment(
            _reseal_assessment(n3_request_contradiction),
            policy_document=n3_policy,
        )
        self.assertIn("assessment-cohort[0]-accepted-above-requested-workers", errors)

        candidate_mode_contradiction = deepcopy(n3)
        candidate_mode_contradiction["candidate_mode"] = "released-capacity"
        errors = validate_pool_proportionality_assessment(
            _reseal_assessment(candidate_mode_contradiction),
            policy_document=n3_policy,
        )
        self.assertIn("assessment-candidate-mode-mismatch", errors)

        released_policy_contradiction = deepcopy(n3)
        released_policy_contradiction["released_capacity"] = 3
        released_policy_contradiction["candidate_mode"] = "released-capacity"
        for evaluation in released_policy_contradiction["cohort_evaluations"]:
            evaluation["within_released_capacity"] = True
        errors = validate_pool_proportionality_assessment(
            _reseal_assessment(released_policy_contradiction),
            policy_document=n3_policy,
        )
        self.assertIn("assessment-released-capacity-policy-mismatch", errors)
        if HAS_JSONSCHEMA:
            from jsonschema import Draft202012Validator

            schema = json.loads(
                (
                    ROOT
                    / "schemas"
                    / "native-pool-proportionality-assessment.schema.json"
                ).read_text(encoding="utf-8")
            )
            validator = Draft202012Validator(schema)
            for contradiction in (
                n2_contradiction,
                n3_release_contradiction,
                n3_ceiling_contradiction,
                n3_request_contradiction,
                candidate_mode_contradiction,
                released_policy_contradiction,
            ):
                self.assertTrue(list(validator.iter_errors(contradiction)))

    def test_assessment_validator_reports_malformed_selection_without_raising(
        self,
    ) -> None:
        readiness, estimates, _, policy = _fixture([480, 480])
        result = pool_proportionality_check(
            readiness,
            estimates,
            requested_workers=2,
            policy_document=policy,
        )
        malformed = deepcopy(result)
        malformed["cohort_evaluations"][0]["worker_count"] = "two"
        malformed["cohort_evaluations"][0]["economics"] = {}
        errors = validate_pool_proportionality_assessment(malformed)
        self.assertIn("assessment-cohort-selection-input-invalid", errors)
        self.assertIn("assessment-cohort[0]-economics-fields-invalid", errors)

        malformed = deepcopy(result)
        malformed["cohort_evaluations"][0]["reasons"] = "not-a-reason-list"
        malformed["cohort_evaluations"][0]["overridden"] = True
        errors = validate_pool_proportionality_assessment(malformed)
        self.assertIn("assessment-cohort[0]-reasons-invalid", errors)
        self.assertIn("assessment-cohort[0]-override-invalid", errors)

        for invalid_source in ([], {}):
            malformed = deepcopy(result)
            malformed["fixed_overhead_source"] = invalid_source
            self.assertIn(
                "assessment-fixed-overhead-source-invalid",
                validate_pool_proportionality_assessment(malformed),
            )

        rejected_readiness, rejected_estimates, _, rejected_policy = _fixture(
            [120, 120]
        )
        rejected = pool_proportionality_check(
            rejected_readiness,
            rejected_estimates,
            requested_workers=2,
            policy_document=rejected_policy,
        )
        for invalid_decision in ([], {}):
            malformed = deepcopy(rejected)
            malformed["decision"] = invalid_decision
            self.assertIn(
                "assessment-decision-invalid",
                validate_pool_proportionality_assessment(
                    malformed,
                    policy_document=rejected_policy,
                ),
            )


if __name__ == "__main__":
    unittest.main()

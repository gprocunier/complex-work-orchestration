from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_pool_proportionality import (  # noqa: E402
    _selection_key,
    PoolProportionalityError,
    canonical_proportionality_sha256,
    load_pool_proportionality_policy,
    pool_proportionality_check,
    proportionality_override_artifacts,
    validate_pool_proportionality_assessment,
)
from tests.test_native_pool_proportionality import (  # noqa: E402
    _fixture,
    _reseal_assessment,
)


class LiteralInt(int):
    """An ordinary integer subclass supported by the existing integer contract."""


def _reseal_readiness(readiness: dict) -> None:
    snapshot = readiness["beads_readiness_snapshot"]
    unsigned = dict(snapshot)
    unsigned.pop("snapshot_sha256", None)
    snapshot["snapshot_sha256"] = canonical_proportionality_sha256(unsigned)
    readiness["beads_readiness_snapshot_sha256"] = snapshot["snapshot_sha256"]
    for cohort in readiness["compatible_ready_sets"]:
        cohort["snapshot_sha256"] = snapshot["snapshot_sha256"]
        unsigned = dict(cohort)
        unsigned.pop("cohort_sha256", None)
        cohort["cohort_sha256"] = canonical_proportionality_sha256(unsigned)


class NativePoolProportionalityTypeBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        (
            self.readiness,
            self.estimates,
            _,
            self.policy,
        ) = _fixture([480, 480])

    def check(self, *, readiness=None, estimates=None, policy=None) -> dict:
        return pool_proportionality_check(
            self.readiness if readiness is None else readiness,
            self.estimates if estimates is None else estimates,
            requested_workers=2,
            policy_document=self.policy if policy is None else policy,
        )

    def test_genuine_policy_and_economic_decisions_remain_valid(self) -> None:
        result = self.check()
        self.assertTrue(result["accepted"])
        self.assertFalse(result["dispatch_authorized"])
        self.assertEqual(
            validate_pool_proportionality_assessment(result, policy_document=self.policy),
            [],
        )
        policy = load_pool_proportionality_policy(self.policy)
        self.assertEqual(policy.override_required_scope, "complete-task")
        self.assertEqual(policy.minimum_child_runtime_p90_ms, 300_000)
        self.assertEqual(
            policy.minimum_gross_savings_overhead_multiple_milli, 2_000
        )

    def test_policy_versions_refuse_boolean_float_and_wrong_literals(self) -> None:
        for version in (True, False, 1.0, 0, "1", None, [], {}):
            with self.subTest(version=version):
                document = deepcopy(self.policy)
                raw = document["native_supervision_pool"]["proportionality"]
                raw["version"] = version
                with self.assertRaisesRegex(
                    PoolProportionalityError, "proportionality-policy-header-invalid"
                ):
                    load_pool_proportionality_policy(document)

    def test_override_scope_containers_have_controlled_refusals(self) -> None:
        for scope in ([], {}, set(), None, True, 1, 1.0, "", "unknown-scope"):
            with self.subTest(scope=scope):
                document = deepcopy(self.policy)
                raw = document["native_supervision_pool"]["proportionality"]
                raw["override_required_scope"] = scope
                with self.assertRaisesRegex(
                    PoolProportionalityError, "proportionality-policy-override-scope-invalid"
                ):
                    load_pool_proportionality_policy(document)
                self.assertIn(
                    "assessment-bound-policy-invalid",
                    validate_pool_proportionality_assessment(
                        self.check(), policy_document=document
                    ),
                )

    def test_malformed_policy_containers_and_keys_are_refused(self) -> None:
        for document in (
            [],
            {"native_supervision_pool": []},
            {"native_supervision_pool": {"proportionality": []}},
            {**self.policy, 1: "non-string-key"},
        ):
            with self.subTest(document=document):
                with self.assertRaises(PoolProportionalityError):
                    load_pool_proportionality_policy(document)
        for key in (1, None, ("non-string",)):
            document = deepcopy(self.policy)
            document["native_supervision_pool"]["proportionality"][key] = 0
            with self.subTest(key=key), self.assertRaises(PoolProportionalityError):
                load_pool_proportionality_policy(document)

    def test_malformed_input_keys_have_controlled_refusals(self) -> None:
        for key in (1, None, ("non-string",)):
            with self.subTest(container="estimates", key=key):
                with self.assertRaisesRegex(
                    PoolProportionalityError, "work-estimates-must-be-object"
                ):
                    self.check(estimates={**self.estimates, key: {}})
            with self.subTest(container="readiness", key=key):
                with self.assertRaisesRegex(
                    PoolProportionalityError, "readiness-evidence-must-be-object"
                ):
                    self.check(readiness={**self.readiness, key: {}})

    def test_resealed_snapshot_and_cohort_version_forgery_is_refused(self) -> None:
        cases = (
            ("snapshot", True, "readiness-snapshot-header-invalid"),
            ("snapshot", 2.0, "readiness-snapshot-header-invalid"),
            ("cohort", True, "compatible-ready-set-header-invalid:0"),
            ("cohort", 1.0, "compatible-ready-set-header-invalid:0"),
        )
        for target, version, message in cases:
            with self.subTest(target=target, version=version):
                readiness = deepcopy(self.readiness)
                if target == "snapshot":
                    readiness["beads_readiness_snapshot"]["version"] = version
                else:
                    readiness["compatible_ready_sets"][0]["version"] = version
                _reseal_readiness(readiness)
                with self.assertRaisesRegex(PoolProportionalityError, message):
                    self.check(readiness=readiness)

    def test_resealed_final_decisions_reject_version_forgery(self) -> None:
        for runtimes in ([480, 480], [120, 120]):
            readiness, estimates, _, policy = _fixture(runtimes)
            baseline = pool_proportionality_check(
                readiness, estimates, requested_workers=2, policy_document=policy
            )
            self.assertEqual(
                validate_pool_proportionality_assessment(baseline, policy_document=policy),
                [],
            )
            for version in (True, 1.0, False, 0, "1", None, [], {}):
                with self.subTest(runtimes=runtimes, version=version):
                    forged = deepcopy(baseline)
                    forged["version"] = version
                    _reseal_assessment(forged)
                    self.assertEqual(
                        validate_pool_proportionality_assessment(
                            forged, policy_document=policy
                        ),
                        ["assessment-header-invalid"],
                    )
                    with self.assertRaisesRegex(
                        PoolProportionalityError,
                        "baseline-proportionality-assessment-invalid:assessment-header-invalid",
                    ):
                        proportionality_override_artifacts(
                            forged,
                            cohort_sha256=forged["cohort_evaluations"][0][
                                "cohort_sha256"
                            ],
                            reason="Exact test-only metadata refusal.",
                            policy_document=policy,
                        )

    def test_supported_integer_subclasses_preserve_literal_commitments(self) -> None:
        baseline = self.check()
        policy = deepcopy(self.policy)
        raw = policy["native_supervision_pool"]["proportionality"]
        raw["version"] = LiteralInt(1)
        self.assertEqual(
            load_pool_proportionality_policy(policy).policy_sha256,
            load_pool_proportionality_policy(self.policy).policy_sha256,
        )
        readiness = deepcopy(self.readiness)
        readiness["beads_readiness_snapshot"]["version"] = LiteralInt(2)
        for cohort in readiness["compatible_ready_sets"]:
            cohort["version"] = LiteralInt(1)
        _reseal_readiness(readiness)
        self.assertEqual(self.check(readiness=readiness, policy=policy), baseline)
        assessment = deepcopy(baseline)
        assessment["version"] = LiteralInt(1)
        _reseal_assessment(assessment)
        self.assertEqual(
            validate_pool_proportionality_assessment(assessment, policy_document=policy),
            [],
        )

    def test_override_action_keeps_its_historical_integer_version(self) -> None:
        readiness, estimates, _, policy = _fixture([120, 120])
        baseline = pool_proportionality_check(
            readiness, estimates, requested_workers=2, policy_document=policy
        )
        self.assertFalse(baseline["accepted"])
        artifacts = proportionality_override_artifacts(
            baseline,
            cohort_sha256=baseline["cohort_evaluations"][0]["cohort_sha256"],
            reason="Test-only exact economic exception artifact.",
            policy_document=policy,
        )
        self.assertIs(type(artifacts["action"]["version"]), int)
        self.assertFalse(baseline["dispatch_authorized"])

    def _rejected_selection_positive(self) -> tuple[dict, dict]:
        readiness, estimates, _, policy = _fixture([120, 120])
        baseline = pool_proportionality_check(
            readiness, estimates, requested_workers=2, policy_document=policy
        )
        self.assertFalse(baseline["accepted"])
        self.assertEqual(baseline["decision"], "single")
        self.assertFalse(baseline["dispatch_authorized"])
        self.assertEqual(
            validate_pool_proportionality_assessment(baseline, policy_document=policy),
            [],
        )
        artifacts = proportionality_override_artifacts(
            baseline,
            cohort_sha256=baseline["cohort_evaluations"][0]["cohort_sha256"],
            reason="Test-only selection boundary positive.",
            policy_document=policy,
        )
        self.assertEqual(
            artifacts["action"]["baseline_assessment_sha256"],
            baseline["assessment_sha256"],
        )
        self.assertEqual(
            artifacts["after_artifact"]["authority_context"]["decision"],
            "operator-override-accept",
        )
        return baseline, policy

    def test_malformed_selection_operands_refuse_at_both_consumers(self) -> None:
        invalid_numbers = (
            float("inf"), float("-inf"), float("nan"), True, False,
            1.0, 1.5, "1", None, [], {}, (),
        )
        positions = (
            (("worker_count",), "members-invalid", (0, -1)),
            (("economics", "net_parallel_savings_ms"), "economics-values-invalid", ()),
            (("ready_order", 0, "rank"), "members-invalid", (-1,)),
        )
        for accepted in (False, True):
            for path, diagnostic, lower_bound_cases in positions:
                for invalid in invalid_numbers + lower_bound_cases:
                    for consumer in ("validator", "override"):
                        with self.subTest(
                            accepted=accepted, path=path, invalid=invalid,
                            consumer=consumer,
                        ):
                            baseline, policy = self._rejected_selection_positive()
                            if accepted:
                                baseline = self.check()
                            self.assertIs(baseline["accepted"], accepted)
                            self.assertEqual(
                                validate_pool_proportionality_assessment(
                                    baseline, policy_document=policy
                                ),
                                [],
                            )
                            malformed = deepcopy(baseline)
                            target = malformed["cohort_evaluations"][0]
                            for component in path[:-1]:
                                target = target[component]
                            target[path[-1]] = invalid
                            if consumer == "validator":
                                errors = validate_pool_proportionality_assessment(
                                    malformed, policy_document=policy
                                )
                                self.assertIsInstance(errors, list)
                                self.assertIn(
                                    "assessment-cohort-selection-input-invalid", errors
                                )
                                self.assertIn(
                                    f"assessment-cohort[0]-{diagnostic}", errors
                                )
                            else:
                                with self.assertRaisesRegex(
                                    PoolProportionalityError,
                                    "baseline-proportionality-assessment-invalid:",
                                ) as refusal:
                                    proportionality_override_artifacts(
                                        malformed,
                                        cohort_sha256=baseline["cohort_evaluations"][0][
                                            "cohort_sha256"
                                        ],
                                        reason="Test-only malformed selection refusal.",
                                        policy_document=policy,
                                    )
                                self.assertIn(
                                    "assessment-cohort-selection-input-invalid",
                                    str(refusal.exception),
                                )

    def test_selection_keys_preserve_exact_signed_integers_and_order(self) -> None:
        baseline = self.check()["cohort_evaluations"][0]
        for integer in (int, LiteralInt):
            keys = []
            for savings in (-10**100, -1, 0, 1, 10**100):
                item = deepcopy(baseline)
                item["worker_count"] = integer(baseline["worker_count"])
                item["economics"]["net_parallel_savings_ms"] = integer(savings)
                for index, entry in enumerate(item["ready_order"]):
                    entry["rank"] = integer(index * 10**100)
                expected_ready = tuple(
                    (index * 10**100, entry["id"])
                    for index, entry in enumerate(item["ready_order"])
                )
                key = _selection_key(item)
                self.assertEqual(
                    key, (-baseline["worker_count"], -savings, expected_ready)
                )
                keys.append(key)
            self.assertEqual(sorted(keys), list(reversed(keys)))

    def test_genuine_signed_savings_remain_valid_at_public_consumers(self) -> None:
        baseline = self.check()
        economics = baseline["cohort_evaluations"][0]["economics"]
        other_overhead = (
            economics["total_orchestration_overhead_ms"]
            - economics["overhead"]["fixed_ms"]
        )
        zero_net_fixed = economics["gross_parallel_savings_ms"] - other_overhead
        for net in (-10**100, -1, 0, 1):
            with self.subTest(net=net):
                result = pool_proportionality_check(
                    self.readiness,
                    self.estimates,
                    requested_workers=2,
                    measured_fixed_overhead_ms=LiteralInt(zero_net_fixed - net),
                    policy_document=self.policy,
                )
                self.assertFalse(result["accepted"])
                self.assertFalse(result["dispatch_authorized"])
                self.assertEqual(
                    result["cohort_evaluations"][0]["economics"][
                        "net_parallel_savings_ms"
                    ],
                    net,
                )
                self.assertEqual(
                    validate_pool_proportionality_assessment(
                        result, policy_document=self.policy
                    ),
                    [],
                )
                artifacts = proportionality_override_artifacts(
                    result,
                    cohort_sha256=result["cohort_evaluations"][0]["cohort_sha256"],
                    reason="Test-only signed economic artifact.",
                    policy_document=self.policy,
                )
                self.assertEqual(
                    artifacts["action"]["baseline_assessment_sha256"],
                    result["assessment_sha256"],
                )

    def test_integer_subclasses_preserve_genuine_selection_commitments(self) -> None:
        for runtimes in ([480, 480, 480, 480], [120, 120]):
            readiness, estimates, _, policy = _fixture(runtimes)
            baseline = pool_proportionality_check(
                readiness, estimates, requested_workers=3, policy_document=policy
            )
            converted = deepcopy(baseline)
            for item in converted["cohort_evaluations"]:
                item["worker_count"] = LiteralInt(item["worker_count"])
                item["economics"]["net_parallel_savings_ms"] = LiteralInt(
                    item["economics"]["net_parallel_savings_ms"]
                )
                for entry in item["ready_order"]:
                    entry["rank"] = LiteralInt(entry["rank"])
                for child in item["child_economics"]:
                    child["rank"] = LiteralInt(child["rank"])
            _reseal_assessment(converted)
            self.assertEqual(converted, baseline)
            self.assertEqual(
                validate_pool_proportionality_assessment(converted, policy_document=policy),
                [],
            )
            self.assertEqual(
                sorted(converted["cohort_evaluations"], key=_selection_key),
                baseline["cohort_evaluations"],
            )
            if baseline["accepted"]:
                self.assertEqual(
                    converted["selected_cohort"]["issue_ids"],
                    ["bead-a", "bead-b", "bead-c"],
                )
            else:
                arguments = {
                    "cohort_sha256": baseline["cohort_evaluations"][0]["cohort_sha256"],
                    "reason": "Test-only integer subclass positive.",
                    "policy_document": policy,
                }
                self.assertEqual(
                    proportionality_override_artifacts(converted, **arguments),
                    proportionality_override_artifacts(baseline, **arguments),
                )


if __name__ == "__main__":
    unittest.main()

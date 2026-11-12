from __future__ import annotations

import json
import math
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo_core.native_progress as progress  # noqa: E402
from tests.test_native_progress import actual as _actual, plan as _plan  # noqa: E402

HUGE = 10**4000






def _policy(**updates):
    thresholds = {
        "early_warning_fraction_of_p50": 0.5,
        "minimum_reads_without_progress": 4,
        "realignment_fraction_of_hard": 0.6,
        "read_ratio_multiplier": 1.5,
        "read_ratio_floor": 6,
        "max_consecutive_reads_without_progress": 8,
    }
    thresholds.update(updates)
    return {
        "work_sizing": {
            "enforcement": {
                "foundation-canary": {
                    "autonomous_replanning": {"progress_thresholds": thresholds}
                }
            }
        }
    }


class NativeProgressNumericBoundariesTest(unittest.TestCase):
    def _evaluate(self, plan=None, actual=None, **kwargs):
        return progress.evaluate_worker_progress(
            _plan() if plan is None else plan,
            _actual() if actual is None else actual,
            policy=kwargs.pop("policy", _policy()),
            **kwargs,
        )

    def _refusal(self, callback, message):
        with (
            patch.object(progress, "_neutral_progress_steering") as steering,
            patch.object(progress, "policy_scope_authority") as authority,
            patch.object(progress, "build_stop_metadata") as stop,
        ):
            with self.assertRaises(ValueError) as raised:
                callback()
            self.assertEqual(str(raised.exception), message)
            steering.assert_not_called()
            authority.assert_not_called()
            stop.assert_not_called()

    def test_number_refusals_and_finite_boundaries(self):
        for value in (
            False, True, float("nan"), float("inf"), -float("inf"),
            HUGE, -HUGE, "1",
        ):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "sample must be a finite number"):
                    progress._number(value, "sample")
        for value in (0, -0.0, 1, 0.5, sys.float_info.max):
            with self.subTest(value=value):
                self.assertEqual(progress._number(value, "sample"), float(value))

    def test_public_actual_numbers_refuse_before_authority(self):
        for field in ("runtime_seconds", "projected_runtime_seconds"):
            with self.subTest(field=field):
                data = _actual(**{field: HUGE})
                self._refusal(
                    lambda: self._evaluate(actual=data),
                    f"actual.{field} must be a finite number >= 0.0",
                )
                with self.assertRaisesRegex(ValueError, rf"actual\.{field}"):
                    progress._normalize_actual(data)

    def test_public_plan_ratio_refuses_before_authority(self):
        data = _plan()
        data["read_to_mutation_ratio"] = HUGE
        self._refusal(
            lambda: self._evaluate(plan=data),
            "plan.read_to_mutation_ratio must be a finite number >= 0.0",
        )
        with self.assertRaisesRegex(ValueError, r"plan\.read_to_mutation_ratio"):
            progress._normalize_plan(data)

    def test_public_policy_numbers_refuse_before_authority(self):
        for field in (
            "early_warning_fraction_of_p50",
            "realignment_fraction_of_hard",
            "read_ratio_multiplier",
            "read_ratio_floor",
        ):
            with self.subTest(field=field):
                policy = _policy(**{field: HUGE})
                self._refusal(
                    lambda: self._evaluate(policy=policy),
                    f"progress_thresholds.{field} must be a finite number >= 0.0",
                )
                with self.assertRaisesRegex(ValueError, rf"progress_thresholds\.{field}"):
                    progress._policy_thresholds(policy)

    def test_confidence_refusals_and_advisory_boundaries(self):
        for value in (HUGE, -HUGE, True, float("nan"), float("inf"), -1, 2):
            with self.subTest(kind=type(value).__name__):
                self._refusal(
                    lambda: self._evaluate(discoveries={"confidence": value}),
                    "discoveries.confidence must be null or a finite number in [0, 1]",
                )
                with self.assertRaisesRegex(ValueError, r"discoveries\.confidence"):
                    progress._normalize_discoveries({"confidence": value})
        for value in (None, 0, 1, 0.91):
            with self.subTest(value=value):
                result = self._evaluate(discoveries={"confidence": value})
                self.assertEqual(result["steering"]["recommendation"]["confidence"], value)
                self.assertFalse(result["dispatch_authorized"])

    def test_zero_and_policy_fraction_boundaries(self):
        data = _plan()
        data["read_to_mutation_ratio"] = 0
        result = self._evaluate(
            plan=data, actual=_actual(runtime_seconds=0, projected_runtime_seconds=0),
            policy=_policy(
                early_warning_fraction_of_p50=1,
                realignment_fraction_of_hard=1,
                read_ratio_multiplier=0,
                read_ratio_floor=0,
            ),
        )
        self.assertEqual(result["outcome"], "continue")
        self.assertEqual(result["calibration"]["actual_read_to_mutation_ratio"], 2.0)
        json.dumps(result, allow_nan=False)
        for field in ("early_warning_fraction_of_p50", "realignment_fraction_of_hard"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "must be in"):
                    self._evaluate(policy=_policy(**{field: 0}))

    def test_huge_equal_and_finite_unequal_counter_ratios(self):
        for mutations, ratio in ((HUGE, 1.0), (HUGE // 2, 2.0)):
            with self.subTest(ratio=ratio):
                result = self._evaluate(
                    actual=_actual(context_reads=HUGE, mutations=mutations, tokens=HUGE)
                )
                self.assertEqual(result["actual"]["context_reads"], HUGE)
                self.assertEqual(result["actual"]["tokens"], HUGE)
                self.assertEqual(result["calibration"]["actual_read_to_mutation_ratio"], ratio)
                self.assertEqual(result["outcome"], "continue")
                self.assertFalse(result["dispatch_authorized"])
        result = self._evaluate(
            actual=_actual(context_reads=HUGE, mutations=10**3692)
        )
        self.assertEqual(result["calibration"]["actual_read_to_mutation_ratio"], 1e308)
        self.assertIn("read-to-mutation-ratio-exceeded", result["reasons"])
        self.assertEqual(result["pm_action"], "packet-refinement")
        self.assertFalse(result["dispatch_authorized"])

    def test_unrepresentable_counter_ratios_do_not_create_stop_authority(self):
        for mutations in (0, 1):
            with self.subTest(mutations=mutations):
                self._refusal(
                    lambda: self._evaluate(
                        actual=_actual(context_reads=HUGE, mutations=mutations),
                        discoveries={"control_loss": True},
                    ),
                    "calibration.actual_read_to_mutation_ratio must be a finite number >= 0.0",
                )

    def test_large_ceilings_preserve_counters_and_ordinary_rounding(self):
        for count, fraction, expected in (
            (10, 0.1, 1),
            (30, 0.6, 18),
            (HUGE, 0.0, 0),
            (HUGE, 0.5, HUGE // 2),
            (HUGE, 1.0, HUGE),
            ((1 << 1100), 2.0**-1022, 1 << 78),
        ):
            with self.subTest(fraction=fraction):
                self.assertEqual(progress._ceil_scaled_count(count, fraction), expected)
        data = _plan()
        data.update(tool_calls_p50=HUGE, tool_calls_p90=2 * HUGE, tool_calls_hard=3 * HUGE)
        for offset, outcome in ((-1, "continue"), (0, "early-warning")):
            with self.subTest(offset=offset):
                result = self._evaluate(
                    plan=data, actual=_actual(tool_calls=HUGE // 2 + offset, context_reads=4)
                )
                self.assertEqual(result["outcome"], outcome)
                self.assertFalse(result["dispatch_authorized"])

    def test_derived_limit_overflow_is_not_protected_stop_authority(self):
        data = _plan()
        data["read_to_mutation_ratio"] = sys.float_info.max
        self._refusal(
            lambda: self._evaluate(plan=data, discoveries={"model_mismatch": True}),
            "progress.read_ratio_limit must be a finite number >= 0.0",
        )

    def test_runtime_delta_refusal_and_representable_cancellation(self):
        data = _plan()
        for field in ("runtime_seconds_p50", "runtime_seconds_p90", "runtime_seconds_hard"):
            data[field] = HUGE
        self._refusal(
            lambda: self._evaluate(plan=data),
            "calibration.runtime_seconds_vs_p90 must be a finite number",
        )
        expected = 2 * int(sys.float_info.max)
        data.update(
            runtime_seconds_p50=0,
            runtime_seconds_p90=expected,
            runtime_seconds_hard=expected,
        )
        result = self._evaluate(
            plan=data,
            actual=_actual(
                runtime_seconds=sys.float_info.max, context_reads=1, mutations=1
            ),
        )
        self.assertEqual(
            result["calibration"]["runtime_seconds_vs_p90"], -sys.float_info.max
        )
        self.assertEqual(result["outcome"], "continue")
        self.assertTrue(math.isfinite(result["calibration"]["runtime_seconds_vs_p90"]))

    def test_large_snapshot_preserves_protected_stop_precedence(self):
        cases = (
            ({"model_mismatch": True}, {}, ["model-substitution"]),
            ({"control_loss": True}, {}, ["security-or-authority-change"]),
            ({"security_violation": True}, {}, ["security-or-authority-change"]),
            ({"authority_violation": True}, {}, ["security-or-authority-change"]),
            (
                {"mutation_attribution_ambiguous": True},
                {},
                ["tainted-mutation-acceptance"],
            ),
            ({"contradictory_validation": True}, {}, ["contradictory-validation"]),
            ({}, {"compactions": 1}, []),
            ({}, {"tool_calls": 30}, ["aggregate-budget-increase"]),
            ({}, {"runtime_seconds": 480}, ["aggregate-budget-increase"]),
        )
        for discoveries, updates, categories in cases:
            with self.subTest(discoveries=discoveries, updates=updates):
                observed = _actual(
                    context_reads=HUGE, mutations=HUGE, artifacts_completed=1,
                    validation_complete=True, **updates,
                )
                result = self._evaluate(
                    actual=observed,
                    discoveries={
                        "architecture_decision_attempted": True,
                        "new_work_class": True,
                        **discoveries,
                    },
                )
                self.assertEqual(result["outcome"], "protected-stop")
                self.assertEqual(result["pm_action"], "protected-stop")
                self.assertEqual(result["required_operator_change_types"], categories)
                self.assertFalse(result["dispatch_authorized"])
                self.assertEqual(result["stop_scope"], "child")
                self.assertEqual(result["authorized_continuation_paths"], [])
                progress.validate_progress_decision_for_productive_use(result)
                result["dispatch_authorized"] = True
                with self.assertRaisesRegex(ValueError, "cannot authorize dispatch"):
                    progress.validate_progress_decision_for_productive_use(result)


if __name__ == "__main__":
    unittest.main()

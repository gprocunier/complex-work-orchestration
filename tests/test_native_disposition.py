from __future__ import annotations

import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_disposition import derive_disposition, validate_disposition  # noqa: E402


MODEL = "gpt-5.3-codex-spark"
BUDGET = {
    "tool_calls_soft": 30,
    "tool_calls_hard": 50,
    "runtime_seconds_soft": 480,
    "runtime_seconds_hard": 720,
    "max_compactions": 0,
    "max_full_suite_runs": 1,
}


def usage(**overrides: int) -> dict[str, int]:
    result = {
        "tool_calls": 1,
        "elapsed_seconds": 1,
        "context_compactions": 0,
        "full_suite_runs": 0,
    }
    result.update(overrides)
    return result


class NativeDispositionTests(unittest.TestCase):
    def derive(self, status: str = "completed", **usage_overrides: int) -> dict:
        return derive_disposition(
            status=status,
            requested_model=MODEL,
            actual_model=MODEL,
            usage=usage(**usage_overrides),
            budget=BUDGET,
        )

    def test_clean_and_single_soft_limit(self) -> None:
        clean = self.derive()
        self.assertEqual(clean["session_disposition"], "accepted")
        self.assertEqual(clean["artifact_disposition"], "accepted")

        warning = self.derive(tool_calls=31)
        self.assertEqual(warning["session_disposition"], "accepted-with-warning")
        self.assertEqual(warning["artifact_disposition"], "accepted")

    def test_budget_only_overruns_allow_one_independent_validation(self) -> None:
        hard = self.derive("budget-exhausted", tool_calls=51)
        self.assertEqual(hard["session_disposition"], "quarantined")
        self.assertEqual(hard["artifact_disposition"], "independent-validation-required")
        self.assertTrue(hard["artifact_validation"]["eligible"])

        multi_soft = self.derive(
            "needs-architect-realignment",
            tool_calls=31,
            elapsed_seconds=481,
        )
        self.assertEqual(multi_soft["artifact_disposition"], "independent-validation-required")

    def test_nonbudget_realignment_requires_architect(self) -> None:
        result = self.derive("needs-architect-realignment")
        self.assertEqual(result["session_disposition"], "quarantined")
        self.assertEqual(result["artifact_disposition"], "architect-adjudication-required")

        claimed_validation = derive_disposition(
            status="needs-architect-realignment",
            requested_model=MODEL,
            actual_model=MODEL,
            usage=usage(),
            budget=BUDGET,
            validation={
                "eligible": False,
                "max_attempts": 1,
                "attempts_used": 1,
                "outcome": "passed",
                "reason": "not budget eligible",
            },
        )
        self.assertEqual(
            claimed_validation["artifact_disposition"],
            "architect-adjudication-required",
        )

    def test_model_mismatch_and_compaction_take_precedence(self) -> None:
        mismatch = derive_disposition(
            status="model-mismatch",
            requested_model=MODEL,
            actual_model="gpt-other",
            usage=usage(context_compactions=1, tool_calls=51),
            budget=BUDGET,
        )
        self.assertEqual(mismatch["artifact_disposition"], "rejected")

        compacted = self.derive("budget-exhausted", context_compactions=1, tool_calls=51)
        self.assertEqual(compacted["artifact_disposition"], "architect-adjudication-required")
        self.assertFalse(compacted["artifact_validation"]["eligible"])

    def test_independent_validation_passes_or_rejects_without_salvage(self) -> None:
        for outcome, artifact in (("passed", "accepted"), ("failed", "rejected")):
            result = derive_disposition(
                status="budget-exhausted",
                requested_model=MODEL,
                actual_model=MODEL,
                usage=usage(tool_calls=51),
                budget=BUDGET,
                validation={
                    "eligible": False,
                    "max_attempts": 1,
                    "attempts_used": 1,
                    "outcome": outcome,
                    "reason": "independent result",
                },
            )
            self.assertEqual(result["artifact_disposition"], artifact)
            self.assertFalse(result["artifact_validation"]["eligible"])

    def test_validator_rejects_second_attempt_and_inconsistent_disposition(self) -> None:
        packet = {"requested_model": MODEL, "budget": BUDGET}
        result = {
            "status": "budget-exhausted",
            "actual_model": MODEL,
            "usage": usage(tool_calls=51),
            "session_disposition": "accepted",
            "artifact_disposition": "accepted",
            "artifact_validation": {
                "eligible": False,
                "max_attempts": 1,
                "attempts_used": 2,
                "outcome": "passed",
                "reason": "invalid retry",
            },
        }
        errors = validate_disposition(packet=packet, result=result, required=True)
        self.assertTrue(any("attempts_used must be 0 or 1" in error for error in errors))
        self.assertTrue(any("session_disposition must be" in error for error in errors))

    def test_legacy_packet_can_omit_fields_but_partial_fields_fail(self) -> None:
        self.assertEqual(validate_disposition(packet={}, result={}, required=False), [])
        errors = validate_disposition(
            packet={},
            result={"session_disposition": "accepted"},
            required=False,
        )
        self.assertEqual(
            errors,
            ["session_disposition, artifact_disposition, and artifact_validation must be provided together"],
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import unittest
from unittest import mock

from cwo_core.native_capability import build_native_capability_receipt
from cwo_core.proportional_execution import (
    FAST_PATH_ROUTE,
    REQUIRED_STEPS,
    SKIPPED_HEAVY_GATES,
    STANDARD_ORCHESTRATION_ROUTE,
    evaluate_proportional_execution,
    immutable_task_sha256,
    immutable_task_payload,
)


MODEL = "gpt-5.3-codex-spark"
TOOL_SURFACE = "native-fast-path"
AT = "2026-07-14T12:00:00Z"
AT_LATER = "2026-07-14T13:00:00Z"
ISSUED = "2026-07-14T00:00:00Z"
EXPIRES = "2026-07-15T00:00:00Z"


def _brief() -> dict:
    return {
        "brief_type": "cwo-proportional-execution-brief",
        "version": 1,
        "identity": {"task_id": "task-1", "lane": "implementation"},
        "model": {"requested_model": MODEL},
        "tool_surface": {"surface": TOOL_SURFACE},
        "output_artifacts": [
            {
                "path": "out/ignored.html",
                "classification": "ignored",
                "tracked": False,
                "publishable": False,
            }
        ],
        "mutation_boundaries": {
            "tracked_source": False,
            "policy": False,
            "schema": False,
            "credential": False,
            "beads_database": False,
            "production": False,
        },
        "access_boundaries": {
            "privileged_access": False,
            "secrets": False,
            "external_disclosure": False,
            "network": False,
        },
        "deterministic_checks": ["sha256-check", "policy-shape"],
        "estimates": {
            "lines": 300,
            "tool_calls": 8,
            "runtime_seconds": 240,
        },
        "unresolved_decisions": {
            "architecture": [],
            "security": [],
            "policy": [],
        },
        "required_worker_capabilities": ["text", "json", "interrupt", "close", "wait"],
        "available_worker_capabilities": ["text", "json", "interrupt", "close", "wait", "image-input"],
        "visual_validation": {
            "owner": "none",
            "trusted_screenshots": [],
        },
        "validation_outputs": ["trusted-brief", "policy-gate"],
        "usage_breakdown": {
            "productive-artifact": {"tool_calls": 4, "elapsed_seconds": 60},
            "validation": {"tool_calls": 1, "elapsed_seconds": 20},
            "orchestration-setup": {"tool_calls": 1, "elapsed_seconds": 10},
            "harness-recovery": {"tool_calls": 0, "elapsed_seconds": 5},
        },
    }


def _receipt(tool_surface: str = TOOL_SURFACE) -> dict:
    evidence = {
        "requested_model": MODEL,
        "configured_model": MODEL,
        "advertised": False,
        "advertised_models": ["gpt-5.6-sol"],
        "spawn_accepted": True,
        "canary_session_id": "canary-1",
        "attestation_source": "trusted-session-jsonl",
        "attested_model": MODEL,
        "tool_calls": 0,
        "context_compactions": 0,
        "runtime_seconds": 1.0,
        "closure_receipt": True,
        "tool_surface_id": tool_surface,
    }
    return build_native_capability_receipt(evidence, [MODEL], ISSUED, EXPIRES)


def _evaluate(brief: dict, receipt: dict | None = None, at: str = AT) -> dict:
    return evaluate_proportional_execution(brief, _receipt() if receipt is None else receipt, at=at)


def _zero_usage() -> dict:
    return {
        bucket: {"tool_calls": 0, "elapsed_seconds": 0}
        for bucket in (
            "productive-artifact",
            "validation",
            "orchestration-setup",
            "harness-recovery",
        )
    }


class ProportionalExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch(
            "cwo_core.proportional_execution.containment_error",
            return_value="",
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_ignored_html_with_receipt_selects_fast_path(self) -> None:
        brief = _brief()
        result = _evaluate(brief)
        self.assertTrue(result["selected"])
        self.assertTrue(result["dispatchable"])
        self.assertTrue(result["selected_work_plan"])
        self.assertTrue(result["dispatch_required"])
        self.assertEqual(result["route"], FAST_PATH_ROUTE)
        self.assertEqual(result["reasons"], [])
        self.assertEqual(result["capability_action"], "reuse-existing")

    def test_missing_receipt_routes_to_standard_without_losing_selection(self) -> None:
        result = evaluate_proportional_execution(_brief(), at=AT)
        self.assertTrue(result["selected"])
        self.assertFalse(result["dispatchable"])
        self.assertFalse(result["selected_work_plan"])
        self.assertFalse(result["dispatch_required"])
        self.assertEqual(result["route"], STANDARD_ORCHESTRATION_ROUTE)
        self.assertEqual(result["reasons"], ["receipt-required"])

    def test_wrong_surface_receipt_routes_to_standard(self) -> None:
        result = _evaluate(_brief(), _receipt("different-surface"))
        self.assertTrue(result["selected"])
        self.assertFalse(result["dispatchable"])
        self.assertEqual(result["route"], STANDARD_ORCHESTRATION_ROUTE)
        self.assertEqual(result["reasons"], ["receipt-invalid"])

    def test_top_level_schema_is_exact(self) -> None:
        missing = _brief()
        missing.pop("identity")
        result = _evaluate(missing)
        self.assertFalse(result["selected"])
        self.assertIn("brief-missing-top-level-fields:identity", result["reasons"])

        extra = _brief()
        extra["assessed_at"] = AT
        result = _evaluate(extra)
        self.assertFalse(result["selected"])
        self.assertIn("brief-unknown-top-level-fields:assessed_at", result["reasons"])

    def test_nested_schemas_are_exact(self) -> None:
        cases = (
            ("identity", "task_id", "identity"),
            ("model", "requested_model", "model"),
            ("tool_surface", "surface", "tool-surface"),
            ("mutation_boundaries", "tracked_source", "mutation-boundaries"),
            ("access_boundaries", "network", "access-boundaries"),
            ("estimates", "lines", "estimates"),
            ("unresolved_decisions", "security", "unresolved-decisions"),
            ("visual_validation", "owner", "visual-validation"),
        )
        for section, required_key, label in cases:
            with self.subTest(section=section):
                brief = _brief()
                brief[section].pop(required_key)
                brief[section]["unexpected"] = False
                result = _evaluate(brief)
                self.assertIn(f"{label}-missing-fields:{required_key}", result["reasons"])
                self.assertIn(f"{label}-unknown-fields:unexpected", result["reasons"])

        artifact = _brief()
        artifact["output_artifacts"][0].pop("path")
        artifact["output_artifacts"][0]["unexpected"] = False
        result = _evaluate(artifact)
        self.assertIn("output-artifact-missing-fields:path", result["reasons"])
        self.assertIn("output-artifact-unknown-fields:unexpected", result["reasons"])

    def test_artifact_path_classification_and_publication_boundaries_reject(self) -> None:
        cases = (
            ("tracked", True, "output-artifact-must-be-unpublishable-and-untracked"),
            ("publishable", True, "output-artifact-must-be-unpublishable-and-untracked"),
            ("classification", "public", "output-artifact-classification-invalid"),
            ("path", "../public.html", "output-artifact-path-path-traversal-or-empty-segment"),
            ("path", "/tmp/public.html", "output-artifact-path-must-be-relative"),
        )
        for key, value, reason in cases:
            with self.subTest(key=key, value=value):
                brief = _brief()
                brief["output_artifacts"][0][key] = value
                result = _evaluate(brief)
                self.assertFalse(result["dispatchable"])
                self.assertEqual(result["route"], STANDARD_ORCHESTRATION_ROUTE)
                self.assertIn(reason, result["reasons"])

    def test_true_mutation_and_access_boundaries_reject(self) -> None:
        for section in ("mutation_boundaries", "access_boundaries"):
            for key in _brief()[section]:
                with self.subTest(section=section, key=key):
                    brief = _brief()
                    brief[section][key] = True
                    result = _evaluate(brief)
                    self.assertFalse(result["dispatchable"])
                    self.assertIn(f"{section}-{key}-must-be-false", result["reasons"])

    def test_unresolved_decisions_reject(self) -> None:
        for key in ("architecture", "security", "policy"):
            with self.subTest(key=key):
                brief = _brief()
                brief["unresolved_decisions"][key] = ["decision-needed"]
                result = _evaluate(brief)
                self.assertFalse(result["dispatchable"])
                self.assertIn(f"unresolved-{key}-must-be-empty-list", result["reasons"])

    def test_required_capabilities_must_be_available(self) -> None:
        brief = _brief()
        brief["required_worker_capabilities"].append("shell")
        result = _evaluate(brief)
        self.assertFalse(result["dispatchable"])
        self.assertIn("required-capabilities-missing:shell", result["reasons"])

    def test_worker_visual_without_image_input_is_rejected_before_dispatch(self) -> None:
        brief = _brief()
        brief["visual_validation"]["owner"] = "worker"
        brief["available_worker_capabilities"] = ["text", "json", "interrupt", "close", "wait"]
        result = _evaluate(brief)
        self.assertFalse(result["dispatchable"])
        self.assertIn("worker-visual-validation-requires-image-input", result["reasons"])
        self.assertNotIn("required-capabilities-missing:image-input", result["reasons"])

    def test_worker_cannot_consume_trusted_screenshots(self) -> None:
        brief = _brief()
        brief["visual_validation"]["owner"] = "worker"
        brief["visual_validation"]["trusted_screenshots"] = ["pm-only.png"]
        result = _evaluate(brief)
        self.assertFalse(result["dispatchable"])
        self.assertIn("trusted-screenshots-not-allowed-for-worker-owner", result["reasons"])

    def test_pm_visual_trusted_screenshots_allows_fast_path(self) -> None:
        brief = _brief()
        brief["visual_validation"]["owner"] = "pm"
        brief["visual_validation"]["trusted_screenshots"] = ["pm-review.png"]
        brief["available_worker_capabilities"] = ["text", "json", "interrupt", "close", "wait"]
        result = _evaluate(brief)
        self.assertTrue(result["dispatchable"])
        self.assertTrue(result["pm_visual_adjudication_required"])
        self.assertEqual(result["reasons"], [])

    def test_evaluation_is_pure(self) -> None:
        brief = _brief()
        before = copy.deepcopy(brief)
        _evaluate(brief)
        self.assertEqual(brief, before)

    def test_generated_fields_and_assessment_time_do_not_affect_hash(self) -> None:
        first = _brief()
        second = copy.deepcopy(first)
        second["validation_outputs"] = ["different-validation"]
        second["usage_breakdown"]["productive-artifact"] = {
            "tool_calls": 11,
            "elapsed_seconds": 599,
        }
        second["visual_validation"]["trusted_screenshots"] = ["screenshot-1.png"]
        second["assessed_at"] = "2099-01-01T00:00:00Z"

        self.assertEqual(immutable_task_sha256(first), immutable_task_sha256(second))
        self.assertEqual(immutable_task_payload(first), immutable_task_payload(second))
        first_result = _evaluate(first, at=AT)
        second.pop("assessed_at")
        second_result = _evaluate(second, at=AT_LATER)
        self.assertEqual(first_result["immutable_task_sha256"], second_result["immutable_task_sha256"])
        self.assertNotEqual(first_result["assessed_at"], second_result["assessed_at"])

    def test_usage_buckets_are_exact_and_separate(self) -> None:
        result = _evaluate(_brief())
        usage = result["normalized_usage"]
        self.assertEqual(
            set(usage),
            {"productive-artifact", "validation", "orchestration-setup", "harness-recovery"},
        )
        self.assertEqual(usage["productive-artifact"], {"tool_calls": 4, "elapsed_seconds": 60})
        self.assertEqual(usage["validation"], {"tool_calls": 1, "elapsed_seconds": 20})
        self.assertEqual(usage["orchestration-setup"], {"tool_calls": 1, "elapsed_seconds": 10})
        self.assertEqual(usage["harness-recovery"], {"tool_calls": 0, "elapsed_seconds": 5})

    def test_invalid_usage_fails_closed_with_zero_buckets(self) -> None:
        brief = _brief()
        brief["usage_breakdown"]["validation"]["unexpected"] = 1
        brief["usage_breakdown"]["productive-artifact"]["tool_calls"] = "four"
        result = _evaluate(brief)
        self.assertFalse(result["usage_breakdown_valid"])
        self.assertFalse(result["dispatchable"])
        self.assertEqual(result["normalized_usage"], _zero_usage())
        self.assertIn("usage-bucket-validation-unknown-fields:unexpected", result["reasons"])
        self.assertIn(
            "usage-bucket-productive-artifact-tool-calls-nonnegative-int",
            result["reasons"],
        )

    def test_required_and_skipped_steps_are_frozen(self) -> None:
        result = _evaluate(_brief())
        self.assertEqual(
            REQUIRED_STEPS,
            [
                "validate-proportional-brief",
                "evaluate-required-boundaries",
                "evaluate-usage-breakdown",
                "evaluate-visual-adjudication",
                "emit-immutable-task-evidence",
            ],
        )
        self.assertEqual(
            SKIPPED_HEAVY_GATES,
            [
                "scheduler-delay-canary",
                "tool-use-canary",
                "non-essential-policy-checks",
            ],
        )
        self.assertEqual(result["required_steps"], REQUIRED_STEPS)
        self.assertEqual(result["skipped_steps"], SKIPPED_HEAVY_GATES)


if __name__ == "__main__":
    unittest.main()

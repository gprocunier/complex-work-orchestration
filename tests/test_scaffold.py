from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import NamedTuple
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.coach import coach_orchestration_prompt  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402
from tests.historical_policy_fixtures import historical_v2_policy  # noqa: E402
from cwo_core.synthesis import recommend_model_synthesis  # noqa: E402
from scaffold_workgraph import (  # noqa: E402
    _normalize_closure_pressure,
    planned_graph,
    recovery_summary,
    try_dep,
)


def ancestors(by_lane: dict[object, dict[str, object]], lane: str) -> set[str]:
    """Every lane that must finish before ``lane`` can start."""
    seen: set[str] = set()
    pending = list(by_lane[lane].get("depends_on_lanes", []))
    while pending:
        dependency = pending.pop()
        name = dependency if isinstance(dependency, str) else str(dependency.get("lane"))
        if name in seen or name not in by_lane:
            continue
        seen.add(name)
        pending.extend(by_lane[name].get("depends_on_lanes", []))
    return seen


def live_spark_capability_evidence() -> dict[str, object]:
    return {
        "source": "trusted-control-plane-session-metadata",
        "observed_at": "2026-09-03T12:00:00Z",
        "fresh": True,
        "spark": {
            "model": "gpt-5.3-codex-spark",
            "exact_model_available": True,
            "quota_status": "usable",
            "capacity_status": "available",
            "fresh_session_supported": True,
            "exact_model_attestation_supported": True,
            "lifecycle_controls": ["interrupt", "close", "wait"],
            "workspace_enforced": True,
            "mutation_enforced": True,
        },
    }


class CoachStopCase(NamedTuple):
    original: str
    prompt: str
    mismatch: bool
    failed_check: str


class ScaffoldTests(unittest.TestCase):
    def assert_native_fields(self, item: dict[str, object]) -> None:
        self.assertTrue(item.get("skills"), item.get("title"))
        self.assertTrue(item.get("acceptance"), item.get("title"))
        self.assertTrue(item.get("design"), item.get("title"))
        self.assertTrue(item.get("notes"), item.get("title"))

    def assert_hard_stop_workerbee_metadata(
        self,
        item: dict[str, object],
        expected_dispatch: dict[str, object],
        *,
        expected_registry_tool_mismatch: bool = True,
    ) -> None:
        metadata = item["metadata"]
        self.assertEqual(metadata.get("workerbee_planned_mode"), "blocked")
        self.assertEqual(metadata.get("workerbee_planned_model"), "")
        self.assertEqual(metadata.get("workerbee_planned_lanes"), [])
        self.assertEqual(metadata.get("workerbee_operational_owner"), "")
        self.assertIs(
            metadata.get("workerbee_registry_tool_mismatch"),
            expected_registry_tool_mismatch,
        )
        self.assertIs(metadata.get("spark_operational_worker"), False)
        self.assertEqual(
            metadata.get("workerbee_planned_delegation"),
            {"mode": "blocked", "model": None, "lanes": []},
        )
        self.assertEqual(metadata.get("workerbee_spark_dispatch"), expected_dispatch)
        self.assertNotIn("no-sol-exec", item["labels"])
        self.assertNotIn("spark-operative-owner", item["labels"])

    def test_closure_pressure_requires_disposition_and_rejects_routine_child(self) -> None:
        route = classify_work("Implement one bounded internal change.")
        with self.assertRaisesRegex(ValueError, "explicit-closure-disposition-required"):
            planned_graph(
                "Closure missing disposition",
                {
                    **route,
                    "closure_pressure": {
                        "active": True,
                        "action": "continue-current-work-unit",
                        "disposition": None,
                    },
                },
            )
        with self.assertRaisesRegex(ValueError, "routine-repair-child-rejected"):
            planned_graph(
                "Closure routine child",
                {
                    **route,
                    "closure_pressure": {
                        "active": True,
                        "action": "create-routine-repair-child",
                        "disposition": "correct",
                    },
                },
            )

    def test_closure_pressure_propagates_every_canonical_disposition(self) -> None:
        route = classify_work("Implement one bounded internal change.")
        for disposition in ["retain", "correct", "quarantine", "defer", "close"]:
            with self.subTest(disposition=disposition):
                graph = planned_graph(
                    f"Closure {disposition}",
                    {
                        **route,
                        "closure_pressure": {
                            "active": True,
                            "action": "continue-current-work-unit",
                            "disposition": disposition,
                        },
                    },
                )
                self.assertTrue(graph)
                for item in graph:
                    metadata = item["metadata"]
                    self.assertTrue(metadata["closure_pressure_active"])
                    self.assertTrue(metadata["routine_repair_child_forbidden"])
                    self.assertEqual(metadata["closure_pressure"]["disposition"], disposition)
                    self.assertTrue(metadata["closure_pressure"]["allowed"])

    def test_inactive_closure_pressure_is_backward_compatible(self) -> None:
        decision = _normalize_closure_pressure({})
        self.assertFalse(decision["active"])
        self.assertTrue(decision["allowed"])
        graph = planned_graph("Inactive closure", classify_work("Review one internal change."))
        for item in graph:
            self.assertFalse(item["metadata"]["closure_pressure_active"])
            self.assertFalse(item["metadata"]["routine_repair_child_forbidden"])

    def test_closure_pressure_cli_fails_before_creation_and_accepts_disposition(self) -> None:
        command = [
            sys.executable,
            str(ROOT / "scripts" / "scaffold_workgraph.py"),
            "--title",
            "Closure CLI",
            "--description",
            "Implement one bounded internal change.",
            "--dry-run",
            "--format",
            "cwo",
            "--closure-pressure-active",
        ]
        rejected = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("explicit-closure-disposition-required", rejected.stderr)

        accepted = subprocess.run(
            [*command, "--closure-disposition", "correct"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        graph = json.loads(accepted.stdout)
        self.assertTrue(graph[0]["metadata"]["closure_pressure_active"])
        self.assertEqual(graph[0]["metadata"]["closure_pressure"]["disposition"], "correct")

    def assert_coach_hard_stop_graph(
        self,
        prompt: str,
        *,
        expected_registry_tool_mismatch: bool,
        expected_failed_check: str,
    ) -> None:
        coach_result = coach_orchestration_prompt(prompt)
        planned = coach_result["workerbee_planned_delegation"]
        self.assertTrue(planned["hard_stop"])
        self.assertEqual(planned["mode"], "blocked")
        self.assertIsNone(planned["model"])
        self.assertEqual(planned["lanes"], [])
        self.assertIs(
            planned["registry_tool_mismatch"],
            expected_registry_tool_mismatch,
        )
        expected_dispatch = planned["spark_dispatch"]
        self.assertEqual(expected_dispatch["status"], "hard-stop")
        self.assertEqual(
            expected_dispatch["failed_native_capability_check"],
            expected_failed_check,
        )

        graph = planned_graph("Coach Hard Stop Example", coach_result["route"])
        for item in graph:
            if item.get("type") == "epic":
                continue
            with self.subTest(lane=item.get("lane")):
                self.assert_hard_stop_workerbee_metadata(
                    item,
                    expected_dispatch,
                    expected_registry_tool_mismatch=expected_registry_tool_mismatch,
                )

    def test_planned_graph_populates_native_beads_fields_for_every_item(self) -> None:
        route = classify_work(
            "Architecture and documentation review for Beads workgraph behavior.",
            requested_roles=["architecture", "documentation"],
        )
        graph = planned_graph("Field Example", route)
        for item in graph:
            with self.subTest(title=item["title"]):
                self.assert_native_fields(item)
                if item.get("type") != "epic":
                    metadata = item.get("metadata")
                    self.assertIsInstance(metadata, dict)
                    planned = metadata.get("workerbee_planned_delegation")
                    self.assertIsInstance(planned, dict)
                    self.assertIn("mode", planned)
                    self.assertIn("model", planned)
                    self.assertIn("lanes", planned)

    def test_workerbee_planned_metadata_from_route_is_preserved_and_deduped_in_lanes(self) -> None:
        route = classify_work(
            "Policy routing and terminology review for public docs and tests.",
            requested_roles=["documentation"],
        )
        route["workerbee_planned_delegation"] = {
            "mode": "review-only",
            "model": "gpt-5.3-codex-spark",
            "lanes": ["policy-routing-review", "policy-routing-review", "", "publish-sanitization-review"],
            "spark_dispatch": {
                "status": "native-first",
                "requested_model": "gpt-5.3-codex-spark",
                "requested_route": "review-only",
                "failed_native_capability_check": "",
                "failed_native_capability_check_justification": "",
                "obsolete_field": "retired-route",
            },
        }
        graph = planned_graph("Field Example", route)
        expected_lanes = ["policy-routing-review", "publish-sanitization-review"]
        expected_dispatch = {
            "status": "native-first",
            "requested_model": "gpt-5.3-codex-spark",
            "requested_route": "review-only",
            "failed_native_capability_check": "",
            "failed_native_capability_check_justification": "",
        }
        for item in graph:
            if item.get("type") == "epic":
                continue
            planned = item.get("metadata", {}).get("workerbee_planned_delegation")
            self.assertEqual(planned.get("mode"), "review-only")
            self.assertEqual(planned.get("model"), "gpt-5.3-codex-spark")
            self.assertEqual(planned.get("lanes"), expected_lanes)
            self.assertEqual(item.get("metadata", {}).get("workerbee_planned_mode"), "review-only")
            self.assertEqual(item.get("metadata", {}).get("workerbee_planned_model"), "gpt-5.3-codex-spark")
            self.assertEqual(item.get("metadata", {}).get("workerbee_planned_lanes"), expected_lanes)
            self.assertEqual(
                item.get("metadata", {}).get("workerbee_spark_dispatch"),
                expected_dispatch,
            )
            self.assertNotIn(
                "obsolete_field",
                item.get("metadata", {}).get("workerbee_spark_dispatch", {}),
            )

    @historical_v2_policy()
    def test_operational_lanes_get_spark_owner_metadata_and_labels(self) -> None:
        route = classify_work(
            "Refactor docs, implementation, and validation with Codex 5.6 Sol and Codex 5.3 Spark roles.",
            requested_roles=["architecture", "documentation", "implementation"],
            operative_capabilities=live_spark_capability_evidence(),
            operative_evaluated_at="2026-09-03T12:00:00Z",
        )
        route["workerbee_planned_delegation"] = {
            "mode": "implementation-capable",
            "model": "gpt-5.3-codex-spark",
            "lanes": ["implementation", "test-construction", "validation-troubleshooting", "docs-reporting-dashboard"],
            "spark_operational_worker": True,
            "spark_dispatch": {
                "status": "native-first",
                "requested_route": "implementation-capable",
                "requested_model": "gpt-5.3-codex-spark",
                "failed_native_capability_check": "",
                "failed_native_capability_check_justification": "",
            },
        }
        graph = planned_graph("Operative Role Example", route)
        by_lane = {item.get("lane"): item for item in graph}

        operative_lanes = {"implementation", "validation", "docs", "wrap-up-report", "dashboard-report"}
        for lane in operative_lanes:
            item = by_lane.get(lane)
            self.assertIsNotNone(item)
            metadata = item["metadata"]
            self.assertEqual(metadata.get("workerbee_planned_mode"), "implementation-capable")
            self.assertEqual(metadata.get("workerbee_planned_model"), "gpt-5.3-codex-spark")
            self.assertEqual(metadata.get("workerbee_operational_owner"), "spark")
            self.assertIn("no-sol-exec", item["labels"])
            self.assertIn("spark-operative-owner", item["labels"])

        self.assertNotIn("no-sol-exec", by_lane["architect"]["labels"])
        self.assertNotIn("spark-operative-owner", by_lane["architect"]["labels"])
        self.assertEqual(by_lane["architect"]["metadata"].get("workerbee_operational_owner"), "")
        if "architect-adjudication" in by_lane:
            self.assertEqual(
                by_lane["architect-adjudication"]["metadata"].get("workerbee_operational_owner"),
                "",
            )
        if "publish-sanitization" in by_lane:
            self.assertEqual(by_lane["publish-sanitization"]["metadata"].get("workerbee_operational_owner"), "spark")

    @historical_v2_policy()
    def test_native_first_route_assigns_spark_operational_metadata_to_operative_lanes(self) -> None:
        route = classify_work(
            "Implement a small helper and verify tests with Spark-native dispatch.",
            requested_roles=["implementation", "documentation", "validation"],
            operative_capabilities=live_spark_capability_evidence(),
            operative_evaluated_at="2026-09-03T12:00:00Z",
        )
        route["workerbee_planned_delegation"] = {
            "mode": "implementation-capable",
            "model": "gpt-5.3-codex-spark",
            "lanes": ["implementation", "validation", "docs", "wrap-up-report", "dashboard-report"],
            "spark_operational_worker": True,
            "spark_dispatch": {
                "status": "native-first",
                "requested_route": "implementation-capable",
                "requested_model": "gpt-5.3-codex-spark",
                "failed_native_capability_check": "",
                "failed_native_capability_check_justification": "",
            },
        }
        graph = planned_graph("Native First Example", route)
        by_lane = {item.get("lane"): item for item in graph}

        operative_lanes = {"implementation", "validation", "docs", "wrap-up-report", "dashboard-report"}
        for lane in operative_lanes:
            item = by_lane[lane]
            self.assertEqual(item["metadata"].get("workerbee_operational_owner"), "spark")
            self.assertIn("no-sol-exec", item["labels"])
            self.assertIn("spark-operative-owner", item["labels"])
            self.assertEqual(item["metadata"].get("workerbee_planned_mode"), "implementation-capable")
            self.assertEqual(item["metadata"].get("workerbee_planned_model"), "gpt-5.3-codex-spark")

    def test_hard_stop_route_normalizes_every_lane_workerbee_metadata(self) -> None:
        trigger_cases = [
            ("planned-hard-stop", True, "native-first"),
            ("dispatch-hard-stop", False, "hard-stop"),
        ]
        for case_name, planned_hard_stop, dispatch_status in trigger_cases:
            with self.subTest(trigger=case_name):
                route = classify_work(
                    "Architectural change with Spark dispatch hard-stop required before implementation.",
                    requested_roles=["implementation", "documentation", "validation"],
                )
                expected_dispatch = {
                    "status": dispatch_status,
                    "requested_model": "gpt-5.3-codex-spark",
                    "requested_route": "implementation-capable",
                    "failed_native_capability_check": "spark-registry-tool-mismatch",
                    "failed_native_capability_check_justification": (
                        "Registry/tool mismatch blocks native Spark worker dispatch."
                    ),
                }
                route["workerbee_planned_delegation"] = {
                    "mode": "implementation-capable",
                    "model": "gpt-5.3-codex-spark",
                    "lanes": ["implementation", "validation", "docs", "wrap-up-report", "dashboard-report"],
                    "spark_operational_worker": True,
                    "hard_stop": planned_hard_stop,
                    "spark_dispatch": {**expected_dispatch, "obsolete_field": "retired-route"},
                }
                graph = planned_graph("Hard Stop Example", route)
                for item in graph:
                    if item.get("type") == "epic":
                        continue
                    with self.subTest(trigger=case_name, lane=item.get("lane")):
                        self.assert_hard_stop_workerbee_metadata(
                            item,
                            expected_dispatch,
                            expected_registry_tool_mismatch=False,
                        )

                architecture = next(item for item in graph if item.get("lane") == "architect")
                self.assertIn(f"status={dispatch_status}", architecture["notes"])
                self.assertIn("requested_route=implementation-capable", architecture["notes"])
                self.assertIn("failed_check=spark-registry-tool-mismatch", architecture["notes"])

    def test_registry_tool_mismatch_overrides_native_first_metadata(self) -> None:
        route = classify_work(
            "Implement with native Spark despite contradictory registry metadata.",
            requested_roles=["implementation", "documentation", "validation"],
        )
        expected_dispatch = {
            "status": "native-first",
            "requested_model": "gpt-5.3-codex-spark",
            "requested_route": "implementation-capable",
            "failed_native_capability_check": "spark-registry-tool-mismatch",
            "failed_native_capability_check_justification": (
                "Registry/tool mismatch overrides executable route metadata."
            ),
        }
        route["workerbee_planned_delegation"] = {
            "mode": "implementation-capable",
            "model": "gpt-5.3-codex-spark",
            "lanes": ["implementation", "validation", "docs", "wrap-up-report", "dashboard-report"],
            "spark_operational_worker": True,
            "hard_stop": False,
            "registry_tool_mismatch": True,
            "spark_dispatch": expected_dispatch,
        }

        graph = planned_graph("Registry Mismatch Example", route)
        for item in graph:
            if item.get("type") == "epic":
                continue
            with self.subTest(lane=item.get("lane")):
                self.assert_hard_stop_workerbee_metadata(item, expected_dispatch)

    @historical_v2_policy()
    def test_real_coach_hard_stop_graph_rows(self) -> None:
        rows = (
            CoachStopCase('test_real_coach_native_tool_unavailable_preserves_non_mismatch_hard_stop', "Plan docs work. Native Spark tooling is unavailable.", False, "spark-native-tool-absence"),
            CoachStopCase('test_real_coach_registry_tool_mismatch_preserves_mismatch_hard_stop', "There is a Spark registry/tool mismatch for this task.", True, "spark-registry-tool-mismatch"),
        )
        for row in rows:
            with self.subTest(original=row.original):
                self.assert_coach_hard_stop_graph(row.prompt, expected_registry_tool_mismatch=row.mismatch,
                                                 expected_failed_check=row.failed_check)

    @historical_v2_policy()
    def test_spark_operational_metadata_does_not_infect_architect_and_model_synthesis_lanes(self) -> None:
        text = (
            "Architect a high-risk public docs migration, with Sol routing as architect and Spark as implementation worker. "
            "Use model synthesis with Claude Opus and Gemini for independent second opinions."
        )
        route = classify_work(
            text,
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture", "documentation", "implementation"],
            operative_capabilities=live_spark_capability_evidence(),
            operative_evaluated_at="2026-09-03T12:00:00Z",
        )
        route = {**route, "model_synthesis": recommend_model_synthesis(text, route)}
        route["workerbee_planned_delegation"] = {
            "mode": "implementation-capable",
            "model": "gpt-5.3-codex-spark",
            "lanes": [
                "implementation",
                "validation",
                "docs",
                "wrap-up-report",
                "dashboard-report",
            ],
            "spark_operational_worker": True,
            "spark_dispatch": {
                "status": "native-first",
                "requested_route": "implementation-capable",
                "requested_model": "gpt-5.3-codex-spark",
                "failed_native_capability_check": "",
                "failed_native_capability_check_justification": "",
            },
        }
        graph = planned_graph("Isolation Example", route)
        by_lane = {item.get("lane"): item for item in graph}

        for lane in ["architect", "architect-adjudication", "model-synthesis"]:
            item = by_lane.get(lane)
            self.assertIsNotNone(item)
            self.assertEqual(item["metadata"].get("workerbee_operational_owner"), "")
            self.assertNotIn("no-sol-exec", item["labels"])
            self.assertNotIn("spark-operative-owner", item["labels"])

        for lane in ["implementation", "validation", "docs", "wrap-up-report", "dashboard-report"]:
            item = by_lane.get(lane)
            if item is not None:
                self.assertEqual(item["metadata"].get("workerbee_operational_owner"), "spark")
                self.assertIn("no-sol-exec", item["labels"])
                self.assertIn("spark-operative-owner", item["labels"])


    def test_dependency_creation_fails_closed(self) -> None:
        with patch("scaffold_workgraph.add_dependency", side_effect=RuntimeError("dependency failure")):
            with self.assertRaises(SystemExit) as context:
                try_dep("blocked-bead", "blocker-bead")
        self.assertIn("could not add dependency blocked-bead -> blocker-bead", str(context.exception))

    def test_external_route_adds_evaluation_and_adjudication(self) -> None:
        route = classify_work(
            "Security review redacted packet behavior.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security"],
        )
        graph = planned_graph("Example", route)
        by_lane = {item.get("lane"): item for item in graph}
        lanes = set(by_lane)
        if route["route"] in ["external-contract", "local-worker"]:
            self.assertIn("evaluation", lanes)
            self.assertIn("architect-adjudication", lanes)
            self.assertIn("architect-adjudication", by_lane["implementation"]["depends_on_lanes"])
            external_review_lanes = [
                item["lane"]
                for item in graph
                if item.get("metadata", {}).get("codex_pickup") == "forbidden"
            ]
            for lane in external_review_lanes:
                self.assertIn(lane, by_lane["evaluation"]["depends_on_lanes"])

    def test_local_worker_route_marks_expert_reviews_forbidden_to_codex_pickup(self) -> None:
        route = classify_work(
            "Documentation review for short internal example notes.",
            requested_roles=["documentation"],
            share_boundary="no-outside-sharing",
            local_ok=True,
            prefer_local=True,
        )
        graph = planned_graph("Local Example", route)
        by_lane = {item.get("lane"): item for item in graph}
        local_review_lanes = [
            item["lane"]
            for item in graph
            if item.get("metadata", {}).get("selected_executor", {}).get("dispatch_mode") == "local_openai_compatible"
        ]
        self.assertTrue(local_review_lanes)
        self.assertIn("evaluation", by_lane)
        self.assertIn("architect-adjudication", by_lane)
        self.assertEqual(by_lane["external-dispatch"]["metadata"]["codex_pickup"], "forbidden")
        self.assertIn("local-worker-only", by_lane["external-dispatch"]["labels"])
        self.assertIn("no-codex-exec", by_lane["external-dispatch"]["labels"])
        for lane in local_review_lanes:
            item = by_lane[lane]
            self.assertEqual(item["metadata"]["codex_pickup"], "forbidden")
            self.assertTrue(item["metadata"]["acceptance_bead_required"])
            self.assertIn("local-worker-only", item["labels"])
            self.assertIn("no-codex-exec", item["labels"])
            # A final-stage review examines the finished content, so its return
            # is evaluated after implementation and docs, not before them.
            final_stage = item["metadata"].get("review_stage") in ("pre-validation", "pre-release")
            self.assertIn(lane, ancestors(by_lane, "final-evaluation" if final_stage else "evaluation"))
            if final_stage:
                self.assertIn("local-worker-only", by_lane["final-dispatch"]["labels"])
                self.assertEqual(by_lane["final-dispatch"]["metadata"]["codex_pickup"], "forbidden")
        self.assertIn("architect-adjudication", by_lane["implementation"]["depends_on_lanes"])

    def test_dual_architecture_critics_create_independent_contractor_lanes(self) -> None:
        route = classify_work(
            "Use Claude Opus 4.6 and Gemini 3.1 Pro Preview as independent second opinion critics "
            "of the Codex architect design for a cross-cutting public contract architecture migration.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture"],
        )
        graph = planned_graph("Dual Critic Example", route)
        by_lane = {item.get("lane"): item for item in graph}

        claude_lane = "expert-review-architecture-critic-claude-architecture-critic"
        gemini_lane = "expert-review-architecture-critic-gemini-architecture-critic"
        self.assertIn(claude_lane, by_lane)
        self.assertIn(gemini_lane, by_lane)
        self.assertIn(claude_lane, by_lane["evaluation"]["depends_on_lanes"])
        self.assertIn(gemini_lane, by_lane["evaluation"]["depends_on_lanes"])
        self.assertNotIn("expert-review-architecture", by_lane)
        self.assertEqual(by_lane[claude_lane]["metadata"]["codex_pickup"], "forbidden")
        self.assertEqual(by_lane[gemini_lane]["metadata"]["codex_pickup"], "forbidden")
        self.assertEqual(
            by_lane[claude_lane]["metadata"]["architecture_critic_contract"]["manual_command"],
            "claude --model claude-opus-4-6 --effort xhigh -p",
        )

    def test_closed_critic_panel_creates_only_authorized_synthesis_inputs(self) -> None:
        route = classify_work(
            "Use Claude Opus and GLM as architecture critics with model synthesis. "
            "The critic panel is closed to those two providers. "
            "Do not add Gemini or ChatGPT Pro.",
            external_ok=True,
            local_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture"],
            model_synthesis=True,
        )
        graph = planned_graph("Closed Critic Panel", route)
        by_lane = {item.get("lane"): item for item in graph}
        claude_lane = "expert-review-architecture-critic-claude-architecture-critic"
        glm_lane = (
            "expert-review-architecture-critic-"
            "rhoai-glm-hardened-architecture-critic"
        )

        critic_lanes = sorted(
            lane
            for lane in by_lane
            if str(lane).startswith("expert-review-architecture-critic-")
        )
        self.assertEqual(critic_lanes, sorted([claude_lane, glm_lane]))
        self.assertIn(claude_lane, by_lane["evaluation"]["depends_on_lanes"])
        self.assertIn(glm_lane, by_lane["evaluation"]["depends_on_lanes"])
        self.assertEqual(
            by_lane["model-synthesis"]["depends_on_lanes"],
            ["evaluation"],
        )
        self.assertEqual(
            [
                item["executor"]
                for item in by_lane["model-synthesis"]["metadata"][
                    "model_synthesis"
                ]["recommended_panel"]
            ],
            [
                "frontier_architect",
                "claude_architecture_critic",
                "rhoai_glm_hardened_architecture_critic",
            ],
        )

    def test_single_claude_critic_direct_adjudication_omits_synthesis_lane(self) -> None:
        route = classify_work(
            "Use Claude Opus as only external architecture critic. "
            "No Gemini/Agy. No GLM. "
            "Do not use model synthesis; direct adjudication.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture"],
        )
        graph = planned_graph("Direct Adjudication Example", route)
        by_lane = {item.get("lane"): item for item in graph}
        critic_lanes = sorted(
            lane
            for lane in by_lane
            if str(lane).startswith("expert-review-architecture-critic-")
        )
        claude_lane = "expert-review-architecture-critic-claude-architecture-critic"

        self.assertEqual(critic_lanes, [claude_lane])
        self.assertNotIn("model-synthesis", by_lane)
        self.assertIn(claude_lane, by_lane["evaluation"]["depends_on_lanes"])
        self.assertEqual(
            by_lane["architect-adjudication"]["depends_on_lanes"],
            ["evaluation"],
        )
        self.assertIn(
            "architect-adjudication",
            by_lane["implementation"]["depends_on_lanes"],
        )

    def test_chatgpt_pro_master_review_is_blocking_gate(self) -> None:
        route = classify_work(
            "Use ChatGPT Pro 5.5 Extended Reasoning as a master plan reviewer for the final execution plan and total work packet.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["master-plan-review"],
        )
        graph = planned_graph("ChatGPT Gate Example", route)
        by_lane = {item.get("lane"): item for item in graph}
        lane = "expert-review-master-plan-review"

        self.assertIn(lane, by_lane)
        self.assertTrue(by_lane[lane]["metadata"]["blocking_review_required"])
        self.assertTrue(by_lane[lane]["metadata"]["blocking_review_active"])
        self.assertTrue(by_lane[lane]["metadata"]["blocking_review_waiver_required"])
        self.assertEqual(
            by_lane[lane]["metadata"]["blocking_review_failure_behavior"],
            "stop-before-implementation-unless-explicit-operator-waiver",
        )
        self.assertIn(lane, by_lane["evaluation"]["depends_on_lanes"])
        self.assertEqual(by_lane["architect-adjudication"]["depends_on_lanes"], ["evaluation"])
        self.assertIn("architect-adjudication", by_lane["implementation"]["depends_on_lanes"])
        self.assertIn("Blocking review gate: chatgpt-pro-5.5-master-plan-review", by_lane[lane]["notes"])

    def test_tight_scaffold_limits_optional_expert_fanout(self) -> None:
        route = classify_work(
            "Security and web design review for contractor packet behavior.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security", "web-design"],
        )
        full_graph = planned_graph("Full Review", route)
        tight_graph = planned_graph("Tight Review", route, scaffold_size="tight")
        full_expert_lanes = [item["lane"] for item in full_graph if item.get("metadata", {}).get("expert")]
        tight_expert_lanes = [item["lane"] for item in tight_graph if item.get("metadata", {}).get("expert")]
        tight_by_lane = {item.get("lane"): item for item in tight_graph}

        self.assertLess(len(tight_graph), len(full_graph))
        self.assertLess(len(tight_expert_lanes), len(full_expert_lanes))
        self.assertIn("expert-review-security", tight_expert_lanes)
        self.assertNotIn("expert-review-architecture", tight_expert_lanes)
        self.assertIn("evaluation", tight_by_lane)
        self.assertIn("architect-adjudication", tight_by_lane)
        self.assertIn("expert-review-security", tight_by_lane["evaluation"]["depends_on_lanes"])
        self.assertIn("architect-adjudication", tight_by_lane["implementation"]["depends_on_lanes"])

    def test_tight_scaffold_preserves_explicit_architecture_critic_contracts(self) -> None:
        route = classify_work(
            "Use Claude Opus 4.6 and Gemini 3.1 Pro Preview as independent second opinion critics "
            "of the Codex architect design for a cross-cutting public contract architecture migration.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture"],
        )
        graph = planned_graph("Tight Critic Review", route, scaffold_size="tight")
        by_lane = {item.get("lane"): item for item in graph}
        claude_lane = "expert-review-architecture-critic-claude-architecture-critic"
        gemini_lane = "expert-review-architecture-critic-gemini-architecture-critic"

        self.assertIn(claude_lane, by_lane)
        self.assertIn(gemini_lane, by_lane)
        self.assertIn(claude_lane, by_lane["evaluation"]["depends_on_lanes"])
        self.assertIn(gemini_lane, by_lane["evaluation"]["depends_on_lanes"])
        self.assertEqual(by_lane[claude_lane]["metadata"]["codex_pickup"], "forbidden")
        self.assertEqual(by_lane[gemini_lane]["metadata"]["codex_pickup"], "forbidden")

    def test_model_synthesis_sits_between_evaluation_and_adjudication(self) -> None:
        text = (
            "Use model synthesis with Claude Opus 4.6 and Gemini 3.1 Pro Preview as independent "
            "second opinion critics of the Codex architect design."
        )
        route = classify_work(
            text,
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture"],
        )
        route = {**route, "model_synthesis": recommend_model_synthesis(text, route)}
        graph = planned_graph("Synthesis External Example", route)
        by_lane = {item.get("lane"): item for item in graph}

        self.assertIn("model-synthesis", by_lane)
        self.assertEqual(by_lane["model-synthesis"]["depends_on_lanes"], ["evaluation"])
        self.assertEqual(by_lane["architect-adjudication"]["depends_on_lanes"], ["model-synthesis"])
        self.assertIn("architect-adjudication", by_lane["implementation"]["depends_on_lanes"])
        self.assertEqual(
            by_lane["model-synthesis"]["metadata"]["model_synthesis"]["recommended_mode"],
            "requested",
        )

    def test_internal_model_synthesis_adds_adjudication_before_implementation(self) -> None:
        text = "Use model synthesis for the Codex architecture review of routing and schema policy."
        route = classify_work(text, requested_roles=["architecture"])
        route = {**route, "model_synthesis": recommend_model_synthesis(text, route)}
        graph = planned_graph("Synthesis Internal Example", route)
        by_lane = {item.get("lane"): item for item in graph}

        self.assertIn("model-synthesis", by_lane)
        self.assertEqual(by_lane["architect-adjudication"]["depends_on_lanes"], ["model-synthesis"])
        self.assertIn("architect-adjudication", by_lane["implementation"]["depends_on_lanes"])
        self.assertNotIn("evaluation", by_lane)

    def test_glm_primary_environment_scaffold_has_pm_architect_counter_review_and_reports(self) -> None:
        route = classify_work(
            "Substitute GLM-5.2 as primary architect with Codex shell PM and Codex 5.6 Sol counter-review.",
            requested_roles=["architecture"],
            execution_environment="connected-codex-glm-primary",
            model_synthesis=True,
        )
        graph = planned_graph("GLM Primary Example", route)
        by_lane = {item.get("lane"): item for item in graph}

        self.assertIn("pm", by_lane)
        self.assertIn("expert-review-architecture", by_lane)
        codex_lane = "expert-review-architecture-critic-codex-architecture-critic"
        self.assertIn(codex_lane, by_lane)
        self.assertIn("model-synthesis", by_lane)
        self.assertIn("wrap-up-report", by_lane)
        self.assertIn("dashboard-report", by_lane)
        self.assertEqual(
            by_lane[codex_lane]["metadata"]["codex_pickup"],
            "forbidden",
        )
        self.assertIn(
            "no-codex-exec",
            by_lane[codex_lane]["labels"],
        )
        self.assertEqual(
            by_lane["expert-review-architecture"]["metadata"]["selected_executor"]["key"],
            "rhoai_glm_primary_architect",
        )
        self.assertEqual(
            by_lane[codex_lane]["metadata"]["executor"],
            "codex_architecture_critic",
        )
        self.assertEqual(
            by_lane["model-synthesis"]["metadata"]["model_synthesis"]["synthesis_owner"],
            "rhoai_glm_primary_architect",
        )
        self.assertEqual(by_lane["wrap-up-report"]["depends_on_lanes"], ["validation"])
        self.assertIn("docs", ancestors(by_lane, "wrap-up-report"))
        self.assertIn("validation", by_lane["dashboard-report"]["depends_on_lanes"])

    def test_high_risk_architect_review_route_adds_architect_adjudication(self) -> None:
        route = classify_work(
            "Architect a high-risk cross-cutting policy migration for route behavior.",
            requested_roles=["architecture"],
        )
        graph = planned_graph("Internal Architect Review", route)
        by_lane = {item.get("lane"): item for item in graph}

        self.assertEqual(route["route"], "architect-review")
        self.assertTrue(route["architect_adjudication_required"])
        self.assertIn("architect-adjudication", by_lane)
        self.assertEqual(by_lane["architect-adjudication"]["depends_on_lanes"], ["architect"])
        self.assertIn("architect-adjudication", by_lane["implementation"]["depends_on_lanes"])

    def test_internal_peer_review_required_route_adds_peer_review_and_adjudication(self) -> None:
        route = classify_work(
            "Evaluate a contractor return for work_rerouting_or_subversion, objective dilution, and critical path deferral.",
            share_boundary="redacted-packet",
        )
        graph = planned_graph("Internal Peer Review", route)
        by_lane = {item.get("lane"): item for item in graph}

        self.assertTrue(route["peer_review_required"])
        self.assertIn("peer-review", by_lane)
        self.assertIn("evaluation", by_lane)
        self.assertIn("architect-adjudication", by_lane)
        self.assertEqual(by_lane["peer-review"]["depends_on_lanes"], ["architect"])
        self.assertEqual(by_lane["evaluation"]["depends_on_lanes"], ["peer-review"])
        self.assertEqual(by_lane["architect-adjudication"]["depends_on_lanes"], ["evaluation"])
        self.assertIn("architect-adjudication", by_lane["implementation"]["depends_on_lanes"])

    def test_public_docs_pages_graph_finishes_docs_before_the_editor_gate(self) -> None:
        route = classify_work(
            "Create documentation plus GitHub Pages for a project using Diataxis and Red Hat UX.",
            file_paths=["docs/index.html", "README.md"],
        )
        graph = planned_graph("Public Docs Site", route)
        by_lane = {item.get("lane"): item for item in graph}

        self.assertTrue(route["editor_gate_required"])
        self.assertIn("expert-review-editor", by_lane)
        self.assertIn("publish-sanitization", by_lane)
        # Docs are content: written after implementation, reviewed by the
        # editor, validated and sanitized, and only then reported.
        self.assertEqual(by_lane["docs"]["depends_on_lanes"], ["implementation"])
        self.assertTrue({"implementation", "docs"} <= set(by_lane["expert-review-editor"]["depends_on_lanes"]))
        self.assertTrue({"implementation", "docs", "expert-review-editor"} <= set(by_lane["validation"]["depends_on_lanes"]))
        self.assertIn("expert-review-editor", by_lane["publish-sanitization"]["depends_on_lanes"])
        self.assertEqual(by_lane["wrap-up-report"]["depends_on_lanes"], ["publish-sanitization"])
        self.assertNotIn("handoff", by_lane["docs"]["labels"])
        self.assertIn("handoff", by_lane["wrap-up-report"]["labels"])
        self.assertTrue(by_lane["expert-review-editor"]["metadata"]["validation_gate_required"])
        self.assertEqual(by_lane["expert-review-editor"]["metadata"]["gate_scope"], "public-docs-pages")

    def test_public_docs_prefer_local_graph_keeps_editor_before_publish(self) -> None:
        route = classify_work(
            "Review public docs and README install guidance with local model evidence.",
            file_paths=["README.md"],
            local_ok=True,
            prefer_local=True,
        )
        graph = planned_graph("Public README Review", route)
        by_lane = {item.get("lane"): item for item in graph}

        self.assertTrue(route["editor_gate_required"])
        self.assertIn("expert-review-editor", by_lane)
        self.assertIn("publish-sanitization", by_lane)
        self.assertIn("expert-review-editor", by_lane["validation"]["depends_on_lanes"])
        self.assertIn("expert-review-editor", by_lane["publish-sanitization"]["depends_on_lanes"])
        self.assertIn("docs", ancestors(by_lane, "expert-review-editor"))
        self.assertTrue(by_lane["expert-review-editor"]["metadata"]["validation_gate_required"])

    def test_recovery_summary_includes_created_ids_and_safe_rerun_guidance(self) -> None:
        summary = recovery_summary(
            {"epic": "cwo-epic", "architect": "cwo-architect"},
            "create implementation",
            "bd command timed out",
        )
        self.assertIn("Partial Beads graph creation detected.", summary)
        self.assertIn("- epic: cwo-epic", summary)
        self.assertIn("bd create --graph", summary)
        self.assertIn("will not silently reuse existing Beads", summary)


class ContentBeforeFinalChecksTests(unittest.TestCase):
    """No final check can cover content that changes after it, on any route shape."""

    ROUTES = {
        "public-docs-pages": lambda: classify_work(
            "Create documentation plus GitHub Pages for a project using Diataxis and Red Hat UX.",
            file_paths=["docs/index.html", "README.md"],
        ),
        "public-readme-prefer-local": lambda: classify_work(
            "Review public docs and README install guidance with local model evidence.",
            file_paths=["README.md"],
            local_ok=True,
            prefer_local=True,
        ),
        "external-security-review": lambda: classify_work(
            "Security review redacted packet behavior.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security"],
        ),
        "external-security-web-design": lambda: classify_work(
            "Security and web design review for contractor packet behavior.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security", "web-design"],
        ),
        "high-risk-architect-review": lambda: classify_work(
            "Architect a high-risk cross-cutting policy migration for route behavior.",
            requested_roles=["architecture"],
        ),
        "internal-peer-review": lambda: classify_work(
            "Evaluate a contractor return for work_rerouting_or_subversion, objective dilution, and critical path deferral.",
            share_boundary="redacted-packet",
        ),
        "small-change": lambda: classify_work("Fix a typo in a code comment."),
        # Final-stage reviewers routed to acceptance beads (external, local).
        "rhacs-external": lambda: classify_work(
            "RHACS security policy review.", external_ok=True, share_boundary="redacted-packet",
        ),
        "rhel-local": lambda: classify_work("RHEL host hardening review.", local_ok=True, prefer_local=True),
        "docs-pages-external": lambda: classify_work(
            "Create documentation plus GitHub Pages for a project using Diataxis and Red Hat UX.",
            external_ok=True,
            share_boundary="redacted-packet",
        ),
        "openshift-ai-mixed": lambda: classify_work(
            "OpenShift AI model serving review.", external_ok=True, share_boundary="redacted-packet", local_ok=True,
        ),
    }

    def graphs(self):
        for name, build in self.ROUTES.items():
            route = build()
            for size in ("full", "tight"):
                by_lane = {item.get("lane"): item for item in planned_graph("Example", route, scaffold_size=size)}
                yield f"{name}/{size}", by_lane, self.final_reviews(route, size)

    @staticmethod
    def final_reviews(route: dict, size: str) -> set[str]:
        """Final-stage reviewer lanes, from the route's expert contracts rather than the generated edges."""
        from cwo_core.routing import expert_review_metadata
        from scaffold_workgraph import expert_review_lane, selected_source_experts

        lanes = set()
        for expert in selected_source_experts(route, size):
            metadata = expert_review_metadata(expert, route)
            if metadata.get("validation_gate_required") or expert.get("review_stage") in ("pre-validation", "pre-release"):
                lanes.add(expert_review_lane(expert))
        return lanes

    def test_graphs_are_acyclic_and_every_dependency_exists(self) -> None:
        for name, by_lane, _ in self.graphs():
            with self.subTest(graph=name):
                for lane, item in by_lane.items():
                    if lane is None:
                        continue
                    for dependency in item.get("depends_on_lanes", []):
                        self.assertIn(dependency, by_lane, f"{lane} depends on a missing lane")
                    self.assertNotIn(lane, ancestors(by_lane, lane), f"{lane} depends on itself")

    def test_every_final_check_follows_all_content_and_precedes_reporting(self) -> None:
        shapes = set()
        for name, by_lane, final_reviews in self.graphs():
            with self.subTest(graph=name):
                content = {"implementation", "docs"}
                final_checks = {"validation", *final_reviews}
                final_checks |= {lane for lane in ("publish-sanitization", "final-dispatch", "final-peer-review",
                                                   "final-evaluation", "final-adjudication") if lane in by_lane}
                self.assertTrue(final_reviews <= set(by_lane), "every final-stage reviewer has a lane")
                for check in final_checks:
                    self.assertTrue(content <= ancestors(by_lane, check), f"{check} can run before content is final")
                for lane in content:
                    self.assertFalse(final_checks & ancestors(by_lane, lane), f"{lane} can change content after a final check")
                self.assertTrue(final_checks - {"final-dispatch"} <= ancestors(by_lane, "wrap-up-report") | {"wrap-up-report"})
                if "final-adjudication" in by_lane:
                    shapes.add("final acceptance")
                if any(lane in final_reviews for lane in by_lane["validation"]["depends_on_lanes"]):
                    shapes.add("internal final review")
        self.assertEqual(shapes, {"final acceptance", "internal final review"}, "both reviewer shapes are exercised")

    def test_final_stage_acceptance_reviews_get_their_own_adjudication_after_content(self) -> None:
        route = classify_work("RHACS security policy review.", external_ok=True, share_boundary="redacted-packet")
        by_lane = {item.get("lane"): item for item in planned_graph("Example", route)}
        reviewer = "expert-review-rhacs"
        self.assertIn(reviewer, by_lane)
        self.assertTrue({"implementation", "docs", "final-dispatch"} <= set(by_lane[reviewer]["depends_on_lanes"]))
        self.assertEqual(by_lane["final-dispatch"]["depends_on_lanes"], ["implementation", "docs"])
        self.assertIn(reviewer, ancestors(by_lane, "final-evaluation"))
        self.assertEqual(by_lane["final-adjudication"]["depends_on_lanes"], ["final-evaluation"])
        self.assertIn("final-adjudication", by_lane["validation"]["depends_on_lanes"])
        self.assertNotIn("final-adjudication", ancestors(by_lane, "implementation"))
        self.assertNotIn(reviewer, ancestors(by_lane, "implementation"), "the final review is not a plan review")

    def test_final_returns_get_the_routes_peer_review_with_its_restrictions(self) -> None:
        route = classify_work(
            "RHACS security policy review.", external_ok=True, share_boundary="redacted-packet",
        )
        route = {**route, "peer_review_required": True, "peer_review_count": 2, "provider_diversity_required": True,
                 "provider_conflict_domains": ["example-provider"]}
        by_lane = {item.get("lane"): item for item in planned_graph("Example", route)}
        reviewer = "expert-review-rhacs"
        self.assertIn("final-peer-review", by_lane)
        peer = by_lane["final-peer-review"]
        self.assertEqual(peer["depends_on_lanes"], [reviewer])
        self.assertEqual(by_lane["final-evaluation"]["depends_on_lanes"], ["final-peer-review"])
        self.assertEqual(peer["metadata"]["codex_pickup"], "forbidden")
        self.assertEqual(peer["metadata"]["peer_review_count"], 2)
        self.assertIs(peer["metadata"]["provider_diversity_required"], True)
        self.assertEqual(peer["metadata"]["provider_conflict_domains"], ["example-provider"])
        self.assertIn("no-codex-exec", peer["labels"])

    def test_direct_creation_and_the_graph_plan_use_the_same_priorities(self) -> None:
        import scaffold_workgraph

        title = "RHACS security policy review."
        route = classify_work(title, external_ok=True, share_boundary="redacted-packet")
        plan = planned_graph(title, route)
        expected = {item["lane"]: scaffold_workgraph.item_priority(item, index) for index, item in enumerate(plan) if index}
        created: dict[str, int] = {}

        def fake_create(title: str, **fields: object) -> dict[str, str]:
            if fields.get("parent"):
                created[next(item["lane"] for item in plan[1:] if item["title"] == title)] = int(fields["priority"])
            return {"id": f"bd-{len(created)}", "title": title}

        argv = ["scaffold_workgraph.py", "--title", title, "--external-ok", "--share-boundary", "redacted-packet"]
        with patch.object(scaffold_workgraph, "create_bead", side_effect=fake_create), \
                patch.object(scaffold_workgraph, "try_dep"), patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                scaffold_workgraph.main()
            except SystemExit:
                pass
        self.assertTrue(created, "direct creation ran")
        self.assertEqual({lane: created[lane] for lane in created}, {lane: expected[lane] for lane in created})
        self.assertEqual(created.get("final-adjudication"), 1)

    def test_final_inspection_and_reporting_change_no_content(self) -> None:
        route = classify_work(
            "Create documentation plus GitHub Pages for a project using Diataxis and Red Hat UX.",
            file_paths=["docs/index.html", "README.md"],
        )
        by_lane = {item.get("lane"): item for item in planned_graph("Public Docs Site", route)}
        for lane in ("publish-sanitization", "wrap-up-report"):
            with self.subTest(lane=lane):
                self.assertIs(by_lane[lane]["metadata"]["inspect_only"], True)
        self.assertIn("Inspect only", by_lane["publish-sanitization"]["design"])
        self.assertIn("Change nothing in this lane", by_lane["publish-sanitization"]["design"])
        self.assertIn("Report only", by_lane["wrap-up-report"]["design"])


if __name__ == "__main__":
    unittest.main()

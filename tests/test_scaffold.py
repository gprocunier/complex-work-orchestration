from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.coach import coach_orchestration_prompt  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402
from cwo_core.synthesis import recommend_model_synthesis  # noqa: E402
from scaffold_workgraph import planned_graph, recovery_summary, try_dep  # noqa: E402


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

    def test_operational_lanes_get_spark_owner_metadata_and_labels(self) -> None:
        route = classify_work(
            "Refactor docs, implementation, and validation with Codex 5.6 Sol and Codex 5.3 Spark roles.",
            requested_roles=["architecture", "documentation", "implementation"],
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

    def test_native_first_route_assigns_spark_operational_metadata_to_operative_lanes(self) -> None:
        route = classify_work(
            "Implement a small helper and verify tests with Spark-native dispatch.",
            requested_roles=["implementation", "documentation", "validation"],
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

    def test_real_coach_native_tool_unavailable_preserves_non_mismatch_hard_stop(self) -> None:
        self.assert_coach_hard_stop_graph(
            "Plan docs work. Native Spark tooling is unavailable.",
            expected_registry_tool_mismatch=False,
            expected_failed_check="spark-native-tool-absence",
        )

    def test_real_coach_registry_tool_mismatch_preserves_mismatch_hard_stop(self) -> None:
        self.assert_coach_hard_stop_graph(
            "There is a Spark registry/tool mismatch for this task.",
            expected_registry_tool_mismatch=True,
            expected_failed_check="spark-registry-tool-mismatch",
        )

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
            self.assertIn(lane, by_lane["evaluation"]["depends_on_lanes"])
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
        self.assertIn("docs", by_lane["wrap-up-report"]["depends_on_lanes"])
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

    def test_public_docs_pages_graph_uses_editor_validation_gate(self) -> None:
        route = classify_work(
            "Create documentation plus GitHub Pages for a project using Diataxis and Red Hat UX.",
            file_paths=["docs/index.html", "README.md"],
        )
        graph = planned_graph("Public Docs Site", route)
        by_lane = {item.get("lane"): item for item in graph}

        self.assertTrue(route["editor_gate_required"])
        self.assertIn("expert-review-editor", by_lane)
        self.assertIn("publish-sanitization", by_lane)
        self.assertIn("expert-review-editor", by_lane["validation"]["depends_on_lanes"])
        self.assertIn("expert-review-editor", by_lane["publish-sanitization"]["depends_on_lanes"])
        self.assertEqual(by_lane["docs"]["depends_on_lanes"], ["publish-sanitization"])
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


if __name__ == "__main__":
    unittest.main()

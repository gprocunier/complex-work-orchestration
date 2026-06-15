from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.routing import classify_work  # noqa: E402
from scaffold_workgraph import planned_graph, recovery_summary  # noqa: E402


class ScaffoldTests(unittest.TestCase):
    def assert_native_fields(self, item: dict[str, object]) -> None:
        self.assertTrue(item.get("skills"), item.get("title"))
        self.assertTrue(item.get("acceptance"), item.get("title"))
        self.assertTrue(item.get("design"), item.get("title"))
        self.assertTrue(item.get("notes"), item.get("title"))

    def test_planned_graph_populates_native_beads_fields_for_every_item(self) -> None:
        route = classify_work(
            "Architecture and documentation review for Beads workgraph behavior.",
            requested_roles=["architecture", "documentation"],
        )
        graph = planned_graph("Field Example", route)
        for item in graph:
            with self.subTest(title=item["title"]):
                self.assert_native_fields(item)

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

        claude_lane = "expert-review-architecture-critic-claude-opus-4-6-architecture-critic"
        gemini_lane = "expert-review-architecture-critic-gemini-3-1-pro-preview-agy"
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

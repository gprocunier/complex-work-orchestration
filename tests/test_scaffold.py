from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import classify_work  # noqa: E402
from scaffold_workgraph import planned_graph  # noqa: E402


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
            "Documentation review for public README examples.",
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


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.routing import classify_work  # noqa: E402
from scaffold_workgraph import planned_graph  # noqa: E402


class PeerReviewPipelineTests(unittest.TestCase):
    def test_external_contract_graph_inserts_peer_review_before_evaluation(self) -> None:
        route = classify_work(
            "Security focused review of auth flow behavior using a redacted contractor packet.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security"],
        )
        self.assertEqual(route["route"], "external-contract")
        self.assertTrue(route["peer_review_required"])
        graph = planned_graph("External security review", route)
        by_lane = {item.get("lane"): item for item in graph}
        self.assertIn("peer-review", by_lane)
        self.assertIn("external-dispatch", by_lane["peer-review"]["depends_on_lanes"])
        self.assertIn("peer-review", by_lane["evaluation"]["depends_on_lanes"])
        self.assertIn("architect-adjudication", by_lane["implementation"]["depends_on_lanes"])
        self.assertEqual(by_lane["peer-review"]["metadata"]["codex_pickup"], "forbidden")

    def test_internal_peer_review_route_inserts_review_evaluation_and_adjudication(self) -> None:
        route = classify_work(
            "Evaluate a contractor return for work_rerouting_or_subversion and non-equivalent substitution.",
            share_boundary="redacted-packet",
        )
        self.assertNotEqual(route["route"], "external-contract")
        self.assertTrue(route["peer_review_required"])
        graph = planned_graph("Internal peer review", route)
        by_lane = {item.get("lane"): item for item in graph}

        self.assertIn("peer-review", by_lane)
        self.assertIn("evaluation", by_lane)
        self.assertIn("architect-adjudication", by_lane)
        self.assertEqual(by_lane["peer-review"]["depends_on_lanes"], ["architect"])
        self.assertEqual(by_lane["evaluation"]["depends_on_lanes"], ["peer-review"])
        self.assertEqual(by_lane["architect-adjudication"]["depends_on_lanes"], ["evaluation"])
        self.assertIn("architect-adjudication", by_lane["implementation"]["depends_on_lanes"])


if __name__ == "__main__":
    unittest.main()

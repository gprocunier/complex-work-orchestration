from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import classify_work  # noqa: E402
from scaffold_workgraph import planned_graph  # noqa: E402


class ScaffoldTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

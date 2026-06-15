from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.routing import classify_work  # noqa: E402
from scaffold_workgraph import planned_graph  # noqa: E402


class ScaffoldDryRunTests(unittest.TestCase):
    def test_external_scaffold_has_eval_adjudication_and_per_expert_executor(self) -> None:
        route = classify_work(
            "Security and web design review for contractor packet behavior.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security", "web-design"],
        )
        graph = planned_graph("Example", route)
        lanes = {item.get("lane") for item in graph}
        self.assertIn("evaluation", lanes)
        self.assertIn("architect-adjudication", lanes)
        expert_items = [item for item in graph if item.get("metadata", {}).get("expert")]
        self.assertTrue(expert_items)
        for item in expert_items:
            self.assertIn("executor", item["metadata"])
            self.assertIn("selected_executor", item["metadata"])
            selected = item["metadata"]["selected_executor"]
            if selected.get("external"):
                self.assertEqual(item["metadata"]["codex_pickup"], "forbidden")
                self.assertIn("contractor-only", item["labels"])
                self.assertIn("no-codex-exec", item["labels"])
                self.assertIn(item["lane"], graph[[node.get("lane") for node in graph].index("evaluation")]["depends_on_lanes"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.routing import classify_work  # noqa: E402
from cwo_core.synthesis import recommend_model_synthesis  # noqa: E402
from scaffold_workgraph import beads_graph_plan, planned_graph  # noqa: E402


class ScaffoldBeadsGraphTests(unittest.TestCase):
    def test_beads_graph_plan_uses_graph_apply_schema(self) -> None:
        route = classify_work("Implement a small Python helper with tests.")
        cwo_graph = planned_graph("Graph Example", route)

        graph = beads_graph_plan(cwo_graph)
        nodes = graph["nodes"]
        edges = graph["edges"]
        by_key = {node["key"]: node for node in nodes}

        self.assertIn("epic", by_key)
        self.assertEqual(by_key["epic"]["type"], "epic")
        self.assertNotIn("parent_key", by_key["epic"])
        for node in nodes[1:]:
            self.assertEqual(node["parent_key"], "epic")
            self.assertIn("cwo_acceptance", node["metadata"])
            for value in node["metadata"].values():
                self.assertIsInstance(value, str)
            self.assertNotIn("depends_on_lanes", node)

        self.assertIn({"from_key": "implementation", "to_key": "architect", "type": "blocks"}, edges)
        self.assertIn({"from_key": "validation", "to_key": "implementation", "type": "blocks"}, edges)
        self.assertIn({"from_key": "docs", "to_key": "validation", "type": "blocks"}, edges)

    def test_beads_graph_plan_preserves_cwo_fields_in_metadata(self) -> None:
        route = classify_work("Document Beads graph import behavior.")
        cwo_graph = planned_graph("Metadata Example", route)
        graph = beads_graph_plan(cwo_graph)

        implementation = next(node for node in graph["nodes"] if node["key"] == "implementation")
        cwo = implementation["metadata"]
        self.assertEqual(cwo["cwo_lane"], "implementation")
        self.assertTrue(json.loads(cwo["cwo_skills"]))
        self.assertTrue(cwo["cwo_acceptance"])
        self.assertTrue(cwo["cwo_design"])
        self.assertTrue(cwo["cwo_notes"])

    def test_beads_graph_plan_exports_model_synthesis_lane(self) -> None:
        text = "Use model synthesis for architecture routing and schema policy."
        route = classify_work(text, requested_roles=["architecture"])
        route = {**route, "model_synthesis": recommend_model_synthesis(text, route)}
        graph = beads_graph_plan(planned_graph("Synthesis Graph", route))
        by_key = {node["key"]: node for node in graph["nodes"]}

        self.assertIn("model-synthesis", by_key)
        self.assertEqual(by_key["model-synthesis"]["metadata"]["cwo_lane"], "model-synthesis")
        self.assertIn(
            {"from_key": "architect-adjudication", "to_key": "model-synthesis", "type": "blocks"},
            graph["edges"],
        )

    def test_cli_beads_graph_output_validates_with_bd_create_graph_dry_run(self) -> None:
        bd = shutil.which("bd")
        if not bd:
            self.skipTest("bd is not installed")

        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "scaffold_workgraph.py"),
                "--title",
                "CLI Graph Example",
                "--description",
                "Implement a small Python helper with tests.",
                "--dry-run",
                "--format",
                "beads-graph",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        graph = json.loads(result.stdout)
        self.assertIsInstance(graph, dict)
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)

        with tempfile.TemporaryDirectory() as temp_dir:
            graph_path = Path(temp_dir) / "graph.json"
            graph_path.write_text(json.dumps(graph), encoding="utf-8")
            dry_run = subprocess.run(
                [bd, "create", "--graph", str(graph_path), "--dry-run", "--json"],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

        self.assertEqual(dry_run.returncode, 0, dry_run.stderr or dry_run.stdout)
        self.assertNotIn("unknown field", dry_run.stderr)
        payload = json.loads(dry_run.stdout)
        self.assertEqual(payload["node_count"], len(graph["nodes"]))
        self.assertEqual(payload["edge_count"], len(graph["edges"]))


if __name__ == "__main__":
    unittest.main()

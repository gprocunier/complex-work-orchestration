from __future__ import annotations

import json
import os
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
from scaffold_workgraph import beads_graph_plan, markdown_workgraph_plan, planned_graph  # noqa: E402
from summarize_resume_state import parse_markdown_workgraph  # noqa: E402

BD_PATH = shutil.which("bd")


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

    def test_beads_graph_plan_preserves_explicit_nonblocking_relationships(self) -> None:
        plan = [
            {
                "title": "Typed relationships",
                "type": "epic",
                "labels": ["orchestration"],
                "metadata": {},
                "skills": [],
                "acceptance": "complete",
                "design": "typed",
                "notes": "test",
            },
            {
                "title": "Implementation",
                "type": "task",
                "lane": "implementation",
                "labels": ["implementation"],
                "depends_on_lanes": [],
                "metadata": {},
                "skills": [],
                "acceptance": "complete",
                "design": "typed",
                "notes": "test",
            },
            {
                "title": "Publication",
                "type": "task",
                "lane": "publication",
                "labels": ["publication"],
                "depends_on_lanes": [
                    {"lane": "implementation", "type": "validates"},
                ],
                "metadata": {},
                "skills": [],
                "acceptance": "complete",
                "design": "typed",
                "notes": "test",
            },
        ]

        graph = beads_graph_plan(plan)

        self.assertIn(
            {
                "from_key": "publication",
                "to_key": "implementation",
                "type": "validates",
            },
            graph["edges"],
        )
        publication = next(node for node in graph["nodes"] if node["key"] == "publication")
        self.assertEqual(
            json.loads(publication["metadata"]["cwo_depends_on_lanes"]),
            [{"lane": "implementation", "type": "validates"}],
        )

    def test_markdown_workgraph_plan_preserves_lane_fields(self) -> None:
        route = classify_work("Document Markdown fallback workgraph behavior.")
        cwo_graph = planned_graph("Markdown Example", route)

        rendered = markdown_workgraph_plan("Markdown Example", cwo_graph)

        self.assertIn("Reduced durability fallback", rendered)
        self.assertIn("### epic: Markdown Example", rendered)
        self.assertIn("### implementation: Implement: Markdown Example", rendered)
        self.assertIn("- Depends on lanes:", rendered)
        self.assertIn("- Skills:", rendered)
        self.assertIn("#### Acceptance", rendered)
        self.assertIn("#### Design", rendered)
        self.assertIn("#### Notes", rendered)

    def test_markdown_workgraph_generator_output_round_trips_through_parser(self) -> None:
        route = classify_work("Document Markdown fallback workgraph behavior.")
        cwo_graph = planned_graph("Markdown Round Trip", route)
        rendered = markdown_workgraph_plan("Markdown Round Trip", cwo_graph)

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "workgraph.md"
            path.write_text(rendered, encoding="utf-8")
            parsed = parse_markdown_workgraph(path)

        by_id = {item["id"]: item for item in parsed}
        self.assertEqual(by_id["epic"]["type"], "epic")
        self.assertEqual(by_id["implementation"]["lane"], "implementation")
        self.assertIn("workerbee", by_id["implementation"]["labels"])
        self.assertIn("architect", by_id["implementation"]["depends_on_lanes"])

    def test_markdown_workgraph_preserves_hard_stop_metadata(self) -> None:
        route = classify_work(
            "Implement a route where Spark-native is hard-stopped but native checks are preserved.",
            requested_roles=["implementation", "documentation"],
        )
        route["workerbee_planned_delegation"] = {
            "mode": "implementation-capable",
            "model": "gpt-5.3-codex-spark",
            "lanes": ["implementation", "validation", "docs", "wrap-up-report", "dashboard-report"],
            "spark_operational_worker": True,
            "hard_stop": True,
            "registry_tool_mismatch": True,
            "spark_dispatch": {
                "status": "hard-stop",
                "requested_route": "implementation-capable",
                "requested_model": "gpt-5.3-codex-spark",
                "failed_native_capability_check": "spark-registry-tool-mismatch",
                "failed_native_capability_check_justification": "Registry/tool mismatch blocks native Spark dispatch.",
                "obsolete_field": "retired-route",
            },
        }
        cwo_graph = planned_graph("Markdown Hard Stop", route)
        rendered = markdown_workgraph_plan("Markdown Hard Stop", cwo_graph)

        expected_dispatch = {
            "status": "hard-stop",
            "requested_model": "gpt-5.3-codex-spark",
            "requested_route": "implementation-capable",
            "failed_native_capability_check": "spark-registry-tool-mismatch",
            "failed_native_capability_check_justification": "Registry/tool mismatch blocks native Spark dispatch.",
        }
        for item in cwo_graph:
            if item.get("type") == "epic":
                continue
            metadata = item["metadata"]
            self.assertEqual(metadata["workerbee_planned_mode"], "blocked")
            self.assertEqual(metadata["workerbee_planned_model"], "")
            self.assertEqual(metadata["workerbee_planned_lanes"], [])
            self.assertEqual(metadata["workerbee_operational_owner"], "")
            self.assertIs(metadata["workerbee_registry_tool_mismatch"], True)
            self.assertIs(metadata["spark_operational_worker"], False)
            self.assertEqual(
                metadata["workerbee_planned_delegation"],
                {"mode": "blocked", "model": None, "lanes": []},
            )
            self.assertEqual(metadata["workerbee_spark_dispatch"], expected_dispatch)
            self.assertNotIn("no-sol-exec", item["labels"])
            self.assertNotIn("spark-operative-owner", item["labels"])
        self.assertNotIn("obsolete_field", rendered)
        self.assertIn("Spark dispatch metadata: status=hard-stop", rendered)
        self.assertIn("requested_route=implementation-capable", rendered)
        self.assertIn("failed_check=spark-registry-tool-mismatch", rendered)

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

    def test_cli_model_synthesis_flag_records_accepted_state(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "scaffold_workgraph.py"),
                "--title",
                "Accepted Synthesis Example",
                "--description",
                "Refactor architecture policy and routing tests.",
                "--model-synthesis",
                "--dry-run",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        graph = json.loads(result.stdout)
        by_lane = {item.get("lane"): item for item in graph}

        self.assertIn("model-synthesis", by_lane)
        synthesis = by_lane["model-synthesis"]["metadata"]["model_synthesis"]
        self.assertEqual(synthesis["recommended_mode"], "accepted")
        self.assertTrue(synthesis["active"])
        self.assertIn("input evaluator dispositions", synthesis["artifact_contract"])

    @unittest.skipUnless(BD_PATH, "bd is not installed")
    def test_cli_beads_graph_output_validates_with_bd_create_graph_dry_run(self) -> None:
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
            init = subprocess.run(
                [BD_PATH or "bd", "init", "--non-interactive", "--skip-agents", "--skip-hooks"],
                cwd=temp_dir,
                capture_output=True,
                text=True,
            )
            self.assertEqual(init.returncode, 0, init.stderr or init.stdout)

            graph_path = Path(temp_dir) / "graph.json"
            graph_path.write_text(json.dumps(graph), encoding="utf-8")
            env = {**os.environ, "BEADS_DIR": str(Path(temp_dir) / ".beads")}
            dry_run = subprocess.run(
                [BD_PATH or "bd", "create", "--graph", str(graph_path), "--dry-run", "--json"],
                cwd=temp_dir,
                env=env,
                capture_output=True,
                text=True,
            )

        self.assertEqual(dry_run.returncode, 0, dry_run.stderr or dry_run.stdout)
        self.assertNotIn("unknown field", dry_run.stderr)
        payload = json.loads(dry_run.stdout)
        if "node_count" in payload:
            self.assertEqual(payload["node_count"], len(graph["nodes"]))
            self.assertEqual(payload["edge_count"], len(graph["edges"]))
        else:
            self.assertEqual(len(payload["ids"]), len(graph["nodes"]))
            self.assertEqual(payload["schema_version"], 1)

    def test_cli_beads_graph_format_requires_dry_run(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "scaffold_workgraph.py"),
                "--title",
                "Invalid Graph Format Example",
                "--description",
                "Attempt real Beads creation with graph format.",
                "--format",
                "beads-graph",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires --dry-run", result.stderr)

    def test_cli_dry_run_beads_graph_does_not_require_bd_on_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_path:
            env = {**os.environ, "PATH": temp_path}
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "scaffold_workgraph.py"),
                    "--title",
                    "Dry Run Without Beads",
                    "--description",
                    "Render a Beads graph without calling the Beads CLI.",
                    "--dry-run",
                    "--format",
                    "beads-graph",
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

        graph = json.loads(result.stdout)
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)

    def test_cli_dry_run_markdown_workgraph_does_not_require_bd_on_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_path:
            env = {**os.environ, "PATH": temp_path}
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "scaffold_workgraph.py"),
                    "--title",
                    "Markdown Without Beads",
                    "--description",
                    "Render fallback graph without calling the Beads CLI.",
                    "--dry-run",
                    "--format",
                    "markdown-workgraph",
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertIn("# Markdown Without Beads", result.stdout)
        self.assertIn("Reduced durability fallback", result.stdout)
        self.assertIn("### implementation: Implement: Markdown Without Beads", result.stdout)

    def test_cli_real_scaffold_fails_clearly_when_bd_missing_from_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_path:
            env = {**os.environ, "PATH": temp_path}
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "scaffold_workgraph.py"),
                    "--title",
                    "No Beads CLI Example",
                    "--description",
                    "Attempt real Beads creation without bd on PATH.",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bd was not found; install Beads or use --dry-run", result.stderr)


if __name__ == "__main__":
    unittest.main()

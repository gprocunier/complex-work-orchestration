from __future__ import annotations

import json
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CWO = ROOT / "scripts" / "cwo.py"
GRAPH = ROOT / "tests" / "fixtures" / "invoice-continuation.md"


class RunStateAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="cwo active run ")))

    def cwo(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(CWO), *args], cwd=self.workspace, capture_output=True, text=True, timeout=30,
        )

    def write(self, name: str, content: str) -> Path:
        path = self.workspace / name
        path.write_text(content, encoding="utf-8")
        return path

    def coach(self, pending: bool) -> Path:
        return self.write("current coach.json", json.dumps({
            "coach_result_type": "complex-work-orchestration-prompt-coach",
            "requires_user_selection_before_plan": pending,
            "selection_before_plan_question_ids": ["scaffold_size"],
        }))

    def test_record_resumes_from_current_inputs_and_ignores_saved_commands(self) -> None:
        graph = self.write("current workgraph.md", GRAPH.read_text(encoding="utf-8"))
        coach = self.coach(True)
        command = ("continue", "--epic=demo", "--sprint=-review", "--format=json", f"--markdown-workgraph={graph.name}")
        plain = self.cwo(*command)
        self.assertEqual(plain.returncode, 0, plain.stderr)
        self.assertNotIn("run_state", json.loads(plain.stdout))
        self.assertFalse((self.workspace / ".orchestration-audit").exists())

        active_command = (*command, "--record-run", f"--coach={coach.name}")
        output = self.cwo(*active_command)
        self.assertEqual(output.returncode, 0, output.stderr)
        paused = json.loads(output.stdout)
        state = paused["run_state"]
        path = Path(paused["run_state_path"])
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), state)
        self.assertEqual(state["current_gate"], "operator-selection")
        self.assertEqual(state["operator_decision_frontier"], ["scaffold_size"])
        self.assertEqual(paused["operator_handoff_packet"]["run_id"], state["run_id"])
        self.assertEqual(paused["operator_handoff_packet"]["exact_command_resume"], state["resume_command"])
        self.assertIn("coach", paused["status_summary"]["outcome"])
        self.assertIsNone(paused["recommended_next_issue"])
        self.assertTrue(paused["ready_issues"])

        poison = self.workspace / "ran stored command"
        path.write_text(json.dumps({**state, "resume_command": f"touch {shlex.quote(str(poison))}"}), encoding="utf-8")
        self.coach(False)
        location, executable = state["resume_command"].split(" && ", 1)
        self.assertEqual(shlex.split(location), ["cd", str(self.workspace)])
        self.assertEqual(shlex.split(executable)[1:3], [str(CWO), "continue"])
        output = self.cwo(*shlex.split(executable)[2:])
        self.assertEqual(output.returncode, 0, output.stderr)
        resumed = json.loads(output.stdout)["run_state"]
        self.assertEqual(resumed["run_id"], state["run_id"])
        self.assertEqual(resumed["current_step"], "demo-17")
        self.assertEqual(resumed["current_gate"], "ready")
        self.assertFalse(poison.exists())

        self.write(graph.name, graph.read_text(encoding="utf-8").replace("`open`", "`done`"))
        output = self.cwo(*active_command)
        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertEqual(json.loads(output.stdout)["run_state"]["current_gate"], "no-work")
        before = path.read_bytes()
        coach.write_text("[]", encoding="utf-8")
        self.assertEqual(self.cwo(*active_command).returncode, 2)
        self.assertEqual(path.read_bytes(), before)

    def test_analysis_checks_both_scaffold_formats_without_writes(self) -> None:
        scaffold = ("scaffold", "--title=CSV invoice exports", "--scaffold-size=tight", "--dry-run")
        saved_graph = self.cwo(*scaffold)
        self.assertEqual(saved_graph.returncode, 0, saved_graph.stderr)
        saved_markdown = self.cwo(*scaffold, "--format=markdown-workgraph")
        self.assertEqual(saved_markdown.returncode, 0, saved_markdown.stderr)
        graph = self.write("scaffold.json", saved_graph.stdout)
        markdown = self.write("scaffold.md", saved_markdown.stdout)
        embedded_route = json.loads(saved_graph.stdout)[0]["metadata"]["orchestration_route"]
        embedded_path = self.write("embedded-route.json", json.dumps(embedded_route))
        routed = self.cwo("route", "--json", "CSV invoice exports")
        self.assertEqual(routed.returncode, 0, routed.stderr)
        route = json.loads(routed.stdout)
        self.assertNotIn("required_experts", route)
        route_path = self.write("route.json", routed.stdout)
        ledger = self.write("ledger.jsonl", "")
        coach = self.coach(True)
        handoff = self.write("handoff.md", "# Missing fields\n")
        plan = json.loads((ROOT / "examples" / "sample-run-readiness-plan.json").read_text(encoding="utf-8"))
        plan["workstreams"][0]["validation_refs"] = ["criterion:unmapped"]
        readiness = self.write("readiness.json", json.dumps(plan))
        artifacts = (graph, markdown, embedded_path, route_path, ledger, coach, readiness, handoff)
        for workgraph in (graph, markdown):
            for saved_route in (embedded_path, route_path):
                with self.subTest(workgraph=workgraph, route=saved_route):
                    clean = self.cwo("analyze", "--workgraph", str(workgraph), "--route", str(saved_route))
                    self.assertEqual(clean.returncode, 0, clean.stderr or clean.stdout)
                    self.assertEqual(json.loads(clean.stdout)["findings"], [])

        route["route"] = "different-route"
        route_path.write_text(json.dumps(route), encoding="utf-8")
        before = {path: path.read_bytes() for path in artifacts}
        for workgraph in (graph, markdown):
            with self.subTest(workgraph=workgraph):
                result = self.cwo(
                    "analyze", "--workgraph", str(workgraph), "--route", str(route_path), "--coach", str(coach),
                    "--handoff", str(handoff), "--readiness-plan", str(readiness), "--convergence-ledger", str(ledger),
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual([finding["id"] for finding in report["findings"]], [
                    "handoff-invalid", "operator-selection-open", "readiness-invalid", "route-workgraph-mismatch",
                    "readiness-scope-unverified",
                ])
                self.assertEqual(report["coverage"]["convergence_records"], 0)
        self.assertEqual({path: path.read_bytes() for path in artifacts}, before)
        self.assertEqual(set(self.workspace.iterdir()), set(artifacts))

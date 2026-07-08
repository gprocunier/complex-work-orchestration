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

from continue_sprint import (  # noqa: E402
    MODELING_NOTE,
    build_continuation_brief,
    load_markdown_items,
)

BD_PATH = shutil.which("bd")


class ContinueSprintTests(unittest.TestCase):
    def test_ranks_ready_issues_by_priority_then_unblocking_value(self) -> None:
        items = [
            {"id": "epic", "title": "Continuation", "type": "epic", "status": "open"},
            {"id": "docs", "title": "Docs", "status": "open", "priority": 2, "labels": ["docs"]},
            {"id": "engine", "title": "Engine", "status": "open", "priority": 1, "labels": ["feature"]},
            {
                "id": "validate",
                "title": "Validate",
                "status": "open",
                "priority": 3,
                "labels": ["validation"],
                "dependencies": ["engine"],
            },
        ]

        result = build_continuation_brief(items, epic_id="epic")

        self.assertEqual(result["recommended_next_issue"]["id"], "engine")
        self.assertIn("priority 1", result["why_next"])
        self.assertIn("unblocks 1 downstream", result["why_next"])
        self.assertEqual([item["id"] for item in result["ready_issues"]], ["engine", "docs"])

    def test_beads_dependency_objects_ignore_parent_child_and_extract_blockers(self) -> None:
        items = [
            {"id": "epic", "title": "Continuation", "issue_type": "epic", "status": "open"},
            {
                "id": "architect",
                "title": "Frame",
                "issue_type": "task",
                "status": "open",
                "labels": ["architect"],
                "dependencies": [
                    {"issue_id": "architect", "depends_on_id": "epic", "type": "parent-child"},
                ],
                "parent": "epic",
            },
            {
                "id": "implementation",
                "title": "Implement",
                "issue_type": "task",
                "status": "open",
                "labels": ["workerbee"],
                "dependencies": [
                    {"issue_id": "implementation", "depends_on_id": "epic", "type": "parent-child"},
                    {"issue_id": "implementation", "depends_on_id": "architect", "type": "blocks"},
                ],
                "parent": "epic",
            },
        ]

        result = build_continuation_brief(items, epic_id="epic")
        blockers = {item["id"]: item["blockers"] for item in result["blocked_issues"]}

        self.assertEqual(result["recommended_next_issue"]["id"], "architect")
        self.assertEqual(blockers["implementation"], ["depends on architect (open)"])

    def test_epic_typed_items_are_not_recommended_as_next_work(self) -> None:
        items = [
            {"id": "requested-epic", "title": "Requested Epic", "type": "epic", "status": "open"},
            {"id": "fallback-epic", "title": "Fallback Epic", "type": "epic", "status": "open", "priority": 0},
            {"id": "task", "title": "Do Work", "type": "task", "status": "open", "priority": 2},
        ]

        result = build_continuation_brief(items, epic_id="requested-epic")

        self.assertEqual(result["recommended_next_issue"]["id"], "task")
        self.assertEqual([item["id"] for item in result["ready_issues"]], ["task"])

    def test_lane_dependency_blocks_on_any_open_item_in_that_lane(self) -> None:
        items = [
            {"id": "epic", "title": "Continuation", "type": "epic", "status": "open"},
            {"id": "design-closed", "title": "Closed Design", "status": "closed", "metadata": {"lane": "design"}},
            {"id": "design-open", "title": "Open Design", "status": "open", "metadata": {"lane": "design"}},
            {
                "id": "implementation",
                "title": "Implement",
                "status": "open",
                "dependencies": ["design"],
            },
        ]

        result = build_continuation_brief(items, epic_id="epic")
        blockers = {item["id"]: item["blockers"] for item in result["blocked_issues"]}

        self.assertEqual(blockers["implementation"], ["depends on design-open (open)"])

    def test_reports_blockers_and_guard_labels(self) -> None:
        items = [
            {"id": "epic", "title": "Continuation", "type": "epic", "status": "open"},
            {"id": "architect", "title": "Frame", "status": "open", "labels": ["architect"]},
            {
                "id": "implementation",
                "title": "Implement",
                "status": "open",
                "labels": ["workerbee"],
                "dependencies": ["architect"],
            },
            {
                "id": "contract",
                "title": "External lane",
                "status": "open",
                "labels": ["contractor-only", "no-codex-exec"],
            },
        ]

        result = build_continuation_brief(items, epic_id="epic")
        blockers = {item["id"]: item["blockers"] for item in result["blocked_issues"]}

        self.assertIn("depends on architect (open)", blockers["implementation"])
        self.assertIn("guard label contractor-only prevents normal Codex pickup", blockers["contract"])
        self.assertIn("guard label no-codex-exec prevents normal Codex pickup", blockers["contract"])

    def test_markdown_fallback_is_reduced_durability_and_preserves_modeling_note(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "workgraph.md"
            path.write_text(
                """# Example

> Reduced durability fallback: Beads is unavailable or not in use.

## Work Items

### epic: Example

- Type: `epic`
- Lane: `epic`
- Labels: `orchestration`
- Depends on lanes: none

### architect: Architect Frame

- Type: `task`
- Lane: `architect`
- Labels: `architect`, `framing`
- Depends on lanes: none

### implementation: Implement Example

- Type: `task`
- Lane: `implementation`
- Labels: `workerbee`, `implementation`
- Depends on lanes: `architect`
""",
                encoding="utf-8",
            )

            items = load_markdown_items(path, "epic")

        result = build_continuation_brief(items, epic_id="epic", source="markdown-workgraph")

        self.assertEqual(result["durability"], "reduced")
        self.assertEqual(result["source"], "markdown-workgraph")
        self.assertEqual(result["modeling_note"], MODELING_NOTE)
        self.assertIn(MODELING_NOTE, result["warnings"])
        self.assertEqual(result["recommended_next_issue"]["id"], "architect")
        self.assertEqual(result["blocked_issues"][0]["id"], "implementation")
        self.assertEqual(
            result["operator_handoff_packet"]["next_executable_bead"],
            "architect Architect Frame",
        )
        self.assertEqual(
            result["operator_handoff_packet"]["exact_command_resume"],
            "python3 scripts/cwo.py continue --epic epic --markdown-workgraph <path>",
        )

    def test_cli_json_uses_markdown_workgraph_without_bd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "workgraph.md"
            path.write_text(
                """# Example

> Reduced durability fallback: Beads is unavailable or not in use.

## Work Items

### epic: Example

- Type: `epic`
- Lane: `epic`
- Labels: `orchestration`
- Depends on lanes: none

### pm: PM Coordinate

- Type: `task`
- Lane: `pm`
- Labels: `pm`, `coordination`
- Depends on lanes: none
""",
                encoding="utf-8",
            )
            env = {**os.environ, "PATH": temp_dir}
            output = subprocess.check_output(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "continue_sprint.py"),
                    "--epic",
                    "epic",
                    "--markdown-workgraph",
                    str(path),
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                env=env,
                text=True,
            )

        result = json.loads(output)
        self.assertEqual(result["continuation_result_type"], "complex-work-orchestration-sprint-continuation")
        self.assertEqual(result["recommended_next_issue"]["id"], "pm")
        self.assertEqual(result["durability"], "reduced")
        self.assertIn("operator_handoff_packet", result)
        self.assertEqual(
            result["operator_handoff_packet"]["exact_command_resume"],
            f"python3 scripts/cwo.py continue --epic epic --markdown-workgraph {path}",
        )

    def test_cwo_entrypoint_runs_continue_text_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "workgraph.md"
            path.write_text(
                """# Example

> Reduced durability fallback: Beads is unavailable or not in use.

## Work Items

### epic: Example

- Type: `epic`
- Lane: `epic`
- Labels: `orchestration`
- Depends on lanes: none

### validation: Validate Example

- Type: `task`
- Lane: `validation`
- Labels: `validation`
- Depends on lanes: none
""",
                encoding="utf-8",
            )
            output = subprocess.check_output(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "cwo.py"),
                    "continue",
                    "--epic",
                    "epic",
                    "--markdown-workgraph",
                    str(path),
                ],
                cwd=ROOT,
                text=True,
            )

        self.assertIn("Sprint Continuation Brief", output)
        self.assertIn("validation Validate Example", output)
        self.assertIn("Operator Handoff Packet", output)
        self.assertIn(f"Exact command/resume: python3 scripts/cwo.py continue --epic epic --markdown-workgraph {path}", output)
        self.assertIn(MODELING_NOTE, output)

    @unittest.skipUnless(BD_PATH, "bd CLI not available")
    def test_cwo_continue_reads_real_bd_dependency_objects(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            subprocess.check_call(["git", "init", "-q"], cwd=temp_dir)
            subprocess.check_call(
                [
                    BD_PATH,
                    "init",
                    "--non-interactive",
                    "--skip-agents",
                    "--skip-hooks",
                    "-p",
                    "cwo",
                ],
                cwd=temp_dir,
                stdout=subprocess.DEVNULL,
            )

            def bd_output(*args: str) -> str:
                return subprocess.check_output([BD_PATH, *args], cwd=temp_dir, text=True).strip()

            epic = bd_output(
                "create",
                "Sprint continuation smoke",
                "--type",
                "epic",
                "--priority",
                "1",
                "--labels",
                "orchestration",
                "--silent",
            )
            architect = bd_output(
                "create",
                "Architect frame",
                "--type",
                "task",
                "--parent",
                epic,
                "--priority",
                "1",
                "--labels",
                "architect",
                "--silent",
            )
            implementation = bd_output(
                "create",
                "Implement next",
                "--type",
                "task",
                "--parent",
                epic,
                "--priority",
                "2",
                "--labels",
                "workerbee",
                "--deps",
                architect,
                "--silent",
            )
            env = {**os.environ, "BEADS_DIR": str(Path(temp_dir) / ".beads")}
            output = subprocess.check_output(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "cwo.py"),
                    "continue",
                    "--epic",
                    epic,
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                env=env,
                text=True,
            )

        result = json.loads(output)
        blockers = {item["id"]: item["blockers"] for item in result["blocked_issues"]}

        self.assertEqual(result["source"], "beads")
        self.assertEqual(result["durability"], "durable")
        self.assertEqual(result["recommended_next_issue"]["id"], architect)
        self.assertEqual(blockers[implementation], [f"depends on {architect} (open)"])
        self.assertIn("operator_handoff_packet", result)


if __name__ == "__main__":
    unittest.main()

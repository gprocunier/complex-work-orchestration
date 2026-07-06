from __future__ import annotations

import json
import os
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
        self.assertIn(MODELING_NOTE, output)


if __name__ == "__main__":
    unittest.main()

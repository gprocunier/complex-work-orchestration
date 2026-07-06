from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from summarize_resume_state import (  # noqa: E402
    coerce_items,
    field,
    labels,
    parse_markdown_workgraph,
    summarize,
)


class SummarizeResumeStateTests(unittest.TestCase):
    def test_coerce_items_accepts_list_or_wrapped_payload(self) -> None:
        item = {"id": "cwo-1", "title": "Task"}
        self.assertEqual(coerce_items([item, "skip"]), [item])
        self.assertEqual(coerce_items({"issues": [item]}), [item])
        self.assertEqual(coerce_items({"data": [item]}), [item])
        self.assertEqual(coerce_items({"other": [item]}), [])

    def test_helpers_render_compact_summary(self) -> None:
        item = {"issue_id": "cwo-2", "summary": "Review", "status": "open", "labels": ["a", "b"]}
        self.assertEqual(field(item, "id", "issue_id"), "cwo-2")
        self.assertEqual(labels(item), "a,b")
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            summarize("Ready", [item], 5)
        self.assertIn("## Ready", buffer.getvalue())
        self.assertIn("cwo-2 Review [open; a,b]", buffer.getvalue())

    def test_parse_markdown_workgraph_extracts_items(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "workgraph.md"
            path.write_text(
                """# Example

> Reduced durability fallback: Beads is unavailable or not in use.

## Work Items

### epic: Example

- Type: `epic`
- Lane: `epic`
- Labels: `orchestration`, `policy-routed`
- Depends on lanes: none
- Skills: `complex-work-orchestration`, `beads`

#### Acceptance

Done.
""",
                encoding="utf-8",
            )

            items = parse_markdown_workgraph(path)

        self.assertEqual(items[0]["id"], "epic")
        self.assertEqual(items[0]["title"], "Example")
        self.assertEqual(items[0]["status"], "markdown-fallback")
        self.assertEqual(items[0]["labels"], ["orchestration", "policy-routed"])

    def test_parse_markdown_workgraph_rejects_unknown_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "notes.md"
            path.write_text("# Notes\n", encoding="utf-8")

            with self.assertRaises(SystemExit) as context:
                parse_markdown_workgraph(path)

        self.assertIn("not a CWO Markdown workgraph fallback", str(context.exception))

    def test_cli_uses_markdown_workgraph_when_bd_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "workgraph.md"
            path.write_text(
                """# Example

> Reduced durability fallback: Beads is unavailable or not in use.

## Work Items

### implementation: Implement Example

- Type: `task`
- Lane: `implementation`
- Labels: `workerbee`, `implementation`
- Depends on lanes: `architect`
- Skills: `implementation`, `beads`
""",
                encoding="utf-8",
            )
            env = {**os.environ, "PATH": temp_dir}
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "summarize_resume_state.py"),
                    "--markdown-workgraph",
                    str(path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertIn("## Markdown workgraph fallback", result.stdout)
        self.assertIn(
            "implementation Implement Example [markdown-fallback; workerbee,implementation]",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()

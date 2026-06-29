from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from summarize_resume_state import coerce_items, field, labels, summarize  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_beads_brief import build_brief  # noqa: E402


SAMPLE_BEAD = [
    {
        "id": "cwo-1",
        "title": "Example Bead",
        "status": "open",
        "issue_type": "task",
        "parent": "cwo-epic",
        "labels": ["orchestration"],
        "description": "Assigned work.",
        "design": "Keep the architect in control.",
        "notes": "Current notes.",
        "dependencies": [
            {"id": "cwo-0", "title": "Rejected old plan", "status": "closed", "notes": "rejected"}
        ],
        "comments": [
            {
                "id": "comment-1",
                "author": "tester",
                "created_at": "2026-06-18T00:00:00Z",
                "text": "Architect accepted the focused plan.",
            },
            {
                "id": "comment-2",
                "author": "tester",
                "created_at": "2026-06-18T00:01:00Z",
                "text": "Gemini return is quarantined due to boundary-tainted claims.",
            },
        ],
    }
]


class BuildBeadsBriefTests(unittest.TestCase):
    @patch("build_beads_brief.show_bead_json")
    def test_none_depth_performs_no_bd_lookup(self, show_bead_json) -> None:
        brief = build_brief("cwo-1", depth="none", audience="subagent")

        show_bead_json.assert_not_called()
        self.assertEqual(brief["depth"], "none")
        self.assertIsNone(brief["bd_command"])
        self.assertFalse(brief["include_comments"])
        self.assertEqual(brief["entries"], [])

    @patch("build_beads_brief.show_bead_json", return_value=SAMPLE_BEAD)
    def test_summary_depth_omits_comments(self, show_bead_json) -> None:
        brief = build_brief("cwo-1", depth="summary", audience="main-thread")

        show_bead_json.assert_called_once_with("cwo-1", include_comments=False, include_dependents=False)
        self.assertEqual(brief["depth"], "summary")
        self.assertFalse(brief["include_comments"])
        self.assertEqual([entry["type"] for entry in brief["entries"]], ["assigned-bead"])

    @patch("build_beads_brief.show_bead_json", return_value=SAMPLE_BEAD)
    def test_focused_depth_includes_internal_comments_and_status_warnings(self, show_bead_json) -> None:
        brief = build_brief("cwo-1", depth="focused", audience="subagent")

        show_bead_json.assert_called_once_with("cwo-1", include_comments=True, include_dependents=False)
        self.assertTrue(brief["include_comments"])
        statuses = {entry.get("status") for entry in brief["entries"]}
        self.assertIn("accepted", statuses)
        self.assertIn("quarantined", statuses)
        self.assertTrue(any("quarantined" in warning for warning in brief["warnings"]))

    @patch("build_beads_brief.show_bead_json", return_value=SAMPLE_BEAD)
    def test_heavy_depth_includes_related_issue_summaries(self, show_bead_json) -> None:
        brief = build_brief("cwo-1", depth="heavy", audience="subagent")

        show_bead_json.assert_called_once_with("cwo-1", include_comments=True, include_dependents=False)
        self.assertIn("dependency", {entry["type"] for entry in brief["entries"]})
        self.assertTrue(any("rejected" in warning for warning in brief["warnings"]))

    def test_comment_bearing_contractor_brief_fails_closed(self) -> None:
        with self.assertRaises(SystemExit):
            build_brief("cwo-1", depth="focused", audience="contractor")


if __name__ == "__main__":
    unittest.main()

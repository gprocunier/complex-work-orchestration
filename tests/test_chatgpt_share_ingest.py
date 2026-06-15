from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from ingest_chatgpt_share_return import (  # noqa: E402
    extract_assistant_text,
    is_chatgpt_share_source,
    locate_reader,
    render_contractor_return,
    run_reader,
)


class FakeCompletedProcess:
    returncode = 0
    stderr = ""

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


class ChatGPTShareIngestTests(unittest.TestCase):
    def test_source_validation_accepts_chatgpt_shares_only(self) -> None:
        self.assertTrue(is_chatgpt_share_source("https://chatgpt.com/s/t_abc"))
        self.assertTrue(is_chatgpt_share_source("https://chatgpt.com/share/abc"))
        self.assertFalse(is_chatgpt_share_source("https://example.com/s/t_abc"))

    def test_locate_reader_prefers_explicit_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            reader = Path(tmpdir) / "reader.py"
            reader.write_text("# test\n", encoding="utf-8")
            self.assertEqual(locate_reader(str(reader)), reader.resolve())

    def test_run_reader_invokes_local_reader_json_mode(self) -> None:
        payload = {
            "messages": [{"role": "assistant", "text": "Plan looks ready.", "content_type": "text"}],
            "meta": {"method": "react-router-stream"},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            reader = Path(tmpdir) / "reader.py"
            reader.write_text("# test\n", encoding="utf-8")
            with patch(
                "ingest_chatgpt_share_return.subprocess.run",
                return_value=FakeCompletedProcess(json.dumps(payload)),
            ) as mocked:
                parsed = run_reader(reader, "https://chatgpt.com/s/t_abc", 30)
        self.assertEqual(parsed["messages"][0]["text"], "Plan looks ready.")
        self.assertIn("--format", mocked.call_args.args[0])
        self.assertIn("json", mocked.call_args.args[0])
        self.assertEqual(mocked.call_args.kwargs["timeout"], 30)

    def test_run_reader_times_out_wedged_reader(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            reader = Path(tmpdir) / "reader.py"
            reader.write_text("# test\n", encoding="utf-8")
            with patch(
                "ingest_chatgpt_share_return.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["reader.py"], 1),
            ):
                with self.assertRaises(SystemExit) as exc:
                    run_reader(reader, "https://chatgpt.com/s/t_abc", 1)
        self.assertIn("timed out", str(exc.exception))

    def test_extract_assistant_text_prefers_last_assistant_message(self) -> None:
        payload = {
            "title": "Review",
            "meta": {"method": "react-router-stream"},
            "messages": [
                {"role": "user", "text": "Please review."},
                {"role": "assistant", "text": "First answer."},
                {"role": "assistant", "text": "Final answer.", "id": "m2"},
            ],
        }
        text, provenance = extract_assistant_text(payload)
        self.assertEqual(text, "Final answer.")
        self.assertEqual(provenance["message_id"], "m2")

    def test_rendered_return_contains_required_sections_and_fenced_evidence(self) -> None:
        rendered = render_contractor_return(
            "Plan looks ready.\nStatus: not a section inside evidence.",
            source="https://chatgpt.com/s/t_abc",
            reader=Path("/tmp/reader.py"),
            provenance={"method": "react-router-stream", "message_id": "m2", "message_count": 2},
            bead_id="cwo-1",
            dispatch_id="dispatch-1",
            share_boundary="redacted-packet",
            job_description="contract-jd-master-plan-review",
            packet_sha256="packet-sha",
            executor="chatgpt_pro_5_5_extended_reasoning_browser",
        )
        self.assertIn("Contractor job description: contract-jd-master-plan-review", rendered)
        self.assertIn("Evidence:\n```text\nPlan looks ready.", rendered)
        self.assertIn("Share-boundary conformance:", rendered)
        self.assertIn("Peer-review disposition: Pending", rendered)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import ingest_chatgpt_share_return  # noqa: E402
from cwo_core.private_artifact import sha256_bytes, write_private_artifact  # noqa: E402
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


CAPTURE_CHECKS = ("request_turn", "response_turn", "completion_confirmed", "content_stable", "conversation_stable", "assistant_extraction")


def write_private_return(directory: Path, text: str, **overrides: object) -> Path:
    response_name = overrides.pop("response_name", "run.response.txt")
    data = text.encode("utf-8")
    write_private_artifact(directory, response_name, data)
    provenance = {
        "artifact_type": "chatgpt-browser-private-response",
        "version": 4,
        "captured_at": "2026-10-21T00:00:00Z",
        "capture_complete": True,
        "capture_checks": {name: True for name in CAPTURE_CHECKS},
        "capture_incomplete_reasons": [],
        "dispatch_id": "dispatch-1",
        "bead_id": "cwo-1",
        "executor": "chatgpt_pro_browser_master_reviewer",
        "packet_sha256": "a" * 64,
        "prompt_sha256": "b" * 64,
        "request_id": "0123456789abcdef0123456789abcdef",
        "submitted_sha256": "c" * 64,
        "conversation_id": "conv-0001",
        "conversation_url": "https://chatgpt.com/c/conv-0001",
        "assistant_message_id": "msg-1",
        "user_message_id": "msg-0",
        "response_extraction": "assistant-message",
        "response_file": response_name,
        "response_sha256": sha256_bytes(data),
        "response_chars": len(text),
        "share": {"created": False},
    }
    provenance.update(overrides)
    return write_private_artifact(directory, "run.provenance.json", json.dumps(provenance).encode("utf-8"))


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
            pins = frozenset({sha256_bytes(reader.read_bytes())})
            with patch(
                "ingest_chatgpt_share_return.subprocess.run",
                return_value=FakeCompletedProcess(json.dumps(payload)),
            ) as mocked:
                parsed = run_reader(reader, "https://chatgpt.com/s/t_abc", 30, pins=pins)
        self.assertEqual(parsed["messages"][0]["text"], "Plan looks ready.")
        self.assertIn("--format", mocked.call_args.args[0])
        self.assertIn("json", mocked.call_args.args[0])
        self.assertEqual(mocked.call_args.kwargs["timeout"], 30)

    def test_run_reader_times_out_wedged_reader(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            reader = Path(tmpdir) / "reader.py"
            reader.write_text("# test\n", encoding="utf-8")
            pins = frozenset({sha256_bytes(reader.read_bytes())})
            with patch(
                "ingest_chatgpt_share_return.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["reader.py"], 1),
            ):
                with self.assertRaises(SystemExit) as exc:
                    run_reader(reader, "https://chatgpt.com/s/t_abc", 1, pins=pins)
        self.assertIn("timed out", str(exc.exception))

    def test_extract_assistant_text_preserves_all_assistant_messages(self) -> None:
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
        self.assertIn("## Primary assistant message (id=m2)", text)
        self.assertLess(text.index("Final answer."), text.index("First answer."))
        self.assertIn("## Earlier Assistant Message Archive", text)
        self.assertIn("### Earlier assistant message 1 of 1", text)
        self.assertIn("First answer.", text)
        self.assertIn("---", text)
        self.assertIn("Final answer.", text)
        self.assertEqual(provenance["message_id"], "m2")
        self.assertEqual(provenance["assistant_message_ids"], ["m2"])
        self.assertEqual(provenance["assistant_message_count"], 2)

    def test_extract_assistant_text_records_string_message_ids_only(self) -> None:
        payload = {
            "messages": [
                {"role": "assistant", "text": "First answer.", "id": {"unexpected": "object"}},
                {"role": "assistant", "text": "Final answer.", "id": "m2"},
            ],
        }
        _text, provenance = extract_assistant_text(payload)
        self.assertEqual(provenance["assistant_message_ids"], ["m2"])

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
            executor="chatgpt_pro_browser_master_reviewer",
        )
        self.assertIn("Contractor job description: contract-jd-master-plan-review", rendered)
        self.assertIn("Evidence:\n```text\nPlan looks ready.", rendered)
        self.assertIn("Share-boundary conformance:", rendered)
        self.assertIn("Peer-review disposition: Pending", rendered)


    def run_ingest_main(self, argv: list[str]) -> tuple[str, BaseException | None]:
        stdout = io.StringIO()
        raised = None
        with patch.object(sys, "argv", ["ingest_chatgpt_share_return.py", *argv]), contextlib.redirect_stdout(stdout):
            try:
                ingest_chatgpt_share_return.main()
            except SystemExit as exc:
                raised = exc
        return stdout.getvalue(), raised

    def test_private_artifact_round_trip_feeds_a_contractor_return(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            provenance = write_private_return(Path(tmpdir) / "returns", "Findings: add an idempotency key.")
            rendered, raised = self.run_ingest_main(["--private-artifact", str(provenance), "--bead", "cwo-1"])
            metadata_out, metadata_raised = self.run_ingest_main(["--private-artifact", str(provenance), "--json"])
        self.assertIsNone(raised)
        self.assertIsNone(metadata_raised)
        self.assertIn("Private ChatGPT browser response ingested", rendered)
        self.assertIn("Findings: add an idempotency key.", rendered)
        self.assertIn("no public share link was created", rendered)
        self.assertNotIn("Share page parsed", rendered)
        metadata = json.loads(metadata_out)
        self.assertEqual(metadata["source_kind"], "private-artifact")
        self.assertEqual(metadata["conversation_id"], "conv-0001")
        self.assertEqual(metadata["response_sha256"], sha256_bytes(b"Findings: add an idempotency key."))

    def test_private_artifact_refuses_substitution_and_mismatch(self) -> None:
        def digest_mismatch(directory: Path) -> Path:
            return write_private_return(directory, "Genuine text", response_sha256="0" * 64)

        def incomplete(directory: Path) -> Path:
            return write_private_return(directory, "Partial", capture_complete=False)

        def unsafe_name(directory: Path) -> Path:
            return write_private_return(directory, "Text", response_file="../escape.txt")

        def wrong_type(directory: Path) -> Path:
            return write_private_return(directory, "Text", artifact_type="something-else")

        def group_readable(directory: Path) -> Path:
            path = write_private_return(directory, "Text")
            os.chmod(path, 0o640)
            return path

        def symlinked_response(directory: Path) -> Path:
            path = write_private_return(directory, "Text", response_name="real.txt", response_file="link.txt")
            (directory / "link.txt").symlink_to(directory / "real.txt")
            return path

        def empty(directory: Path) -> Path:
            return write_private_return(directory, "   ")

        cases = {
            "digest mismatch": (digest_mismatch, []),
            "incomplete capture": (incomplete, []),
            "unsafe response name": (unsafe_name, []),
            "wrong artifact type": (wrong_type, []),
            "group readable provenance": (group_readable, []),
            "symlinked response": (symlinked_response, []),
            "empty response": (empty, []),
            "version 1 record": (lambda d: write_private_return(d, "Text", version=1), []),
            "unverified check": (lambda d: write_private_return(d, "Text", capture_checks={name: name != "response_turn" for name in CAPTURE_CHECKS}), []),
            "version 2 record": (lambda d: write_private_return(d, "Text", version=2), []),
            "version 3 record without request binding": (lambda d: write_private_return(d, "Text", version=3), []),
            "missing request id": (lambda d: write_private_return(d, "Text", request_id=None), []),
            "malformed request id": (lambda d: write_private_return(d, "Text", request_id="0123"), []),
            "bad submitted digest": (lambda d: write_private_return(d, "Text", submitted_sha256="not-a-digest"), []),
            "conversation on another origin": (lambda d: write_private_return(d, "Text", conversation_url="https://chatgpt.com.example/c/conv-0001"), []),
            "url names another conversation": (lambda d: write_private_return(d, "Text", conversation_url="https://chatgpt.com/c/other-0002"), []),
            "length mismatch": (lambda d: write_private_return(d, "Text", response_chars=999), []),
            "missing assistant id": (lambda d: write_private_return(d, "Text", assistant_message_id=None), []),
            "missing user id": (lambda d: write_private_return(d, "Text", user_message_id=None), []),
            "missing conversation": (lambda d: write_private_return(d, "Text", conversation_id=None), []),
            "missing packet identity": (lambda d: write_private_return(d, "Text", packet_sha256=None), []),
            "bad prompt digest": (lambda d: write_private_return(d, "Text", prompt_sha256="not-a-digest"), []),
            "fallback extraction": (lambda d: write_private_return(d, "Text", response_extraction="conversation-delta"), []),
            "old extraction label": (lambda d: write_private_return(d, "Text", response_extraction="assistant-selector"), []),
            "wrong packet": (lambda d: write_private_return(d, "Text"), ["--packet-sha256", "q" * 64]),
            "wrong dispatch": (lambda d: write_private_return(d, "Text"), ["--dispatch-id", "other"]),
            "wrong bead": (lambda d: write_private_return(d, "Text"), ["--bead", "cwo-2"]),
        }
        for label, (build, extra) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                provenance = build(Path(tmpdir) / "returns")
                rendered, raised = self.run_ingest_main(["--private-artifact", str(provenance), *extra])
                self.assertIsNotNone(raised)
                self.assertEqual(rendered, "")

    def test_private_reads_are_pinned_and_never_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            provenance = write_private_return(base / "returns", "Text")
            # A symlinked parent directory is refused even though the files are genuine.
            (base / "alias").symlink_to(base / "returns")
            rendered, raised = self.run_ingest_main(["--private-artifact", str(base / "alias" / provenance.name)])
            self.assertIsNotNone(raised)
            self.assertEqual(rendered, "")
            # A parent-directory component is refused rather than collapsed: here
            # it would erase the symlinked component and still name the genuine files.
            (base / "returns" / "sub").mkdir(mode=0o700)
            rendered, raised = self.run_ingest_main(["--private-artifact", str(base / "alias" / ".." / "returns" / provenance.name)])
            self.assertIsNotNone(raised)
            self.assertIn("parent-directory", str(raised))
            self.assertEqual(rendered, "")
            rendered, raised = self.run_ingest_main(["--private-artifact", str(base / "returns" / "sub" / ".." / provenance.name)])
            self.assertIsNotNone(raised)
            self.assertEqual(rendered, "")
            # A FIFO in place of the response file is refused at once, not waited on.
            fifo_dir = base / "fifo"
            fifo_provenance = write_private_return(fifo_dir, "Text", response_name="real.txt", response_file="pipe.txt")
            os.mkfifo(fifo_dir / "pipe.txt", 0o600)
            started = time.monotonic()
            rendered, raised = self.run_ingest_main(["--private-artifact", str(fifo_provenance)])
            self.assertLess(time.monotonic() - started, 10)
            self.assertIsNotNone(raised)

    def test_refused_ingest_creates_or_changes_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            provenance = write_private_return(base / "returns", "Text", response_chars=999)
            fresh = base / "fresh.md"
            existing = base / "existing.md"
            existing.write_text("previous evaluation input\n", encoding="utf-8")
            for target in (fresh, existing):
                with self.subTest(target=target.name):
                    rendered, raised = self.run_ingest_main(["--private-artifact", str(provenance), "--output", str(target)])
                    self.assertIsNotNone(raised)
                    self.assertEqual(rendered, "")
            self.assertFalse(fresh.exists())
            self.assertEqual(existing.read_text(encoding="utf-8"), "previous evaluation input\n")

    def test_ingested_private_return_feeds_evaluation(self) -> None:
        from cwo_core.returns import make_acceptance_decision

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            provenance = write_private_return(base / "returns", "Findings: add an idempotency key before enabling retries.")
            output = base / "return.md"
            _, raised = self.run_ingest_main(["--private-artifact", str(provenance), "--output", str(output), "--bead", "cwo-1"])
            self.assertIsNone(raised)
            decision = make_acceptance_decision(output.read_text(encoding="utf-8"), bead_id="cwo-1", dispatch_id="dispatch-1")
        self.assertIn("verdict", decision)
        self.assertIn("architect_review_required", decision)

    def test_reader_admission_never_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            fifo = Path(tmpdir) / "read_chatgpt_share.py"
            os.mkfifo(fifo)
            started = time.monotonic()
            with self.assertRaisesRegex(SystemExit, "share-reader-not-pinned"):
                ingest_chatgpt_share_return.require_trusted_reader(fifo)  # no pins: nothing is read
            with self.assertRaisesRegex(SystemExit, "share-reader-not-pinned"):
                ingest_chatgpt_share_return.require_trusted_reader(fifo, frozenset({"0" * 64}))  # pins: non-blocking, not regular
            self.assertLess(time.monotonic() - started, 5)

    def test_unpinned_reader_never_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            marker = Path(tmpdir) / "READER_RAN"
            reader = Path(tmpdir) / "read_chatgpt_share.py"
            reader.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\nprint('{{}}')\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "share-reader-not-pinned"):
                ingest_chatgpt_share_return.run_reader(reader, "https://chatgpt.com/share/abc", 5)
            self.assertFalse(marker.exists(), "an unpinned reader is never executed")
            # A caller-chosen hash is not a pin: only CWO's own constant counts.
            rendered, raised = self.run_ingest_main(["https://chatgpt.com/share/abc", "--reader", str(reader)])
            self.assertIsNotNone(raised)
            self.assertFalse(marker.exists())

    def test_pinned_reader_runs_its_verified_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            reader = Path(tmpdir) / "read_chatgpt_share.py"
            reader.write_text("import json\nprint(json.dumps({'messages': [{'role': 'assistant', 'text': 'ok'}]}))\n", encoding="utf-8")
            pins = frozenset({sha256_bytes(reader.read_bytes())})
            payload = ingest_chatgpt_share_return.run_reader(reader, "https://chatgpt.com/share/abc", 10, pins=pins)
            self.assertEqual(payload["messages"][0]["text"], "ok")

    def test_exactly_one_source_is_required(self) -> None:
        for argv in ([], ["https://chatgpt.com/share/abc", "--private-artifact", "/nonexistent/p.json"]):
            with self.subTest(argv=argv):
                rendered, raised = self.run_ingest_main(argv)
                self.assertIsNotNone(raised)
                self.assertEqual(rendered, "")

if __name__ == "__main__":
    unittest.main()

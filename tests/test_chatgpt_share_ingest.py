from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import ingest_chatgpt_share_return  # noqa: E402
from cwo_core.host_records import HostRecordStore, using_test_store  # noqa: E402
from tests.browser_provenance_fixture import publish_return, saved_capture  # noqa: E402
from cwo_core.private_artifact import sha256_bytes  # noqa: E402
CAPTURE_CHECKS = ("request_turn", "response_turn", "completion_confirmed", "content_stable", "conversation_stable", "assistant_extraction")


PRIVATE_SELECTIONS: dict[str, list[str]] = {}


def write_private_return(directory: Path, text: str, **overrides: object) -> Path:
    path, selection = publish_return(directory, text, **overrides)
    PRIVATE_SELECTIONS[str(path.resolve())] = selection
    return path


class ChatGPTShareIngestTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = HostRecordStore.for_tests(Path(temp.name) / "host")
        self.directory = Path(temp.name)
        context = using_test_store(self.store)
        context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        PRIVATE_SELECTIONS.clear()

    def run_ingest_main(self, argv: list[str], *, with_expectations: bool = True) -> tuple[str, BaseException | None]:
        if with_expectations and "--private-artifact" in argv:
            path = Path(argv[argv.index("--private-artifact") + 1])
            selection = PRIVATE_SELECTIONS.get(str(path.resolve()), [])
            argv = [*argv, *selection]
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
            target = Path(tmpdir) / "return.md"
            stdout, raised = self.run_ingest_main(["--private-artifact", str(provenance), "--bead", "cwo-1", "--output", str(target)])
            self.assertTrue(stdout == "", "explicit body output also emitted stdout")
            rendered = target.read_text() if target.exists() else ""
            metadata_out, metadata_raised = self.run_ingest_main(["--private-artifact", str(provenance), "--json"])
        self.assertIsNone(raised)
        self.assertIsNone(metadata_raised)
        self.assertTrue("Private ChatGPT browser response ingested" in rendered, "private return summary missing")
        self.assertTrue("Findings: add an idempotency key." in rendered, "private return body missing")
        self.assertTrue("no public share link was created" in rendered, "private return boundary missing")
        self.assertFalse("Share page parsed" in rendered, "private return claims share parsing")
        metadata = json.loads(metadata_out)
        self.assertEqual(metadata["source_kind"], "private-artifact")
        self.assertEqual(metadata["conversation_id"], "conv-0001")
        self.assertEqual(metadata["response_sha256"], sha256_bytes(b"Findings: add an idempotency key."))

    def test_private_intake_requires_independent_expectations(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            provenance = write_private_return(Path(tmpdir) / "returns", "PRIVATE_SENTINEL")
            output = Path(tmpdir) / "output.md"
            rendered, raised = self.run_ingest_main(["--private-artifact", str(provenance), "--output", str(output)], with_expectations=False)
            self.assertIsNotNone(raised)
            self.assertTrue(rendered == "", "refusal produced output")
            self.assertFalse(output.exists())

    def test_private_return_preserves_exact_utf8_bytes_and_body_free_metadata(self) -> None:
        from cwo_core import browser_provenance as api, host_records
        text = " \nPRIVATE_SENTINEL Résumé — 雪\r\n  "
        with tempfile.TemporaryDirectory() as tmpdir:
            provenance = write_private_return(Path(tmpdir) / "returns", text)
            selection = PRIVATE_SELECTIONS[str(provenance.resolve())]
            packet = json.loads(Path(selection[1]).read_text())
            expected = api.select_private_capture(packet, packet_source_sha256=selection[3], capture_event_hash=selection[5])
            decoded, record, _ = ingest_chatgpt_share_return.load_private_response(provenance, expected=expected)
            self.assertTrue(decoded.encode() == text.encode(), "response bytes changed")
            self.assertEqual(record["response_bytes"], len(text.encode()))
            metadata, raised = self.run_ingest_main(["--private-artifact", str(provenance), "--json"])
            self.assertIsNone(raised)
            self.assertFalse("PRIVATE_SENTINEL" in metadata, "response body entered metadata")
            self.assertFalse("PRIVATE_SENTINEL" in host_records.configured_store().audit_file.read_text(), "response body entered audit")
            self.assertIn("same-user", json.loads(metadata)["access_limit"])

    def test_private_default_stdout_is_metadata_and_output_body_is_explicit(self) -> None:
        text = " \nPRIVATE_DEFAULT_SENTINEL Résumé — 雪\r\n  "
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            provenance = write_private_return(base / "returns", text)
            stdout, raised = self.run_ingest_main(["--private-artifact", str(provenance)])
            self.assertIsNone(raised)
            self.assertFalse("PRIVATE_DEFAULT_SENTINEL" in stdout, "default stdout exposed response")
            self.assertEqual(json.loads(stdout)["source_kind"], "private-artifact")
            target = base / "return.md"
            stdout, raised = self.run_ingest_main(["--private-artifact", str(provenance), "--output", str(target)])
            self.assertIsNone(raised)
            self.assertTrue(stdout == "", "explicit body output also emitted stdout")
            self.assertTrue(text.encode() in target.read_bytes(), "explicit output changed response bytes")

    def test_coherently_rewritten_chain_cannot_replace_independent_audit(self) -> None:
        from cwo_core import host_records
        substitutions = {
            "subject": {"kind": "packet-input", "source_sha256": "0" * 64},
            "packet_source_sha256": "0" * 64, "packet_sha256": "0" * 64,
            "request_id": "2" * 32, "outbound_source_sha256": "0" * 64,
            "outbound_export_sha256": "0" * 64, "outbound_prepared_sha256": "0" * 64,
            "outbound_screen_version": 999, "send_admission_sha256": "0" * 64,
            "submitted_sha256": "0" * 64, "conversation_id": "conv-9999",
            "user_message_id": "other-user", "assistant_message_id": "other-assistant",
            "observed_document_request_id": "2" * 32, "observed_user_sha256": "0" * 64,
            "response": "REWRITTEN_PRIVATE_SENTINEL",
        }
        for key, value in substitutions.items():
            with self.subTest(field=key), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                provenance = write_private_return(base / "returns", "PRIVATE_SENTINEL")
                record = json.loads(provenance.read_text())
                if key == "response":
                    response = provenance.parent / record["response_file"]
                    response.write_text(value)
                    record.update(response_sha256=sha256_bytes(value.encode()), response_bytes=len(value.encode()),
                                  response_chars=len(value))
                else:
                    record[key] = value
                if key == "conversation_id":
                    record.update(pinned_conversation_id=value, conversation_url="https://chatgpt.com/c/" + value)
                provenance.write_text(json.dumps(record))
                target = base / "existing.md"
                target.write_text("previous evaluation\n")
                audit_before = host_records.configured_store().audit_file.read_bytes()
                stdout, raised = self.run_ingest_main(["--private-artifact", str(provenance), "--output", str(target)])
                self.assertIsNotNone(raised)
                self.assertTrue("independent audit provenance digest" in str(raised), "unexpected refusal boundary")
                self.assertFalse("PRIVATE_SENTINEL" in str(raised), "response body entered diagnostics")
                self.assertTrue(stdout == "", "refusal produced output")
                self.assertTrue(target.read_text() == "previous evaluation\n", "refusal replaced output")
                self.assertEqual(sha256_bytes(host_records.configured_store().audit_file.read_bytes()), sha256_bytes(audit_before))

    def test_current_packet_and_capture_reference_are_independently_selected(self) -> None:
        from cwo_core.util import packet_payload_hash
        with tempfile.TemporaryDirectory() as tmpdir:
            provenance = write_private_return(Path(tmpdir) / "returns", "PRIVATE_SENTINEL")
            selection = PRIVATE_SELECTIONS[str(provenance.resolve())]
            for index, value in ((3, "invalid-source"), (3, "0" * 64), (5, "0" * 64)):
                changed = list(selection)
                changed[index] = value
                stdout, raised = self.run_ingest_main(["--private-artifact", str(provenance), *changed], with_expectations=False)
                self.assertTrue(stdout == "", "refusal produced output")
                self.assertIsNotNone(raised)
                self.assertFalse("PRIVATE_SENTINEL" in str(raised), "response body entered diagnostics")
            packet_path = Path(selection[1])
            packet = json.loads(packet_path.read_text())
            packet["dispatch_id"] = "replacement"
            packet["packet_sha256"] = packet_payload_hash(packet)
            packet_path.write_text(json.dumps(packet))
            stdout, raised = self.run_ingest_main(["--private-artifact", str(provenance)])
            self.assertTrue(stdout == "", "refusal produced output")
            self.assertIsNotNone(raised)

    def test_private_file_substitution_hardlinks_and_missing_response_refuse(self) -> None:
        for kind in ("provenance-symlink", "provenance-hardlink", "response-hardlink", "missing-response", "open-directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmpdir:
                base = Path(tmpdir)
                provenance = write_private_return(base / "returns", "PRIVATE_SENTINEL")
                selection = PRIVATE_SELECTIONS[str(provenance.resolve())]
                record = json.loads(provenance.read_text())
                response = provenance.parent / record["response_file"]
                if kind == "provenance-symlink":
                    real = provenance.with_name("real.json")
                    provenance.rename(real)
                    provenance.symlink_to(real)
                elif kind == "provenance-hardlink":
                    os.link(provenance, provenance.with_name("alias.json"))
                elif kind == "response-hardlink":
                    os.link(response, response.with_name("alias.txt"))
                elif kind == "missing-response":
                    response.unlink()
                else:
                    provenance.parent.chmod(0o755)
                # Keep the original independently selected event even when the path changes.
                stdout, raised = self.run_ingest_main(["--private-artifact", str(provenance), *selection], with_expectations=False)
                self.assertTrue(stdout == "", "refusal produced output")
                self.assertIsNotNone(raised)
                self.assertFalse("PRIVATE_SENTINEL" in str(raised), "response body entered diagnostics")

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
            "version 4 record": (lambda d: write_private_return(d, "Text", version=4), []),
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

    def test_saved_capture_metadata_and_explicit_output_use_independent_audit(self) -> None:
        path, response, packet, source_sha256, event = saved_capture(self.directory / "capture", self.store)
        original_audit = self.store.audit_file.read_bytes()
        selection = ["--private-artifact", str(path), "--packet", str(packet),
                     "--packet-source-sha256", source_sha256, "--capture-event", event["event_hash"]]
        out, raised = self.run_ingest_main(selection, with_expectations=False)
        self.assertIsNone(raised)
        self.assertEqual(json.loads(out)["response_sha256"], sha256_bytes(response))
        self.assertNotIn(response.decode().strip(), out)
        target = self.directory / "return.md"
        out, raised = self.run_ingest_main([*selection, "--output", str(target)], with_expectations=False)
        self.assertIsNone(raised)
        self.assertEqual(out, "")
        self.assertIn(response, target.read_bytes())
        self.assertEqual(self.store.audit_file.read_bytes(), original_audit)

    def test_retired_sources_refuse_before_reads_or_writes(self) -> None:
        html = self.directory / "share.html"
        html.write_text("Example saved page", encoding="utf-8")
        target = self.directory / "return.md"
        target.write_text("Existing return", encoding="utf-8")
        for source in ("https://chatgpt.com/share/example", str(html), str(html.with_suffix(".missing"))):
            with self.subTest(source=source), patch.object(Path, "is_file") as stat_file, \
                    patch.object(Path, "read_text") as read_file, \
                    patch.object(ingest_chatgpt_share_return, "private_capture_expectation") as select, \
                    patch.object(ingest_chatgpt_share_return, "atomic_write_text") as write:
                out, raised = self.run_ingest_main(
                    [source, "--reader", "/missing/reader", "--timeout", "1", "--packet", "/missing/packet",
                     "--output", str(target), "--json"], with_expectations=False)
                self.assertEqual(str(raised), "share URL and HTML intake is retired; use --private-artifact for browser returns")
                self.assertEqual(out, "")
                for effect in (stat_file, read_file, select, write):
                    effect.assert_not_called()
            self.assertEqual(target.read_text(encoding="utf-8"), "Existing return")
        self.assertFalse(self.store.audit_file.exists())

    def test_exactly_one_source_is_required(self) -> None:
        for argv in ([], ["https://chatgpt.com/share/abc", "--private-artifact", "/nonexistent/p.json"]):
            with self.subTest(argv=argv):
                rendered, raised = self.run_ingest_main(argv)
                self.assertIsNotNone(raised)
                self.assertEqual(rendered, "")

if __name__ == "__main__":
    unittest.main()

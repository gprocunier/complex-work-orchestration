"""Formal candidate subjects use real inert current-source verification, never candidate labels."""
from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import audit, candidate_identity as ci, host_records, requirement_baseline as rb  # noqa: E402
from cwo_core import browser_provenance as api  # noqa: E402
from cwo_core.private_artifact import sha256_bytes, write_private_artifact  # noqa: E402
from tests.browser_provenance_fixture import capture_record, production_packet  # noqa: E402


def candidate_fixture(parent: Path) -> dict:
    """Small synthetic loose-object fixture; no clone, Git command or mutable real repository."""
    repo = parent / "source"
    objects = repo / ".git/objects"
    objects.mkdir(parents=True)
    (repo / ".git/refs").mkdir()
    (repo / ".git/config").write_text("[core]\nrepositoryformatversion = 0\nbare = false\n")

    def obj(kind: str, content: bytes) -> str:
        raw = kind.encode() + b" " + str(len(content)).encode() + b"\0" + content
        digest = hashlib.sha1(raw).hexdigest()
        path = objects / digest[:2] / digest[2:]
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(zlib.compress(raw))
        return digest

    content = b"implementation\n"
    blob = obj("blob", content)
    tree = obj("tree", b"100644 source.txt\0" + bytes.fromhex(blob))
    commit = obj("commit", (f"tree {tree}\nauthor Test <test@example.invalid> 0 +0000\n"
                            "committer Test <test@example.invalid> 0 +0000\n\nfixture\n").encode())
    (repo / ".git/HEAD").write_text(commit + "\n")
    (repo / "source.txt").write_bytes(content)
    baseline = json.loads((ROOT / "tests/fixtures/requirement-baseline/baseline-v1.json").read_text())
    chain = rb.resolve_chain(baseline)
    record = ci.capture_candidate(repo, chain=chain, base_commit=commit, scope_paths=["source.txt"])
    return {"candidate_record": record, "candidate_root": repo}


class BrowserSubjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.context = host_records.using_test_store(host_records.HostRecordStore.for_tests(self.base / "host"))
        self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.candidate = candidate_fixture(self.base)

    def selected(self):
        packet = production_packet(**self.candidate)
        identity = {key: packet[key] for key in ("packet_sha256", "dispatch_id", "bead_id")}
        audit.record_audit_event({"event_type": "packet_built", **identity})
        record, source = capture_record(packet, "Exact candidate findings.")
        raw = json.dumps(record).encode()
        event = audit.record_audit_event({"event_type": "chatgpt_browser_dispatch", **identity,
                                         **api.capture_audit_fields(record, sha256_bytes(raw))})
        expectation = api.select_private_capture(packet, packet_source_sha256=source,
                                                capture_event_hash=event["event_hash"], **self.candidate)
        return packet, record, raw, expectation

    def test_formal_candidate_packet_preparation_capture_and_audit_positive(self):
        packet, record, raw, expected = self.selected()
        self.assertEqual(packet["subject"]["candidate_sha256"], ci.candidate_digest(self.candidate["candidate_record"]))
        self.assertEqual(set(packet["subject"]), {"kind", "source_sha256", "candidate_sha256"})
        self.assertTrue(api.validate_private_capture(record, b"Exact candidate findings.", expected=expected,
                                                     provenance_bytes=raw) == "Exact candidate findings.", "response bytes changed")

    def test_review_identity_does_not_require_closure_history(self):
        context = {key: self.candidate[key] for key in ("candidate_record", "candidate_root")}
        packet = production_packet(**context)
        self.assertEqual(packet["subject"]["candidate_sha256"], ci.candidate_binding(context["candidate_record"]))

    def test_candidate_cli_intake_uses_private_record_and_actual_current_source(self):
        import ingest_chatgpt_share_return as ingest
        packet, record, raw, expected = self.selected()
        directory = self.base / "returns"
        provenance = write_private_artifact(directory, "run.provenance.json", raw)
        write_private_artifact(directory, record["response_file"], b"Exact candidate findings.")
        packet_path, candidate_path = self.base / "packet.json", self.base / "candidate.json"
        packet_path.write_text(json.dumps(packet))
        candidate_path.write_text(json.dumps(self.candidate["candidate_record"]))
        args = ["ingest_chatgpt_share_return.py", "--private-artifact", str(provenance), "--packet", str(packet_path),
                "--packet-source-sha256", expected.packet_source_sha256, "--capture-event", expected.capture_event_hash,
                "--candidate", str(candidate_path), "--candidate-root", str(self.candidate["candidate_root"]), "--json"]
        output = io.StringIO()
        with patch.object(sys, "argv", args), contextlib.redirect_stdout(output):
            ingest.main()
        metadata = json.loads(output.getvalue())
        self.assertEqual(metadata["response_sha256"], record["response_sha256"])
        self.assertFalse("Exact candidate findings." in output.getvalue(), "response body entered CLI metadata")
        (self.candidate["candidate_root"] / "source.txt").write_text("drift\n")
        output = io.StringIO()
        with patch.object(sys, "argv", args), contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            ingest.main()
        self.assertTrue(output.getvalue() == "", "stale candidate emitted output")

    def test_subject_rejects_private_records_and_fake_candidate_labels(self):
        from cwo_core.packets import contractor_subject_errors
        packet = production_packet()
        for subject in ({**packet["subject"], "candidate_record": self.candidate["candidate_record"]},
                        {**packet["subject"], "kind": "candidate", "candidate_sha256": "selected-label"},
                        {**packet["subject"], "kind": "candidate"}, {"kind": "packet-input", "source_sha256": "bad"}):
            with self.subTest(fields=list(subject)):
                self.assertTrue(contractor_subject_errors({**packet, "subject": subject}))

    def test_current_candidate_source_changes_after_selection_refuse(self):
        _, record, raw, expected = self.selected()
        (self.candidate["candidate_root"] / "source.txt").write_text("changed after selection\n")
        with self.assertRaises(SystemExit):
            api.validate_private_capture(record, b"Exact candidate findings.", expected=expected, provenance_bytes=raw)

    def test_malformed_stale_substituted_and_absent_candidate_context_refuse(self):
        packet, _, _, expected = self.selected()
        args = {"packet_source_sha256": expected.packet_source_sha256, "capture_event_hash": expected.capture_event_hash}
        for candidate in ({}, {**self.candidate, "candidate_record": {"candidate": "label"}},
                          {**self.candidate, "candidate_root": self.base / "absent"}):
            with self.subTest(candidate=list(candidate)), self.assertRaises(SystemExit):
                api.select_private_capture(packet, **args, **candidate)
        substituted = copy.deepcopy(self.candidate["candidate_record"])
        substituted["tree"] = "0" * 40
        with self.assertRaises(SystemExit):
            api.select_private_capture(packet, **args, **{**self.candidate, "candidate_record": substituted})
        (self.candidate["candidate_root"] / "source.txt").write_text("stale source\n")
        with self.assertRaises(SystemExit):
            api.select_private_capture(packet, **args, **self.candidate)


if __name__ == "__main__":
    unittest.main()

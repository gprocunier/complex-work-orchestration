"""Private capture identity and independently persisted intake expectations."""
from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_contractor_packet  # noqa: E402
from cwo_core import audit, host_records  # noqa: E402
from cwo_core.outbound_screen import require_clean  # noqa: E402
from cwo_core.prepared_outbound import PreparedSource  # noqa: E402
from cwo_core.private_artifact import sha256_bytes  # noqa: E402
from cwo_core.util import artifact_hash, packet_payload_hash  # noqa: E402


def production_packet() -> dict:
    bead = json.loads((ROOT / "examples/sample-bead.json").read_text())
    bead["labels"] = ["contract-jd-master-plan-review", "contractor-only", "no-codex-exec"]
    return build_contractor_packet.build_packet(
        bead_id="cwo-1", bead_json=bead, executor="chatgpt_pro_browser_master_reviewer",
        share_boundary="redacted-packet", job_description_label="contract-jd-master-plan-review",
        allowed_files=[], inline_snippets=["Review the retry design."], external_opt_in=True,
        opt_in_basis="cli-flag", quota_info={"quota_checked": True, "quota_remaining": 4},
        dispatch_id="dispatch-1",
    )


class BrowserProvenanceTests(unittest.TestCase):
    def setUp(self):
        from cwo_core import browser_provenance
        self.api = browser_provenance
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.store = host_records.HostRecordStore.for_tests(self.base / "host")
        self.context = host_records.using_test_store(self.store)
        self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.packet = production_packet()
        audit.record_audit_event({"event_type": "packet_built", **self.identity()})
        self.prompt = "Review retry semantics."
        submitted = self.prompt + "\nRequest ID: " + "1" * 32
        source = PreparedSource.capture({"packet": self.packet, "load_options": {"review": True}})
        self.packet_source = source.sha256
        prepared = PreparedSource.capture({"prompt": self.prompt, "inputs": [source.sha256]})
        self.prepared = prepared.bind(prepared.value(), require_clean(submitted, surface="ChatGPT browser Send"))
        self.text = " \nRésumé — 雪\r\n  "
        self.browser = {
            "response_text": self.text, "capture_complete": True,
            "capture_checks": dict.fromkeys(browser_provenance.CAPTURE_CHECKS, True),
            "capture_incomplete_reasons": [], "request_id": "1" * 32,
            "submitted_sha256": artifact_hash(submitted), **self.prepared.metadata(),
            "send_admission_sha256": "d" * 64,
            "pinned_conversation_id": "conv-0001", "observed_document_request_id": "1" * 32,
            "observed_user_sha256": sha256_bytes(submitted.strip().encode()),
            "submitted_user_sha256": sha256_bytes(submitted.strip().encode()),
            "user_text_normalization": "crlf-strip-v1", "conversation_id": "conv-0001",
            "conversation_url": "https://chatgpt.com/c/conv-0001", "user_message_id": "user-1",
            "assistant_message_id": "assistant-1", "response_extraction": "assistant-message",
        }
        self.record = browser_provenance.build_private_provenance(
            {**self.packet, "packet_source_sha256": source.sha256}, self.prompt, self.browser,
            response_file="response.txt", captured_at="2026-11-14T00:00:00Z",
        )
        self.raw = (json.dumps(self.record, sort_keys=True) + "\n").encode()
        self.fields = browser_provenance.capture_audit_fields(self.record, sha256_bytes(self.raw))
        self.event = audit.record_audit_event({"event_type": "chatgpt_browser_dispatch", **self.identity(), **self.fields,
                                              "response_text": self.text})

    def identity(self):
        return {key: self.packet[key] for key in ("dispatch_id", "bead_id", "packet_sha256")}

    def expected(self, **changes):
        args = {"packet_source_sha256": self.packet_source, "capture_event_hash": self.event["event_hash"]}
        args.update(changes)
        return self.api.select_private_capture(self.packet, **args)

    def validate(self, record=None, raw=None, expected=None, response=None):
        return self.api.validate_private_capture(
            self.record if record is None else record,
            self.text.encode() if response is None else response,
            expected=self.expected() if expected is None else expected,
            provenance_bytes=self.raw if raw is None else raw,
        )

    def test_real_preparation_and_persisted_sanitizer_positive(self):
        self.assertTrue(self.validate() == self.text, "response bytes changed")
        self.assertNotEqual(self.packet_source, self.record["outbound_source_sha256"])
        self.assertEqual(self.record["response_bytes"], len(self.text.encode()))
        persisted = self.store.audit_events()[-1]
        for key, value in self.fields.items():
            self.assertEqual(persisted[key], value, key)
        self.assertFalse(self.text in self.store.audit_file.read_text(), "response body entered audit")
        self.assertIn("same-user", self.expected().access_limit)

    def test_missing_expectations_and_missing_independent_pins_refuse(self):
        with self.assertRaises(SystemExit):
            self.api.validate_private_capture(self.record, self.text.encode(), expected=None, provenance_bytes=self.raw)
        for changes in ({"packet_source_sha256": None}, {"capture_event_hash": None},
                        {"capture_event_hash": "0" * 64}, {"packet_source_sha256": "0" * 64}):
            with self.subTest(changes=changes), self.assertRaises(SystemExit):
                self.expected(**changes)

    def test_packet_rehash_does_not_establish_production_provenance(self):
        self.packet["dispatch_id"] = "substituted"
        self.packet["packet_sha256"] = packet_payload_hash(self.packet)
        with self.assertRaises(SystemExit):
            self.expected()

    def test_coherent_provenance_rewrite_retains_independent_audit_refusal(self):
        changed = {**self.record, "conversation_id": "conv-9999", "pinned_conversation_id": "conv-9999",
                   "conversation_url": "https://chatgpt.com/c/conv-9999"}
        with self.assertRaisesRegex(SystemExit, "independent.*digest"):
            self.validate(changed, json.dumps(changed).encode())

    def test_replaced_expectation_cannot_authenticate_its_own_rewritten_json(self):
        changed = {**self.record, "conversation_id": "conv-9999", "pinned_conversation_id": "conv-9999",
                   "conversation_url": "https://chatgpt.com/c/conv-9999"}
        raw = json.dumps(changed).encode()
        event = {**self.event, **self.api.capture_audit_fields(changed, sha256_bytes(raw))}
        forged = replace(self.expected(), event_json=json.dumps(event))
        with self.assertRaises(SystemExit):
            self.validate(changed, raw, expected=forged)

    def test_complete_chain_substitutions_refuse(self):
        changes = {"packet_source_sha256": "0" * 64, "request_id": "2" * 32,
                   "outbound_source_sha256": "0" * 64, "outbound_export_sha256": "0" * 64,
                   "outbound_prepared_sha256": "0" * 64, "outbound_screen_version": 999,
                   "send_admission_sha256": "0" * 64, "submitted_sha256": "0" * 64,
                   "conversation_id": "conv-9999", "user_message_id": "other-user",
                   "assistant_message_id": "other-assistant", "observed_document_request_id": "2" * 32,
                   "observed_user_sha256": "0" * 64, "submitted_user_sha256": "0" * 64,
                   "subject": {"kind": "packet-input", "source_sha256": "0" * 64}}
        for field, value in changes.items():
            changed = {**self.record, field: value}
            with self.subTest(field=field), self.assertRaises(SystemExit):
                self.validate(changed, json.dumps(changed).encode())
        with self.assertRaises(SystemExit):
            self.validate(response=b"changed response")

    def test_subject_is_private_safe_and_inside_packet_hash(self):
        self.assertEqual(set(self.packet["subject"]), {"kind", "source_sha256"})
        self.assertEqual(self.packet["subject"]["kind"], "packet-input")
        original = self.packet["packet_sha256"]
        changed = copy.deepcopy(self.packet)
        changed["subject"]["source_sha256"] = "0" * 64
        self.assertNotEqual(packet_payload_hash(changed), original)
        with self.assertRaises(SystemExit):
            self.api.packet_subject(self.packet, candidate_record={"candidate": "label"})

    def test_omitted_chain_is_incomplete_and_historical_is_never_upgraded(self):
        for field in ("send_admission_sha256", "outbound_source_sha256", "observed_user_sha256"):
            browser = {key: value for key, value in self.browser.items() if key != field}
            record = self.api.build_private_provenance(self.packet, self.prompt, browser,
                                                      response_file="response.txt", captured_at="now")
            self.assertFalse(record["capture_complete"])
        for version in (1, 2, 3, 4):
            changed = {**self.record, "version": version}
            with self.subTest(version=version), self.assertRaises(SystemExit):
                self.validate(changed, json.dumps(changed).encode())

    def test_malformed_screen_metadata_produces_safe_validation_errors(self):
        for value in (float("nan"), float("inf"), [], {}, True):
            with self.subTest(value_type=type(value).__name__):
                errors = self.api.provenance_errors({**self.record, "outbound_screen_version": value})
                self.assertTrue(errors)
                self.assertFalse(self.text in str(errors))


if __name__ == "__main__":
    unittest.main()

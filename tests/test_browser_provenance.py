"""Private capture identity and independently persisted intake expectations."""
from __future__ import annotations

import copy
import contextlib
from dataclasses import replace
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_contractor_packet  # noqa: E402
from cwo_core import audit, browser_capture, host_records  # noqa: E402
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

    def test_trusted_host_publishes_exact_response_for_independent_intake(self):
        from ingest_chatgpt_share_return import load_private_response

        metadata = {**self.packet, "packet_source_sha256": self.packet_source}
        directory = browser_capture.resolve_response_dir(str(self.base / "returns"))
        artifact = browser_capture.write_private_response(
            directory, metadata=metadata, prompt=self.prompt, browser_result=self.browser,
        )
        provenance_path = Path(artifact["provenance_path"])
        with self.assertRaisesRegex(SystemExit, "independently selected"):
            load_private_response(provenance_path)
        with self.assertRaisesRegex(SystemExit, "independent audit provenance digest"):
            load_private_response(provenance_path, expected=self.expected())

        result = {**metadata, "epic_id": metadata.get("epic_id"), "prompt_sha256": artifact_hash(self.prompt),
                  "status": "completed", "response_artifact": artifact,
                  "response_text": self.text, "conversation_url": self.browser["conversation_url"]}
        event = browser_capture.record_browser_dispatch(result, quota_info={})
        self.assertEqual(event["event_type"], "chatgpt_browser_dispatch")
        self.assertEqual(artifact["capture_event_hash"], event["event_hash"])
        expected = self.expected(capture_event_hash=event["event_hash"])
        text, provenance, digest = load_private_response(provenance_path, expected=expected)
        self.assertEqual(text.encode("utf-8"), self.text.encode("utf-8"))
        self.assertTrue(provenance["capture_complete"])
        self.assertEqual(digest, event["private_provenance_sha256"])
        self.assertEqual(event["response_sha256"], sha256_bytes(self.text.encode("utf-8")))
        self.assertIsNone(provenance["model_attestation"])
        self.assertFalse(provenance["share"]["created"])
        persisted = self.store.audit_events()[-1]
        self.assertEqual(persisted, event)
        self.assertNotIn("response_text", persisted)
        self.assertNotIn("conversation_url", persisted)
        audit_text = json.dumps(persisted, ensure_ascii=False)
        self.assertNotIn(self.text.strip(), audit_text)
        self.assertNotIn(self.browser["conversation_url"], audit_text)

    def private_evaluation_args(self, *, observed=True, observation=None, **capture):
        from browser_request import prepare_browser_packet_request

        packet_path = self.base / "packet.json"
        packet_path.write_text(json.dumps(self.packet), encoding="utf-8")
        request = prepare_browser_packet_request(packet_path)
        submitted = request.require_unchanged()
        user_sha256 = artifact_hash(submitted.decode("utf-8").replace("\r\n", "\n").strip())
        attestation = {"required": True, "status": "confirmed"}
        browser = {
            **self.browser, **request.outbound.metadata(), "model_attestation": attestation,
            "request_id": request.request_id, "observed_document_request_id": request.request_id,
            "submitted_sha256": sha256_bytes(submitted), "observed_user_sha256": user_sha256,
            "submitted_user_sha256": user_sha256, **capture,
        }
        artifact = browser_capture.write_private_response(
            self.base / "returns", metadata=request.metadata, prompt=request.prompt, browser_result=browser,
        )
        dispatch_id = self.packet["dispatch_id"]
        prepared = self.store.write_dispatch(
            dispatch_id=dispatch_id, dispatch_role="executor", provider=self.packet["provider_family"],
            model_family=None, model_id=None, reasoning_effort=None, session_id=None,
            packet_sha256=self.packet["packet_sha256"], request_sha256=request.outbound.payload.sha256,
            bead_id=self.packet["bead_id"], executor=self.packet["executor"], provider_key=self.packet["provider_key"],
            evaluation_metadata={"dispatch_mode": "browser_automation", "peer_review_required": True},
        )
        event = browser_capture.record_browser_dispatch(
            {**request.metadata, "prompt_sha256": artifact_hash(request.prompt), "status": "completed",
             "response_artifact": artifact, "model_attestation": browser["model_attestation"],
             "share_url": browser.get("share_url")}, quota_info={},
        )
        if observed:
            self.store.write_observed_dispatch(
                dispatch_id, prepared_record_sha256=prepared, observation_sha256=observation or event["event_hash"],
                provider=self.packet["provider_family"], model_family="fixture-family", model_id="fixture-model",
                reasoning_effort="fixture-effort", session_id="fixture-session",
            )
        return ["evaluate_return.py", "--private-artifact", artifact["provenance_path"],
                "--contractor-packet", str(packet_path), "--packet-source-sha256", request.packet_source.sha256,
                "--capture-event", event["event_hash"], "--json"]

    def test_private_evaluation_round_trip(self):
        import evaluate_return

        self.text = (" \r\nStatus: completed\r\nSummary: PRIVATE_CAPTURE_SENTINEL Résumé 雪\r\n"
                     "Sources inspected: PRIVATE_CAPTURE_SENTINEL\r\n  ")
        self.browser["response_text"] = self.text
        argv = self.private_evaluation_args()
        wrong_event = argv.copy()
        wrong_event[wrong_event.index("--capture-event") + 1] = "0" * 64
        with patch.object(sys, "argv", wrong_event), self.assertRaisesRegex(SystemExit, "independent audit store"):
            evaluate_return.main()
        self.assertFalse(self.store.find("return-received"))
        self.assertFalse(self.store.find("evaluation"))

        stdout = io.StringIO()
        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout):
            evaluate_return.main()
        dispatch_id = self.packet["dispatch_id"]
        digest = sha256_bytes(self.text.encode("utf-8"))
        receipt = self.store.require_return(dispatch_id, digest)
        evaluation, = self.store.find("evaluation", dispatch_id=dispatch_id)
        self.assertEqual(evaluation["return_record_sha256"], receipt["_record_sha256"])
        self.assertEqual(evaluation["return_sha256"], digest)
        self.assertTrue(evaluation["evaluation"]["peer_review_required"])
        self.assertTrue(evaluation["evaluation"]["architect_review_required"])
        self.assertFalse(evaluation["evaluation"]["execution_permitted"])
        self.assertNotIn("PRIVATE_CAPTURE_SENTINEL", stdout.getvalue())
        self.assertNotIn("PRIVATE_CAPTURE_SENTINEL", self.store.audit_file.read_text())
        self.assertEqual(json.loads(stdout.getvalue())["verdict"], evaluation["evaluation"]["verdict"])

        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            evaluate_return.main()
        self.assertEqual(self.store.find("return-received", dispatch_id=dispatch_id), [receipt])

    def test_private_evaluation_requires_observed_dispatch_before_receipting(self):
        import evaluate_return

        argv = self.private_evaluation_args(observed=False)
        with patch.object(sys, "argv", argv), self.assertRaisesRegex(SystemExit, "observed browser dispatch"):
            evaluate_return.main()
        self.assertFalse(self.store.find("return-received"))
        self.assertFalse(self.store.find("evaluation"))

    def test_private_evaluation_requires_observed_dispatch_to_pin_capture(self):
        import evaluate_return

        argv = self.private_evaluation_args(observation="0" * 64)
        with patch.object(sys, "argv", argv), self.assertRaisesRegex(SystemExit, "observed browser dispatch"):
            evaluate_return.main()
        self.assertFalse(self.store.find("return-received"))
        self.assertFalse(self.store.find("evaluation"))

    def test_private_evaluation_refuses_unconfirmed_model(self):
        import evaluate_return

        argv = self.private_evaluation_args(model_attestation={"required": False, "status": "skipped"})
        with patch.object(sys, "argv", argv), self.assertRaisesRegex(SystemExit, "confirmed model attestation"):
            evaluate_return.main()
        self.assertFalse(self.store.find("return-received"))

    def test_private_evaluation_refuses_public_capture(self):
        import evaluate_return

        argv = self.private_evaluation_args(share_url="https://chatgpt.com/share/fixture")
        with patch.object(sys, "argv", argv), self.assertRaisesRegex(SystemExit, "without a public share"):
            evaluate_return.main()
        self.assertFalse(self.store.find("return-received"))

    def test_private_evaluation_cannot_use_a_caller_audit_file(self):
        import evaluate_return

        argv = self.private_evaluation_args()
        for override in (["--audit-file", str(self.base / "alternative.jsonl")],
                         ["--no-audit", "--waiver-reason", "offline check"]):
            with self.subTest(override=override), patch.object(sys, "argv", [*argv, *override]), (
                self.assertRaisesRegex(SystemExit, "configured host audit store")
            ):
                evaluate_return.main()
        self.assertFalse(self.store.find("return-received"))

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

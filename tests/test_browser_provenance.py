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
from cwo_core import audit, host_records  # noqa: E402
from cwo_core.outbound_screen import OutboundRefused  # noqa: E402
from cwo_core.private_artifact import sha256_bytes, write_private_artifact  # noqa: E402
from cwo_core.util import artifact_hash, packet_payload_hash  # noqa: E402
from tests.browser_provenance_fixture import capture_record, saved_capture  # noqa: E402
from tests.outbound_approval_helpers import REFERENCE, approved_outbound, outbound_grant  # noqa: E402


def production_packet() -> dict:
    bead = json.loads((ROOT / "examples/sample-bead.json").read_text())
    bead["id"] = "cwo-1"
    bead["labels"] = ["contract-jd-master-plan-review", "contractor-only", "no-codex-exec"]
    return build_contractor_packet.build_packet(
        bead_id="cwo-1", bead_json=bead, executor="chatgpt_pro_browser_master_reviewer",
        share_boundary="redacted-packet", job_description_label="contract-jd-master-plan-review",
        allowed_files=[], inline_snippets=["Review the retry design.\r\nCheck its recovery path."], external_opt_in=True,
        opt_in_basis="host-approval", quota_info={"quota_checked": True, "quota_remaining": 4},
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
        self.enterContext(approved_outbound(outbound_grant(self.packet["bead_id"], None, self.packet["executor"])))
        audit.record_audit_event({"event_type": "packet_built", "operator_approval_ref": REFERENCE, **self.identity()})
        self.text = " \nRésumé — 雪\r\n  "
        self.record, self.packet_source = capture_record(self.packet, self.text)
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

    def test_saved_capture_without_independent_audit_refuses(self):
        from ingest_chatgpt_share_return import load_private_response

        store = host_records.HostRecordStore.for_tests(self.base / "saved-host")
        provenance, response, packet_path, source, event = saved_capture(self.base / "saved-returns", store)
        packet = json.loads(packet_path.read_bytes())
        with host_records.using_test_store(store):
            with self.assertRaisesRegex(SystemExit, "independently selected"):
                load_private_response(provenance)
            expected = self.api.select_private_capture(
                packet, packet_source_sha256=source, capture_event_hash=event["event_hash"],
            )
            text, record, digest = load_private_response(provenance, expected=expected)
            self.assertEqual(text.encode("utf-8"), response)
            self.assertTrue(record["capture_complete"])
            self.assertEqual(digest, event["private_provenance_sha256"])
            self.assertNotIn(text.strip(), store.audit_file.read_text())
            store.state_root.rename(self.base / "disconnected-host")
            with self.assertRaisesRegex(SystemExit, "absent or ambiguous in the independent audit store"):
                load_private_response(provenance, expected=expected)

    def test_evaluate_saved_capture_uses_observed_release_dispatch(self):
        from cwo import main

        store = host_records.HostRecordStore.for_tests(self.base / "saved-host")
        provenance, response, packet, _, event = saved_capture(self.base / "saved-returns", store)
        dispatch = store.require_dispatch(event["dispatch_id"])
        self.assertEqual(dispatch["observation_sha256"], event["event_hash"])
        out = io.StringIO()
        with host_records.using_test_store(store), contextlib.redirect_stdout(out):
            main(["evaluate", "--private-artifact", str(provenance), "--contractor-packet", str(packet), "--json"])
        receipt = store.require_return(event["dispatch_id"], sha256_bytes(response))
        result = json.loads(out.getvalue())
        self.assertEqual(result["return_sha256"], sha256_bytes(response))
        self.assertEqual(receipt["dispatch_record_sha256"], dispatch["_record_sha256"])
        self.assertTrue(result["peer_review_required"])
        self.assertTrue(result["architect_review_required"])
        self.assertFalse(result["execution_permitted"])
        self.assertNotIn("Résumé", out.getvalue())
        self.assertNotIn("Résumé", store.audit_file.read_text())

    def private_evaluation_args(self, *, observed=True, observation=None, explicit_pins=True, **capture):
        from browser_request import prepare_browser_packet_request

        packet_path = self.base / "packet.json"
        packet_path.write_text(json.dumps(self.packet), encoding="utf-8")
        request = prepare_browser_packet_request(packet_path)
        submitted = request.require_unchanged()
        dispatch_id = self.packet["dispatch_id"]
        prepared = request.record_dispatch()
        dispatch = self.store.require_dispatch(dispatch_id)
        self.assertEqual(dispatch["_record_sha256"], prepared)
        self.assertEqual(dispatch["request_sha256"], sha256_bytes(submitted))
        self.assertEqual(dispatch["evaluation_metadata"]["packet_source_sha256"], request.packet_source.sha256)
        self.assertEqual(dispatch["evaluation_metadata"]["request_id"], request.request_id)
        self.assertEqual(dispatch["evaluation_metadata"]["outbound_prepared_sha256"], request.outbound.sha256)
        for field in ("model_family", "model_id", "reasoning_effort", "session_id"):
            self.assertIsNone(dispatch[field])
        user_sha256 = artifact_hash(submitted.decode("utf-8").replace("\r\n", "\n").strip())
        self.assertNotEqual(sha256_bytes(submitted), user_sha256)
        self.assertEqual(dispatch["evaluation_metadata"]["submitted_user_sha256"], user_sha256)
        model_attestation = capture.pop("model_attestation", {"required": True, "status": "confirmed"})
        share_created = bool(capture.pop("share_url", None))
        record, _ = capture_record(self.packet, self.text)
        record.update(
            **request.outbound.metadata(), model_attestation=model_attestation, share={"created": share_created},
            packet_source_sha256=request.packet_source.sha256, prompt_sha256=artifact_hash(request.prompt),
            request_id=request.request_id, observed_document_request_id=request.request_id,
            submitted_sha256=sha256_bytes(submitted), observed_user_sha256=user_sha256,
            submitted_user_sha256=user_sha256,
        )
        record.update(capture)
        raw = (json.dumps(record, sort_keys=True) + "\n").encode()
        directory = self.base / "returns"
        write_private_artifact(directory, record["response_file"], self.text.encode())
        provenance_path = write_private_artifact(directory, "run.provenance.json", raw)
        event = audit.record_audit_event({
            "event_type": "chatgpt_browser_dispatch", **self.identity(),
            "telemetry_status": "completed", "telemetry_kind": "browser_dispatch",
            "model_attestation_required": model_attestation.get("required"),
            "model_attestation_status": model_attestation.get("status"),
            "share_url_present": share_created,
            **self.api.capture_audit_fields(record, sha256_bytes(raw)),
        })
        if observed:
            self.store.write_observed_dispatch(
                dispatch_id, prepared_record_sha256=prepared, observation_sha256=observation or event["event_hash"],
                provider=self.packet["provider_family"], model_family="fixture-family", model_id="fixture-model",
                reasoning_effort="fixture-effort", session_id="fixture-session",
            )
        argv = ["evaluate_return.py", "--private-artifact", str(provenance_path),
                "--contractor-packet", str(packet_path), "--json"]
        if explicit_pins:
            argv.extend(["--packet-source-sha256", request.packet_source.sha256,
                         "--capture-event", event["event_hash"]])
        return argv

    def test_prepared_dispatch_refuses_a_changed_packet_before_recording(self):
        from browser_request import prepare_browser_packet_request

        packet_path = self.base / "packet.json"
        original = json.dumps(self.packet).encode("utf-8")
        packet_path.write_bytes(original)
        request = prepare_browser_packet_request(packet_path)
        packet_path.write_bytes(original + b"\n")
        with self.assertRaisesRegex(OutboundRefused, "input file changed after capture"):
            request.record_dispatch()
        self.assertFalse(self.store.find("dispatch"))

    def test_prepared_dispatch_requires_the_configured_host_packet_audit(self):
        from browser_request import prepare_browser_packet_request

        packet_path = self.base / "packet.json"
        packet_path.write_text(json.dumps(self.packet), encoding="utf-8")
        request = prepare_browser_packet_request(packet_path)
        unrelated_store = host_records.HostRecordStore.for_tests(self.base / "unrelated-host")
        with host_records.using_test_store(unrelated_store):
            with self.assertRaisesRegex(SystemExit, "contractor packet has no production provenance"):
                request.record_dispatch()
            self.assertFalse(unrelated_store.find("dispatch"))

    def test_host_scoring_preserves_browser_trace_in_its_dispatch(self):
        from cwo_core.host_acceptance import _evaluate, _host_inputs

        self.private_evaluation_args()
        dispatch_id = self.packet["dispatch_id"]
        dispatch = self.store.require_dispatch(dispatch_id)
        inputs = _host_inputs(dispatch, self.packet["bead_id"], dispatch_id)
        pending, _ = _evaluate(self.text, inputs, None)
        self.assertTrue(pending["peer_review_required"])
        self.assertTrue(pending["architect_review_required"])
        self.assertFalse(pending["execution_permitted"])
        trace = self.store.require_dispatch(dispatch_id)["evaluation_metadata"]
        for field in ("packet_source_sha256", "request_id", "outbound_prepared_sha256", "submitted_user_sha256"):
            self.assertTrue(trace[field])
            self.assertNotIn(field, inputs)

    def test_private_evaluation_round_trip(self):
        import evaluate_return

        self.text = (" \r\nStatus: completed\r\nSummary: PRIVATE_CAPTURE_SENTINEL Résumé 雪\r\n"
                     "Sources inspected: PRIVATE_CAPTURE_SENTINEL\r\n  ")
        explicit_argv = self.private_evaluation_args()
        argv = explicit_argv.copy()
        for flag in ("--packet-source-sha256", "--capture-event"):
            index = explicit_argv.index(flag)
            wrong_pin = explicit_argv.copy()
            wrong_pin[index + 1] = "0" * 64
            with self.subTest(flag=flag), patch.object(sys, "argv", wrong_pin), self.assertRaisesRegex(
                SystemExit, flag + " does not match the observed browser dispatch",
            ):
                evaluate_return.main()
            index = argv.index(flag)
            del argv[index:index + 2]
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

        with patch.object(sys, "argv", explicit_argv), contextlib.redirect_stdout(io.StringIO()):
            evaluate_return.main()
        self.assertEqual(self.store.find("return-received", dispatch_id=dispatch_id), [receipt])

    def test_private_evaluation_requires_observed_dispatch_before_receipting(self):
        import evaluate_return

        argv = self.private_evaluation_args(observed=False, explicit_pins=False)
        with patch.object(sys, "argv", argv), self.assertRaisesRegex(SystemExit, "observed browser dispatch"):
            evaluate_return.main()
        self.assertFalse(self.store.find("return-received"))
        self.assertFalse(self.store.find("evaluation"))

    def test_private_evaluation_requires_observed_dispatch_to_pin_capture(self):
        import evaluate_return

        argv = self.private_evaluation_args(observation="0" * 64, explicit_pins=False)
        with patch.object(sys, "argv", argv), self.assertRaisesRegex(SystemExit, "independent audit store"):
            evaluate_return.main()
        self.assertFalse(self.store.find("return-received"))
        self.assertFalse(self.store.find("evaluation"))

    def test_private_evaluation_checks_capture_request_id_against_preparation(self):
        import evaluate_return

        other_request_id = "0" * 32
        argv = self.private_evaluation_args(
            request_id=other_request_id, observed_document_request_id=other_request_id,
        )
        with patch.object(sys, "argv", argv), self.assertRaisesRegex(SystemExit, "recorded browser preparation"):
            evaluate_return.main()
        self.assertFalse(self.store.find("return-received"))
        self.assertFalse(self.store.find("evaluation"))

    def test_private_evaluation_checks_normalized_user_turn_against_preparation(self):
        import evaluate_return

        unrelated_user_sha256 = sha256_bytes(b"An unrelated user turn.")
        argv = self.private_evaluation_args(observed_user_sha256=unrelated_user_sha256,
                                            submitted_user_sha256=unrelated_user_sha256)
        with patch.object(sys, "argv", argv), self.assertRaisesRegex(SystemExit, "recorded browser preparation"):
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

    def test_missing_capture_fields_and_historical_versions_refuse_even_when_pinned(self):
        missing = [{key: value for key, value in self.record.items() if key != field}
                   for field in ("send_admission_sha256", "outbound_source_sha256", "observed_user_sha256")]
        historical = [{**self.record, "version": version} for version in (1, 2, 3, 4)]
        for changed in missing + historical:
            raw = json.dumps(changed, sort_keys=True).encode()
            event = audit.record_audit_event({
                "event_type": "chatgpt_browser_dispatch", **self.identity(),
                **self.api.capture_audit_fields(changed, sha256_bytes(raw)),
            })
            expectation = self.expected(capture_event_hash=event["event_hash"])
            with self.assertRaisesRegex(SystemExit, "incomplete or mismatched"):
                self.validate(changed, raw, expected=expectation)

    def test_malformed_screen_metadata_produces_safe_validation_errors(self):
        for value in (float("nan"), float("inf"), [], {}, True):
            with self.subTest(value_type=type(value).__name__):
                errors = self.api.provenance_errors({**self.record, "outbound_screen_version": value})
                self.assertTrue(errors)
                self.assertFalse(self.text in str(errors))


if __name__ == "__main__":
    unittest.main()

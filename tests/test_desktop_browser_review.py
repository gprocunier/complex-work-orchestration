"""Offline witnesses for the desktop Chrome handoff through the CWO CLI."""
from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import cwo
from cwo_core import host_records
from cwo_core.policy import load_policy
from generate_manual_dispatch_prompt import render_packet_prompt
from tests.test_browser_provenance import production_packet
from tests.test_outbound_screen import packet_with


class DesktopBrowserReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.store = host_records.HostRecordStore.for_tests(base / "host")
        store_context = host_records.using_test_store(self.store)
        store_context.__enter__()
        self.addCleanup(store_context.__exit__, None, None, None)
        self.packet = production_packet()
        self.packet_path = base / "packet.json"
        self.reply_path = base / "reply.txt"
        self.reply = (" \r\nStatus: completed\r\nSummary: PRIVATE_CHROME_REPLY café\r\n"
                      "Sources inspected: supplied plan\r\n  ").encode("utf-8")
        self.reply_path.write_bytes(self.reply)
        self.link_packet(self.packet)

    def link_packet(self, packet):
        self.packet_path.write_text(json.dumps(packet), encoding="utf-8")
        self.store.record_audit_event({"event_type": "packet_built", **{
            key: packet[key] for key in ("dispatch_id", "bead_id", "packet_sha256")}})

    def invoke(self, *args):
        stdout = io.StringIO()
        with redirect_stdout(stdout), patch.object(sys, "argv", sys.argv):
            cwo.main(list(args))
        return stdout.getvalue()

    def prepare(self):
        request = self.invoke("prepare-browser", "--packet", str(self.packet_path))
        prefix = render_packet_prompt(self.packet).rstrip() + "\n\nCWO request id: "
        self.assertTrue(request.startswith(prefix))
        request_id = request.removeprefix(prefix)
        self.assertRegex(request_id, r"\A[0-9a-f]{32}\Z")
        dispatch = self.store.require_dispatch(self.packet["dispatch_id"])
        self.assertEqual(dispatch["request_sha256"], hashlib.sha256(request.encode()).hexdigest())
        return request, request_id

    def evaluate(self, request_id, *, model="GPT-5.4 Pro", extra=()):
        return self.invoke("evaluate", "--contractor-packet", str(self.packet_path),
                           "--browser-reply", str(self.reply_path), "--request-id", request_id,
                           "--model-label", model, "--json", *extra)

    def test_desktop_round_trip_records_private_reply_and_sender_label(self):
        request, request_id = self.prepare()
        self.assertEqual(self.invoke("prepare-browser", "--packet", str(self.packet_path)), request)
        self.assertNotIn(request_id.encode(), self.reply)
        stdout = self.evaluate(request_id)
        dispatch = self.store.require_dispatch(self.packet["dispatch_id"])
        for field in ("model_id", "model_family", "session_id", "reasoning_effort"):
            self.assertIsNone(dispatch[field])
        digest = hashlib.sha256(self.reply).hexdigest()
        receipt = self.store.require_return(self.packet["dispatch_id"], digest)
        self.assertEqual(receipt["dispatch_record_sha256"], dispatch["_record_sha256"])
        self.assertEqual(receipt["desktop_browser"]["request_id"], request_id)
        self.assertEqual(receipt["desktop_browser"]["model_label"], "GPT-5.4 Pro")
        artifact = self.store.state_root / "browser-returns" / receipt["desktop_browser"]["response_file"]
        self.assertEqual(artifact.read_bytes(), self.reply)
        self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
        self.assertEqual(artifact.parent.stat().st_mode & 0o777, 0o700)
        result = json.loads(stdout)
        evaluation = self.store.get(result["evaluation_record_sha256"], "evaluation")
        self.assertEqual(evaluation["return_record_sha256"], receipt["_record_sha256"])
        self.assertEqual(result["return_sha256"], digest)
        self.assertTrue(result["peer_review_required"])
        self.assertTrue(result["architect_review_required"])
        self.assertFalse(result["execution_permitted"])
        self.assertNotIn("PRIVATE_CHROME_REPLY", stdout)
        audit = self.store.audit_events()
        self.assertNotIn("PRIVATE_CHROME_REPLY", json.dumps(audit))
        self.assertTrue(any(event.get("host_record_sha256") == receipt["_record_sha256"] for event in audit))
        self.evaluate(request_id)
        self.assertEqual(self.store.find("return-received"), [receipt])

    def test_unmatched_request_and_audit_override_create_no_receipt(self):
        _, request_id = self.prepare()
        with self.assertRaisesRegex(SystemExit, "recorded browser preparation"):
            self.evaluate("0" * 32)
        with self.assertRaisesRegex(SystemExit, "configured host audit store"):
            self.evaluate(request_id, extra=("--audit-file", str(self.packet_path)))
        with self.assertRaisesRegex(SystemExit, "a prepared desktop browser return requires --browser-reply"):
            self.invoke("evaluate", "--contractor-packet", str(self.packet_path), "--file", str(self.reply_path))
        self.reply_path.write_bytes(b"\xff")
        with self.assertRaisesRegex(SystemExit, "--browser-reply is unreadable or is not UTF-8"):
            self.evaluate(request_id)
        self.assertFalse(self.store.find("return-received"))
        self.assertFalse(self.store.find("evaluation"))

    def test_completed_request_refuses_replacement_reply_or_model_label(self):
        _, request_id = self.prepare()
        self.evaluate(request_id)
        self.reply_path.write_bytes(b"Different response.")
        with self.assertRaisesRegex(SystemExit, "already has a different reply or model label"):
            self.evaluate(request_id)
        self.reply_path.write_bytes(self.reply)
        with self.assertRaisesRegex(SystemExit, "already has a different reply or model label"):
            self.evaluate(request_id, model="Thinking")
        self.assertEqual(len(self.store.find("return-received")), 1)

    def test_screening_stops_preparation_before_output_or_dispatch(self):
        self.link_packet(packet_with(r'Inspect {"\u0070assword":"VelvetSunset42!"}'))
        stdout = io.StringIO()
        with redirect_stdout(stdout), patch.object(sys, "argv", sys.argv), self.assertRaisesRegex(
            SystemExit, "outbound screening refused ChatGPT browser Send"
        ):
            cwo.main(["prepare-browser", "--packet", str(self.packet_path)])
        self.assertEqual(stdout.getvalue(), "")
        self.assertFalse(self.store.find("dispatch"))

    def test_tampered_private_reply_is_refused(self):
        _, request_id = self.prepare()
        self.evaluate(request_id)
        digest = hashlib.sha256(self.reply).hexdigest()
        receipt = self.store.require_return(self.packet["dispatch_id"], digest)
        artifact = self.store.state_root / "browser-returns" / receipt["desktop_browser"]["response_file"]
        artifact.write_bytes(b"Changed retained bytes.")
        with self.assertRaisesRegex(SystemExit, "already has a different private reply"):
            self.evaluate(request_id)

    def test_new_packet_identifies_desktop_chrome_and_uses_picker_at_dispatch(self):
        self.assertEqual(self.packet["executor_transport"], {
            "kind": "chatgpt-desktop-chrome", "default_model_label": "Pro",
        })
        self.assertIsNone(self.packet["manual_command"])
        _, request_id = self.prepare()
        self.evaluate(request_id, model="Latest > 6 Pro")
        receipt = self.store.require_return(self.packet["dispatch_id"], hashlib.sha256(self.reply).hexdigest())
        self.assertEqual(receipt["desktop_browser"]["model_label"], "Latest > 6 Pro")

    def test_packet_from_legacy_registry_resumes_and_evaluates(self):
        registry = deepcopy(load_policy("executor-registry"))
        registry["executors"][self.packet["executor"]]["transport"] = {
            "kind": "chatgpt-browser",
            "config_env": "CWO_CHATGPT_BROWSER_CONFIG",
            "default_config": "~/.config/cwo/chatgpt-browser.json",
            "default_model_label": "ChatGPT Pro 5.5",
            "default_reasoning_label": "Extended Reasoning",
            "share_link_required": True,
            "response_timeout_seconds": 1800,
        }
        with patch("build_contractor_packet.load_policy", side_effect=lambda name: (
            registry if name == "executor-registry" else load_policy(name)
        )):
            self.packet = production_packet()
            self.link_packet(self.packet)
            request, request_id = self.prepare()
        saved = self.packet_path.read_bytes()
        self.assertEqual(self.invoke("prepare-browser", "--packet", str(self.packet_path)), request)
        evaluation = json.loads(self.evaluate(request_id))
        self.assertEqual(evaluation["return_sha256"], hashlib.sha256(self.reply).hexdigest())
        self.assertEqual(self.packet_path.read_bytes(), saved)

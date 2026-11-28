from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from browser_request import prepare_browser_packet_request
from cwo_core.outbound_screen import OutboundRefused
from generate_manual_dispatch_prompt import render_packet_prompt
from tests.dispatch_workload_fixture import write_workload
from tests.test_outbound_screen import packet_with, with_provenance


class BrowserPacketRequestTests(unittest.TestCase):
    def test_prepared_request_binds_exact_wire_bytes_and_packet_file(self) -> None:
        packet = packet_with("Review café.\nPreserve exact bytes.")
        request_id = "0123456789abcdef0123456789abcdef"
        with tempfile.TemporaryDirectory() as tmp, with_provenance(packet):
            path = Path(tmp) / "packet.json"
            original = json.dumps(packet).encode("utf-8")
            path.write_bytes(original)
            workload = write_workload(path.with_name("workload.json"), packet, browser=True)
            with patch("browser_request.secrets.token_hex", return_value=request_id) as nonce:
                request = prepare_browser_packet_request(path, workload_path=workload)
            nonce.assert_called_once_with(16)

            prompt = render_packet_prompt(packet)
            expected = (prompt.rstrip() + "\n\nCWO request id: " + request_id).encode("utf-8")
            self.assertEqual(request.prompt, prompt)
            self.assertEqual(request.request_id, request_id)
            self.assertEqual(request.require_unchanged(), expected)
            self.assertEqual(request.outbound.payload.sha256, hashlib.sha256(expected).hexdigest())
            self.assertEqual(request.outbound.payload.surface, "ChatGPT browser Send")
            self.assertEqual(request.metadata["packet_source_sha256"], request.packet_source.sha256)
            request.metadata["subject"].clear()
            self.assertEqual(request.metadata["subject"], packet["subject"])

            with self.assertRaisesRegex(OutboundRefused, "payload changed after it was screened"):
                request.outbound.require_unchanged(request.outbound.source.value(), expected + b"\n")
            path.write_bytes(original + b"\n")
            with self.assertRaisesRegex(OutboundRefused, "input file changed after capture"):
                request.require_unchanged()

    def test_linked_packet_with_encoded_context_is_refused_by_send_screen(self) -> None:
        packet = packet_with(r'Inspect {"\u0070assword":"VelvetSunset42!"}')
        with tempfile.TemporaryDirectory() as tmp, with_provenance(packet):
            path = Path(tmp) / "packet.json"
            path.write_text(json.dumps(packet), encoding="utf-8")
            with self.assertRaisesRegex(OutboundRefused, "outbound screening refused ChatGPT browser Send") as caught:
                prepare_browser_packet_request(path)
            self.assertNotIn("VelvetSunset42!", str(caught.exception))

    def test_packet_without_production_link_is_refused(self) -> None:
        packet = packet_with("Review the plan.")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packet.json"
            path.write_text(json.dumps(packet), encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "contractor packet has no production provenance"):
                prepare_browser_packet_request(path, audit_file=Path(tmp) / "audit.jsonl")

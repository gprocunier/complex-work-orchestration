"""Offline witnesses for workload sizing at the public copy-out boundaries."""
from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo
from cwo_core import host_records
from generate_manual_dispatch_prompt import render_packet_prompt
from tests.dispatch_workload_fixture import planned_export, write_workload
from tests.outbound_approval_helpers import REFERENCE, approved_outbound, outbound_grant
from tests.test_outbound_screen import packet_with
from tests.test_route_feasibility_preparation import bind, planner


class ManagedExportSizingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="EXAMPLE-managed-sizing-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = host_records.HostRecordStore.for_tests(self.root / "host")
        self.enterContext(host_records.using_test_store(self.store))
        self.packet = packet_with("Review this EXAMPLE checklist. Include one concrete observation.")
        grant = outbound_grant(self.packet["bead_id"], self.packet.get("epic_id"), self.packet["executor"])
        self.enterContext(approved_outbound(grant))
        self.store.record_audit_event({"event_type": "packet_built", "operator_approval_ref": REFERENCE, **{
            key: self.packet[key] for key in ("dispatch_id", "bead_id", "packet_sha256")}})
        self.packet_path = self.root / "packet.json"
        self.packet_path.write_text(json.dumps(self.packet), encoding="utf-8")
        self.workload_path = self.root / "workload.json"

    def call(self, command, *options):
        cwo.main([command, "--packet", str(self.packet_path), *options])

    def assert_refused(self, command, *options):
        before = self.store.audit_events()
        stdout = io.StringIO()
        with patch.object(sys, "argv", sys.argv), redirect_stdout(stdout):
            with self.assertRaisesRegex(SystemExit, "workload sizing required|workload sizing refused"):
                self.call(command, *options)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(self.store.find("dispatch"), [])
        self.assertEqual(self.store.audit_events(), before)

    def test_contractor_dispatch_without_workload_refuses_before_export_or_audit(self):
        self.assert_refused("dispatch", "--json")

    def test_manual_packet_prompt_without_workload_refuses_before_export(self):
        self.assert_refused("manual-prompt", "--json")

    def test_desktop_browser_without_workload_refuses_before_preparation(self):
        self.assert_refused("prepare-browser")

    def test_number_only_stale_and_over_budget_workload_refuse(self):
        for command in ("dispatch", "manual-prompt", "prepare-browser"):
            for rejection in ("number", "drift", "budget"):
                with self.subTest(command=command, rejection=rejection):
                    data = planned_export(self.packet, browser=command == "prepare-browser")
                    route = data["route_input"]
                    node = route["nodes"][0]
                    if rejection == "drift":
                        node["prompt"] += " Different EXAMPLE task."
                    if rejection == "budget":
                        route["limits"]["runtime_seconds"] = 1
                    node["rendered_request"] = planner.render_request(node)
                    bind(route)
                    self.workload_path.write_text(json.dumps(600 if rejection == "number" else data), encoding="utf-8")
                    self.assert_refused(command, "--workload", str(self.workload_path))

    def test_desktop_requires_explicit_request_marker_allowance(self):
        workload = planned_export(self.packet, browser=True)
        route = workload["route_input"]
        route["nodes"][0]["additional_input_tokens_upper"] = 49
        self.workload_path.write_text(json.dumps({**workload, "route_input": bind(route)}), encoding="utf-8")
        self.assert_refused("prepare-browser", "--workload", str(self.workload_path))

    def test_workload_bound_desktop_request_is_exact_and_resumes(self):
        stdout = io.StringIO()
        workload = write_workload(self.workload_path, self.packet, browser=True)
        with patch.object(sys, "argv", sys.argv), redirect_stdout(stdout):
            self.call("prepare-browser", "--workload", workload)
        sent = stdout.getvalue()
        self.assertRegex(sent, r"\n\nCWO request id: [0-9a-f]{32}\Z")
        dispatch = self.store.require_dispatch(self.packet["dispatch_id"])
        self.assertEqual(dispatch["request_sha256"], hashlib.sha256(sent.encode()).hexdigest())
        sized = dispatch["evaluation_metadata"]["dispatch_workload"]
        self.assertEqual(sized["request_sha256"], dispatch["request_sha256"])
        self.assertEqual(sized["execution"]["model"], "Pro")
        replay = io.StringIO()
        with patch.object(sys, "argv", sys.argv), redirect_stdout(replay):
            self.call("prepare-browser", "--workload", workload)
        self.assertEqual(replay.getvalue(), sent)

    def test_workload_bound_manual_dispatch_exports_only_after_sizing(self):
        stdout = io.StringIO()
        workload = write_workload(self.workload_path, self.packet)
        with patch.object(sys, "argv", sys.argv), redirect_stdout(stdout):
            self.call("manual-prompt", "--workload", workload)
            self.assertEqual(stdout.getvalue(), render_packet_prompt(self.packet) + "\n")
        stdout = io.StringIO()
        with patch.object(sys, "argv", sys.argv), redirect_stdout(stdout):
            self.call("dispatch", "--workload", workload, "--json")
        self.assertEqual(json.loads(stdout.getvalue())["manual_prompt"], render_packet_prompt(self.packet))
        dispatch = self.store.require_dispatch(self.packet["dispatch_id"])
        self.assertEqual(dispatch["request_sha256"], hashlib.sha256(render_packet_prompt(self.packet).encode()).hexdigest())
        self.assertEqual(dispatch["evaluation_metadata"]["dispatch_workload"]["request_sha256"], dispatch["request_sha256"])

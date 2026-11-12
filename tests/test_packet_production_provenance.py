"""A contractor packet is production input only with production provenance.

A content hash is not provenance. Anyone can edit a packet (for example remove the
``result_class: nonproduction-rehearsal`` label of a rehearsal packet) and recompute
``packet_sha256``. Production provenance is the ``packet_built`` audit event that only
``build_contractor_packet.py`` appends, matching the packet's dispatch_id, Bead and hash.
Every production packet consumer now requires it:

- ``dispatch_work.py --packet`` and ``chatgpt_browser_review.py --packet`` (already linked;
  the operator-only ``--allow-unlinked-packet`` waiver, which needs ``--waiver-reason``, is kept);
- ``generate_manual_dispatch_prompt.py --packet``, ``normalize_contractor_return.py
  --contractor-packet`` and ``evaluate_return.py --contractor-packet`` (no link before; no waiver).

Each refusal asserts the exit, empty stdout, an unchanged audit file and zero calls on the
effect spies. The positive controls (a production packet) reach stdout of every consumer,
``write_export`` in dispatch_work and the manual prompt, ``record_audit_event`` in dispatch_work,
evaluate_return and chatgpt_browser_review, the audit file and the acceptance verdict. The other
spies are guards that no positive control reaches, so their zero counts show nothing by
themselves: network (``socket.create_connection``, ``urllib.request.urlopen``,
``dispatch_work.execute_local_envelope``), Beads (``cwo_core.beads.run_bd`` and
``run_bd_structured``), the browser runner, the release spies and ``cwo_core.audit.record_audit_event``
(CLIs import it by name).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_contractor_packet  # noqa: E402
import chatgpt_browser_review  # noqa: E402
import dispatch_work  # noqa: E402
import evaluate_return  # noqa: E402
import generate_manual_dispatch_prompt  # noqa: E402
import normalize_contractor_return  # noqa: E402
import record_audit_event  # noqa: E402
from cwo_core import beads, policy  # noqa: E402
from cwo_core.util import packet_payload_hash  # noqa: E402

from tests.test_policy_current_effects import RETURN_TEXT, EffectSpies, current_policy  # noqa: E402

NO_PROVENANCE = "contractor packet has no production provenance"
BEAD_FILE = str(ROOT / "examples" / "sample-bead.json")
BROWSER_EXECUTOR = "chatgpt_pro_browser_master_reviewer"


class ConsumerSpies(EffectSpies):
    BOUNDARIES = {
        **EffectSpies.BOUNDARIES,
        "export: dispatch_work.write_export": (dispatch_work, "write_export"),
        "export: generate_manual_dispatch_prompt.write_export": (generate_manual_dispatch_prompt, "write_export"),
        "persistence: chatgpt_browser_review.record_audit_event": (chatgpt_browser_review, "record_audit_event"),
        "persistence: normalize_contractor_return.atomic_write_text": (normalize_contractor_return, "atomic_write_text"),
        "dispatch: chatgpt_browser_review.PlaywrightChatGPTRunner": (chatgpt_browser_review, "PlaywrightChatGPTRunner"),
        "network: socket.create_connection": (socket, "create_connection"),
        "network: urllib.request.urlopen": (urllib.request, "urlopen"),
        "beads: cwo_core.beads.run_bd": (beads, "run_bd"),
        "beads: cwo_core.beads.run_bd_structured": (beads, "run_bd_structured"),
    }


def run_consumer(module: Any, argv: list[str]) -> tuple[ConsumerSpies, BaseException | None]:
    raised: BaseException | None = None
    with mock.patch.object(sys, "argv", argv), ConsumerSpies() as spies:
        try:
            module.main()
        except SystemExit as exc:
            raised = exc
    return spies, raised


def audit_bytes(home: Path) -> bytes:
    path = home / "audit" / "audit.jsonl"
    return path.read_bytes() if path.exists() else b""


def write_browser_config(directory: Path) -> Path:
    path = directory / "chatgpt-browser.json"
    path.write_text(json.dumps({
        "chrome_user_data_dir": str(directory / "profile"),
        "model_label": "ChatGPT Pro 5.5",
        "reasoning_label": "Extended Reasoning",
        "selectors": {
            "model_label_confirmation_selector": "[data-testid='model-switcher']",
            "reasoning_label_confirmation_selector": "[data-testid='reasoning-switcher']",
        },
    }), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


class ProvenanceCase(unittest.TestCase):
    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def build(self, home: Path, *extra: str, dispatch_id: str, executor: str = "claude_code_manual") -> dict[str, Any]:
        output = home / f"{dispatch_id}.json"
        argv = [
            "build_contractor_packet.py", "--bead", "complex-work-orchestration-example", "--bead-json-file", BEAD_FILE,
            "--executor", executor, "--external-ok", "--epic", "epic-1", "--dispatch-id", dispatch_id,
            "--share-boundary", "redacted-packet", "--format", "json", "--output", str(output), *extra,
        ]
        if executor == BROWSER_EXECUTOR:
            argv += ["--job-description", "contract-jd-security-reasoning"]
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            build_contractor_packet.main()
        return json.loads(output.read_text(encoding="utf-8"))

    @staticmethod
    def write(home: Path, value: Any, name: str) -> Path:
        path = home / name
        path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
        return path

    @staticmethod
    def strip_and_rehash(packet: dict[str, Any]) -> dict[str, Any]:
        stripped = {key: value for key, value in packet.items() if key != "result_class"}
        stripped["packet_sha256"] = packet_payload_hash(stripped)
        return stripped

    def consumers(self, home: Path, packet_path: Path, browser_packet_path: Path) -> dict[str, tuple[Any, list[str]]]:
        return_file = home / "return.md"
        return_file.write_text(RETURN_TEXT, encoding="utf-8")
        config = write_browser_config(home)
        return {
            "dispatch_work --packet": (dispatch_work, ["dispatch_work.py", "--packet", str(packet_path), "--json"]),
            "generate_manual_dispatch_prompt --packet": (
                generate_manual_dispatch_prompt, ["generate_manual_dispatch_prompt.py", "--packet", str(packet_path)]),
            "chatgpt_browser_review --packet --dry-run": (chatgpt_browser_review, [
                "chatgpt_browser_review.py", "--packet", str(browser_packet_path), "--config", str(config), "--dry-run"]),
            "normalize_contractor_return --contractor-packet": (normalize_contractor_return, [
                "normalize_contractor_return.py", "--file", str(return_file), "--contractor-packet", str(packet_path)]),
            "evaluate_return --contractor-packet": (evaluate_return, [
                "evaluate_return.py", "--file", str(return_file), "--contractor-packet", str(packet_path), "--json"]),
        }

    def assert_refused_everywhere(self, home: Path, packet_path: Path, browser_packet_path: Path, *fragments: str) -> None:
        before = audit_bytes(home)
        for label, (module, argv) in self.consumers(home, packet_path, browser_packet_path).items():
            with self.subTest(consumer=label):
                spies, raised = run_consumer(module, argv)
                self.assertIsNotNone(raised, f"{label} accepted the packet; effects {spies.counts()}")
                for fragment in fragments:
                    self.assertIn(fragment, str(raised))
                self.assertEqual(spies.counts(), {name: 0 for name in spies.counts()})
                self.assertEqual(spies.stdout.getvalue(), "")
                self.assertEqual(audit_bytes(home), before)


class ProductionPacketControlTests(ProvenanceCase):
    def test_every_consumer_accepts_a_production_packet(self) -> None:
        # Positive control for every refusal in this module.
        reached = {
            "dispatch_work --packet": ("export: dispatch_work.write_export", "persistence: dispatch_work.record_audit_event"),
            "generate_manual_dispatch_prompt --packet": ("export: generate_manual_dispatch_prompt.write_export",),
            "chatgpt_browser_review --packet --dry-run": ("persistence: chatgpt_browser_review.record_audit_event",),
            "normalize_contractor_return --contractor-packet": (),
            "evaluate_return --contractor-packet": ("persistence: evaluate_return.record_audit_event",),
        }
        with current_policy() as home:
            packet_path = self.write(home, self.build(home, dispatch_id="dispatch-prod"), "prod.json")
            browser_path = self.write(
                home, self.build(home, dispatch_id="dispatch-prod-browser", executor=BROWSER_EXECUTOR), "prod-browser.json")
            for label, (module, argv) in self.consumers(home, packet_path, browser_path).items():
                with self.subTest(consumer=label):
                    before = audit_bytes(home)
                    spies, raised = run_consumer(module, argv)
                    self.assertIsNone(raised, str(raised))
                    self.assertNotEqual(spies.stdout.getvalue(), "")
                    for spy in reached[label]:
                        self.assertEqual(spies.mocks[spy].call_count, 1, spy)
                    if any(spy.endswith("record_audit_event") for spy in reached[label]):
                        self.assertNotEqual(audit_bytes(home), before)
                    if label.startswith("evaluate_return"):
                        self.assertEqual(len(spies.verdicts), 1)


class StrippedRehearsalPacketTests(ProvenanceCase):
    REHEARSALS = {
        "rehearsal with its audit record": ("--rehearsal",),
        "rehearsal without audit records": ("--rehearsal", "--no-audit", "--waiver-reason", "rehearsal test"),
    }

    def test_stripped_and_rehashed_rehearsal_packet_is_refused_by_every_consumer(self) -> None:
        for case, extra in self.REHEARSALS.items():
            with self.subTest(build=case), current_policy() as home:
                rehearsal = self.build(home, *extra, dispatch_id="dispatch-rehearsal")
                browser = self.build(home, *extra, dispatch_id="dispatch-rehearsal-browser", executor=BROWSER_EXECUTOR)
                self.assertEqual(rehearsal["result_class"], "nonproduction-rehearsal")
                stripped = self.strip_and_rehash(rehearsal)
                self.assertNotIn("result_class", stripped)
                self.assertEqual(stripped["packet_sha256"], packet_payload_hash(stripped))
                self.assert_refused_everywhere(
                    home,
                    self.write(home, stripped, "stripped.json"),
                    self.write(home, self.strip_and_rehash(browser), "stripped-browser.json"),
                    NO_PROVENANCE,
                    "a recomputed packet_sha256 is not provenance",
                )

    def test_the_rehearsal_audit_record_does_not_vouch_for_the_stripped_packet(self) -> None:
        with current_policy() as home:
            rehearsal = self.build(home, "--rehearsal", dispatch_id="dispatch-rehearsal")
            events = [json.loads(line) for line in audit_bytes(home).decode("utf-8").splitlines()]
            self.assertEqual([event["packet_sha256"] for event in events if event["event_type"] == "packet_built"],
                             [rehearsal["packet_sha256"]])
            stripped = self.strip_and_rehash(rehearsal)
            self.assertNotEqual(stripped["packet_sha256"], rehearsal["packet_sha256"])

    def test_the_unlinked_packet_waiver_still_requires_a_reason(self) -> None:
        # The existing degraded path is kept exactly: without --waiver-reason it is refused.
        with current_policy() as home:
            forged = self.write(home, self.strip_and_rehash(
                self.build(home, "--rehearsal", dispatch_id="dispatch-rehearsal")), "stripped.json")
            for module, argv in (
                (dispatch_work, ["dispatch_work.py", "--packet", str(forged), "--allow-unlinked-packet", "--json"]),
                (chatgpt_browser_review, ["chatgpt_browser_review.py", "--packet", str(forged), "--allow-unlinked-packet",
                                          "--config", str(write_browser_config(home)), "--dry-run"]),
            ):
                with self.subTest(consumer=argv[0]):
                    before = audit_bytes(home)
                    spies, raised = run_consumer(module, argv)
                    self.assertIn("--waiver-reason", str(raised))
                    self.assertEqual(spies.counts(), {name: 0 for name in spies.counts()})
                    self.assertEqual(spies.stdout.getvalue(), "")
                    self.assertEqual(audit_bytes(home), before)


class ForgedProvenanceTests(ProvenanceCase):
    def test_record_audit_event_cannot_append_a_packet_built_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_file = Path(tmpdir) / "audit.jsonl"
            base = ["record_audit_event.py", "--dispatch-id", "dispatch-rehearsal", "--bead",
                    "complex-work-orchestration-example", "--packet-sha256", "0" * 64, "--audit-file", str(audit_file)]
            stdout = io.StringIO()
            with mock.patch.object(sys, "argv", [base[0], "--event-type", "packet_built", *base[1:]]), \
                    contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
                record_audit_event.main()
            self.assertIn("packet_built events are recorded only by build_contractor_packet.py", str(raised.exception))
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(audit_file.exists())
            # Positive control: any other event type is still recorded.
            with mock.patch.object(sys, "argv", [base[0], "--event-type", "dispatch", *base[1:]]), \
                    contextlib.redirect_stdout(stdout):
                record_audit_event.main()
            self.assertEqual(len(audit_file.read_text(encoding="utf-8").splitlines()), 1)

    def test_a_forged_link_attempt_leaves_every_consumer_refusing(self) -> None:
        with current_policy() as home:
            stripped = self.strip_and_rehash(self.build(home, "--rehearsal", dispatch_id="dispatch-rehearsal"))
            browser = self.strip_and_rehash(
                self.build(home, "--rehearsal", dispatch_id="dispatch-rehearsal-browser", executor=BROWSER_EXECUTOR))
            for packet in (stripped, browser):
                argv = ["record_audit_event.py", "--event-type", "packet_built", "--dispatch-id", packet["dispatch_id"],
                        "--bead", packet["bead_id"], "--packet-sha256", packet["packet_sha256"]]
                with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()), \
                        self.assertRaises(SystemExit):
                    record_audit_event.main()
            self.assert_refused_everywhere(
                home, self.write(home, stripped, "stripped.json"), self.write(home, browser, "stripped-browser.json"),
                NO_PROVENANCE)


class RehearsalOutputTests(ProvenanceCase):
    """Rehearsal outputs without a hash or audit link cannot be used as packets: refused by construction."""

    TASK = "Claude security review for auth token handling."

    def rehearsal_outputs(self, home: Path) -> dict[str, Path]:
        raw = [self.TASK, "--external-ok", "--share-boundary", "redacted-packet", "--requested-role", "security",
               "--allow-raw-manual-prompt", "--rehearsal", "--waiver-reason", "rehearsal test", "--json"]
        outputs = {}
        for name, module, argv in (
            ("raw manual prompt", generate_manual_dispatch_prompt, ["generate_manual_dispatch_prompt.py", *raw]),
            ("route-path dispatch artifact", dispatch_work, ["dispatch_work.py", *raw, "--no-audit"]),
        ):
            stdout = io.StringIO()
            with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout):
                module.main()
            outputs[name] = self.write(home, json.loads(stdout.getvalue()), f"{name.replace(' ', '-')}.json")
        return outputs

    def test_unhashed_rehearsal_outputs_are_refused_as_packets(self) -> None:
        with current_policy() as home:
            for name, path in self.rehearsal_outputs(home).items():
                with self.subTest(output=name):
                    self.assert_refused_everywhere(home, path, path, "packet is missing required field")


if __name__ == "__main__":
    unittest.main()

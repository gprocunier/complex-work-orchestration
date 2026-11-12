"""The packet builder's default refuses outside disclosure, and rehearsal packets are nonproduction.

Default disclosure and nonproduction boundaries are driven through real entry points with the effect spies of
``tests.test_policy_current_effects`` (dispatch artifact on stdout, ``record_audit_event`` in each
caller, the audit file, the packet file writer, acceptance verdicts):

- "Align the packet-builder disclosure default with no-outside-sharing through an explicit
  compatibility/migration change; preserve already-conservative callers" and "default outside
  disclosure refuses";
- "test/rehearsal results are labelled nonproduction and refused by production consumers" and
  "forged test-result relabelling fail".

Positive controls: the same invocations with an explicit outside boundary, or without
``--rehearsal``, reach the packet writer, the audit spies, the dispatch artifact and an
acceptance verdict.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_contractor_packet  # noqa: E402
import dispatch_work  # noqa: E402
import evaluate_return  # noqa: E402
import generate_manual_dispatch_prompt  # noqa: E402
import normalize_contractor_return  # noqa: E402
from cwo_core import packets, policy  # noqa: E402
from cwo_core.util import packet_payload_hash  # noqa: E402

from tests.test_policy_current_effects import RETURN_TEXT, current_policy, run_main  # noqa: E402

NONPRODUCTION = "nonproduction-rehearsal"
LABEL_REFUSAL = (
    "packet is a nonproduction rehearsal result and cannot be used by a production consumer; "
    "build the packet without --rehearsal"
)
DEFAULT_REFUSAL = (
    "no --share-boundary given: the contracting-controls default 'no-outside-sharing' does not allow outside "
    "disclosure; pass --share-boundary redacted-packet (or another outside boundary) explicitly"
)
BEAD_FILE = str(ROOT / "examples" / "sample-bead.json")


def packet_argv(output: Path | None, *extra: str, boundary: str | None = "redacted-packet",
                dispatch_id: str = "dispatch-w10b", fmt: str = "json", bead_file: str | None = BEAD_FILE) -> list[str]:
    argv = ["build_contractor_packet.py", "--bead", "complex-work-orchestration-example"]
    if bead_file is not None:
        argv += ["--bead-json-file", bead_file]
    argv += [
        "--executor", "claude_code_manual", "--external-ok", "--epic", "epic-1", "--dispatch-id", dispatch_id,
        "--format", fmt,
    ]
    if output is not None:
        argv += ["--output", str(output)]
    if boundary is not None:
        argv += ["--share-boundary", boundary]
    return argv + list(extra)


def audit_lines(home: Path) -> list[dict[str, Any]]:
    path = home / "audit" / "audit.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


class PacketDisclosureDefaultTests(unittest.TestCase):
    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def assert_default_refusal(self, home: Path, output: Path, spies: Any, raised: BaseException | None) -> None:
        self.assertIsNotNone(raised, "a packet without an explicit boundary was built")
        self.assertEqual(str(raised), DEFAULT_REFUSAL)
        self.assertEqual(spies.total(), 0, spies.counts())
        self.assertEqual(spies.stdout.getvalue(), "")
        self.assertFalse(output.exists())
        self.assertEqual(audit_lines(home), [])

    def test_build_without_a_boundary_refuses_before_reading_the_bead_from_beads(self) -> None:
        # No --bead-json-file: the Bead read is show_bead_json, observed here; the explicit-boundary
        # control shows the same invocation reaches it.
        bead = json.loads(Path(BEAD_FILE).read_text(encoding="utf-8"))
        with current_policy() as home:
            output = home / "packet.json"
            with mock.patch.object(build_contractor_packet, "show_bead_json", return_value=bead) as bead_reader:
                spies, raised = run_main(build_contractor_packet, packet_argv(output, boundary=None, bead_file=None))
                self.assert_default_refusal(home, output, spies, raised)
                bead_reader.assert_not_called()
                _, raised = run_main(build_contractor_packet, packet_argv(output, bead_file=None))
                self.assertIsNone(raised, str(raised))
                bead_reader.assert_called_once_with("complex-work-orchestration-example")
                self.assertTrue(output.exists())

    def test_build_without_a_boundary_refuses_before_opening_the_bead_file(self) -> None:
        # With --bead-json-file the Bead read is that file's read_text, observed here.
        real_read_text = Path.read_text
        bead_reads: list[Path] = []

        def read_text(path: Path, *args: Any, **kwargs: Any) -> str:
            if Path(path) == Path(BEAD_FILE):
                bead_reads.append(Path(path))
            return real_read_text(path, *args, **kwargs)

        with current_policy() as home, mock.patch.object(Path, "read_text", read_text):
            output = home / "packet.json"
            spies, raised = run_main(build_contractor_packet, packet_argv(output, boundary=None))
            self.assert_default_refusal(home, output, spies, raised)
            self.assertEqual(bead_reads, [])
            _, raised = run_main(build_contractor_packet, packet_argv(output))
            self.assertIsNone(raised, str(raised))
            self.assertEqual(bead_reads, [Path(BEAD_FILE)])


    def test_manual_prompt_routing_defaults_to_no_outside_sharing(self) -> None:
        text = "Claude security review for auth token handling."
        base = ["generate_manual_dispatch_prompt.py", text, "--external-ok", "--requested-role", "security"]
        with current_policy():
            spies, raised = run_main(generate_manual_dispatch_prompt, [*base, "--json"])
            self.assertIsNone(raised)
            route = json.loads(spies.stdout.getvalue())["route"]
            self.assertEqual(route["share_boundary"], "no-outside-sharing")
            self.assertNotEqual(route["route"], "external-contract")
            # An explicit outside boundary keeps the old routing and its packet requirement.
            spies, raised = run_main(generate_manual_dispatch_prompt, [*base, "--share-boundary", "redacted-packet", "--json"])
            self.assertIn("external manual prompts require --packet", str(raised))
            self.assertEqual(spies.stdout.getvalue(), "")

    def test_already_conservative_caller_is_still_refused(self) -> None:
        with current_policy() as home:
            output = home / "packet.json"
            spies, raised = run_main(build_contractor_packet, packet_argv(output, boundary="no-outside-sharing"))
            self.assertEqual(str(raised), "share boundary 'no-outside-sharing' does not allow external contracting")
            self.assertEqual(spies.total(), 0, spies.counts())
            self.assertFalse(output.exists())


    def test_explicit_outside_boundary_is_unchanged(self) -> None:
        with current_policy() as home:
            output = home / "packet.json"
            spies, raised = run_main(build_contractor_packet, packet_argv(output))
            self.assertIsNone(raised)
            self.assertEqual(spies.mocks["persistence: build_contractor_packet.atomic_write_text"].call_count, 1)
            self.assertEqual(spies.mocks["persistence: build_contractor_packet.record_audit_event"].call_count, 1)
            packet = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(packet["share_boundary"], "redacted-packet")
            self.assertNotIn("result_class", packet)


class NonproductionPacketTests(unittest.TestCase):
    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def build(self, home: Path, *extra: str, dispatch_id: str = "dispatch-w10b") -> dict[str, Any]:
        output = home / f"{dispatch_id}.json"
        _, raised = run_main(build_contractor_packet, packet_argv(output, *extra, dispatch_id=dispatch_id))
        self.assertIsNone(raised)
        return json.loads(output.read_text(encoding="utf-8"))

    def write(self, home: Path, packet: dict[str, Any], name: str = "candidate.json") -> Path:
        path = home / name
        path.write_text(json.dumps(packet, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def consumers(self, home: Path, packet_path: Path) -> dict[str, tuple[Any, list[str]]]:
        return_file = home / "return.md"
        return_file.write_text(RETURN_TEXT, encoding="utf-8")
        return {
            "dispatch_work --packet": (dispatch_work, ["dispatch_work.py", "--packet", str(packet_path), "--json"]),
            "generate_manual_dispatch_prompt --packet": (
                generate_manual_dispatch_prompt, ["generate_manual_dispatch_prompt.py", "--packet", str(packet_path)]),
            "normalize_contractor_return --contractor-packet": (normalize_contractor_return, [
                "normalize_contractor_return.py", "--file", str(return_file), "--contractor-packet", str(packet_path)]),
            "evaluate_return --contractor-packet": (evaluate_return, [
                "evaluate_return.py", "--file", str(return_file), "--contractor-packet", str(packet_path), "--json"]),
        }

    def assert_refused(self, home: Path, packet_path: Path, *fragments: str) -> None:
        before = (home / "audit" / "audit.jsonl").read_bytes() if (home / "audit" / "audit.jsonl").exists() else b""
        for label, (module, argv) in self.consumers(home, packet_path).items():
            with self.subTest(consumer=label):
                spies, raised = run_main(module, argv)
                self.assertIsNotNone(raised, f"{label} accepted the packet; effects {spies.counts()}")
                for fragment in fragments:
                    self.assertIn(fragment, str(raised))
                self.assertEqual(spies.total(), 0, spies.counts())
                self.assertEqual(spies.stdout.getvalue(), "")
                after = (home / "audit" / "audit.jsonl").read_bytes() if (home / "audit" / "audit.jsonl").exists() else b""
                self.assertEqual(after, before)

    def test_rehearsal_packet_is_labelled_inside_its_hash(self) -> None:
        with current_policy() as home:
            packet = self.build(home, "--rehearsal")
            self.assertEqual(packet["result_class"], NONPRODUCTION)
            self.assertEqual(packet["packet_sha256"], packet_payload_hash(packet))
            self.assertEqual(packets.validate_contractor_packet(packet, allow_nonproduction=True), [])
            self.assertEqual(packets.validate_contractor_packet(packet), [LABEL_REFUSAL])
            spies, raised = run_main(build_contractor_packet, packet_argv(
                None, "--rehearsal", dispatch_id="dispatch-w10b-md", fmt="markdown"))
            self.assertIsNone(raised)
            self.assertIn(f"Result class: {NONPRODUCTION} (not production dispatch or acceptance evidence)",
                          spies.stdout.getvalue())

    def test_forged_relabelling_is_refused(self) -> None:
        with current_policy() as home:
            rehearsal = self.build(home, "--rehearsal")
            stripped = {key: value for key, value in rehearsal.items() if key != "result_class"}
            # The label removed, hash kept: the payload no longer matches its hash.
            self.assert_refused(home, self.write(home, stripped, "stale-hash.json"),
                                "packet_sha256 does not match packet payload")
            # The label removed and the hash recomputed: the content check alone cannot tell, so every
            # production consumer requires the packet_built provenance, which no build recorded for this hash
            # (the operator-only --allow-unlinked-packet waiver of dispatch and browser review aside).
            stripped["packet_sha256"] = packet_payload_hash(stripped)
            self.assertEqual(packets.validate_contractor_packet(stripped), [])
            self.assert_refused(home, self.write(home, stripped, "rehashed.json"),
                                "contractor packet has no production provenance")
            # Any other label value is refused outright.
            relabelled = dict(rehearsal, result_class="production")
            relabelled["packet_sha256"] = packet_payload_hash(relabelled)
            self.assert_refused(home, self.write(home, relabelled, "relabelled.json"),
                                f"packet result_class must be {NONPRODUCTION!r} when present")


    def test_production_consumers_accept_a_production_packet(self) -> None:
        # Positive control for every consumer below: the same packet without --rehearsal is used.
        with current_policy() as home:
            packet_path = self.write(home, self.build(home))
            expected = {
                "dispatch_work --packet": "persistence: dispatch_work.record_audit_event",
                "evaluate_return --contractor-packet": "persistence: evaluate_return.record_audit_event",
            }
            for label, (module, argv) in self.consumers(home, packet_path).items():
                with self.subTest(consumer=label):
                    spies, raised = run_main(module, argv)
                    self.assertIsNone(raised, str(raised))
                    self.assertNotEqual(spies.stdout.getvalue(), "")
                    if label in expected:
                        self.assertEqual(spies.mocks[expected[label]].call_count, 1)
                    if label.startswith("evaluate_return"):
                        self.assertEqual(len(spies.verdicts), 1)


    def test_production_consumers_refuse_a_rehearsal_packet_with_zero_effects(self) -> None:
        for extra in (("--rehearsal",), ("--rehearsal", "--no-audit", "--waiver-reason", "rehearsal test")):
            with self.subTest(build=extra), current_policy() as home:
                packet_path = self.write(home, self.build(home, *extra))
                self.assert_refused(home, packet_path, LABEL_REFUSAL)

    def test_production_packet_shape_is_unchanged(self) -> None:
        with current_policy() as home:
            packet = self.build(home)
            self.assertNotIn("result_class", packet)
            self.assertEqual(set(packets.CONTRACTOR_PACKET_REQUIRED_FIELDS) - set(packet), set())


if __name__ == "__main__":
    unittest.main()

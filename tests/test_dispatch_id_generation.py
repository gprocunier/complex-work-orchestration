"""Automatic preparation IDs: deterministic, offline producer/consumer contracts."""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import socket
import subprocess
import sys
import unittest
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_contractor_packet  # noqa: E402
import render_harness_dispatch  # noqa: E402
from cwo_core import util  # noqa: E402
from cwo_core.outbound_screen import OutboundRefused, require_clean, screen_outbound  # noqa: E402
from cwo_core.util import packet_payload_hash  # noqa: E402
from tests.test_policy_current_effects import current_policy  # noqa: E402


FIRST = uuid.UUID("01234567-89ab-4cde-8fab-0123456789ab")
SECOND = uuid.UUID("fedcba98-7654-4321-8abc-fedcba987654")
THIRD = uuid.UUID("a1b2c3d4-e5f6-4789-9abc-0123456789ab")


from cwo_core.harness import validate_harness_dispatch_envelope

class FixedDatetime(dt.datetime):
    @classmethod
    def now(cls, tz: dt.tzinfo | None = None) -> FixedDatetime:
        return cls(2026, 10, 24, 16, 0, 0, tzinfo=dt.timezone.utc)


@contextlib.contextmanager
def no_effects() -> Iterator[None]:
    with contextlib.ExitStack() as stack:
        guards = []
        for owner, name in (
            (subprocess, "run"),
            (socket, "create_connection"),
            (urllib.request, "urlopen"),
            (build_contractor_packet, "show_bead_json"),
            (build_contractor_packet, "record_audit_event"),
            (build_contractor_packet, "atomic_write_text"),
            (render_harness_dispatch, "record_audit_event"),
        ):
            guards.append(stack.enter_context(mock.patch.object(
                owner, name, side_effect=AssertionError("preparation reached an effect")
            )))
        try:
            yield
        finally:
            for guard in guards:
                guard.assert_not_called()


class DispatchIdGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        clock = mock.patch.object(util.dt, "datetime", FixedDatetime)
        clock.start()
        self.addCleanup(clock.stop)

    def _packet(self, dispatch_id: str | None = None) -> dict[str, Any]:
        bead = json.loads((ROOT / "examples" / "sample-bead.json").read_text(encoding="utf-8"))
        return build_contractor_packet.build_packet(
            bead_id="complex-work-orchestration-example",
            bead_json=bead,
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label=build_contractor_packet.find_job_label(
                build_contractor_packet.extract_labels(bead)
            ),
            allowed_files=[], inline_snippets=[],
            dispatch_id=dispatch_id,
            include_expert_profile=False,
            degraded_context_justification="Offline identifier fixture.",
            external_opt_in=True, opt_in_basis="cli-flag", epic_id="epic-1",
            nonproduction=True,
        )

    def _render(
        self, dispatch_id: str | None = None, *, as_json: bool = True, bead_id: str = "bounded-task"
    ) -> str:
        argv = [
            "render_harness_dispatch.py", "Review bounded documentation.",
            "--environment", "connected-codex", "--role", "architect",
            "--bead", bead_id, "--no-audit",
            "--waiver-reason", "offline identifier fixture",
        ]
        if as_json:
            argv.append("--json")
        if dispatch_id is not None:
            argv.extend(["--dispatch-id", dispatch_id])
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout):
            render_harness_dispatch.main()
        return stdout.getvalue()

    def test_same_second_preparations_have_distinct_default_ids(self) -> None:
        with mock.patch.object(uuid, "uuid4", side_effect=[FIRST, SECOND, THIRD]) as nonce:
            first = util.make_dispatch_id("bounded-task")
            second = util.make_dispatch_id("bounded-task")
            other = util.make_dispatch_id("other-bounded-task")
        self.assertEqual(first, f"{FIRST}.dispatch-bounded-task-20261024T160000Z")
        self.assertEqual(other, f"{THIRD}.dispatch-other-bounded-task-20261024T160000Z")
        self.assertNotEqual(first, other)
        self.assertNotEqual(first, second, "fresh same-second preparations must not reuse an ID")
        for value in (first, second, other):
            self.assertRegex(value, r"\A[A-Za-z0-9_.-]+\Z")
            self.assertEqual(uuid.UUID(value.split(".", 1)[0]).version, 4)
        self.assertEqual(nonce.call_count, 3)

    def test_explicit_timestamp_retains_readable_segment_and_still_gets_freshness(self) -> None:
        with mock.patch.object(uuid, "uuid4", side_effect=[FIRST, SECOND]) as nonce:
            first = util.make_dispatch_id("bounded-task", "20010203T040506Z")
            second = util.make_dispatch_id("bounded-task", "20010203T040506Z")
        self.assertEqual(first, f"{FIRST}.dispatch-bounded-task-20010203T040506Z")
        self.assertEqual(second, f"{SECOND}.dispatch-bounded-task-20010203T040506Z")
        self.assertNotEqual(first, second)
        self.assertEqual(nonce.call_count, 2)

    def test_empty_timestamp_uses_current_clock(self) -> None:
        with mock.patch.object(uuid, "uuid4", return_value=FIRST) as nonce:
            identifier = util.make_dispatch_id("bounded-task", "")
        self.assertEqual(identifier, f"{FIRST}.dispatch-bounded-task-20261024T160000Z")
        nonce.assert_called_once_with()

    def test_sanitization_unknown_beads_and_long_input_remain_supported(self) -> None:
        cases = [
            ("task / alpha", "task-alpha"),
            ("---", "unassigned"), ("", "unassigned"),
            ("unknown-bead", "unknown-bead"), ("Task._-9", "Task._-9"),
        ]
        with mock.patch.object(uuid, "uuid4", return_value=FIRST):
            for bead, safe in cases:
                with self.subTest(bead=bead):
                    value = util.make_dispatch_id(bead)
                    self.assertEqual(value, f"{FIRST}.dispatch-{safe}-20261024T160000Z")
                    self.assertRegex(value, r"\A[A-Za-z0-9_.-]+\Z")
            # No prefix truncation or new ID length cap is introduced.
            long_bead = "task-" + "a" * 160
            value = util.make_dispatch_id(long_bead)
            self.assertEqual(value, f"{FIRST}.dispatch-{long_bead}-20261024T160000Z")
            self.assertEqual(len(value), 228)

    def test_bead_separation_and_sanitization_collisions(self) -> None:
        with mock.patch.object(uuid, "uuid4", return_value=FIRST):
            first = util.make_dispatch_id("bounded-task")
            other = util.make_dispatch_id("other-bounded-task")
        self.assertNotEqual(first, other)
        with mock.patch.object(uuid, "uuid4", side_effect=[FIRST, SECOND]):
            left = util.make_dispatch_id("task/a")
            right = util.make_dispatch_id("task?a")
        self.assertEqual(left, f"{FIRST}.dispatch-task-a-20261024T160000Z")
        self.assertEqual(right, f"{SECOND}.dispatch-task-a-20261024T160000Z")
        self.assertNotEqual(left, right)

    def test_entropy_failure_propagates_without_a_predictable_id(self) -> None:
        for timestamp in (None, "20010203T040506Z"):
            with self.subTest(timestamp=timestamp):
                failure = OSError("entropy unavailable")
                with mock.patch.object(uuid, "uuid4", side_effect=failure) as nonce:
                    with self.assertRaises(OSError) as raised:
                        util.make_dispatch_id("bounded-task", timestamp)
                self.assertIs(raised.exception, failure)
                nonce.assert_called_once_with()

    def test_real_outbound_screen_accepts_ids_and_keeps_entropy_refusal(self) -> None:
        with mock.patch.object(uuid, "uuid4", side_effect=[FIRST, SECOND, THIRD]):
            for _ in range(3):
                identifier = util.make_dispatch_id("bounded-task")
                for payload in (
                    f"Dispatch ID: {identifier}\n",
                    json.dumps({"dispatch_id": identifier, "task": "Review documentation."}),
                ):
                    screened = require_clean(payload, surface="offline preparation")
                    self.assertTrue(screened.allowed)
                    self.assertEqual(screened.require_unchanged(payload), payload.encode())
        # The real policy must continue to reject a separate entropic value.
        sensitive = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0rU"
        screened = screen_outbound(sensitive, surface="entropy negative control")
        self.assertIn("entropy", {finding.rule for finding in screened.findings})
        with self.assertRaises(OutboundRefused):
            require_clean(sensitive, surface="entropy negative control")

    def test_actual_packet_preparations_refresh_implicit_timestamp_ids(self) -> None:
        with current_policy(), no_effects(), mock.patch.object(
            uuid, "uuid4", side_effect=[FIRST, SECOND]
        ) as nonce:
            first = self._packet()
            second = self._packet()
            self.assertEqual(first["generated_at"], "2026-10-24T16:00:00Z")
            self.assertEqual(second["generated_at"], first["generated_at"])
            self.assertNotEqual(first["dispatch_id"], second["dispatch_id"])
            self.assertNotEqual(first["packet_sha256"], second["packet_sha256"])
            for packet in (first, second):
                self.assertTrue(packet["dispatch_id"].endswith(
                    ".dispatch-complex-work-orchestration-example-20261024T160000Z"
                ))
                self.assertEqual(packet["result_class"], "nonproduction-rehearsal")
                self.assertEqual(packet["packet_sha256"], packet_payload_hash(packet))
                self.assertEqual(json.loads(json.dumps(packet))["dispatch_id"], packet["dispatch_id"])
                self.assertIn(f"Dispatch ID: {packet['dispatch_id']}\n",
                              build_contractor_packet.packet_markdown(packet))
            self.assertEqual(nonce.call_count, 2)


    def test_render_entropy_failure_stops_before_builder_or_output(self) -> None:
        stdout = io.StringIO()
        argv = ["render_harness_dispatch.py", "Review docs.", "--no-audit",
                "--waiver-reason", "offline identifier fixture"]
        with no_effects(), mock.patch.object(uuid, "uuid4", side_effect=OSError("entropy unavailable")), \
                mock.patch.object(render_harness_dispatch, "build_harness_dispatch",
                                  side_effect=AssertionError("entropy failure must stop before rendering")) as builder, \
                mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout):
            with self.assertRaises(OSError):
                render_harness_dispatch.main()
            builder.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")

    def test_predecessor_clean_token_prefix_beads_remain_clean(self) -> None:
        # Establish genuine old-format positives before the rejected-format control.
        for identifier in (
            "dispatch-bounded-task-20261024T160000Z",
            "dispatch-sk-20261024T160000Z",
        ):
            self.assertTrue(require_clean(
                f"Dispatch ID: {identifier}\n", surface="old ID positive control"
            ).allowed)
        rejected = f"dispatch-sk-20261024T160000Z.{FIRST}"
        screened = screen_outbound(rejected, surface="rejected suffix control")
        self.assertIn("token-prefix", {finding.rule for finding in screened.findings})
        with self.assertRaises(OutboundRefused):
            require_clean(rejected, surface="rejected suffix control")
        beads = (
            "sk", "sk-a", "sk-ab", "ghp_", "ghp_a", "ghp_ab",
            "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
            "AIza", "npm_", "pypi", "dop_v1_", "shpat_", "ya29.",
        )
        with mock.patch.object(uuid, "uuid4", return_value=FIRST):
            for bead in beads:
                with self.subTest(bead=bead):
                    old = f"dispatch-{bead}-20261024T160000Z"
                    for payload in (
                        f"Dispatch ID: {old}\n",
                        json.dumps({"dispatch_id": old}),
                    ):
                        self.assertTrue(require_clean(payload, surface="old ID control").allowed)
                    identifier = util.make_dispatch_id(bead)
                    for payload in (
                        f"Dispatch ID: {identifier}\n",
                        json.dumps({"dispatch_id": identifier}),
                    ):
                        screened = require_clean(payload, surface="fresh ID control")
                        self.assertEqual(screened.require_unchanged(payload), payload.encode())
                    self.assertEqual(identifier, f"{FIRST}.{old}")

    def test_predecessor_clean_harness_renders_remain_clean(self) -> None:
        cases = (
            ("bounded-task", "dispatch-bounded-task-20261024T160000Z"),
            ("sk", "dispatch-sk-20261024T160000Z"),
            ("ghp_", "dispatch-ghp_-20261024T160000Z"),
        )
        with current_policy(), no_effects(), mock.patch.object(
            uuid, "uuid4", side_effect=[FIRST, SECOND, THIRD]
        ) as nonce:
            for (bead, old), expected in zip(cases, (FIRST, SECOND, THIRD)):
                with self.subTest(bead=bead):
                    historical = self._render(old, as_json=False, bead_id=bead)
                    self.assertIn(f"Dispatch ID: {old}\n", historical)
                    self.assertTrue(require_clean(historical, surface="old harness control").allowed)
                    rendered = self._render(as_json=False, bead_id=bead)
                    self.assertTrue(require_clean(rendered, surface="fresh harness control").allowed)
                    self.assertIn(f"Dispatch ID: {expected}.{old}\n", rendered)
            self.assertEqual(nonce.call_count, 3)

    def test_secret_bead_content_remains_visible_and_refused(self) -> None:
        bead = "sk-" + "a" * 24
        old = f"dispatch-{bead}-20261024T160000Z"
        with mock.patch.object(uuid, "uuid4", return_value=FIRST):
            identifier = util.make_dispatch_id(bead)
        self.assertEqual(identifier, f"{FIRST}.{old}")
        for value in (old, identifier):
            with self.subTest(value=value):
                screened = screen_outbound(value, surface="secret Bead negative control")
                self.assertIn("token-prefix", {finding.rule for finding in screened.findings})
                with self.assertRaises(OutboundRefused):
                    require_clean(value, surface="secret Bead negative control")


    def test_actual_harness_renders_are_fresh_valid_and_do_not_execute(self) -> None:
        with current_policy(), no_effects(), mock.patch.object(
            uuid, "uuid4", side_effect=[FIRST, SECOND, THIRD]
        ) as nonce:
            first = json.loads(self._render())
            second = json.loads(self._render())
            self.assertNotEqual(first["dispatch_id"], second["dispatch_id"])
            for envelope in (first, second):
                self.assertEqual(validate_harness_dispatch_envelope(envelope), [])
                self.assertIs(envelope["execution_enabled"], False)
                self.assertEqual(envelope["lifecycle_state"], "rendered")
                self.assertTrue(envelope["dispatch_id"].endswith(".dispatch-bounded-task-20261024T160000Z"))
            rendered = self._render(as_json=False)
            self.assertIn(f"Dispatch ID: {THIRD}.dispatch-bounded-task-20261024T160000Z\n", rendered)
            self.assertTrue(require_clean(rendered, surface="offline harness render").allowed)
            self.assertEqual(nonce.call_count, 3)

    def test_caller_provided_ids_bypass_generation_and_remain_byte_unchanged(self) -> None:
        explicit = "dispatch-Legacy.BeAd-20010203T040506Z"
        with current_policy(), no_effects(), mock.patch.object(
            uuid, "uuid4", side_effect=AssertionError("explicit ID must bypass generation")
        ) as nonce:
            packet = self._packet(dispatch_id=explicit)
            envelope = json.loads(self._render(dispatch_id=explicit))
            self.assertEqual(packet["dispatch_id"].encode(), explicit.encode())
            self.assertEqual(envelope["dispatch_id"].encode(), explicit.encode())
            self.assertEqual(validate_harness_dispatch_envelope(envelope), [])
            self.assertIs(envelope["execution_enabled"], False)
            nonce.assert_not_called()


if __name__ == "__main__":
    unittest.main()

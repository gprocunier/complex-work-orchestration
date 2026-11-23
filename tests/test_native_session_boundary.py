from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import traceback
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_session_boundary import (  # noqa: E402
    NativeSessionBoundaryError,
    assert_prefix_intact,
    capture_boundary,
    capture_unique_boundary,
    locate_unique_session,
    same_boundary,
    session_source_identity,
    telemetry_markers,
    trusted_terminal_event,
    trusted_turn_context,
)


class NativeSessionBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.active = self.root / "sessions" / "2026" / "07"
        self.archive = self.root / "archived_sessions"
        self.active.mkdir(parents=True)
        self.archive.mkdir()
        self.session_id = "session-one"
        self.turn_id = "turn-one"
        self.path = self.active / f"rollout-{self.session_id}.jsonl"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def records(self) -> list[dict]:
        return [
            {"type": "session_meta", "payload": {"id": self.session_id}},
            {
                "type": "turn_context",
                "payload": {
                    "turn_id": self.turn_id,
                    "model": "gpt-5.3-codex-spark",
                    "effort": "low",
                },
            },
            {"type": "event_msg", "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3}}}},
        ]

    def write(self, path: Path | None = None, records: list[dict] | None = None) -> Path:
        target = path or self.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(json.dumps(item) + "\n" for item in (records or self.records())), encoding="utf-8")
        return target

    def test_capture_complete_boundary_and_context(self) -> None:
        self.write()
        boundary, records = capture_boundary(self.path, self.session_id)
        self.assertEqual(boundary["record_count"], 3)
        self.assertEqual(boundary["byte_offset"], self.path.stat().st_size)
        index, context = trusted_turn_context(
            records,
            turn_id=self.turn_id,
            model="gpt-5.3-codex-spark",
            effort="low",
        )
        self.assertEqual(index, 1)
        self.assertEqual(context["turn_id"], self.turn_id)
        self.assertTrue(same_boundary(boundary, boundary))

    def test_active_to_archive_relocation_preserves_prefix(self) -> None:
        self.write()
        initial, baseline, _records = capture_unique_boundary(self.root, self.session_id)
        archived = self.archive / self.path.name
        self.path.rename(archived)
        located, current, _records = capture_unique_boundary(
            self.root, self.session_id, baseline=baseline
        )
        self.assertEqual(located.store, "archived_sessions")
        self.assertEqual(initial.source_identity_sha256, located.source_identity_sha256)
        self.assertTrue(same_boundary(baseline, current))

    def test_capture_checks_prefix_on_the_same_bytes_it_parses_and_hashes(self) -> None:
        records = self.records()
        records[0]["payload"]["cwd"] = "/original"
        self.write(records=records[:1])
        _, baseline, _ = capture_unique_boundary(self.root, self.session_id)
        original = self.path.read_bytes()
        appended = original + (json.dumps(records[1]) + "\n").encode("utf-8")
        rewritten = appended.replace(b'"/original"', b'"/modified"', 1)
        with patch.object(Path, "read_bytes", side_effect=[appended, rewritten]) as read:
            _, current, observed = capture_unique_boundary(self.root, self.session_id, baseline=baseline)
        self.assertEqual(observed, records[:2])
        self.assertEqual(current["boundary_sha256"], sha256(appended).hexdigest())
        read.assert_called_once_with()

    def test_symlink_and_identical_content_replacement_are_rejected(self) -> None:
        outside = self.root / "outside.jsonl"
        self.write(outside)
        self.path.symlink_to(outside)
        with self.assertRaisesRegex(NativeSessionBoundaryError, "symlink"):
            locate_unique_session(self.root, self.session_id)
        self.path.unlink()
        self.write()
        original_identity = session_source_identity(self.path, self.session_id)
        replacement = self.path.with_suffix(".replacement")
        replacement.write_bytes(self.path.read_bytes())
        replacement.replace(self.path)
        self.assertNotEqual(original_identity, session_source_identity(self.path, self.session_id))

    def test_duplicate_active_and_archive_fails_closed(self) -> None:
        self.write()
        self.write(self.archive / self.path.name)
        with self.assertRaisesRegex(NativeSessionBoundaryError, "duplicate active/archive"):
            locate_unique_session(self.root, self.session_id)

    def test_reported_path_is_deduplicated_and_outside_rejected(self) -> None:
        self.write()
        located = locate_unique_session(self.root, self.session_id, reported_path=self.path)
        self.assertEqual(located.path, self.path.resolve())
        outside = self.root.parent / f"outside-{self.session_id}.jsonl"
        outside.write_text(self.path.read_text(), encoding="utf-8")
        self.addCleanup(outside.unlink)
        with self.assertRaisesRegex(NativeSessionBoundaryError, "outside codexHome"):
            locate_unique_session(self.root, self.session_id, reported_path=outside)

    def test_partial_malformed_and_identity_mismatch_rejected(self) -> None:
        self.path.write_text('{"type":"session_meta","payload":{"id":"session-one"}}', encoding="utf-8")
        with self.assertRaisesRegex(NativeSessionBoundaryError, "trailing partial"):
            capture_boundary(self.path, self.session_id)
        for malformed in (b"not-json\n", b"\xff\n", b'{"value":NaN}\n', b'{"value":1e309}\n'):
            with self.subTest(malformed=malformed):
                self.path.write_bytes(malformed)
                with self.assertRaisesRegex(NativeSessionBoundaryError, r"^session record 1 is invalid$"):
                    capture_boundary(self.path, self.session_id)
        self.write(records=[{"type": "session_meta", "payload": {"id": "other"}}])
        with self.assertRaisesRegex(NativeSessionBoundaryError, "identity"):
            capture_boundary(self.path, self.session_id)

    def test_boundary_refuses_duplicate_json_keys_without_exposing_record_data(self) -> None:
        cases = {
            "record identity": b'{"session_id":"other","sess\\u0069on_id":"session-one"}',
            "same-turn model": (b'{"type":"turn_context","payload":{"turn_id":"turn-one",'
                                b'"model":"other","model":"gpt-5.3-codex-spark","effort":"low"}}'),
            "nested field": b'{"type":"event_msg","payload":[{"private-fixture-field":7,"private-fixture-field":7}]}',
        }
        for case, record in cases.items():
            with self.subTest(case=case):
                self.write(records=self.records()[:1])
                with self.path.open("ab") as source:
                    source.write(record + b"\n")
                with self.assertRaisesRegex(NativeSessionBoundaryError, r"^session record 2 is invalid$") as caught:
                    capture_boundary(self.path, self.session_id)
                diagnostic = "".join(traceback.format_exception(caught.exception))
                self.assertNotIn("private-fixture-field", diagnostic)

    def test_truncation_rewrite_and_delayed_append(self) -> None:
        self.write()
        baseline, _records = capture_boundary(self.path, self.session_id)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"type": "event_msg", "payload": {"type": "user_message"}}) + "\n")
        assert_prefix_intact(self.path, baseline)
        _, current, _records = capture_unique_boundary(self.root, self.session_id, baseline=baseline)
        self.assertGreater(current["record_count"], baseline["record_count"])
        raw = self.path.read_bytes()
        self.path.write_bytes(b"x" + raw[1:])
        with self.assertRaisesRegex(NativeSessionBoundaryError, "prefix was rewritten"):
            assert_prefix_intact(self.path, baseline)
        with self.assertRaisesRegex(NativeSessionBoundaryError, "prefix was rewritten"):
            capture_unique_boundary(self.root, self.session_id, baseline=baseline)
        self.path.write_bytes(raw[: max(1, baseline["byte_offset"] - 1)])
        with self.assertRaisesRegex(NativeSessionBoundaryError, "truncated"):
            assert_prefix_intact(self.path, baseline)
        with self.assertRaisesRegex(NativeSessionBoundaryError, "truncated"):
            capture_unique_boundary(self.root, self.session_id, baseline=baseline)

    def test_wrong_turn_model_effort_and_compaction_reroute_terminal(self) -> None:
        records = self.records() + [
            {"type": "compacted", "payload": {}},
            {"type": "event_msg", "payload": {"type": "model_rerouted"}},
            {"type": "event_msg", "payload": {"type": "task_complete", "turn_id": self.turn_id}},
        ]
        self.write(records=records)
        _boundary, loaded = capture_boundary(self.path, self.session_id)
        with self.assertRaisesRegex(NativeSessionBoundaryError, "not singular"):
            trusted_turn_context(loaded, turn_id="wrong", model="gpt-5.3-codex-spark", effort="low")
        with self.assertRaisesRegex(NativeSessionBoundaryError, "not singular"):
            trusted_turn_context(loaded, turn_id=self.turn_id, model="wrong", effort="low")
        markers = telemetry_markers(loaded, turn_id=self.turn_id)
        self.assertEqual(markers["compaction_indices"], [3])
        self.assertEqual(markers["reroute_indices"], [4])
        self.assertEqual(markers["terminal_indices"], [5])
        self.assertEqual(
            trusted_terminal_event(loaded, turn_id=self.turn_id),
            {
                "record_index": 5,
                "event_type": "task_complete",
                "status": "completed",
                "count": 1,
            },
        )

    def test_conflicting_current_turn_context_cannot_be_ignored(self) -> None:
        records = self.records()
        payload = records[1]["payload"]
        for change in (
            {"model": "other-model"},
            {"effort": "high"},
            {"turn_id": "other-turn", "turnId": self.turn_id, "effort": "high"},
        ):
            with self.subTest(change=change):
                conflicting = {"type": "turn_context", "payload": {**payload, **change}}
                self.write(records=[*records, conflicting])
                _, observed = capture_boundary(self.path, self.session_id)
                with self.assertRaisesRegex(NativeSessionBoundaryError, "not singular"):
                    trusted_turn_context(observed, turn_id=self.turn_id, model=payload["model"], effort=payload["effort"])

    def test_current_turn_context_refuses_conflicting_aliases(self) -> None:
        records = self.records()
        payload = records[1]["payload"]
        for change in ({"turnId": "other-turn"}, {"reasoning_effort": "high"}):
            with self.subTest(change=change):
                conflicting = {"type": "turn_context", "payload": {**payload, **change}}
                self.write(records=[records[0], conflicting])
                _, observed = capture_boundary(self.path, self.session_id)
                with self.assertRaisesRegex(NativeSessionBoundaryError, "not singular"):
                    trusted_turn_context(observed, turn_id=self.turn_id, model=payload["model"], effort=payload["effort"])

    def test_current_turn_context_ignores_other_turn_and_accepts_legacy_aliases(self) -> None:
        records = self.records()
        payload = records[1]["payload"]
        legacy = {"type": "turn_context", "payload": {"turnId": self.turn_id,
                  "model": payload["model"], "reasoning_effort": payload["effort"]}}
        unrelated = {"type": "turn_context", "payload": {**payload, "turn_id": "other-turn", "model": "other-model"}}
        self.write(records=[records[0], unrelated, legacy, records[2]])
        _, observed = capture_boundary(self.path, self.session_id)
        index, context = trusted_turn_context(observed, turn_id=self.turn_id, model=payload["model"], effort=payload["effort"])
        self.assertEqual((index, context), (2, legacy["payload"]))

    def test_task_complete_error_is_failed_terminal_without_exposing_error(
        self,
    ) -> None:
        cases = (
            ({}, "completed"),
            ({"error": None}, "completed"),
            (
                {
                    "error": {
                        "message": "Selected model is at capacity.",
                        "codex_error_info": "server_overloaded",
                    }
                },
                "failed",
            ),
        )
        for extra, expected_status in cases:
            with self.subTest(extra=extra):
                terminal = trusted_terminal_event(
                    self.records()
                    + [
                        {
                            "type": "event_msg",
                            "payload": {
                                "type": "task_complete",
                                "turn_id": self.turn_id,
                                **extra,
                            },
                        }
                    ],
                    turn_id=self.turn_id,
                )
                self.assertEqual(
                    terminal,
                    {
                        "record_index": 3,
                        "event_type": "task_complete",
                        "status": expected_status,
                        "count": 1,
                    },
                )

    def test_terminal_grammar_rejects_duplicates_unknowns_and_wrong_attribution(self) -> None:
        base = self.records()
        duplicate = base + [
            {
                "type": "event_msg",
                "payload": {"type": "task_complete", "turn_id": self.turn_id},
            },
            {
                "type": "event_msg",
                "payload": {"type": "turn_aborted", "turn_id": self.turn_id},
            },
        ]
        with self.assertRaisesRegex(NativeSessionBoundaryError, "not singular"):
            trusted_terminal_event(duplicate, turn_id=self.turn_id)
        unknown = base + [
            {
                "type": "event_msg",
                "payload": {"type": "turn_cancelled", "turn_id": self.turn_id},
            }
        ]
        with self.assertRaisesRegex(NativeSessionBoundaryError, "unknown exact-turn"):
            trusted_terminal_event(unknown, turn_id=self.turn_id)
        for payload in (
            {"type": "task_complete", "turnId": self.turn_id},
            {
                "type": "task_complete",
                "turn_id": self.turn_id,
                "turnId": self.turn_id,
            },
            {
                "type": "task_complete",
                "turn_id": self.turn_id,
                "turnId": "conflicting-turn",
            },
            {
                "type": "task_complete",
                "turn_id": "conflicting-turn",
                "turnId": self.turn_id,
            },
        ):
            with self.subTest(payload=payload), self.assertRaisesRegex(
                NativeSessionBoundaryError, "not canonical"
            ):
                trusted_terminal_event(
                    base + [{"type": "event_msg", "payload": payload}],
                    turn_id=self.turn_id,
                )
        wrong_turn = base + [
            {
                "type": "event_msg",
                "payload": {"type": "task_failed", "turn_id": "other-turn"},
            }
        ]
        self.assertIsNone(trusted_terminal_event(wrong_turn, turn_id=self.turn_id))


if __name__ == "__main__":
    unittest.main()

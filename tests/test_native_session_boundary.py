from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


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
        self.path.write_text("not-json\n", encoding="utf-8")
        with self.assertRaisesRegex(NativeSessionBoundaryError, "record 1 is invalid"):
            capture_boundary(self.path, self.session_id)
        self.write(records=[{"type": "session_meta", "payload": {"id": "other"}}])
        with self.assertRaisesRegex(NativeSessionBoundaryError, "identity"):
            capture_boundary(self.path, self.session_id)

    def test_truncation_rewrite_and_delayed_append(self) -> None:
        self.write()
        baseline, _records = capture_boundary(self.path, self.session_id)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"type": "event_msg", "payload": {"type": "user_message"}}) + "\n")
        assert_prefix_intact(self.path, baseline)
        current, _records = capture_boundary(self.path, self.session_id)
        self.assertGreater(current["record_count"], baseline["record_count"])
        raw = self.path.read_bytes()
        self.path.write_bytes(b"x" + raw[1:])
        with self.assertRaisesRegex(NativeSessionBoundaryError, "prefix was rewritten"):
            assert_prefix_intact(self.path, baseline)
        self.path.write_bytes(raw[: max(1, baseline["byte_offset"] - 1)])
        with self.assertRaisesRegex(NativeSessionBoundaryError, "truncated"):
            assert_prefix_intact(self.path, baseline)

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


if __name__ == "__main__":
    unittest.main()

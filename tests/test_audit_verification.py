from __future__ import annotations

import json
import multiprocessing
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.audit import (  # noqa: E402
    iter_audit_events,
    record_audit_event,
    verify_audit_log,
)


def write_audit_events(audit_path: str, worker: int, count: int) -> None:
    for index in range(count):
        record_audit_event(
            {
                "event_type": "packet_built",
                "dispatch_id": f"d-{worker}-{index}",
                "bead_id": f"b-{worker}",
            },
            Path(audit_path),
        )


class AuditVerificationTests(unittest.TestCase):
    def test_hash_chained_audit_log_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_file = Path(tmp) / "audit.jsonl"
            first = record_audit_event({"event_type": "packet_built", "dispatch_id": "d1", "bead_id": "b1"}, audit_file)
            second = record_audit_event({"event_type": "return_evaluated", "dispatch_id": "d1", "bead_id": "b1"}, audit_file)
            self.assertEqual(second["previous_event_hash"], first["event_hash"])
            self.assertEqual(first["audit_lock_mode"], "posix-flock")
            self.assertTrue(verify_audit_log(audit_file)["valid"])

    def test_hash_chained_audit_log_rejects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_file = Path(tmp) / "audit.jsonl"
            record_audit_event({"event_type": "packet_built", "dispatch_id": "d1", "bead_id": "b1"}, audit_file)
            event = json.loads(audit_file.read_text(encoding="utf-8").splitlines()[0])
            event["bead_id"] = "changed"
            audit_file.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")
            result = verify_audit_log(audit_file)
            self.assertFalse(result["valid"])
            self.assertTrue(any("event_hash mismatch" in error for error in result["errors"]))

    def test_hash_chained_audit_log_rejects_reordered_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_file = Path(tmp) / "audit.jsonl"
            record_audit_event({"event_type": "packet_built", "dispatch_id": "d1", "bead_id": "b1"}, audit_file)
            record_audit_event({"event_type": "return_evaluated", "dispatch_id": "d1", "bead_id": "b1"}, audit_file)
            lines = audit_file.read_text(encoding="utf-8").splitlines()
            audit_file.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")

            result = verify_audit_log(audit_file)

            self.assertFalse(result["valid"])
            self.assertTrue(any("previous_event_hash" in error for error in result["errors"]))

    def test_iter_audit_events_is_strict_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_file = Path(tmp) / "audit.jsonl"
            audit_file.write_text('{"event_type":"ok"}\nnot-json\n', encoding="utf-8")

            with self.assertRaises(SystemExit):
                iter_audit_events(audit_file)

            self.assertEqual(iter_audit_events(audit_file, strict=False), [{"event_type": "ok"}])

    def test_concurrent_audit_writes_do_not_lose_events_or_break_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_file = Path(tmp) / "audit.jsonl"
            process_count = 4
            events_per_process = 8
            processes = [
                multiprocessing.Process(target=write_audit_events, args=(str(audit_file), worker, events_per_process))
                for worker in range(process_count)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(10)
            for process in processes:
                self.assertEqual(process.exitcode, 0)
            result = verify_audit_log(audit_file)
            self.assertTrue(result["valid"], result["errors"])
            self.assertEqual(result["event_count"], process_count * events_per_process)


if __name__ == "__main__":
    unittest.main()

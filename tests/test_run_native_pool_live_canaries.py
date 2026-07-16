from __future__ import annotations

import datetime as dt
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "run_native_pool_live_canaries", ROOT / "scripts" / "run_native_pool_live_canaries.py"
)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)


class FakeCalibrationServer:
    def __init__(self, root: Path, *, early_status: str | None = None, command_status: str = "inProgress") -> None:
        self.codex_home = root / "codex-home"
        self.active = self.codex_home / "sessions" / "2026" / "07"
        self.archive = self.codex_home / "archived_sessions"
        self.active.mkdir(parents=True)
        self.archive.mkdir(parents=True)
        self.thread_id = str(uuid.uuid4())
        self.turn_id = str(uuid.uuid4())
        self.path = self.active / f"rollout-{self.thread_id}.jsonl"
        self.read_count = 0
        self.interrupted = False
        self.early_status = early_status
        self.command_status = command_status
        self.rpc_latencies = {}

    def _write(self, records: list[dict]) -> None:
        self.path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")

    def start_thread(self, _cwd: Path, *, mutable: bool) -> tuple[dict, float]:
        self.assert_false(mutable)
        return {
            "model": LIVE.EXACT_MODEL,
            "modelProvider": "trusted",
            "thread": {"id": self.thread_id, "turns": [], "path": str(self.path)},
        }, 1.0

    @staticmethod
    def assert_false(value: bool) -> None:
        if value:
            raise AssertionError("expected false")

    def start_turn(self, thread_id: str, _prompt: str) -> tuple[dict, float]:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        self._write(
            [
                {"type": "session_meta", "payload": {"id": self.thread_id}},
                {"type": "event_msg", "payload": {"type": "task_started", "turn_id": self.turn_id}},
                {"type": "response_item", "payload": {"type": "message", "role": "user"}},
            ]
        )
        return {"id": self.turn_id}, 1.0

    def _thread(self) -> dict:
        status = "interrupted" if self.interrupted else self.early_status or "inProgress"
        items: list[dict] = []
        if self.read_count >= 3:
            items.append(
                {
                    "id": "command-one",
                    "type": "commandExecution",
                    "command": "sleep 20",
                    "commandActions": [],
                    "cwd": "/private",
                    "source": "agent",
                    "status": self.command_status,
                }
            )
        return {
            "id": self.thread_id,
            "path": str(self.path),
            "turns": [{"id": self.turn_id, "status": status, "items": items}],
        }

    def read_thread(self, thread_id: str) -> tuple[dict, float]:
        if thread_id != self.thread_id:
            raise AssertionError("thread mismatch")
        self.read_count += 1
        if self.read_count == 3:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        {
                            "type": "turn_context",
                            "payload": {
                                "turn_id": self.turn_id,
                                "model": LIVE.EXACT_MODEL,
                                "effort": "low",
                            },
                        }
                    )
                    + "\n"
                )
        return self._thread(), 1.0

    def interrupt_turn(self, thread_id: str, turn_id: str) -> float:
        if (thread_id, turn_id) != (self.thread_id, self.turn_id):
            raise AssertionError("interrupt mismatch")
        self.interrupted = True
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {"type": "turn_aborted", "turn_id": self.turn_id},
                    }
                )
                + "\n"
            )
        return 1.0

    def archive_thread(self, thread_id: str) -> float:
        if thread_id != self.thread_id:
            raise AssertionError("archive mismatch")
        target = self.archive / self.path.name
        shutil.move(self.path, target)
        self.path = target
        return 1.0

    def notifications(self, _thread_id: str, _method: str | None = None) -> list[dict]:
        return []


class LiveCanaryMaterializationTests(unittest.TestCase):
    def owner(self) -> dict:
        return {"pid": 1, "start_ticks": 1, "boot_id_sha256": "a" * 64}

    def test_inprogress_before_turn_context_keeps_polling_then_interrupts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_dir = root / "records"
            record_dir.mkdir()
            server = FakeCalibrationServer(root)
            receipt, evidence = LIVE.calibration(
                server,
                root,
                record_dir,
                self.owner(),
                run_nonce=str(uuid.uuid4()),
                phase_nonce=str(uuid.uuid4()),
            )
            self.assertEqual(receipt["validation_outcome"], "accepted")
            self.assertTrue(evidence["interrupt_confirmed"])
            self.assertGreaterEqual(server.read_count, 8)
            materialization = evidence["materialization_evidence"]
            self.assertEqual(materialization["disposition"], "accepted")
            self.assertNotIn("path", json.dumps(materialization).lower())
            self.assertLessEqual(evidence["poll_interval_max_ms"], 250)

    def test_early_completion_and_failed_or_declined_command_are_nonaccepting(self) -> None:
        for early, command, expected in (
            ("completed", "inProgress", "completed-before-deliberate-interrupt"),
            (None, "failed", "command-terminal-before-interrupt"),
            (None, "declined", "command-terminal-before-interrupt"),
        ):
            with self.subTest(early=early, command=command), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                record_dir = root / "records"
                record_dir.mkdir()
                server = FakeCalibrationServer(root, early_status=early, command_status=command)
                with self.assertRaisesRegex(LIVE.AppServerError, expected):
                    LIVE.calibration(
                        server,
                        root,
                        record_dir,
                        self.owner(),
                        run_nonce=str(uuid.uuid4()),
                        phase_nonce=str(uuid.uuid4()),
                    )

    def test_containment_archives_allocated_threads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = FakeCalibrationServer(root)
            server.start_thread(root, mutable=False)
            server.start_turn(server.thread_id, "prompt")
            server.started_threads = {server.thread_id: server.turn_id}
            result = LIVE.contain_started_threads(server)
            self.assertTrue(result["all_contained"])
            self.assertEqual(result["archived_count"], 1)


if __name__ == "__main__":
    unittest.main()

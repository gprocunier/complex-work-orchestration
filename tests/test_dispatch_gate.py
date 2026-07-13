from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

from cwo_core.native_worker_contracts import (  # noqa: E402
    verify_armed_supervision_state,
    verify_completed_supervision_state,
)
from cwo_core.util import artifact_hash  # noqa: E402
from test_supervise_native_worker import planned_packet  # noqa: E402

PREPARE = ROOT / "scripts" / "prepare_native_worker.py"


def run_prepare(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(PREPARE), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _packet() -> dict:
    return {"packet_id": "pkt-1", "bead_id": "bead-1", "payload": "x"}


def _armed_state(packet: dict) -> dict:
    return {
        "result_type": "cwo-native-supervision-state",
        "status": "armed",
        "packet_id": packet["packet_id"],
        "packet_sha256": artifact_hash(json.dumps(packet, sort_keys=True)),
        "control_turn_id": "turn-1",
    }


def _completed_state(packet: dict) -> dict:
    state = _armed_state(packet)
    state["status"] = "completed"
    state["finalized_at"] = "2026-07-13T00:00:00+00:00"
    return state


class ArmedSupervisionGateTests(unittest.TestCase):
    def test_armed_state_passes(self) -> None:
        packet = _packet()
        self.assertEqual(verify_armed_supervision_state(_armed_state(packet), packet, "turn-1"), [])

    def test_wrong_status_fails(self) -> None:
        packet = _packet()
        state = _armed_state(packet)
        state["status"] = "created"
        errors = verify_armed_supervision_state(state, packet, "turn-1")
        self.assertTrue(any("armed" in error for error in errors), errors)

    def test_wrong_packet_hash_fails(self) -> None:
        packet = _packet()
        state = _armed_state(packet)
        packet["payload"] = "tampered"
        errors = verify_armed_supervision_state(state, packet, "turn-1")
        self.assertTrue(any("packet_sha256" in error for error in errors), errors)

    def test_wrong_control_turn_fails(self) -> None:
        packet = _packet()
        errors = verify_armed_supervision_state(_armed_state(packet), packet, "other-turn")
        self.assertTrue(any("control-turn-id" in error for error in errors), errors)

    def test_empty_control_turn_fails(self) -> None:
        packet = _packet()
        errors = verify_armed_supervision_state(_armed_state(packet), packet, "  ")
        self.assertTrue(any("non-empty" in error for error in errors), errors)

    def test_wrong_result_type_fails(self) -> None:
        packet = _packet()
        state = _armed_state(packet)
        state["result_type"] = "something-else"
        errors = verify_armed_supervision_state(state, packet, "turn-1")
        self.assertTrue(any("result_type" in error for error in errors), errors)


class CompletedSupervisionGateTests(unittest.TestCase):
    def test_completed_state_passes(self) -> None:
        packet = _packet()
        self.assertEqual(verify_completed_supervision_state(_completed_state(packet), packet), [])

    def test_running_state_fails(self) -> None:
        packet = _packet()
        state = _completed_state(packet)
        state["status"] = "running"
        errors = verify_completed_supervision_state(state, packet)
        self.assertTrue(any("finalized" in error for error in errors), errors)

    def test_missing_finalized_at_fails(self) -> None:
        packet = _packet()
        state = _completed_state(packet)
        state["finalized_at"] = None
        errors = verify_completed_supervision_state(state, packet)
        self.assertTrue(any("finalized_at" in error for error in errors), errors)

    def test_wrong_packet_hash_fails(self) -> None:
        packet = _packet()
        state = _completed_state(packet)
        packet["payload"] = "tampered"
        errors = verify_completed_supervision_state(state, packet)
        self.assertTrue(any("packet_sha256" in error for error in errors), errors)


class RenderDispatchGateCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="cwo-dispatch-gate-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.packet = planned_packet(packet_id="packet-dispatch-gate")
        self.packet_path = self.root / "packet.json"
        self.packet_path.write_text(json.dumps(self.packet), encoding="utf-8")

    def _armed_state_file(self, *, control_turn_id: str = "turn-gate") -> Path:
        state = {
            "result_type": "cwo-native-supervision-state",
            "status": "armed",
            "packet_id": self.packet["packet_id"],
            "packet_sha256": artifact_hash(json.dumps(self.packet, sort_keys=True)),
            "control_turn_id": control_turn_id,
        }
        path = self.root / "state.json"
        path.write_text(json.dumps(state), encoding="utf-8")
        return path

    def test_preview_only_renders_watermarked_prompt(self) -> None:
        result = run_prepare("render", str(self.packet_path), "--preview-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PREVIEW ONLY - NOT FOR DISPATCH", result.stdout)
        self.assertIn("Native Worker Packet Prompt", result.stdout)

    def test_render_without_mode_flag_fails(self) -> None:
        result = run_prepare("render", str(self.packet_path))
        self.assertNotEqual(result.returncode, 0)

    def test_supervised_render_passes_with_armed_state(self) -> None:
        state_path = self._armed_state_file()
        result = run_prepare(
            "render",
            str(self.packet_path),
            "--supervision-state",
            str(state_path),
            "--control-turn-id",
            "turn-gate",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("PREVIEW ONLY", result.stdout)
        self.assertIn("Native Worker Packet Prompt", result.stdout)

    def test_supervised_render_rejects_wrong_control_turn(self) -> None:
        state_path = self._armed_state_file()
        result = run_prepare(
            "render",
            str(self.packet_path),
            "--supervision-state",
            str(state_path),
            "--control-turn-id",
            "other-turn",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dispatch gate failed", result.stderr)

    def test_validate_return_waiver_requires_reason(self) -> None:
        result = run_prepare(
            "validate-return",
            "--packet",
            str(self.packet_path),
            "--return",
            str(self.packet_path),
            "--allow-unsupervised-return",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--waiver-reason is required", result.stderr)


if __name__ == "__main__":
    unittest.main()

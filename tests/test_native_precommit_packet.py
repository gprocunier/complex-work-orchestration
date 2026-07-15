from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_precommit import (  # noqa: E402
    arm_precommit,
    check_precommit,
    finalize_precommit,
    issue_precommit_receipt,
    mark_fit_dispatched,
    create_precommit_state,
)
from cwo_core.work_sizing import (  # noqa: E402
    build_worker_commitment_from_receipt,
    canonical_work_estimate_sha256,
    evaluate_work_estimate,
    validate_worker_commitment,
)
from prepare_native_worker import build_native_worker_packet, validate_native_worker_packet  # noqa: E402
from tests.test_native_work_sizing import _valid_v2_payload  # noqa: E402


MODEL = "gpt-5.3-codex-spark"
CONTROL = "packet-precommit-control-turn"


def session_meta(session_id: str) -> dict:
    return {
        "timestamp": "2026-07-15T00:00:00Z",
        "type": "session_meta",
        "payload": {"id": session_id},
        "turn_context": {
            "model": MODEL,
            "attestation_source": "trusted-control-plane-session-metadata",
            "token_count": {"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0},
        },
    }


def fit_records(session_id: str) -> list[dict]:
    response = json.dumps(
        {
            "decision": "accept",
            "tool_calls_p50": 4,
            "tool_calls_p90": 8,
            "runtime_seconds_p50": 40,
            "runtime_seconds_p90": 100,
        },
        sort_keys=True,
    )
    return [
        {
            "timestamp": "2026-07-15T00:00:01Z",
            "session_id": session_id,
            "type": "response_item",
            "turn_context": {"model": MODEL, "attestation_source": "trusted-control-plane-session-metadata"},
            "response_item": {"type": "message", "role": "user", "content": "fit"},
        },
        {
            "timestamp": "2026-07-15T00:00:02Z",
            "session_id": session_id,
            "type": "response_item",
            "turn_context": {"model": MODEL, "attestation_source": "trusted-control-plane-session-metadata"},
            "response_item": {"type": "message", "role": "assistant", "content": response},
        },
        {
            "timestamp": "2026-07-15T00:00:03Z",
            "session_id": session_id,
            "event_msg": "task_complete",
            "turn_context": {"model": MODEL, "attestation_source": "trusted-control-plane-session-metadata"},
        },
    ]


def write_records(path: Path, records: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )


class NativePrecommitPacketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cwo-precommit-packet-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.registry = self.root / "registry"
        self.original_registry = os.environ.get("CWO_PRECOMMIT_REGISTRY_ROOT")
        os.environ["CWO_PRECOMMIT_REGISTRY_ROOT"] = str(self.registry)
        self.addCleanup(self.restore_registry)
        self.session_id = "packet-precommit-session"
        self.session_file = self.root / "session.jsonl"
        write_records(self.session_file, [session_meta(self.session_id)])
        self.state_file = self.root / "state.json"
        self.receipt_file = self.root / "receipt.json"
        self.audit_file = self.root / "audit.jsonl"
        self.plan = evaluate_work_estimate(_valid_v2_payload())
        self.packet_id = "packet-receipt-bound-candidate"
        self.receipt = self.make_receipt()

    def restore_registry(self) -> None:
        if self.original_registry is None:
            os.environ.pop("CWO_PRECOMMIT_REGISTRY_ROOT", None)
        else:
            os.environ["CWO_PRECOMMIT_REGISTRY_ROOT"] = self.original_registry

    def make_receipt(self) -> dict:
        create_precommit_state(
            packet_id=self.packet_id,
            attempt_nonce="packet-attempt-nonce",
            work_plan=self.plan,
            session_id=self.session_id,
            session_file=self.session_file,
            agent_id="spark-fit-agent",
            workdir=ROOT,
            state_file=self.state_file,
            owner_pid=os.getpid(),
            audit_file=self.audit_file,
            now="2026-07-15T00:00:00Z",
        )
        arm_precommit(self.state_file, CONTROL, now="2026-07-15T00:00:00.100Z")
        _, code = mark_fit_dispatched(
            self.state_file,
            CONTROL,
            "native-fit-submission",
            now="2026-07-15T00:00:00.200Z",
        )
        self.assertEqual(code, 0)
        write_records(self.session_file, [session_meta(self.session_id), *fit_records(self.session_id)])
        _, code = check_precommit(self.state_file, CONTROL, now="2026-07-15T00:00:00.300Z")
        self.assertEqual(code, 0)
        finalize_precommit(self.state_file, CONTROL, "worker-completed", now="2026-07-15T00:00:00.400Z")
        finalize_precommit(self.state_file, CONTROL, "close-confirmed", now="2026-07-15T00:00:00.500Z")
        issue_precommit_receipt(self.state_file, receipt_file=self.receipt_file)
        return json.loads(self.receipt_file.read_text(encoding="utf-8"))

    def build(self, *, receipt: dict | None = None, commitment: dict | None = None) -> dict:
        selected = receipt or self.receipt
        return build_native_worker_packet(
            bead_id=self.plan["bead_id"],
            lane="implementation",
            workdir=str(ROOT),
            allowed_paths=self.plan["write_paths"],
            acceptance_checks=self.plan["acceptance_checks"],
            work_plan=self.plan,
            worker_commitment=commitment,
            precommit_receipt=selected,
            packet_id=self.packet_id,
        )

    def test_commitment_v2_derives_identity_and_activity_authority_from_receipt(self) -> None:
        commitment = build_worker_commitment_from_receipt(self.plan, self.receipt)
        self.assertEqual(commitment["version"], 2)
        self.assertEqual(commitment["session_id"], self.receipt["session_id"])
        self.assertEqual(commitment["agent_id"], self.receipt["agent_id"])
        self.assertNotIn("tool_calls_before_commitment", commitment)
        self.assertNotIn("context_compactions_before_commitment", commitment)
        self.assertEqual(validate_worker_commitment(commitment, self.plan, precommit_receipt=self.receipt), [])
        tampered = copy.deepcopy(commitment)
        tampered["session_id"] = "different"
        self.assertTrue(any("derive exclusively" in error for error in validate_worker_commitment(tampered, self.plan, precommit_receipt=self.receipt)))

    def test_commitment_v1_is_historical_only(self) -> None:
        legacy = {
            "commitment_type": "cwo-native-worker-fit-commitment",
            "version": 1,
            "work_unit_id": self.plan["work_unit_id"],
            "bead_id": self.plan["bead_id"],
            "requested_model": MODEL,
            "session_id": self.session_id,
            "attestation_source": "trusted-session-jsonl",
            "attested_model": MODEL,
            "work_estimate_sha256": canonical_work_estimate_sha256(self.plan),
            "decision": "accept",
            "confidence": 0.9,
            "estimates": {"tool_calls_p50": 4, "tool_calls_p90": 8, "runtime_seconds_p50": 40, "runtime_seconds_p90": 100},
            "tool_calls_before_commitment": 0,
            "context_compactions_before_commitment": 0,
            "reason": "historical",
        }
        self.assertEqual(validate_worker_commitment(legacy, self.plan), [])
        self.assertIn("historical-inspection-only", " ".join(validate_worker_commitment(legacy, self.plan, dispatchable=True)))

    def test_candidate_packet_is_structurally_valid_and_operatively_forbidden(self) -> None:
        packet = self.build()
        self.assertEqual(packet["stage"], "precommit-validated")
        self.assertFalse(packet["operative_dispatch_authorized"])
        self.assertEqual(packet["release_requires"], "complex-work-orchestration-fsh.3")
        self.assertEqual(packet["precommit_receipt_sha256"], self.receipt["receipt_sha256"])
        self.assertEqual(validate_native_worker_packet(packet), [])
        dispatch_errors = validate_native_worker_packet(packet, dispatchable=True)
        self.assertTrue(any("operative-dispatch-forbidden" in error for error in dispatch_errors))

    def test_receipt_replay_changed_plan_and_intervening_session_are_rejected(self) -> None:
        self.build()
        with self.assertRaisesRegex(SystemExit, "replay"):
            self.build()
        altered = copy.deepcopy(self.plan)
        altered["primary_outcome"] = altered["primary_outcome"] + " with changed PM refinement"
        with self.assertRaisesRegex(SystemExit, "work_plan_sha256"):
            build_native_worker_packet(
                bead_id=altered["bead_id"],
                lane="implementation",
                workdir=str(ROOT),
                allowed_paths=altered["write_paths"],
                acceptance_checks=altered["acceptance_checks"],
                work_plan=altered,
                precommit_receipt=self.receipt,
                packet_id=self.packet_id,
            )
        write_records(self.session_file, [session_meta(self.session_id), *fit_records(self.session_id), {"timestamp": "2026-07-15T00:00:04Z", "session_id": self.session_id, "event_msg": "extra"}])
        with self.assertRaisesRegex(SystemExit, "intervening session"):
            build_native_worker_packet(
                bead_id=self.plan["bead_id"],
                lane="implementation",
                workdir=str(ROOT),
                allowed_paths=self.plan["write_paths"],
                acceptance_checks=self.plan["acceptance_checks"],
                work_plan=self.plan,
                precommit_receipt=self.receipt,
                packet_id=self.packet_id,
            )

    def test_render_and_native_supervisor_reject_candidate(self) -> None:
        packet = self.build()
        packet_file = self.root / "packet.json"
        packet_file.write_text(json.dumps(packet), encoding="utf-8")
        render = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "prepare_native_worker.py"), "render", str(packet_file)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(render.returncode, 0)
        self.assertIn("native-precommit-containment-active", render.stderr)
        start = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "supervise_native_worker.py"),
                "start",
                "--packet",
                str(packet_file),
                "--session-id",
                self.session_id,
                "--session-file",
                str(self.session_file),
                "--agent-id",
                "spark-agent",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(start.returncode, 0)
        self.assertIn("native-precommit-containment-active", start.stderr)


if __name__ == "__main__":
    unittest.main()

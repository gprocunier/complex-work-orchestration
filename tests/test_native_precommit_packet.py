from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shlex
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
    release_precommit_receipt_reservation,
    reserve_precommit_receipt,
)
import cwo_core.native_precommit as native_precommit  # noqa: E402
from cwo_core.native_release import authorize_operative_packet  # noqa: E402
from cwo_core.work_sizing import (  # noqa: E402
    build_worker_commitment_from_receipt,
    canonical_work_estimate_sha256,
    evaluate_work_estimate,
    validate_worker_commitment,
)
from prepare_native_worker import (  # noqa: E402
    _direct_execution_contract_errors,
    _render_prompt,
    build_native_worker_packet,
    validate_native_worker_packet,
)
from tests.native_precommit_fixtures import issue_accepting_precommit_receipt  # noqa: E402
from tests.test_native_work_sizing import _valid_v2_payload  # noqa: E402


MODEL = "gpt-5.3-codex-spark"
CONTROL = "packet-precommit-control-turn"


def canary_work_plan() -> dict:
    return {
        "work_unit_id": "fsh3-positive-canary",
        "bead_id": "complex-work-orchestration-fsh.3.5",
        "requested_model": MODEL,
        "task_class": "bounded-implementation",
        "scores": {
            "reasoning_uncertainty": 0,
            "subsystem_coupling": 0,
            "contract_risk": 0,
            "diagnostic_uncertainty": 0,
            "context_breadth": 0,
            "validation_breadth": 0,
        },
        "aggregate_allowance": {
            "tool_calls_soft": 1,
            "tool_calls_hard": 1,
            "runtime_seconds_soft": 30,
            "runtime_seconds_hard": 120,
        },
    }


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

    def build(
        self,
        *,
        receipt: dict | None = None,
        commitment: dict | None = None,
        budget_overrides: dict | None = None,
    ) -> dict:
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
            budget_overrides=budget_overrides,
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

    def test_direct_execution_contract_requires_explicit_canonical_authority(self) -> None:
        eligible = {
            "task_profile": {
                "task_class": "literal-command",
                "commands": [{"argv": ["git", "status", "--short"]}],
                "execution_contract": {"mode": "direct", "checked_command_specs": []},
            }
        }
        self.assertEqual(_direct_execution_contract_errors(eligible), [])

        for contract in (
            None,
            {"mode": "direct", "checked_command_specs": [{}]},
            {"mode": "checked-sequence-v1", "checked_command_specs": []},
            {"mode": "direct", "checked_command_specs": [], "unexpected": True},
        ):
            malformed = copy.deepcopy(eligible)
            if contract is None:
                malformed["task_profile"].pop("execution_contract")
            else:
                malformed["task_profile"]["execution_contract"] = contract
            self.assertTrue(_direct_execution_contract_errors(malformed), contract)

        noneligible = copy.deepcopy(eligible)
        noneligible["task_profile"]["task_class"] = "bounded-implementation"
        noneligible["task_profile"].pop("execution_contract")
        self.assertEqual(_direct_execution_contract_errors(noneligible), [])

        packet = self.build()
        packet["work_plan"]["task_profile"] = copy.deepcopy(eligible["task_profile"])
        packet["work_plan"]["task_profile"].pop("execution_contract")
        errors = validate_native_worker_packet(packet, dispatchable=True)
        self.assertTrue(any("execution_contract mode direct" in error for error in errors))
        packet["work_plan"]["task_profile"]["execution_contract"] = {
            "mode": "direct",
            "checked_command_specs": [],
        }
        errors = validate_native_worker_packet(packet, dispatchable=True)
        self.assertFalse(any("execution_contract mode direct" in error for error in errors))

    def test_render_exact_argv_requires_direct_contract_and_uses_shell_quoting(self) -> None:
        packet = self.build()
        argv = ["python3", "-c", "print('hello world')"]
        packet["work_plan"] = {
            "fit_mode": "deterministic",
            "task_class": "literal-command",
            "write_paths": [],
            "task_profile": {
                "task_class": "literal-command",
                "commands": [{"argv": argv}],
                "execution_contract": {"mode": "direct", "checked_command_specs": []},
            },
        }
        rendered = _render_prompt(packet)
        self.assertIn("Deterministic execution contract:", rendered)
        self.assertIn(f"1. {shlex.join(argv)}", rendered)
        self.assertIn(f'"commands_run": [\n    "{shlex.join(argv).replace(chr(34), chr(92) + chr(34))}"', rendered)

        packet["work_plan"]["task_profile"].pop("execution_contract")
        rendered_without_authority = _render_prompt(packet)
        self.assertNotIn("Deterministic execution contract:", rendered_without_authority)
        self.assertNotIn(f"1. {shlex.join(argv)}", rendered_without_authority)
        self.assertIn("Checked command execution:", rendered_without_authority)

        packet["work_plan"]["task_profile"]["execution_contract"] = {
            "mode": "direct",
            "checked_command_specs": [],
        }
        packet["work_plan"]["task_profile"]["commands"] = []
        self.assertNotIn("Deterministic execution contract:", _render_prompt(packet))

    def test_candidate_packet_is_structurally_valid_and_operatively_forbidden(self) -> None:
        packet = self.build()
        self.assertEqual(packet["stage"], "precommit-validated")
        self.assertFalse(packet["operative_dispatch_authorized"])
        self.assertEqual(packet["release_requires"], "complex-work-orchestration-fsh.3")
        self.assertEqual(packet["precommit_receipt_sha256"], self.receipt["receipt_sha256"])
        self.assertEqual(validate_native_worker_packet(packet), [])
        dispatch_errors = validate_native_worker_packet(packet, dispatchable=True)
        self.assertTrue(any("operative-dispatch-forbidden" in error for error in dispatch_errors))

    def test_adjudicated_packet_is_dispatchable_only_with_bound_release_evidence(self) -> None:
        canary_workspace = self.root / "canary-workspace"
        canary_workspace.mkdir()
        canary_receipt = issue_accepting_precommit_receipt(
            work_plan=canary_work_plan(),
            packet_id="packet-canary-proof",
            artifact_root=self.root / "canary-receipt",
            workdir=canary_workspace,
            estimates={
                "tool_calls_p50": 1,
                "tool_calls_p90": 1,
                "runtime_seconds_p50": 10,
                "runtime_seconds_p90": 20,
            },
        )
        canary_hash = canary_receipt["receipt_sha256"]
        allowance = self.plan["aggregate_allowance"]
        candidate = self.build(
            budget_overrides={
                "tool_calls_soft": allowance["tool_calls_hard"],
                "tool_calls_hard": allowance["tool_calls_hard"],
                "runtime_seconds_soft": allowance["runtime_seconds_hard"],
                "runtime_seconds_hard": allowance["runtime_seconds_hard"],
            },
        )
        packet = authorize_operative_packet(
            candidate_packet=candidate,
            adjudication={
                "adjudication_type": "cwo-native-operative-release-adjudication",
                "version": 1,
                "bead_id": "complex-work-orchestration-fsh.3.5",
                "decision": "GO",
                "accepted_high_severity_findings": 0,
                "validation_sha256": "3" * 64,
                "critic_evidence_sha256": "4" * 64,
                "canary_receipt_sha256": canary_hash,
            },
            canary_receipt=canary_receipt,
        )
        self.assertEqual(packet["stage"], "operative-authorized")
        self.assertTrue(packet["operative_dispatch_authorized"])
        self.assertEqual(validate_native_worker_packet(packet, dispatchable=True), [])
        tampered = copy.deepcopy(packet)
        tampered["release_evidence_sha256"] = "0" * 64
        self.assertTrue(validate_native_worker_packet(tampered, dispatchable=True))

    def test_release_cli_writes_private_dispatchable_packet(self) -> None:
        allowance = self.plan["aggregate_allowance"]
        candidate = self.build(
            budget_overrides={
                "tool_calls_soft": allowance["tool_calls_hard"],
                "tool_calls_hard": allowance["tool_calls_hard"],
                "runtime_seconds_soft": allowance["runtime_seconds_hard"],
                "runtime_seconds_hard": allowance["runtime_seconds_hard"],
            },
        )
        canary_workspace = self.root / "cli-canary-workspace"
        canary_workspace.mkdir()
        canary_receipt = issue_accepting_precommit_receipt(
            work_plan=canary_work_plan(),
            packet_id="packet-cli-canary-proof",
            artifact_root=self.root / "cli-canary-receipt",
            workdir=canary_workspace,
            estimates={
                "tool_calls_p50": 1,
                "tool_calls_p90": 1,
                "runtime_seconds_p50": 10,
                "runtime_seconds_p90": 20,
            },
        )
        canary_hash = canary_receipt["receipt_sha256"]
        adjudication = {
            "adjudication_type": "cwo-native-operative-release-adjudication",
            "version": 1,
            "bead_id": "complex-work-orchestration-fsh.3.5",
            "decision": "GO",
            "accepted_high_severity_findings": 0,
            "validation_sha256": "3" * 64,
            "critic_evidence_sha256": "4" * 64,
            "canary_receipt_sha256": canary_hash,
        }
        candidate_path = self.root / "candidate.json"
        canary_path = self.root / "canary.json"
        adjudication_path = self.root / "adjudication.json"
        output_path = self.root / "authorized.json"
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        canary_path.write_text(json.dumps(canary_receipt), encoding="utf-8")
        adjudication_path.write_text(json.dumps(adjudication), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "manage_native_release.py"),
                "authorize-packet",
                "--candidate-packet",
                str(candidate_path),
                "--adjudication",
                str(adjudication_path),
                "--canary-receipt",
                str(canary_path),
                "--output",
                str(output_path),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)
        packet = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(validate_native_worker_packet(packet, dispatchable=True), [])

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

    def test_concurrent_packet_builders_allow_exactly_one_consumption(self) -> None:
        def build_once() -> tuple[str, str]:
            try:
                packet = self.build()
            except SystemExit as exc:
                return "rejected", str(exc)
            return "built", packet["packet_id"]

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: build_once(), range(2)))
        self.assertEqual(sum(status == "built" for status, _ in results), 1)
        rejected = [message for status, message in results if status == "rejected"]
        self.assertEqual(len(rejected), 1)
        self.assertRegex(rejected[0], "active packet-build reservation|replay detected")

    def test_failed_packet_build_releases_receipt_reservation(self) -> None:
        with self.assertRaisesRegex(SystemExit, "unknown lane"):
            build_native_worker_packet(
                bead_id=self.plan["bead_id"],
                lane="unknown-lane",
                workdir=str(ROOT),
                allowed_paths=self.plan["write_paths"],
                acceptance_checks=self.plan["acceptance_checks"],
                work_plan=self.plan,
                precommit_receipt=self.receipt,
                packet_id=self.packet_id,
            )
        self.assertEqual(self.build()["packet_id"], self.packet_id)

    def test_stale_reservation_cleanup_requires_dead_owner_and_terminal_state(self) -> None:
        reservation_id = reserve_precommit_receipt(self.receipt, "stale-build")
        sleeper = subprocess.Popen(["sleep", "30"])
        self.addCleanup(lambda: sleeper.poll() is None and sleeper.terminate())
        registry_path = self.registry / "receipt-reservations.json"
        reservations = json.loads(registry_path.read_text(encoding="utf-8"))
        reservations[self.receipt["receipt_sha256"]]["owner_identity"] = native_precommit._capture_owner_identity(
            sleeper.pid,
            reservation_id,
        )
        registry_path.write_text(
            json.dumps(reservations, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        sleeper.terminate()
        sleeper.wait(timeout=5)
        replacement = reserve_precommit_receipt(self.receipt, "replacement-build")
        release_precommit_receipt_reservation(self.receipt, replacement)

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

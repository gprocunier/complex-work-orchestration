from __future__ import annotations

import copy
import json
import importlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None

from prepare_native_worker import (  # noqa: E402
    _policy_budgets_for_lane,
    _policy_lanes,
    build_native_worker_packet,
    validate_native_worker_packet,
    validate_native_worker_return,
)
from cwo_core.native_disposition import derive_disposition  # noqa: E402
from cwo_core import native_worker_contracts as contracts  # noqa: E402


def set_disposition(packet: dict, result: dict) -> None:
    result.update(
        derive_disposition(
            status=result["status"],
            requested_model=packet["requested_model"],
            actual_model=result.get("actual_model"),
            usage=result["usage"],
            budget=packet["budget"],
            validation=result.get("artifact_validation"),
        )
    )


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "prepare_native_worker.py"), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


class NativeWorkerPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads((ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8"))

    def test_schemas_are_loadable(self) -> None:
        for schema in [
            ROOT / "schemas" / "native-worker-packet.schema.json",
            ROOT / "schemas" / "native-worker-return.schema.json",
        ]:
            json.loads(schema.read_text(encoding="utf-8"))

    @staticmethod
    def _schema(path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))

    def test_packet_schema_property_contract_parity(self) -> None:
        schema = self._schema(ROOT / "schemas" / "native-worker-packet.schema.json")
        properties = schema["properties"]
        self.assertEqual(set(properties.keys()), contracts.ALLOWED_PACKET_FIELDS)
        self.assertEqual(set(properties["session_policy"]["properties"].keys()), contracts.ALLOWED_SESSION_POLICY_FIELDS)
        self.assertEqual(
            set(properties["session_policy"]["properties"]["attestation"]["properties"].keys()),
            contracts.ALLOWED_ATTESTATION_FIELDS,
        )
        self.assertEqual(set(properties["scope"]["properties"].keys()), contracts.ALLOWED_SCOPE_FIELDS)
        self.assertEqual(set(properties["budget"]["properties"].keys()), contracts.ALLOWED_BUDGET_FIELDS)
        self.assertEqual(set(properties["budget_provenance"]["properties"].keys()), contracts.ALLOWED_BUDGET_PROVENANCE_FIELDS)
        self.assertEqual(set(properties["supervision"]["properties"].keys()), contracts.ALLOWED_SUPERVISION_FIELDS)
        self.assertEqual(
            set(properties["supervision"]["properties"]["interrupt_thresholds"]["properties"].keys()),
            contracts.ALLOWED_INTERRUPT_THRESHOLD_FIELDS,
        )
        self.assertEqual(set(properties["validation_lineage"]["properties"].keys()), contracts.ALLOWED_VALIDATION_LINEAGE_FIELDS)
        self.assertEqual(set(properties["escalation_triggers"]["properties"].keys()), contracts.ALLOWED_ESCALATION_TRIGGER_FIELDS)
        self.assertEqual(
            set(properties["escalation_triggers"]["properties"]["soft_limit"]["properties"].keys()),
            contracts.ALLOWED_ESCALATION_SOFT_LIMIT_FIELDS,
        )
        self.assertEqual(
            set(properties["escalation_triggers"]["properties"]["hard_limit"]["properties"].keys()),
            contracts.ALLOWED_ESCALATION_HARD_LIMIT_FIELDS,
        )
        self.assertEqual(
            set(properties["escalation_triggers"]["properties"]["compaction"]["properties"].keys()),
            contracts.ALLOWED_ESCALATION_COMPACTION_FIELDS,
        )
        self.assertEqual(set(properties["return_contract"]["properties"].keys()), contracts.ALLOWED_RETURN_CONTRACT_FIELDS)
        self.assertEqual(set(properties["command_contract"]["properties"].keys()), contracts.ALLOWED_COMMAND_CONTRACT_FIELDS)

    def test_return_schema_property_contract_parity(self) -> None:
        schema = self._schema(ROOT / "schemas" / "native-worker-return.schema.json")
        properties = schema["properties"]
        self.assertEqual(set(properties.keys()), contracts.ALLOWED_RETURN_FIELDS)
        self.assertEqual(set(properties["usage"]["properties"].keys()), contracts.ALLOWED_RETURN_USAGE_FIELDS)

    def test_build_outputs_policy_derived_budget_and_contract(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            allowed = Path(workdir) / "allowed"
            allowed.mkdir()
            result = run_cli(
                "build",
                "--bead-id",
                "bead-1",
                "--lane",
                "implementation",
                "--workdir",
                workdir,
                "--allowed-path",
                str(allowed),
                "--acceptance-check",
                "tests pass",
                "--acceptance-check",
                "artifact clean",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            packet = json.loads(result.stdout)

            self.assertEqual(packet["packet_type"], "cwo-native-worker-packet")
            self.assertEqual(packet["version"], 2)
            self.assertEqual(packet["lane"], "implementation")
            self.assertEqual(packet["requested_model"], "gpt-5.3-codex-spark")
            self.assertEqual(packet["budget"], _policy_budgets_for_lane("implementation"))
            self.assertEqual(
                packet["budget_provenance"],
                {
                    "profile": "implementation",
                    "policy_source": "policy/native-worker-execution.yaml",
                    "overrides_applied": False,
                    "overridden_fields": [],
                },
            )
            self.assertEqual(
                packet["supervision"]["interrupt_thresholds"],
                {"tool_calls": 90, "runtime_seconds": 972},
            )
            self.assertEqual(packet["supervision"]["segment_start_grace_seconds"], 10)
            self.assertEqual(packet["supervision"]["poll_lag_tolerance_ms"], 1500)
            self.assertEqual(packet["supervision"]["arm_to_dispatch_max_ms"], 5000)
            self.assertTrue(packet["supervision"]["control_turn_required"])
            self.assertEqual(packet["validation_lineage"]["attempt"], 0)
            self.assertTrue(packet["command_contract"]["required"])
            self.assertEqual(packet["command_contract"]["wrapper"], "scripts/run_checked_command.py")
            self.assertIsNone(packet["validation_lineage"]["parent_packet_id"])
            if HAS_JSONSCHEMA:
                import jsonschema

                schema = json.loads((ROOT / "schemas" / "native-worker-packet.schema.json").read_text(encoding="utf-8"))
                jsonschema.validate(packet, schema)
            self.assertEqual(
                packet["return_contract"]["allowed_statuses"],
                self.policy["return_statuses"],
            )
            self.assertIn("scope", packet)
            self.assertEqual(packet["scope"]["workdir"], str(Path(workdir).resolve()))
            self.assertEqual(
                packet["escalation_triggers"]["soft_limit"],
                {"distinct_soft_limits_required": 2},
            )
            self.assertEqual(
                packet["escalation_triggers"]["hard_limit"],
                {"any_hard_limit": "realignment", "status": "needs-architect-realignment"},
            )
            self.assertEqual(
                packet["escalation_triggers"]["compaction"],
                {"any_compaction": "hard-stop/realignment", "status": "needs-architect-realignment"},
            )

    def test_build_rejects_unknown_lane(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            result = run_cli(
                "build",
                "--bead-id",
                "bead-1",
                "--lane",
                "mystery",
                "--workdir",
                workdir,
                "--allowed-path",
                ".",
                "--acceptance-check",
                "tests pass",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown lane", result.stderr.lower())

    def test_explicit_luna_packet_binds_exact_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            allowed = Path(workdir) / "allowed"
            allowed.mkdir()
            packet = build_native_worker_packet(
                bead_id="bead-luna",
                lane="implementation",
                workdir=workdir,
                allowed_paths=[str(allowed)],
                acceptance_checks=["focused tests pass"],
                requested_model="gpt-5.6-luna",
            )
            self.assertEqual(packet["requested_model"], "gpt-5.6-luna")
            self.assertEqual(
                packet["session_policy"]["attestation"]["required_actual_model"],
                "gpt-5.6-luna",
            )
            self.assertEqual(validate_native_worker_packet(packet), [])

            if HAS_JSONSCHEMA:
                from jsonschema import Draft202012Validator

                schema = json.loads((ROOT / "schemas" / "native-worker-packet.schema.json").read_text(encoding="utf-8"))
                validator = Draft202012Validator(schema)
                validator.validate(packet)

            packet["session_policy"]["attestation"]["required_actual_model"] = "gpt-5.3-codex-spark"
            self.assertIn(
                "session_policy.attestation.required_actual_model must match packet.requested_model",
                validate_native_worker_packet(packet),
            )
            if HAS_JSONSCHEMA:
                self.assertTrue(list(validator.iter_errors(packet)))

    def test_build_rejects_unauthorized_native_model(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            with self.assertRaisesRegex(SystemExit, "is not authorized"):
                build_native_worker_packet(
                    bead_id="bead-model",
                    lane="implementation",
                    workdir=workdir,
                    allowed_paths=["."],
                    acceptance_checks=["focused tests pass"],
                    requested_model="gpt-5.6-sol",
                )

    def test_build_rejects_traversal_and_out_of_scope_allowed_paths(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            inside = Path(workdir) / "inside"
            outside = Path(workdir).parent / "outside"
            inside.mkdir()
            outside.mkdir(exist_ok=True)
            result = run_cli(
                "build",
                "--bead-id",
                "bead-1",
                "--lane",
                _policy_lanes()[0],
                "--workdir",
                workdir,
                "--allowed-path",
                "..",
                "--acceptance-check",
                "tests pass",
            )
            self.assertNotEqual(result.returncode, 0)
            result_abs = run_cli(
                "build",
                "--bead-id",
                "bead-1",
                "--lane",
                _policy_lanes()[0],
                "--workdir",
                workdir,
                "--allowed-path",
                str(outside),
                "--acceptance-check",
                "tests pass",
            )
            self.assertNotEqual(result_abs.returncode, 0)

            result_ok = run_cli(
                "build",
                "--bead-id",
                "bead-1",
                "--lane",
                _policy_lanes()[0],
                "--workdir",
                workdir,
                "--allowed-path",
                str(inside),
                "--acceptance-check",
                "tests pass",
            )
            self.assertEqual(result_ok.returncode, 0, result_ok.stderr)

    def test_build_rejects_empty_acceptance_check(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            allowed = Path(workdir) / "allowed"
            allowed.mkdir()
            result = run_cli(
                "build",
                "--bead-id",
                "bead-1",
                "--lane",
                _policy_lanes()[0],
                "--workdir",
                workdir,
                "--allowed-path",
                str(allowed),
                "--acceptance-check",
                "",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("non-empty", result.stderr.lower())

    def test_cli_validate_rejects_model_and_relaxed_budget(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            allowed = Path(workdir) / "allowed"
            allowed.mkdir()
            packet = build_native_worker_packet(
                bead_id="bead-1",
                lane="implementation",
                workdir=workdir,
                allowed_paths=[str(allowed)],
                acceptance_checks=["tests pass"],
            )
            packet_path = Path(workdir) / "packet.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            with open(packet_path, "r+", encoding="utf-8") as handle:
                payload = json.load(handle)
                payload["requested_model"] = "different-model"
                handle.seek(0)
                handle.truncate()
                handle.write(json.dumps(payload))
            result = run_cli("validate", str(packet_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requested_model must be an authorized native operative model", result.stderr)

            packet = build_native_worker_packet(
                bead_id="bead-1",
                lane="validation",
                workdir=workdir,
                allowed_paths=[str(allowed)],
                acceptance_checks=["tests pass"],
            )
            with open(packet_path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(packet))
            with open(packet_path, "r+", encoding="utf-8") as handle:
                payload = json.load(handle)
                payload["budget"]["tool_calls_hard"] = 999
                handle.seek(0)
                handle.truncate()
                handle.write(json.dumps(payload))
            with open(packet_path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload))
            result_budget = run_cli("validate", str(packet_path))
            self.assertNotEqual(result_budget.returncode, 0)
            self.assertIn("budget.tool_calls_hard may only tighten policy profile", result_budget.stderr)

    def test_build_accepts_only_tightening_budget_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            allowed = Path(workdir) / "allowed"
            allowed.mkdir()
            result = run_cli(
                "build",
                "--bead-id",
                "bead-budget",
                "--lane",
                "implementation",
                "--workdir",
                workdir,
                "--allowed-path",
                str(allowed),
                "--acceptance-check",
                "focused tests pass",
                "--tool-calls-soft",
                "5",
                "--tool-calls-hard",
                "10",
                "--runtime-seconds-soft",
                "30",
                "--runtime-seconds-hard",
                "60",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            packet = json.loads(result.stdout)
            self.assertEqual(packet["budget"]["tool_calls_soft"], 5)
            self.assertEqual(packet["budget"]["tool_calls_hard"], 10)
            self.assertEqual(packet["budget"]["runtime_seconds_soft"], 30)
            self.assertEqual(packet["budget"]["runtime_seconds_hard"], 60)
            self.assertEqual(
                packet["budget_provenance"]["overridden_fields"],
                [
                    "runtime_seconds_hard",
                    "runtime_seconds_soft",
                    "tool_calls_hard",
                    "tool_calls_soft",
                ],
            )
            self.assertTrue(packet["budget_provenance"]["overrides_applied"])
            self.assertEqual(
                packet["supervision"]["interrupt_thresholds"],
                {"tool_calls": 7, "runtime_seconds": 54},
            )
            self.assertEqual(validate_native_worker_packet(packet), [])
            corrupted_provenance = copy.deepcopy(packet)
            corrupted_provenance["budget_provenance"]["overridden_fields"] = []
            corrupted_provenance["budget_provenance"]["overrides_applied"] = False
            self.assertIn(
                "must match effective budget differences",
                " ".join(validate_native_worker_packet(corrupted_provenance)),
            )

            relaxed = run_cli(
                "build",
                "--bead-id",
                "bead-budget",
                "--lane",
                "implementation",
                "--workdir",
                workdir,
                "--allowed-path",
                str(allowed),
                "--acceptance-check",
                "focused tests pass",
                "--tool-calls-hard",
                "101",
            )
            self.assertNotEqual(relaxed.returncode, 0)
            self.assertIn("may only tighten", relaxed.stderr)

            invalid_relation = run_cli(
                "build",
                "--bead-id",
                "bead-budget",
                "--lane",
                "implementation",
                "--workdir",
                workdir,
                "--allowed-path",
                str(allowed),
                "--acceptance-check",
                "focused tests pass",
                "--tool-calls-soft",
                "10",
                "--tool-calls-hard",
                "5",
            )
            self.assertNotEqual(invalid_relation.returncode, 0)
            self.assertIn("must not exceed", invalid_relation.stderr)

    def test_packet_v1_is_historical_only(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            allowed = Path(workdir) / "allowed"
            allowed.mkdir()
            packet = build_native_worker_packet(
                bead_id="bead-v1",
                lane="review",
                workdir=workdir,
                allowed_paths=[str(allowed)],
                acceptance_checks=["review complete"],
            )
            packet["version"] = 1
            packet.pop("budget_provenance")
            packet.pop("supervision")
            packet.pop("validation_lineage")
            self.assertEqual(validate_native_worker_packet(packet), [])
            self.assertIn("dispatch-forbidden", " ".join(validate_native_worker_packet(packet, dispatchable=True)))
            packet_path = Path(workdir) / "v1.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            rendered = run_cli("render", str(packet_path))
            self.assertNotEqual(rendered.returncode, 0)
            self.assertIn("dispatch-forbidden", rendered.stderr)

    def test_validation_lineage_allows_one_attempt_and_forbids_recursion(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            allowed = Path(workdir) / "allowed"
            allowed.mkdir()
            packet = build_native_worker_packet(
                bead_id="bead-validation",
                lane="validation",
                workdir=workdir,
                allowed_paths=[str(allowed)],
                acceptance_checks=["validate"],
                packet_id="validation-child",
                validation_root_packet_id="implementation-root",
                validation_parent_packet_id="implementation-root",
                validation_attempt=1,
            )
            self.assertEqual(
                packet["validation_lineage"],
                {
                    "root_packet_id": "implementation-root",
                    "parent_packet_id": "implementation-root",
                    "attempt": 1,
                },
            )
            self.assertEqual(validate_native_worker_packet(packet), [])
            with self.assertRaisesRegex(SystemExit, "0 or 1"):
                build_native_worker_packet(
                    bead_id="bead-validation",
                    lane="validation",
                    workdir=workdir,
                    allowed_paths=[str(allowed)],
                    acceptance_checks=["validate"],
                    validation_parent_packet_id="validation-child",
                    validation_attempt=2,
                )
            with self.assertRaisesRegex(SystemExit, "explicit root"):
                build_native_worker_packet(
                    bead_id="bead-validation",
                    lane="validation",
                    workdir=workdir,
                    allowed_paths=[str(allowed)],
                    acceptance_checks=["validate"],
                    validation_parent_packet_id="implementation-root",
                    validation_attempt=1,
                )
            recursive = copy.deepcopy(packet)
            recursive["validation_lineage"]["parent_packet_id"] = packet["packet_id"]
            self.assertIn(
                "cannot reference its own packet_id",
                " ".join(validate_native_worker_packet(recursive)),
            )

    def test_build_render_cli_mode(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            allowed = Path(workdir) / "allowed"
            allowed.mkdir()
            packet = build_native_worker_packet(
                bead_id="bead-1",
                lane="implementation",
                workdir=workdir,
                allowed_paths=[str(allowed)],
                acceptance_checks=["tests pass"],
            )
            packet_path = Path(workdir) / "packet.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            result = run_cli("render", str(packet_path))
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertIn("dispatchable packet requires work_plan and worker_commitment", result.stderr)

    def test_validate_native_worker_packet_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            allowed = Path(workdir) / "allowed"
            allowed.mkdir()
            packet = build_native_worker_packet(
                bead_id="bead-1",
                lane="implementation",
                workdir=workdir,
                allowed_paths=[str(allowed)],
                acceptance_checks=["tests pass"],
            )
            self.assertEqual(validate_native_worker_packet(copy.deepcopy(packet)), [])
            corrupted = copy.deepcopy(packet)
            corrupted["scope"]["allowed_paths"] = []
            self.assertNotEqual(validate_native_worker_packet(corrupted), [])
            corrupted_top = copy.deepcopy(packet)
            corrupted_top["policy"] = {"unexpected": True}
            self.assertNotEqual(validate_native_worker_packet(corrupted_top), [])
            corrupted_nested = copy.deepcopy(packet)
            corrupted_nested["session_policy"]["unexpected"] = True
            self.assertNotEqual(validate_native_worker_packet(corrupted_nested), [])

    def test_validate_return_completed_and_model_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            allowed = Path(workdir) / "allowed"
            allowed.mkdir()
            packet = build_native_worker_packet(
                bead_id="bead-1",
                lane="implementation",
                workdir=workdir,
                allowed_paths=[str(allowed)],
                acceptance_checks=["tests pass"],
            )
            packet_path = Path(workdir) / "packet.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            valid_return = {
                "return_type": "cwo-native-worker-return",
                "version": 1,
                "packet_id": packet["packet_id"],
                "bead_id": "bead-1",
                "session_id": "session-1",
                "segment_id": "segment-1",
                "status": "completed",
                "requested_model": packet["requested_model"],
                "actual_model": packet["requested_model"],
                "attestation_source": "trusted-control-plane-session-metadata",
                "attestation_status": "trusted",
                "completed_evidence": "implementation complete",
                "files_touched": ["allowed/file.txt"],
                "mutation_state": "modified",
                "commands_run": ["pytest"],
                "validation": {"status": "pass"},
                "decision_required": [],
                "bounded_options": [],
                "recommendation": "",
                "remaining_scope": {},
                "usage": {
                    "tool_calls": 1,
                    "elapsed_seconds": 1,
                    "context_compactions": 0,
                    "full_suite_runs": 0,
                    "cached_input_tokens": 2,
                    "reasoning_tokens": 1,
                },
                "residual_risks": [],
            }
            mismatch_return = copy.deepcopy(valid_return)
            mismatch_return["actual_model"] = "gpt-5.3-codex-spark-mismatch"
            mismatch_return["status"] = "model-mismatch"
            mismatch_return["decision_required"] = ["refresh session"]
            mismatch_return["bounded_options"] = ["redo segment"]
            mismatch_return["recommendation"] = "realign"
            mismatch_return["remaining_scope"] = {"focus": "remaining tasks"}
            set_disposition(packet, valid_return)
            set_disposition(packet, mismatch_return)
            self.assertEqual(validate_native_worker_return(packet, valid_return), [])
            self.assertEqual(validate_native_worker_return(packet, mismatch_return), [])
            mismatch_return["status"] = "completed"
            set_disposition(packet, mismatch_return)
            self.assertNotEqual(validate_native_worker_return(packet, mismatch_return), [])

            mismatch_path = Path(workdir) / "return.json"
            mismatch_path.write_text(json.dumps(mismatch_return), encoding="utf-8")
            result = run_cli("validate-return", "--packet", str(packet_path), "--return", str(mismatch_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("completed return requires exact model match", result.stdout + result.stderr)

            missing_attestation_return = copy.deepcopy(valid_return)
            missing_attestation_return["status"] = "needs-architect-realignment"
            missing_attestation_return["attestation_status"] = "missing"
            missing_attestation_return["attestation_source"] = "missing"
            missing_attestation_return["actual_model"] = None
            missing_attestation_return["decision_required"] = ["wait for architect"]
            missing_attestation_return["bounded_options"] = ["request fresh session"]
            missing_attestation_return["recommendation"] = "pause"
            missing_attestation_return["remaining_scope"] = {"focus": "same task"}
            set_disposition(packet, missing_attestation_return)
            self.assertEqual(validate_native_worker_return(packet, missing_attestation_return), [])
            missing_attestation_return["return_surplus"] = "not allowed"
            self.assertNotEqual(validate_native_worker_return(packet, missing_attestation_return), [])

            missing_attestation_return.pop("return_surplus")
            missing_attestation_return["usage"]["unexpected_tokens"] = 11
            self.assertNotEqual(validate_native_worker_return(packet, missing_attestation_return), [])

    def test_validate_return_enforces_hard_budgets_and_compaction(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            allowed = Path(workdir) / "allowed"
            allowed.mkdir()
            packet = build_native_worker_packet(
                bead_id="bead-1",
                lane="validation",
                workdir=workdir,
                allowed_paths=[str(allowed)],
                acceptance_checks=["tests pass"],
            )
            bad_return = {
                "return_type": "cwo-native-worker-return",
                "version": 1,
                "packet_id": packet["packet_id"],
                "bead_id": "bead-1",
                "session_id": "session-1",
                "segment_id": "segment-1",
                "status": "completed",
                "requested_model": packet["requested_model"],
                "actual_model": packet["requested_model"],
                "attestation_source": "trusted-control-plane-session-metadata",
                "attestation_status": "trusted",
                "completed_evidence": "validation complete",
                "files_touched": ["allowed/file.txt"],
                "mutation_state": "modified",
                "commands_run": ["pytest"],
                "validation": {"status": "pass"},
                "decision_required": [],
                "bounded_options": [],
                "recommendation": "",
                "remaining_scope": {},
                "usage": {
                    "tool_calls": packet["budget"]["tool_calls_hard"] + 1,
                    "elapsed_seconds": 1,
                    "context_compactions": packet["budget"]["max_compactions"],
                    "full_suite_runs": 0,
                },
                "residual_risks": [],
            }
            set_disposition(packet, bad_return)
            self.assertNotEqual(validate_native_worker_return(packet, bad_return), [])

            bad_return["usage"]["tool_calls"] = 1
            bad_return["usage"]["context_compactions"] = packet["budget"]["max_compactions"] + 1
            bad_return["status"] = "needs-architect-realignment"
            bad_return["decision_required"] = ["fix compaction"]
            bad_return["bounded_options"] = ["reduce context"]
            bad_return["recommendation"] = "continue under guardrails"
            bad_return["remaining_scope"] = {"allowed": packet["scope"]["allowed_paths"]}
            set_disposition(packet, bad_return)
            self.assertEqual(validate_native_worker_return(packet, bad_return), [])

    def test_validate_return_requires_realignment_fields(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            allowed = Path(workdir) / "allowed"
            allowed.mkdir()
            packet = build_native_worker_packet(
                bead_id="bead-1",
                lane="review",
                workdir=workdir,
                allowed_paths=[str(allowed)],
                acceptance_checks=["tests pass"],
            )
            realignment = {
                "return_type": "cwo-native-worker-return",
                "version": 1,
                "packet_id": packet["packet_id"],
                "bead_id": "bead-1",
                "session_id": "session-1",
                "segment_id": "segment-1",
                "status": "needs-architect-realignment",
                "requested_model": packet["requested_model"],
                "actual_model": "gpt-5.3-codex-spark",
                "attestation_source": "trusted-control-plane-session-metadata",
                "attestation_status": "trusted",
                "completed_evidence": "stopped on ambiguity",
                "files_touched": ["allowed/file.txt"],
                "mutation_state": "modified",
                "commands_run": ["rg"],
                "validation": {"status": "blocked"},
                "decision_required": [],
                "bounded_options": [],
                "recommendation": "",
                "remaining_scope": {},
                "usage": {
                    "tool_calls": 1,
                    "elapsed_seconds": 1,
                    "context_compactions": 0,
                    "full_suite_runs": 0,
                },
                "residual_risks": ["scope ambiguity"],
            }
            set_disposition(packet, realignment)
            self.assertNotEqual(validate_native_worker_return(packet, realignment), [])

            realignment["decision_required"] = ["resolve scope and architecture ambiguity"]
            realignment["bounded_options"] = ["scope split"]
            realignment["recommendation"] = "continue after architect direction"
            realignment["remaining_scope"] = {"allowed_paths": packet["scope"]["allowed_paths"]}
            set_disposition(packet, realignment)
            self.assertEqual(validate_native_worker_return(packet, realignment), [])

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed in test environment")
    def test_validate_return_schema_conditional_invariants(self) -> None:
        from jsonschema import Draft202012Validator

        schema = json.loads((ROOT / "schemas" / "native-worker-return.schema.json").read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        base_return = {
            "return_type": "cwo-native-worker-return",
            "version": 1,
            "packet_id": "packet-1",
            "bead_id": "bead-1",
            "session_id": "session-1",
            "segment_id": "segment-1",
            "requested_model": "gpt-5.3-codex-spark",
            "attestation_source": "trusted-control-plane-session-metadata",
            "attestation_status": "trusted",
            "completed_evidence": "complete",
            "files_touched": ["allowed/file.txt"],
            "mutation_state": "modified",
            "commands_run": ["pytest"],
            "validation": {"status": "pass"},
            "usage": {
                "tool_calls": 1,
                "elapsed_seconds": 0.1,
                "context_compactions": 0,
                "full_suite_runs": 0,
            },
            "residual_risks": [],
        }
        completed = dict(base_return)
        completed.update(
            {
                "status": "completed",
                "actual_model": "gpt-5.3-codex-spark",
                "decision_required": [],
                "bounded_options": [],
                "recommendation": "",
                "remaining_scope": {},
            }
        )
        validator.validate(completed)
        completed_luna = dict(completed)
        completed_luna["requested_model"] = "gpt-5.6-luna"
        completed_luna["actual_model"] = "gpt-5.6-luna"
        validator.validate(completed_luna)
        completed_cross_model = dict(completed)
        completed_cross_model["actual_model"] = "gpt-5.6-luna"
        self.assertTrue(list(validator.iter_errors(completed_cross_model)))
        completed_luna_cross_model = dict(completed_luna)
        completed_luna_cross_model["actual_model"] = "gpt-5.3-codex-spark"
        self.assertTrue(list(validator.iter_errors(completed_luna_cross_model)))
        completed_bad_model = dict(completed)
        completed_bad_model["requested_model"] = "gpt-other"
        self.assertTrue(list(validator.iter_errors(completed_bad_model)))
        completed_bad_status = dict(completed)
        completed_bad_status["actual_model"] = "gpt-other"
        self.assertTrue(list(validator.iter_errors(completed_bad_status)))

        for status in ("needs-architect-realignment", "budget-exhausted", "model-mismatch"):
            status_return = dict(base_return)
            status_return.update(
                {
                    "status": status,
                    "actual_model": None if status == "needs-architect-realignment" else "gpt-5.3-codex-spark-mismatch",
                    "decision_required": ["fix scope"],
                    "bounded_options": ["request alignment"],
                    "recommendation": "retry after architect guidance",
                    "remaining_scope": {"focus": "resume"},
                }
            )
            validator.validate(status_return)

            status_return["decision_required"] = []
            self.assertTrue(list(validator.iter_errors(status_return)))
            status_return["decision_required"] = ["fix scope"]
            status_return["bounded_options"] = []
            self.assertTrue(list(validator.iter_errors(status_return)))
            status_return["bounded_options"] = ["request alignment"]
            status_return["recommendation"] = ""
            self.assertTrue(list(validator.iter_errors(status_return)))
            status_return["recommendation"] = "retry"
            status_return["remaining_scope"] = {}
            self.assertTrue(list(validator.iter_errors(status_return)))
            if status == "model-mismatch":
                status_return["actual_model"] = None
                self.assertTrue(list(validator.iter_errors(status_return)))

        blocked = dict(base_return)
        blocked.update(
            {
                "status": "blocked",
                "actual_model": None,
                "decision_required": [],
                "bounded_options": [],
                "recommendation": "",
                "remaining_scope": {},
            }
        )
        validator.validate(blocked)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import importlib
import tests.test_supervise_native_worker as supervisor_fixtures
from tests.test_supervise_native_worker import (  # noqa: E402
    CONTROL_TURN,
    MODEL,
    ROOT,
    planned_packet,
    run_cli,
    session_meta,
    write_records,
)
from cwo_core.native_retry import build_retry_authorization, canonical_work_sha256
from cwo_core.native_recovery_authority import (
    RecoveryActionStore,
    RecoveryAuthorityError,
    VerifiedRecoveryAction,
)
from cwo_core.native_recovery_policy import (
    RECOVERY_SIGNAL_FIELDS,
    build_recovery_audit_decision,
)
from cwo_core.paths import cwo_temp_path
from cwo_core.policy import load_policy

HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def _workspace_report(
    *, mutation_detected: bool = False, unexpected_mutation_detected: bool = False,
    attribution_ambiguous: bool = False, incomplete: bool = False
) -> dict:
    return {
        "mutation_detected": mutation_detected,
        "unexpected_mutation_detected": unexpected_mutation_detected,
        "attribution_ambiguous": attribution_ambiguous,
        "incomplete": incomplete,
    }


def _semantic_result(*, status: str = "no-progress", trusted: bool = True, artifact_accepted: bool = False, contradiction: bool = False) -> dict:
    return {
        "status": status,
        "trusted": trusted,
        "artifact_accepted": artifact_accepted,
        "contradiction": contradiction,
    }


def _fresh_attestation(*, session_id: str, model: str = MODEL, tool_surface_id: str = "native-supervision-tool-surface") -> dict:
    return {
        "session_id": session_id,
        "requested_model": model,
        "attested_model": model,
        "attestation_source": "trusted-session-jsonl",
        "tool_calls": 0,
        "context_compactions": 0,
        "closure_receipt": True,
        "tool_surface_id": tool_surface_id,
    }


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


def _reseal_retry_receipt(receipt: dict) -> None:
    body = copy.deepcopy(receipt)
    body.pop("receipt_sha256", None)
    receipt["receipt_sha256"] = _canonical_sha256(body)


def _reseal_retry_evidence_bindings(receipt: dict) -> None:
    evidence_sha256 = _canonical_sha256(receipt["evidence_bindings"])
    receipt["retry_evidence_sha256"] = evidence_sha256
    provenance = receipt["evidence_provenance"]
    provenance["source_sha256"] = evidence_sha256
    provenance["verification"]["evidence_sha256"] = evidence_sha256
    provenance_body = copy.deepcopy(provenance)
    provenance_body.pop("provenance_sha256", None)
    provenance["provenance_sha256"] = _canonical_sha256(provenance_body)
    _reseal_retry_receipt(receipt)


class NativeRetrySupervisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="cwo-native-retry-supervision-")
        self.root = Path(self.tmp.name)
        supervisor_fixtures._FIXTURE_ROOT = self.root
        self.environment = mock.patch.dict(
            os.environ,
            {
                "CWO_PRECOMMIT_REGISTRY_ROOT": str(self.root / "precommit-registry"),
                "CWO_SESSION_ID": self.root.name,
            },
        )
        self.environment.start()
        self.session_id = "spark-session"
        self.session_file = self.root / "session.jsonl"
        self.packet_file = self.root / "packet.json"
        self.retry_packet_file = self.root / "retry-packet.json"
        self.state_file = self.root / "state.json"
        self.audit_file = self.root / "audit.jsonl"
        self.workspace_report_file = self.root / "workspace.json"
        self.semantic_result_file = self.root / "semantic.json"
        self.attestation_file = self.root / "attestation.json"
        self.retry_authorization_file = self.root / "retry-authorization.json"

        self.parent_packet = planned_packet(
            packet_id="packet-native-retry-supervision-parent",
            budget_overrides={"tool_calls_soft": 5, "tool_calls_hard": 10, "runtime_seconds_soft": 30, "runtime_seconds_hard": 60},
        )
        self.packet_file.write_text(json.dumps(self.parent_packet), encoding="utf-8")
        write_records(self.session_file, [session_meta(self.session_id)])

    def tearDown(self) -> None:
        self.environment.stop()
        supervisor_fixtures._FIXTURE_ROOT = None
        self.tmp.cleanup()

    def _reset_workflow_artifacts(self) -> None:
        for path in (self.state_file, self.audit_file):
            if path.exists():
                path.unlink()

    def _start(
        self, *, packet_file: Path | None = None, retry_authorization: Path | None = None, now: str = "2026-07-11T00:00:00Z"
    ) -> subprocess.CompletedProcess[str]:
        args = [
            "start",
            "--packet",
            str(packet_file or self.packet_file),
            "--session-id",
            self.session_id,
            "--session-file",
            str(self.session_file),
            "--agent-id",
            "agent-spark",
            "--state-file",
            str(self.state_file),
            "--audit-file",
            str(self.audit_file),
            "--now",
            now,
            "--json",
        ]
        if retry_authorization is not None:
            args.extend(["--retry-authorization", str(retry_authorization)])
        return run_cli(*args)

    def _start_args(
        self,
        *,
        packet_file: Path | None = None,
        retry_authorization: Path | None = None,
        now: str = "2026-07-11T00:00:00Z",
    ) -> argparse.Namespace:
        return argparse.Namespace(
            packet=str(packet_file or self.packet_file),
            session_id=self.session_id,
            session_file=str(self.session_file),
            agent_id="agent-spark",
            state_file=str(self.state_file),
            audit_file=str(self.audit_file),
            retry_authorization=(
                str(retry_authorization) if retry_authorization is not None else None
            ),
            now=now,
            json=True,
        )

    def _assess(self, *, now: str, workspace: dict, semantic: dict) -> subprocess.CompletedProcess[str]:
        self.workspace_report_file.write_text(json.dumps(workspace, separators=(",", ":")), encoding="utf-8")
        self.semantic_result_file.write_text(json.dumps(semantic, separators=(",", ":")), encoding="utf-8")
        return run_cli(
            "assess-retry",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            CONTROL_TURN,
            "--workspace-report",
            str(self.workspace_report_file),
            "--semantic-result",
            str(self.semantic_result_file),
            "--now",
            now,
            "--json",
        )

    def _authorize(
        self,
        *,
        retry_packet: dict,
        workspace: dict,
        semantic: dict,
        fresh_attestation: dict,
        now: str = "2026-07-11T00:01:00Z",
    ) -> subprocess.CompletedProcess[str]:
        self.retry_packet_file.write_text(json.dumps(retry_packet, separators=(",", ":")), encoding="utf-8")
        self.workspace_report_file.write_text(json.dumps(workspace, separators=(",", ":")), encoding="utf-8")
        self.semantic_result_file.write_text(json.dumps(semantic, separators=(",", ":")), encoding="utf-8")
        self.attestation_file.write_text(json.dumps(fresh_attestation, separators=(",", ":")), encoding="utf-8")
        return run_cli(
            "authorize-retry",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            CONTROL_TURN,
            "--retry-packet",
            str(self.retry_packet_file),
            "--fresh-attestation",
            str(self.attestation_file),
            "--workspace-report",
            str(self.workspace_report_file),
            "--semantic-result",
            str(self.semantic_result_file),
            "--now",
            now,
            "--json",
        )

    def _check(self, *, now: str = "2026-07-11T00:01:30Z") -> subprocess.CompletedProcess[str]:
        return run_cli(
            "check",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            CONTROL_TURN,
            "--now",
            now,
            "--json",
        )

    def _load_state(self) -> dict:
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def _write_state(self, state: dict) -> None:
        self.state_file.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")

    def _read_audits(self) -> list[dict]:
        if not self.audit_file.exists():
            return []
        return [json.loads(line) for line in self.audit_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    def _make_retry_packet(self, *, packet_id: str) -> dict:
        retry_packet = copy.deepcopy(self.parent_packet)
        retry_packet["packet_id"] = packet_id
        retry_packet["validation_lineage"] = {
            "attempt": 0,
            "parent_packet_id": None,
            "root_packet_id": packet_id,
        }
        # Keep immutable work identical by copying the parent work_plan.
        retry_packet["work_plan"] = copy.deepcopy(self.parent_packet["work_plan"])
        return retry_packet

    def _make_retry_authorization(
        self,
        *,
        parent: dict,
        retry: dict,
        observed_tool_calls: int = 3,
        observed_runtime_seconds: int = 2,
        cumulative_tool_calls: int = 0,
        cumulative_runtime_seconds: int = 0,
        model: str | None = None,
        retry_session_id: str | None = None,
    ) -> dict:
        policy = load_policy("native-worker-execution")
        if not isinstance(policy.get("bounded_native_retry"), dict):
            raise AssertionError("bounded_native_retry policy missing in tests")
        state = {
            "decision": "interrupt",
            "requested_model": model or parent["requested_model"],
            "reasons": ["tool-call-interrupt-threshold"],
            "control_timing": {"monitor_armed_before_dispatch": True, "late_poll_count": 0},
            "observed": {"tool_calls": observed_tool_calls, "runtime_seconds": observed_runtime_seconds, "context_compactions": 0, "full_suite_runs": 0},
            "recovery": {"attempt": 0, "cumulative_usage": {"tool_calls": cumulative_tool_calls, "runtime_seconds": cumulative_runtime_seconds}},
            "session_id": "session-parent",
        }
        return build_retry_authorization(
            parent_packet=parent,
            retry_packet=retry,
            supervision_state=state,
            workspace_report=_workspace_report(),
            semantic_result=_semantic_result(status="no-progress"),
            recovery_policy=policy["bounded_native_retry"],
            fresh_attestation=_fresh_attestation(
                session_id=retry_session_id or self.session_id,
                model=model or parent["requested_model"],
            ),
        )

    def _make_provisional_recovery_action(
        self,
        authorization: dict,
    ) -> tuple[RecoveryActionStore, VerifiedRecoveryAction]:
        signals = {field: False for field in RECOVERY_SIGNAL_FIELDS}
        signals["pre_dispatch_transport_failure"] = True
        decision = build_recovery_audit_decision(
            signals,
            replacement_count=0,
            construction_attempt_count=0,
            evidence_sha256="c" * 64,
            fixed_cohort_sha256="a" * 64,
            admitted_bead_id=authorization["bead_id"],
            admitted_child_sha256="b" * 64,
        )
        store = RecoveryActionStore()
        return store, store.issue_provisional(authorization, decision)

    def _make_closed_interrupt_state(
        self,
        *,
        decision: str = "interrupt",
        reasons: list[str] | None = None,
        observed: dict | None = None,
        recovery_cumulative: dict | None = None,
        control_receipts: list[str] | None = None,
        requested_model: str | None = None,
        packet: dict | None = None,
    ) -> dict:
        self._reset_workflow_artifacts()
        if packet is not None:
            self.packet_file.write_text(json.dumps(packet), encoding="utf-8")
        start = self._start()
        self.assertEqual(start.returncode, 0, start.stderr)
        state = self._load_state()
        state.update(
            {
                "status": "closed",
                "decision": decision,
                "reasons": reasons or ["tool-call-interrupt-threshold"],
                "control_turn_id": CONTROL_TURN,
                "control_action_required": False,
                "control_timing": {
                    **state["control_timing"],
                    "monitor_armed_before_dispatch": True,
                    "late_poll_count": 0,
                },
            }
        )
        state["observed"] = observed or {"tool_calls": 4, "elapsed_seconds": 4, "context_compactions": 0, "full_suite_runs": 0}
        state["recovery"] = {
            "attempt": 0,
            "cumulative_usage": recovery_cumulative or {"tool_calls": 0, "runtime_seconds": 0},
            "eligibility": None,
            "authorization": None,
        }
        state["control_receipts"] = control_receipts or ["interrupt-confirmed", "close-confirmed"]
        if requested_model is not None:
            state["requested_model"] = requested_model
        self._write_state(state)
        return state

    def test_start_bindings(self) -> None:
        result = self._start()
        self.assertEqual(result.returncode, 0, result.stderr)
        state = self._load_state()
        self.assertTrue(Path(state["packet_file"]).is_absolute())
        self.assertEqual(state["packet_file"], str(self.packet_file.resolve()))

        packet = json.loads(self.packet_file.read_text(encoding="utf-8"))
        self.assertEqual(state["immutable_work_sha256"], canonical_work_sha256(packet))
        self.assertEqual(
            state["recovery"],
            {
                "attempt": 0,
                "cumulative_usage": {"tool_calls": 0, "runtime_seconds": 0},
                "eligibility": None,
                "authorization": None,
            },
        )

        if HAS_JSONSCHEMA:
            import jsonschema

            schema = json.loads((ROOT / "schemas" / "native-supervision-state.schema.json").read_text(encoding="utf-8"))
            jsonschema.validate(state, schema)

    def test_start_with_retry_authorization_is_audit_only_and_tamper_fails(self) -> None:
        retry_packet = self._make_retry_packet(packet_id="packet-native-retry-supervision-retry")
        retry_authorization = self._make_retry_authorization(parent=self.parent_packet, retry=retry_packet)
        self.retry_authorization_file.write_text(json.dumps(retry_authorization), encoding="utf-8")

        self.packet_file.write_text(json.dumps(retry_packet), encoding="utf-8")
        baseline_path = cwo_temp_path(
            f"{retry_packet['packet_id']}-{self.session_id}-workspace-baseline.json",
            purpose="native-supervision",
        )
        baseline_path.unlink(missing_ok=True)
        started = self._start(retry_authorization=self.retry_authorization_file)
        self.assertNotEqual(started.returncode, 0)
        self.assertIn("serialized retry authorization is audit-only", started.stderr)
        self.assertFalse(self.state_file.exists())
        self.assertFalse(self.audit_file.exists())
        self.assertFalse(baseline_path.exists())

        for label, tamper in (
            ("retry_packet_id", {"retry_packet_id": "wrong-retry-id"}),
            ("bead_id", {"bead_id": "bead-other"}),
            ("model", {"requested_model": "gpt-5.6-luna", "attested_model": "gpt-5.6-luna"}),
            ("work_sha256", {"work_sha256": "0" * 64}),
            ("attempt_lineage", {"attempt_from": 1}),
            ("receipt_hash", {"receipt_sha256": "1" * 64}),
        ):
            with self.subTest(label=label):
                self._reset_workflow_artifacts()
                self.packet_file.write_text(json.dumps(retry_packet), encoding="utf-8")
                tampered = copy.deepcopy(retry_authorization)
                tampered.update(tamper)
                self.retry_authorization_file.write_text(json.dumps(tampered), encoding="utf-8")
                result = self._start(retry_authorization=self.retry_authorization_file)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.state_file.exists())
                self.assertFalse(self.audit_file.exists())
                self.assertFalse(baseline_path.exists())

    def test_retry_start_rechecks_live_session_packet_and_policy_evidence(self) -> None:
        retry_packet = self._make_retry_packet(
            packet_id="packet-native-retry-supervision-live-bindings"
        )
        authorization = self._make_retry_authorization(
            parent=self.parent_packet,
            retry=retry_packet,
        )
        self.packet_file.write_text(json.dumps(retry_packet), encoding="utf-8")
        baseline_path = cwo_temp_path(
            f"{retry_packet['packet_id']}-{self.session_id}-workspace-baseline.json",
            purpose="native-supervision",
        )

        cases: list[tuple[str, dict, str]] = []
        wrong_session = copy.deepcopy(authorization)
        wrong_session["retry_session_id"] = "other-retry-session"
        _reseal_retry_receipt(wrong_session)
        cases.append(("session", wrong_session, "session mismatch"))

        wrong_packet = copy.deepcopy(authorization)
        wrong_packet["evidence_bindings"]["retry_packet_sha256"] = "f" * 64
        _reseal_retry_evidence_bindings(wrong_packet)
        cases.append(("packet", wrong_packet, "packet evidence mismatch"))

        wrong_policy = copy.deepcopy(authorization)
        wrong_policy["evidence_bindings"]["recovery_policy_sha256"] = "f" * 64
        _reseal_retry_evidence_bindings(wrong_policy)
        cases.append(("policy", wrong_policy, "policy evidence mismatch"))

        for label, receipt, expected in cases:
            with self.subTest(label=label):
                self._reset_workflow_artifacts()
                baseline_path.unlink(missing_ok=True)
                self.retry_authorization_file.write_text(
                    json.dumps(receipt),
                    encoding="utf-8",
                )
                result = self._start(
                    retry_authorization=self.retry_authorization_file
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
                self.assertFalse(self.state_file.exists())
                self.assertFalse(self.audit_file.exists())
                self.assertFalse(baseline_path.exists())

    def test_provisional_recovery_action_is_consumed_then_rejected_before_writes(self) -> None:
        retry_packet = self._make_retry_packet(
            packet_id="packet-native-retry-supervision-provisional"
        )
        authorization = self._make_retry_authorization(
            parent=self.parent_packet,
            retry=retry_packet,
        )
        self.packet_file.write_text(json.dumps(retry_packet), encoding="utf-8")
        self.retry_authorization_file.write_text(
            json.dumps(authorization), encoding="utf-8"
        )
        store, action = self._make_provisional_recovery_action(authorization)

        with (
            mock.patch.object(supervisor_fixtures.supervisor, "_require_packet_release"),
            mock.patch.object(
                supervisor_fixtures.supervisor,
                "validate_native_worker_packet",
                return_value=[],
            ),
            mock.patch.object(
                supervisor_fixtures.supervisor, "_persist_workspace_baseline"
            ) as persist_baseline,
            mock.patch.object(
                supervisor_fixtures.supervisor, "_write_state"
            ) as write_state,
            mock.patch.object(
                supervisor_fixtures.supervisor, "_audit_event"
            ) as audit_event,
        ):
            with self.assertRaisesRegex(
                SystemExit,
                "provisional and non-dispatching",
            ):
                supervisor_fixtures.supervisor.start(
                    self._start_args(
                        packet_file=self.packet_file,
                        retry_authorization=self.retry_authorization_file,
                    ),
                    verified_recovery_action=action,
                    recovery_action_store=store,
                )

        persist_baseline.assert_not_called()
        write_state.assert_not_called()
        audit_event.assert_not_called()
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "not-registered-or-spent",
        ):
            store.inspect(action)
        self.assertFalse(self.state_file.exists())
        self.assertFalse(self.audit_file.exists())

    def test_recovery_action_binding_mismatch_fails_read_only_without_consuming(self) -> None:
        first_packet = self._make_retry_packet(
            packet_id="packet-native-retry-supervision-binding-first"
        )
        first_authorization = self._make_retry_authorization(
            parent=self.parent_packet,
            retry=first_packet,
        )
        store, action = self._make_provisional_recovery_action(first_authorization)

        second_packet = self._make_retry_packet(
            packet_id="packet-native-retry-supervision-binding-second"
        )
        second_authorization = self._make_retry_authorization(
            parent=self.parent_packet,
            retry=second_packet,
        )
        self.packet_file.write_text(json.dumps(second_packet), encoding="utf-8")
        self.retry_authorization_file.write_text(
            json.dumps(second_authorization), encoding="utf-8"
        )

        with (
            mock.patch.object(supervisor_fixtures.supervisor, "_require_packet_release"),
            mock.patch.object(
                supervisor_fixtures.supervisor,
                "validate_native_worker_packet",
                return_value=[],
            ),
            mock.patch.object(
                supervisor_fixtures.supervisor, "_persist_workspace_baseline"
            ) as persist_baseline,
        ):
            with self.assertRaisesRegex(SystemExit, "binding mismatch"):
                supervisor_fixtures.supervisor.start(
                    self._start_args(
                        packet_file=self.packet_file,
                        retry_authorization=self.retry_authorization_file,
                    ),
                    verified_recovery_action=action,
                    recovery_action_store=store,
                )

        persist_baseline.assert_not_called()
        self.assertEqual(
            store.inspect(action)["retry_packet_id"],
            first_packet["packet_id"],
        )

    def test_recovery_action_identity_store_rejects_forgery_without_protocol_calls(self) -> None:
        retry_packet = self._make_retry_packet(
            packet_id="packet-native-retry-supervision-identity"
        )
        authorization = self._make_retry_authorization(
            parent=self.parent_packet,
            retry=retry_packet,
        )
        store, action = self._make_provisional_recovery_action(authorization)

        class HostileAlias:
            def __init__(self) -> None:
                self.eq_calls = 0
                self.hash_calls = 0

            def __eq__(self, other: object) -> bool:
                self.eq_calls += 1
                raise AssertionError("attacker equality must not run")

            def __hash__(self) -> int:
                self.hash_calls += 1
                raise AssertionError("attacker hash must not run")

        hostile = HostileAlias()
        with self.assertRaisesRegex(RecoveryAuthorityError, "type-invalid"):
            store.inspect(hostile)
        self.assertEqual((hostile.eq_calls, hostile.hash_calls), (0, 0))

        forged = object.__new__(VerifiedRecoveryAction)
        with self.assertRaisesRegex(RecoveryAuthorityError, "not-registered-or-spent"):
            store.inspect(forged)

        class ForgedActionSubclass(VerifiedRecoveryAction):
            pass

        forged_subclass = object.__new__(ForgedActionSubclass)
        with self.assertRaisesRegex(RecoveryAuthorityError, "type-invalid"):
            store.inspect(forged_subclass)

        class StoreSubclass(RecoveryActionStore):
            pass

        with self.assertRaisesRegex(RecoveryAuthorityError, "store-invalid"):
            StoreSubclass().inspect(action)
        with self.assertRaisesRegex(RecoveryAuthorityError, "store-invalid"):
            object.__new__(RecoveryActionStore).inspect(action)

        other_store = RecoveryActionStore()
        with self.assertRaisesRegex(RecoveryAuthorityError, "not-registered-or-spent"):
            other_store.inspect(action)
        store.consume(action)
        with self.assertRaisesRegex(RecoveryAuthorityError, "not-registered-or-spent"):
            store.consume(action)

    def test_stray_recovery_hooks_without_retry_fail_before_writes(self) -> None:
        with mock.patch.object(
            supervisor_fixtures.supervisor,
            "_persist_workspace_baseline",
        ) as persist_baseline:
            with self.assertRaisesRegex(
                SystemExit,
                "hooks require --retry-authorization",
            ):
                supervisor_fixtures.supervisor.start(
                    self._start_args(),
                    verified_recovery_action=object(),
                    recovery_action_store=RecoveryActionStore(),
                )
        persist_baseline.assert_not_called()

    def test_assess_retry_eligible_projection(self) -> None:
        self._make_closed_interrupt_state()
        workspace = _workspace_report()
        semantic = _semantic_result(status="no-progress")
        assessed = self._assess(now="2026-07-11T00:00:10Z", workspace=workspace, semantic=semantic)
        self.assertEqual(assessed.returncode, 0, assessed.stderr)
        assessment = json.loads(assessed.stdout)
        self.assertTrue(assessment["eligible"])
        self.assertEqual(
            assessment["next_action"], "await-verified-recovery-action"
        )
        self.assertFalse(assessment["dispatch_authorized"])
        self.assertEqual(assessment["receipt_authority"], "audit-only")
        self.assertEqual(
            assessment["required_dispatch_authority"],
            "opaque-verified-recovery-action",
        )
        state = self._load_state()
        self.assertEqual(state["recovery"]["eligibility"], assessment)

        events = self._read_audits()
        self.assertIn("native_retry_assessed", [event["event_type"] for event in events])
        self.assertEqual(events[-1]["event_type"], "native_retry_assessed")

        decision = self._check(now="2026-07-11T00:01:10Z")
        self.assertEqual(decision.returncode, 0, decision.stderr)
        decision_payload = json.loads(decision.stdout)

        if HAS_JSONSCHEMA:
            import jsonschema

            schema = json.loads((ROOT / "schemas" / "native-supervision-decision.schema.json").read_text(encoding="utf-8"))
            jsonschema.validate(decision_payload, schema)

    def test_protected_stops(self) -> None:
        base_workspace = _workspace_report()
        base_semantic = _semantic_result(status="no-progress")

        with self.subTest(case="control_lost_requires_closed_interrupt_path"):
            self._make_closed_interrupt_state(decision="control-lost")
            assessed = self._assess(now="2026-07-11T00:00:10Z", workspace=base_workspace, semantic=base_semantic)
            self.assertNotEqual(assessed.returncode, 0)

        with self.subTest(case="missing_receipts_fails"):
            self._make_closed_interrupt_state(control_receipts=["interrupt-confirmed"])
            assessed = self._assess(now="2026-07-11T00:00:10Z", workspace=base_workspace, semantic=base_semantic)
            self.assertNotEqual(assessed.returncode, 0)
            self.assertIn("interrupt-confirmed and close-confirmed", assessed.stderr)

        with self.subTest(case="workspace_mutation"):
            self._make_closed_interrupt_state()
            mutated_workspace = _workspace_report(mutation_detected=True)
            assessed = self._assess(now="2026-07-11T00:00:10Z", workspace=mutated_workspace, semantic=base_semantic)
            self.assertEqual(assessed.returncode, 0, assessed.stderr)
            assessment = json.loads(assessed.stdout)
            self.assertFalse(assessment["eligible"])
            self.assertIn("workspace-mutation-detected", assessment["reasons"])
            authorize = self._authorize(
                retry_packet=self._make_retry_packet(packet_id="auth-retry-mut"),
                workspace=mutated_workspace,
                semantic=base_semantic,
                fresh_attestation=_fresh_attestation(session_id="fresh-retry-session"),
            )
            self.assertNotEqual(authorize.returncode, 0)

        with self.subTest(case="workspace_attribution_ambiguity"):
            self._make_closed_interrupt_state()
            ambiguous_workspace = _workspace_report(attribution_ambiguous=True)
            assessed = self._assess(now="2026-07-11T00:00:10Z", workspace=ambiguous_workspace, semantic=base_semantic)
            self.assertEqual(assessed.returncode, 0, assessed.stderr)
            assessment = json.loads(assessed.stdout)
            self.assertFalse(assessment["eligible"])
            self.assertIn("workspace-attribution-ambiguous", assessment["reasons"])

        with self.subTest(case="semantic_contradiction"):
            self._make_closed_interrupt_state()
            contradictory_semantic = _semantic_result(status="no-progress", contradiction=True)
            assessed = self._assess(now="2026-07-11T00:00:10Z", workspace=base_workspace, semantic=contradictory_semantic)
            self.assertEqual(assessed.returncode, 0, assessed.stderr)
            assessment = json.loads(assessed.stdout)
            self.assertFalse(assessment["eligible"])
            self.assertIn("semantic-contradiction", assessment["reasons"])

        with self.subTest(case="model_mismatch"):
            self._make_closed_interrupt_state(requested_model="gpt-5.6-luna")
            assessed = self._assess(now="2026-07-11T00:00:10Z", workspace=base_workspace, semantic=base_semantic)
            self.assertEqual(assessed.returncode, 0, assessed.stderr)
            assessment = json.loads(assessed.stdout)
            self.assertFalse(assessment["eligible"])
            self.assertIn("model-mismatch", assessment["reasons"])

        with self.subTest(case="context_compaction"):
            self._make_closed_interrupt_state()
            state = self._load_state()
            state["observed"]["context_compactions"] = 1
            self._write_state(state)
            assessed = self._assess(now="2026-07-11T00:00:10Z", workspace=base_workspace, semantic=base_semantic)
            self.assertEqual(assessed.returncode, 0, assessed.stderr)
            assessment = json.loads(assessed.stdout)
            self.assertFalse(assessment["eligible"])
            self.assertIn("context-compaction", assessment["reasons"])

        with self.subTest(case="aggregate_budget_exhausted"):
            self._make_closed_interrupt_state(recovery_cumulative={"tool_calls": 17, "runtime_seconds": 300})
            assessed = self._assess(now="2026-07-11T00:00:10Z", workspace=base_workspace, semantic=base_semantic)
            self.assertEqual(assessed.returncode, 0, assessed.stderr)
            assessment = json.loads(assessed.stdout)
            self.assertFalse(assessment["eligible"])
            self.assertIn("aggregate-allowance-exhausted", assessment["reasons"])
            self.assertEqual(assessment["next_action"], "protected-stop")

    def test_authorization_freshness_and_tamper(self) -> None:
        self._make_closed_interrupt_state()
        workspace = _workspace_report()
        semantic = _semantic_result(status="no-progress")
        assessed = self._assess(now="2026-07-11T00:00:10Z", workspace=workspace, semantic=semantic)
        self.assertEqual(assessed.returncode, 0, assessed.stderr)

        retry_packet = self._make_retry_packet(packet_id="packet-native-retry-supervision-auth")
        attestation = _fresh_attestation(session_id="spark-native-retry-auth-session")
        authorized = self._authorize(retry_packet=retry_packet, workspace=workspace, semantic=semantic, fresh_attestation=attestation)
        self.assertEqual(authorized.returncode, 0, authorized.stderr)
        authorization = json.loads(authorized.stdout)
        state = self._load_state()
        self.assertEqual(state["recovery"]["authorization"], authorization)
        events = self._read_audits()
        native_retry_authorized = [item for item in events if item["event_type"] == "native_retry_authorized"]
        self.assertTrue(native_retry_authorized)
        self.assertEqual(native_retry_authorized[-1]["native_retry_receipt_sha256"], authorization["receipt_sha256"])

        attestation_events = "|".join(event["event_type"] for event in events)
        self.assertNotIn("native-spawn", attestation_events)
        self.assertNotIn("native-replay", attestation_events)

        with self.subTest(change="evidence_after_assessment"):
            changed_workspace = _workspace_report(mutation_detected=True)
            failed = self._authorize(
                retry_packet=retry_packet,
                workspace=changed_workspace,
                semantic=semantic,
                fresh_attestation=attestation,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("retry requires re-assessing", failed.stderr)

        with self.subTest(change="immutable_work"):
            altered_packet = copy.deepcopy(self.parent_packet)
            altered_packet["acceptance_checks"] = ["altered-check"]
            self.packet_file.write_text(json.dumps(altered_packet), encoding="utf-8")
            try:
                failed = self._authorize(
                    retry_packet=retry_packet,
                    workspace=workspace,
                    semantic=semantic,
                    fresh_attestation=attestation,
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("control-lost: bound packet changed after supervision start", failed.stderr)
            finally:
                self.packet_file.write_text(json.dumps(self.parent_packet), encoding="utf-8")

        with self.subTest(change="model"):
            failed = self._authorize(
                retry_packet=retry_packet,
                workspace=workspace,
                semantic=semantic,
                fresh_attestation=_fresh_attestation(session_id="spark-native-retry-auth-session", model="gpt-5.6-luna"),
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("fresh retry model attestation mismatch", failed.stderr)

        with self.subTest(change="session"):
            failed = self._authorize(
                retry_packet=retry_packet,
                workspace=workspace,
                semantic=semantic,
                fresh_attestation=_fresh_attestation(session_id=self.session_id),
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("retry requires a fresh session", failed.stderr)

        with self.subTest(change="source"):
            failed = self._authorize(
                retry_packet=retry_packet,
                workspace=workspace,
                semantic=semantic,
                fresh_attestation={**_fresh_attestation(session_id="spark-native-retry-auth-session"), "attestation_source": "untrusted"},
            )
            self.assertNotEqual(failed.returncode, 0)

        with self.subTest(change="tool"):
            failed_attestation = _fresh_attestation(session_id="spark-native-retry-auth-session")
            failed_attestation["tool_calls"] = 1
            failed = self._authorize(
                retry_packet=retry_packet,
                workspace=workspace,
                semantic=semantic,
                fresh_attestation=failed_attestation,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("fresh retry attestation must use zero tools", failed.stderr)

        with self.subTest(change="compaction"):
            failed_attestation = _fresh_attestation(session_id="spark-native-retry-auth-session")
            failed_attestation["context_compactions"] = 1
            failed = self._authorize(
                retry_packet=retry_packet,
                workspace=workspace,
                semantic=semantic,
                fresh_attestation=failed_attestation,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("fresh retry attestation must have zero compactions", failed.stderr)

        with self.subTest(change="closure"):
            failed_attestation = _fresh_attestation(session_id="spark-native-retry-auth-session")
            failed_attestation["closure_receipt"] = False
            failed = self._authorize(
                retry_packet=retry_packet,
                workspace=workspace,
                semantic=semantic,
                fresh_attestation=failed_attestation,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("fresh retry attestation requires closure receipt", failed.stderr)

        with self.subTest(change="retry_packet_id"):
            failed_packet = copy.deepcopy(self.parent_packet)
            failed = self._authorize(
                retry_packet=failed_packet,
                workspace=workspace,
                semantic=semantic,
                fresh_attestation=attestation,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("retry packet requires a distinct packet_id", failed.stderr)


if __name__ == "__main__":
    unittest.main()

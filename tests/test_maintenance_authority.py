"""Controller-only authority fixtures; no model calls or real operator grants."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.maintenance_authority import (  # noqa: E402
    MaintenanceAuthorityError,
    MaintenanceAuthorityVerifier,
    MaintenanceStateStore,
    VerifiedMaintenanceOperation,
    mission_sha256,
    normalize_maintenance_mission,
    require_maintenance_operation,
    sign_controller_directive,
)
from cwo_core.native_authority import canonical_authority_sha256  # noqa: E402
from cwo_core.native_pool_contracts import canonical_sha256  # noqa: E402


class MaintenanceAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.controller = self.root / "controller"
        self.controller.mkdir(mode=0o700)
        self.adapter = self.controller / "installed_adapter.py"
        self.marker = self.root / "import-marker"
        self.adapter.write_text(f"from pathlib import Path\nPath({str(self.marker)!r}).touch()\n", encoding="utf-8")
        self.key = b"test-only-injected-controller-key-not-a-real-grant"
        self.actor = "test-operator"
        self.identity = "test-only-authenticated-parent"
        self.mission = {
            "mission_type": "cwo-maintenance-mission", "version": 1,
            "mission_id": "test-maintenance", "objective": "Test CWO maintenance only",
            "provenance": {"adoption_id": "test-only-adoption", "user_request_sha256": "a" * 64},
            "scope": {"effect_scope": "cwo-maintenance", "workspace_roots": [str(self.workspace)], "models": ["test-model"], "roles": ["product", "review"], "factory_ids": ["installed-native-v1"]},
            "budget": {"mode": "unbounded"}, "lifetime": {"mode": "until-revoked"},
        }
        self.mission_hash = mission_sha256(self.mission)
        self.directive = self.sign(self.mission_hash, "test-mission-directive")
        self.registry = {"installed-native-v1": {"adapter_path": str(self.adapter), "adapter_sha256": hashlib.sha256(self.adapter.read_bytes()).hexdigest()}}
        self.store = MaintenanceStateStore(self.controller, mission_id=self.mission["mission_id"], mission_sha256=self.mission_hash)
        self.store.initialize()
        self.verifier = self.make_verifier()

    def sign(self, action: str, directive_id: str, *, parent: str | None = None, key: bytes | None = None) -> dict:
        return sign_controller_directive(verification_key=self.key if key is None else key, actor_id=self.actor, identity_source=self.identity, action_sha256=action, directive_id=directive_id, parent_receipt_sha256=parent)

    def make_verifier(self, **overrides) -> MaintenanceAuthorityVerifier:
        kwargs = dict(mission=self.mission, operator_directive=self.directive, verification_key=self.key, expected_actor_id=self.actor, expected_identity_source=self.identity, factory_registry=self.registry, state_reader=self.store.read_state, claim_operation=self.store.claim_operation)
        kwargs.update(overrides)
        return MaintenanceAuthorityVerifier(**kwargs)

    def operation(self, *, operation_id: str = "operation-1", role: str = "product", workspace: Path | None = None) -> tuple[dict, dict, dict]:
        writes = [] if role == "review" else ["result.txt"]
        plan = {"transaction_id": operation_id, "authority_sha256": self.mission_hash,
                "runtime_adapter_path": str(self.adapter), "runtime_adapter_sha256": self.registry["installed-native-v1"]["adapter_sha256"],
                "selected_model": "test-model", "required_session_count": 2,
                "budget": {"mode": "maintenance-unbounded", "cumulative_before": 763, "reserved_sessions": 2},
                "children": [{"requested_model": "test-model", "write_paths": writes, "read_only": role == "review"}]}
        plan["plan_sha256"] = canonical_sha256(plan)
        operation = {"operation_id": operation_id, "mission_id": self.mission["mission_id"], "mission_sha256": self.mission_hash, "revocation_generation": 0, "plan_sha256": plan["plan_sha256"], "factory_id": "installed-native-v1", "workspace": str(workspace or self.workspace), "model": "test-model", "role": role, "write_paths": list(writes),
                     "reservation": {"mode": "finite-operation", "sessions": 2, "tool_calls": 12, "runtime_seconds": 90, "cleanup_seconds": 15, "max_concurrency": 1}}
        return plan, operation, self.sign_operation(operation)

    def sign_operation(self, operation: dict) -> dict:
        return self.sign(canonical_authority_sha256(operation), "test-operation-directive", parent=canonical_authority_sha256(self.directive))

    def reseal(self, plan: dict, operation: dict) -> dict:
        plan["plan_sha256"] = canonical_sha256({k: v for k, v in plan.items() if k != "plan_sha256"})
        operation["plan_sha256"] = plan["plan_sha256"]
        return self.sign_operation(operation)

    def test_product_authority_claim_settlement_and_fresh_continuation(self) -> None:
        plan, operation, directive = self.operation()
        capability = self.verifier.verify_operation(plan, operation, directive)
        self.assertEqual(capability.adapter_path, self.adapter)
        self.assertFalse(self.marker.exists(), "verifying authority must not import the adapter")
        self.assertEqual(self.store.read_state()["operations"], {})
        require_maintenance_operation(capability, plan=plan, verifier=self.verifier, require_claimed=False)
        with self.assertRaisesRegex(MaintenanceAuthorityError, "not-live-claimed"):
            require_maintenance_operation(capability, verifier=self.verifier)
        capability.claim()
        require_maintenance_operation(capability, plan=plan, verifier=self.verifier)
        self.store.settle(operation["operation_id"], capability.operation_sha256, outcome="accepted")
        with self.assertRaisesRegex(MaintenanceAuthorityError, "not-live-claimed"):
            capability.revalidate()
        next_plan, next_operation, next_directive = self.operation(operation_id="operation-2")
        next_capability = self.verifier.verify_operation(next_plan, next_operation, next_directive)
        next_capability.claim()
        self.assertEqual(len(self.store.read_state()["operations"]), 2)
        self.assertEqual(next_plan["budget"]["cumulative_before"], 763)

    def test_review_positive_no_write_authority(self) -> None:
        capability = self.verifier.verify_operation(*self.operation(role="review"))
        capability.claim()
        self.assertEqual(capability.evidence()["operation"]["write_paths"], [])

    def test_unicode_plan_uses_existing_transaction_hash_contract(self) -> None:
        plan, operation, _ = self.operation()
        plan["description"] = "maintenance café"
        directive = self.reseal(plan, operation)
        self.verifier.verify_operation(plan, operation, directive).claim()

    def test_no_total_budget_or_deadline_is_fabricated(self) -> None:
        normalized = normalize_maintenance_mission(self.mission)
        self.assertEqual(normalized["budget"], {"mode": "unbounded"})
        self.assertEqual(normalized["lifetime"], {"mode": "until-revoked"})
        self.assertNotIn("cumulative_ceiling", self.operation()[0]["budget"])
        for invalid in (None, False, {"mode": "unbounded", "ceiling": 10**100}, {"mode": "unbounded", "ceiling": None}, {"mode": "unbounded", "ceiling": float("inf")}, {"mode": "finite"}):
            with self.subTest(invalid=invalid), self.assertRaises(MaintenanceAuthorityError):
                normalize_maintenance_mission(dict(self.mission, budget=invalid))

    def test_missing_and_worker_signed_mission_denied(self) -> None:
        for invalid in (None, False, {}, []):
            with self.subTest(invalid=invalid), self.assertRaises(MaintenanceAuthorityError):
                self.make_verifier(operator_directive=invalid)
        attacker = self.sign(self.mission_hash, "copied-request", key=b"worker-chosen-key")
        with self.assertRaisesRegex(MaintenanceAuthorityError, "directive-verification-failed"):
            self.make_verifier(operator_directive=attacker)
        with self.assertRaisesRegex(MaintenanceAuthorityError, "directive-verification-failed"):
            self.make_verifier(expected_actor_id="worker")
        self.assertFalse(self.marker.exists())

    def test_missing_invalid_and_wrong_parent_operation_directive_denied(self) -> None:
        plan, operation, directive = self.operation()
        for invalid in (None, False, {}, [], dict(directive, version=True), dict(directive, parent_receipt_sha256="b" * 64), dict(directive, signature="0" * 64)):
            with self.subTest(invalid=invalid), self.assertRaises(MaintenanceAuthorityError):
                self.verifier.verify_operation(plan, operation, invalid)
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.store.read_state()["operations"], {})

    def test_rehashing_worker_plan_cannot_create_authority(self) -> None:
        plan, operation, directive = self.operation()
        plan["children"][0]["write_paths"] = ["changed.txt"]
        plan["plan_sha256"] = canonical_sha256({k: v for k, v in plan.items() if k != "plan_sha256"})
        operation["write_paths"] = ["changed.txt"]
        operation["plan_sha256"] = plan["plan_sha256"]
        with self.assertRaisesRegex(MaintenanceAuthorityError, "directive-verification-failed"):
            self.verifier.verify_operation(plan, operation, directive)

    def test_valid_signatures_still_require_mission_scope(self) -> None:
        for field, bad_value in (("workspace", str(self.controller)), ("model", "other-model"), ("role", "publication"), ("factory_id", "worker-factory"), ("mission_id", "other-mission"), ("mission_sha256", "c" * 64), ("revocation_generation", 1)):
            plan, operation, _ = self.operation()
            operation[field] = bad_value
            with self.subTest(field=field), self.assertRaises(MaintenanceAuthorityError):
                self.verifier.verify_operation(plan, operation, self.sign_operation(operation))

    def test_closed_installed_factory_rejects_self_selected_hash_and_marker(self) -> None:
        plan, operation, _ = self.operation()
        worker_adapter = self.workspace / "worker_adapter.py"
        worker_adapter.write_text(self.adapter.read_text(), encoding="utf-8")
        plan["runtime_adapter_path"] = str(worker_adapter)
        plan["runtime_adapter_sha256"] = hashlib.sha256(worker_adapter.read_bytes()).hexdigest()
        directive = self.reseal(plan, operation)
        with self.assertRaisesRegex(MaintenanceAuthorityError, "unregistered-adapter"):
            self.verifier.verify_operation(plan, operation, directive)
        self.assertFalse(self.marker.exists())

    def test_registered_adapter_drift_after_verification_denies_before_claim(self) -> None:
        capability = self.verifier.verify_operation(*self.operation())
        self.adapter.write_text("raise AssertionError('must not execute')\n", encoding="utf-8")
        with self.assertRaisesRegex(MaintenanceAuthorityError, "factory-adapter-drift"):
            capability.claim()
        self.assertEqual(self.store.read_state()["operations"], {})

    def test_operation_and_reservation_exact_types(self) -> None:
        for field, bad_value in (("revocation_generation", True), ("write_paths", "result.txt"), ("role", False)):
            plan, operation, _ = self.operation()
            operation[field] = bad_value
            with self.subTest(field=field), self.assertRaises(MaintenanceAuthorityError):
                self.verifier.verify_operation(plan, operation, self.sign_operation(operation))
        for field in ("sessions", "tool_calls", "runtime_seconds", "cleanup_seconds", "max_concurrency"):
            for bad in (True, 0, -1, 1.0, None):
                plan, operation, _ = self.operation()
                operation["reservation"][field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(MaintenanceAuthorityError):
                    self.verifier.verify_operation(plan, operation, self.sign_operation(operation))

    def test_write_scope_and_review_negatives(self) -> None:
        for bad in (["../escape"], ["/absolute"], ["a/../escape"], ["./result.txt"], ["."], ["result.txt", "result.txt"]):
            plan, operation, _ = self.operation()
            plan["children"][0]["write_paths"] = list(bad)
            operation["write_paths"] = list(bad)
            directive = self.reseal(plan, operation)
            with self.subTest(bad=bad), self.assertRaises(MaintenanceAuthorityError):
                self.verifier.verify_operation(plan, operation, directive)
        plan, operation, _ = self.operation()
        operation["role"] = "review"
        with self.assertRaisesRegex(MaintenanceAuthorityError, "role-write-mismatch"):
            self.verifier.verify_operation(plan, operation, self.sign_operation(operation))

    def test_symlink_workspace_or_target_denied(self) -> None:
        linked = self.root / "linked"
        linked.symlink_to(self.workspace, target_is_directory=True)
        plan, operation, _ = self.operation(workspace=linked)
        with self.assertRaisesRegex(MaintenanceAuthorityError, "symlink-forbidden"):
            self.verifier.verify_operation(plan, operation, self.sign_operation(operation))
        (self.workspace / "result.txt").symlink_to(self.controller / "state")
        with self.assertRaisesRegex(MaintenanceAuthorityError, "symlink-forbidden"):
            self.verifier.verify_operation(*self.operation())

    def test_worker_serialization_and_python_copy_are_not_capabilities(self) -> None:
        plan, operation, directive = self.operation()
        capability = self.verifier.verify_operation(plan, operation, directive)
        for copy_value in (capability.evidence(), operation, directive, {}, None, copy.copy(capability)):
            with self.subTest(type=type(copy_value).__name__), self.assertRaises(MaintenanceAuthorityError):
                require_maintenance_operation(copy_value, require_claimed=False)
        other = self.make_verifier()
        with self.assertRaisesRegex(MaintenanceAuthorityError, "foreign-controller"):
            require_maintenance_operation(capability, verifier=other, require_claimed=False)
        with self.assertRaisesRegex(MaintenanceAuthorityError, "construction-forbidden"):
            VerifiedMaintenanceOperation(self.verifier, plan, operation, None, object())

    def test_input_and_evidence_copies_do_not_mutate_live_capability(self) -> None:
        plan, operation, directive = self.operation()
        capability = self.verifier.verify_operation(plan, operation, directive)
        operation["write_paths"].append("another.txt")
        plan["selected_model"] = "other-model"
        evidence = capability.evidence()
        evidence["operation"]["reservation"]["sessions"] = 100
        capability.claim()
        with self.assertRaisesRegex(MaintenanceAuthorityError, "capability-plan-mismatch"):
            capability.revalidate(plan=plan)
        self.assertEqual(capability.evidence()["operation"]["reservation"]["sessions"], 2)

    def test_runtime_scope_exact_join_and_expected_controller_required(self) -> None:
        plan, operation, directive = self.operation()
        capability = self.verifier.verify_operation(plan, operation, directive)
        capability.claim()
        scope = {key: operation[key] for key in ("workspace", "model", "role", "write_paths")}
        require_maintenance_operation(capability, verifier=self.verifier, plan=plan, runtime_scope=scope)
        with self.assertRaisesRegex(MaintenanceAuthorityError, "trusted-verifier-required"):
            require_maintenance_operation(capability)
        for field, value in (("workspace", str(self.controller)), ("model", "other"), ("role", "review"), ("write_paths", [])):
            with self.subTest(field=field), self.assertRaisesRegex(MaintenanceAuthorityError, "runtime-scope-mismatch"):
                require_maintenance_operation(capability, verifier=self.verifier, runtime_scope=dict(scope, **{field: value}))

    def test_exact_adapter_bytes_available_only_after_claim(self) -> None:
        capability = self.verifier.verify_operation(*self.operation())
        with self.assertRaisesRegex(MaintenanceAuthorityError, "not-live-claimed"):
            capability.read_adapter_source()
        capability.claim()
        source = capability.read_adapter_source()
        self.assertEqual(source, self.adapter.read_bytes())
        self.assertFalse(self.marker.exists())
        self.adapter.write_bytes(b"raise AssertionError('untrusted replacement')\n")
        with self.assertRaisesRegex(MaintenanceAuthorityError, "factory-adapter-drift"):
            capability.read_adapter_source()
        self.assertNotEqual(source, self.adapter.read_bytes())

    def test_workspace_inode_replacement_rejected(self) -> None:
        capability = self.verifier.verify_operation(*self.operation())
        self.workspace.rename(self.root / "original-workspace")
        self.workspace.mkdir()
        with self.assertRaisesRegex(MaintenanceAuthorityError, "workspace-replaced"):
            capability.claim()

    def test_late_state_reader_adapter_mutation_is_rejected(self) -> None:
        calls = []
        def observing_reader():
            calls.append(True)
            value = self.store.read_state()
            if len(calls) > 1:
                self.adapter.write_bytes(b"raise AssertionError('late callback mutation')\n")
            return value
        verifier = self.make_verifier(state_reader=observing_reader)
        with self.assertRaisesRegex(MaintenanceAuthorityError, "factory-adapter-drift"):
            verifier.verify_operation(*self.operation())
        self.assertEqual(self.store.read_state()["operations"], {})

    def test_revocation_denies_pending_and_claimed_operations(self) -> None:
        pending = self.verifier.verify_operation(*self.operation())
        claimed = self.verifier.verify_operation(*self.operation(operation_id="claimed"))
        claimed.claim()
        self.store.revoke()
        with self.assertRaisesRegex(MaintenanceAuthorityError, "authority-not-current"):
            pending.claim()
        with self.assertRaisesRegex(MaintenanceAuthorityError, "authority-not-current"):
            claimed.revalidate()
        self.store.settle("claimed", claimed.operation_sha256, outcome="contained")
        state = self.store.read_state()
        self.assertEqual(state["revocation_generation"], 1)
        self.assertEqual(state["operations"]["claimed"]["outcome"], "contained")

    def test_fresh_identity_required_including_after_failed_operation(self) -> None:
        plan, operation, directive = self.operation()
        first = self.verifier.verify_operation(plan, operation, directive)
        duplicate = self.verifier.verify_operation(plan, operation, directive)
        first.claim()
        for action in (duplicate.claim, first.claim, lambda: self.verifier.verify_operation(plan, operation, directive)):
            with self.assertRaisesRegex(MaintenanceAuthorityError, "operation-already-consumed"):
                action()
        self.store.settle(operation["operation_id"], first.operation_sha256, outcome="failed")
        with self.assertRaisesRegex(MaintenanceAuthorityError, "operation-already-consumed"):
            self.verifier.verify_operation(plan, operation, directive)
        self.verifier.verify_operation(*self.operation(operation_id="fresh-correction")).claim()

    def test_state_store_cannot_reinitialize_or_reset_consumed_identity(self) -> None:
        capability = self.verifier.verify_operation(*self.operation())
        capability.claim()
        with self.assertRaises(FileExistsError):
            self.store.initialize()
        self.assertEqual(len(self.store.read_state()["operations"]), 1)
        self.assertEqual(stat_mode(self.controller / "maintenance-state.json"), 0o600)

    def test_two_independent_controller_instances_claim_once(self) -> None:
        second_store = MaintenanceStateStore(self.controller, mission_id=self.mission["mission_id"], mission_sha256=self.mission_hash)
        second = self.make_verifier(state_reader=second_store.read_state, claim_operation=second_store.claim_operation)
        first_cap = self.verifier.verify_operation(*self.operation())
        second_cap = second.verify_operation(*self.operation())
        def attempt(cap):
            try:
                cap.claim()
                return True
            except MaintenanceAuthorityError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, (first_cap, second_cap)))
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(len(self.store.read_state()["operations"]), 1)

    def test_ambiguous_claim_failure_never_releases_attempt(self) -> None:
        def claim_then_raise(*args):
            self.store.claim_operation(*args)
            raise OSError("test persistence acknowledgement lost")
        verifier = self.make_verifier(claim_operation=claim_then_raise)
        capability = verifier.verify_operation(*self.operation())
        with self.assertRaisesRegex(OSError, "acknowledgement"):
            capability.claim()
        with self.assertRaisesRegex(MaintenanceAuthorityError, "operation-already-consumed"):
            capability.claim()

    def test_reentrant_claim_callback_is_rejected_before_second_claim(self) -> None:
        holder = {}
        def claim_reentrant(*args):
            holder["cap"].claim()
        verifier = self.make_verifier(claim_operation=claim_reentrant)
        holder["cap"] = verifier.verify_operation(*self.operation())
        with self.assertRaisesRegex(MaintenanceAuthorityError, "verification-reentrant"):
            holder["cap"].claim()
        self.assertEqual(self.store.read_state()["operations"], {})

    def test_capability_cannot_be_inherited_into_different_process(self) -> None:
        capability = self.verifier.verify_operation(*self.operation())
        with mock.patch("cwo_core.maintenance_authority.os.getpid", return_value=os.getpid() + 1):
            with self.assertRaisesRegex(MaintenanceAuthorityError, "controller-process-mismatch"):
                capability.claim()

    def test_private_state_directory_and_symlink_file_enforced(self) -> None:
        self.controller.chmod(0o755)
        with self.assertRaisesRegex(MaintenanceAuthorityError, "state-directory-not-private"):
            MaintenanceStateStore(self.controller, mission_id=self.mission["mission_id"], mission_sha256=self.mission_hash)
        self.controller.chmod(0o700)
        state_path = self.controller / "maintenance-state.json"
        backup = self.controller / "backup.json"
        state_path.rename(backup)
        state_path.symlink_to(backup)
        with self.assertRaises(OSError):
            self.store.read_state()

    def test_tampered_current_state_and_wrong_generation_types_denied(self) -> None:
        for key, bad in (("mission_sha256", "f" * 64), ("revocation_generation", True), ("status", "unknown")):
            state = self.store.read_state()
            state[key] = bad
            with self.subTest(key=key), self.assertRaises(MaintenanceAuthorityError):
                self.make_verifier(state_reader=lambda value=state: value)


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()

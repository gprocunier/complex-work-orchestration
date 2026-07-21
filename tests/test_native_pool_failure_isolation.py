from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_live_allocation_ledger import (  # noqa: E402
    NativeLiveAllocationLedgerStore,
)
from cwo_core.native_pool import _build_admitted_pool_coordinator  # noqa: E402
from cwo_core.native_pool_admitted import run_admitted_native_pool  # noqa: E402
from cwo_core.native_pool_admission import (  # noqa: E402
    ADMISSION_VERSION,
    DISPATCH_AUTHORITY,
    DISPATCH_SCHEMA,
    DISPATCH_TYPE,
    _seal as seal_admission_artifact,
    build_dispatch_context,
)
from cwo_core.native_pool_capacity import load_pool_capacity  # noqa: E402
from cwo_core.native_pool_contracts import (  # noqa: E402
    canonical_sha256,
    seal_artifact,
    validate_pool_receipt,
    zero_usage,
)
from cwo_core.native_pool_leases import PoolLeaseRegistry  # noqa: E402
from cwo_core.native_pool_preflight import run_pool_preflight  # noqa: E402
from cwo_core.native_pool_reporting import (  # noqa: E402
    NativePoolReportingError,
    build_pool_status_report,
)
from cwo_core.native_recovery_authority import (  # noqa: E402
    FixedCohortRecoveryActionStore,
)
from cwo_core.native_recovery_policy import (  # noqa: E402
    RECOVERY_SIGNAL_FIELDS,
    build_recovery_audit_decision,
)
from tests.test_native_live_allocation_ledger import (  # noqa: E402
    bindings_v2,
    seed_contained_turn_dispatch,
)
from tests.test_native_pool import FakeClock  # noqa: E402
from tests.test_native_pool_admission import _live  # noqa: E402
from tests.test_native_pool_admission_contracts import (  # noqa: E402
    _admitted_artifacts,
    _execution_inputs,
)


def _signals(field: str) -> dict[str, bool]:
    value = {name: False for name in RECOVERY_SIGNAL_FIELDS}
    value[field] = True
    return value


class NativePoolFailureIsolationTests(unittest.TestCase):
    @staticmethod
    def _bare_authority(root: Path, contract: dict):
        return FixedCohortRecoveryActionStore.create(
            root / "bare-recovery-controller",
            [
                {
                    "bead_id": child["bead_id"],
                    "work_unit_id": child["work_unit_id"],
                    "admitted_child_sha256": child[
                        "admitted_child_sha256"
                    ],
                }
                for child in contract["children"]
            ],
        )

    def _authority(
        self,
        root: Path,
        contract: dict,
        *,
        child_index: int = 0,
    ):
        cohort = [
            {
                "bead_id": child["bead_id"],
                "work_unit_id": child["work_unit_id"],
                "admitted_child_sha256": child["admitted_child_sha256"],
            }
            for child in contract["children"]
        ]
        store, controller_root = FixedCohortRecoveryActionStore.create(
            root / "recovery-controller",
            cohort,
        )
        child = contract["children"][child_index]
        ledger = NativeLiveAllocationLedgerStore(root / "contained-ledger")
        ledger_bindings = bindings_v2()
        ledger_bindings["bead_id"] = child["bead_id"]
        ledger_bindings["work_unit_id"] = child["work_unit_id"]
        ledger.initialize(ledger_bindings, version=2)
        thread_id, turn_intent_id, _ = seed_contained_turn_dispatch(
            ledger,
            resolution="turn-bound",
        )
        containment_entry = next(
            entry
            for entry in reversed(ledger.load()["entries"])
            if entry["event"] == "containment-audited"
        )
        witness = ledger.verify_contained_turn_dispatch(
            thread_id,
            turn_intent_id,
        )
        evidence = store.register_contained_ledger_evidence(
            controller_root,
            recovery_class="individual-child-failure",
            bead_id=child["bead_id"],
            admitted_work_unit_id=child["work_unit_id"],
            admitted_child_sha256=child["admitted_child_sha256"],
            ledger_store=ledger,
            ledger_witness=witness,
            expected_thread_id=thread_id,
            expected_turn_intent_id=turn_intent_id,
        )
        state = store.read_state()
        bead_state = next(
            item
            for item in state["bead_states"]
            if item["bead_id"] == child["bead_id"]
        )
        decision = build_recovery_audit_decision(
            _signals("individual_child_failure"),
            replacement_count=bead_state["replacement_count"],
            construction_attempt_count=bead_state[
                "construction_attempt_count"
            ],
            evidence_sha256=containment_entry["evidence_sha256"],
            fixed_cohort_sha256=state["fixed_cohort_sha256"],
            admitted_bead_id=child["bead_id"],
            admitted_child_sha256=child["admitted_child_sha256"],
        )
        action = store.issue(controller_root, decision, evidence)
        return (
            store,
            controller_root,
            action,
            containment_entry["evidence_sha256"],
        )

    def _launch(
        self,
        root: Path,
        *,
        size: int,
        completion_policy: str,
        evidence_mode: str,
        recovery: tuple | None = None,
    ):
        fixture, reservation, contract, request = _admitted_artifacts(
            root,
            size=size,
            completion_policy=completion_policy,
        )
        result = run_pool_preflight(
            request,
            policy_document=fixture.policy_document,
        )
        self.assertTrue(result["accepted"], result["findings"])
        (
            child_contracts,
            tasks,
            child_callbacks,
            adapters,
            pool_callbacks,
            _clock,
        ) = _execution_inputs(fixture, contract)
        for adapter in adapters.values():
            adapter.decisions = ["continue", "complete"]

        recovery_evidence_sha256 = recovery[3] if recovery is not None else None

        def read_child_evidence(*, child_id: str, state_file: str) -> dict:
            calls = adapters[child_id].calls
            target = child_id == contract["children"][0]["child_id"]
            triggered = target and calls.count("check") >= 2
            state_sha256 = canonical_sha256(
                {"child_id": child_id, "state_file": state_file, "calls": calls}
            )
            protected_fault = triggered and evidence_mode == "protected"
            control_loss = triggered and evidence_mode == "control-loss"
            return {
                "state_sha256": state_sha256,
                "usage": zero_usage(),
                "protected_fault": protected_fault,
                "control_loss": control_loss,
                "failure_class": (
                    "control-security-failure"
                    if control_loss
                    else "individual-child-failure"
                    if protected_fault
                    else None
                ),
                "recovery_evidence_sha256": (
                    recovery_evidence_sha256 or state_sha256
                    if protected_fault or control_loss
                    else None
                ),
                "reasons": ["isolated-child-failure"] if triggered else [],
                "session_disposition": "accepted",
                "artifact_disposition": "accepted",
            }

        pool_callbacks["read_child_evidence"] = read_child_evidence
        kwargs = {}
        if recovery is not None:
            store, controller_root, resolver, _evidence_sha256 = recovery
            kwargs = {
                "recovery_authority_store": store,
                "recovery_controller_root": controller_root,
                "recovery_action_resolver": resolver,
            }
        launched = run_admitted_native_pool(
            reservation,
            fixture.admission_capability,
            contract,
            request,
            result,
            child_contracts,
            tasks,
            child_callbacks,
            claim_adapter=fixture.claim_adapter,
            live_revalidate=_live,
            pool_callbacks=pool_callbacks,
            lease_registry=PoolLeaseRegistry(
                root / "failure-isolation-leases.json",
                owner_alive=lambda _owner: True,
                now=FakeClock.now_utc,
            ),
            capability_receipt=fixture.pool_capability_receipt,
            policy_document=fixture.policy_document,
            **kwargs,
        )
        return contract, adapters, launched["pool_receipt"]

    def _launch_with_exact_recovery_fault(
        self,
        root: Path,
        *,
        reason: str,
        failure_class: str = "individual-child-failure",
        evidence_override: str | None = None,
        provide_recovery: bool = True,
    ) -> dict:
        fixture, reservation, contract, request = _admitted_artifacts(
            root,
            size=2,
            completion_policy="best-effort",
        )
        result = run_pool_preflight(
            request,
            policy_document=fixture.policy_document,
        )
        store, controller_root, action, action_evidence_sha256 = self._authority(
            root,
            contract,
        )
        (
            child_contracts,
            tasks,
            child_callbacks,
            adapters,
            pool_callbacks,
            _clock,
        ) = _execution_inputs(fixture, contract)
        for adapter in adapters.values():
            adapter.decisions = ["continue", "complete"]
        state_path = root / "exact-recovery-pool-state.json"
        resolver_calls: list[dict] = []

        def evidence(*, child_id: str, state_file: str) -> dict:
            calls = adapters[child_id].calls
            triggered = (
                child_id == contract["children"][0]["child_id"]
                and calls.count("check") >= 2
            )
            state_sha256 = canonical_sha256(
                {"child_id": child_id, "state_file": state_file, "calls": calls}
            )
            return {
                "state_sha256": state_sha256,
                "usage": zero_usage(),
                "protected_fault": triggered,
                "control_loss": False,
                "failure_class": failure_class if triggered else None,
                "recovery_evidence_sha256": (
                    evidence_override or action_evidence_sha256
                    if triggered
                    else None
                ),
                "reasons": [reason] if triggered else [],
                "session_disposition": "accepted",
                "artifact_disposition": "accepted",
            }

        def resolver(**kwargs):
            resolver_calls.append(dict(kwargs))
            return action

        pool_callbacks["read_child_evidence"] = evidence
        recovery_kwargs = (
            {
                "recovery_authority_store": store,
                "recovery_controller_root": controller_root,
                "recovery_action_resolver": resolver,
            }
            if provide_recovery
            else {}
        )
        launched = run_admitted_native_pool(
            reservation,
            fixture.admission_capability,
            contract,
            request,
            result,
            child_contracts,
            tasks,
            child_callbacks,
            claim_adapter=fixture.claim_adapter,
            live_revalidate=_live,
            pool_callbacks=pool_callbacks,
            lease_registry=PoolLeaseRegistry(
                root / "exact-recovery-leases.json",
                owner_alive=lambda _owner: True,
                now=FakeClock.now_utc,
            ),
            capability_receipt=fixture.pool_capability_receipt,
            policy_document=fixture.policy_document,
            state_file=state_path,
            **recovery_kwargs,
        )
        return {
            "fixture": fixture,
            "reservation": reservation,
            "contract": contract,
            "state": json.loads(state_path.read_text(encoding="utf-8")),
            "launched": launched,
            "adapters": adapters,
            "resolver_calls": resolver_calls,
            "action_evidence_sha256": action_evidence_sha256,
        }

    def test_verified_containment_yields_exact_partial_receipt_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, reservation, contract, request = _admitted_artifacts(
                root,
                size=3,
                completion_policy="best-effort",
                offline_candidate_harness=True,
            )
            result = run_pool_preflight(
                request,
                policy_document=fixture.policy_document,
            )
            self.assertIsNone(fixture.admission_capability)
            self.assertFalse(reservation["dispatch_authorized"])
            (
                store,
                controller_root,
                action,
                recovery_evidence_sha256,
            ) = self._authority(root, contract)
            (
                child_contracts,
                tasks,
                child_callbacks,
                adapters,
                pool_callbacks,
                _clock,
            ) = _execution_inputs(fixture, contract)
            for adapter in adapters.values():
                adapter.decisions = ["continue", "complete"]
            state_path = root / "pool-state.json"
            observed_statuses: list[str] = []

            def evidence(*, child_id: str, state_file: str) -> dict:
                if state_path.is_file():
                    observed_statuses.append(
                        json.loads(state_path.read_text(encoding="utf-8"))["status"]
                    )
                calls = adapters[child_id].calls
                triggered = (
                    child_id == contract["children"][0]["child_id"]
                    and calls.count("check") >= 2
                )
                state_sha256 = canonical_sha256(
                    {"child_id": child_id, "state_file": state_file, "calls": calls}
                )
                return {
                    "state_sha256": state_sha256,
                    "usage": zero_usage(),
                    "protected_fault": triggered,
                    "control_loss": False,
                    "failure_class": (
                        "individual-child-failure" if triggered else None
                    ),
                    "recovery_evidence_sha256": (
                        recovery_evidence_sha256 if triggered else None
                    ),
                    "reasons": ["isolated-child-failure"] if triggered else [],
                    "session_disposition": "accepted",
                    "artifact_disposition": "accepted",
                }

            pool_callbacks["read_child_evidence"] = evidence
            lease_registry = PoolLeaseRegistry(
                root / "leases.json",
                owner_alive=lambda _owner: True,
                now=FakeClock.now_utc,
            )
            acquired = lease_registry.acquire_many(
                contract,
                [child["child_id"] for child in contract["children"]],
                capacity_limits=load_pool_capacity(fixture.policy_document),
            )
            dispatch_context = build_dispatch_context(
                reservation,
                pool_contract_sha256=contract["contract_sha256"],
                preflight_request_sha256=result["request_sha256"],
                preflight_result_sha256=result["result_sha256"],
                lease_set_sha256=canonical_sha256({"leases": acquired}),
            )
            dispatch = seal_admission_artifact(
                {
                    "dispatch_type": DISPATCH_TYPE,
                    "version": ADMISSION_VERSION,
                    "schema": DISPATCH_SCHEMA,
                    "dispatch_id": canonical_sha256(
                        {
                            "offline_candidate": reservation[
                                "reservation_sha256"
                            ]
                        }
                    ),
                    "consumed_at": "2026-07-21T20:00:03.000Z",
                    **dispatch_context,
                    "authority": DISPATCH_AUTHORITY,
                    "dispatch_authorized": True,
                },
                "dispatch_sha256",
            )
            coordinator = _build_admitted_pool_coordinator(
                contract,
                child_contracts,
                tasks,
                child_callbacks,
                pool_callbacks=pool_callbacks,
                lease_registry=lease_registry,
                capability_receipt=fixture.pool_capability_receipt,
                preacquired_leases=acquired,
                reservation_receipt=reservation,
                dispatch_receipt=dispatch,
                policy_document=fixture.policy_document,
                recovery_authority_store=store,
                recovery_controller_root=controller_root,
                recovery_action_resolver=lambda **_kwargs: action,
                state_file=state_path,
            )
            receipt = coordinator.run()
            runtimes = {
                item["child_id"]: item["runtime_disposition"]
                for item in receipt["child_dispositions"]
            }
            self.assertEqual(receipt["pool_disposition"], "partial")
            self.assertFalse(receipt["accepting"])
            self.assertIn("partial-drain", observed_statuses)
            self.assertEqual(list(runtimes.values()).count("failed-contained"), 1)
            self.assertEqual(list(runtimes.values()).count("completed"), 2)
            failed_id = contract["children"][0]["child_id"]
            failed = next(
                item
                for item in receipt["child_dispositions"]
                if item["child_id"] == failed_id
            )
            self.assertEqual(failed["session_disposition"], "quarantined")
            self.assertEqual(failed["artifact_disposition"], "rejected")
            self.assertFalse(failed["implementation_bead_close_authorized"])
            self.assertEqual(
                failed["recovery_projection"]["evidence_sha256"],
                recovery_evidence_sha256,
            )
            self.assertIn("interrupt", adapters[failed_id].calls)
            for child in contract["children"][1:]:
                self.assertNotIn("interrupt", adapters[child["child_id"]].calls)
            report = build_pool_status_report(
                contract,
                json.loads(state_path.read_text(encoding="utf-8")),
                receipt,
                policy_document=fixture.policy_document,
                admission_reservation=reservation,
                dispatch_receipt=dispatch,
            )
            self.assertEqual(report["completion_policy"], "best-effort")
            self.assertEqual(report["pool_disposition"], "partial")
            self.assertEqual(
                [item["runtime_disposition"] for item in report["children"]],
                ["failed-contained", "completed", "completed"],
            )

            terminal_state = json.loads(state_path.read_text(encoding="utf-8"))
            projection_swap = deepcopy(receipt)
            projection_swap["child_dispositions"][0]["recovery_projection"], (
                projection_swap["child_dispositions"][1]["recovery_projection"]
            ) = (
                projection_swap["child_dispositions"][1]["recovery_projection"],
                projection_swap["child_dispositions"][0]["recovery_projection"],
            )
            projection_swap = seal_artifact(
                projection_swap,
                "receipt_sha256",
            )
            projection_errors = validate_pool_receipt(
                projection_swap,
                contract=contract,
                terminal_state=terminal_state,
                admission_reservation=reservation,
                dispatch_receipt=dispatch,
                capacity_limits=load_pool_capacity(fixture.policy_document),
            )
            self.assertTrue(
                any("recovery-projection" in error for error in projection_errors),
                projection_errors,
            )

            receipt_hash_swap = deepcopy(receipt)
            receipt_hash_swap["child_terminal_receipts"][0]["receipt_sha256"], (
                receipt_hash_swap["child_terminal_receipts"][1]["receipt_sha256"]
            ) = (
                receipt_hash_swap["child_terminal_receipts"][1]["receipt_sha256"],
                receipt_hash_swap["child_terminal_receipts"][0]["receipt_sha256"],
            )
            receipt_hash_swap = seal_artifact(
                receipt_hash_swap,
                "receipt_sha256",
            )
            hash_errors = validate_pool_receipt(
                receipt_hash_swap,
                contract=contract,
                terminal_state=terminal_state,
                admission_reservation=reservation,
                dispatch_receipt=dispatch,
                capacity_limits=load_pool_capacity(fixture.policy_document),
            )
            self.assertTrue(
                any("state-receipt-sha256-mismatch" in error for error in hash_errors),
                hash_errors,
            )

    def test_security_fault_cannot_reuse_valid_individual_action(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outcome = self._launch_with_exact_recovery_fault(
                Path(temporary),
                reason="forbidden-tool-activity",
            )
        receipt = outcome["launched"]["pool_receipt"]
        self.assertEqual(outcome["resolver_calls"], [])
        self.assertEqual(receipt["pool_disposition"], "quarantined")
        self.assertNotIn(
            "failed-contained",
            [item["runtime_disposition"] for item in receipt["child_dispositions"]],
        )
        self.assertTrue(
            all("interrupt" in adapter.calls for adapter in outcome["adapters"].values())
        )

    def test_same_child_action_must_match_current_fault_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outcome = self._launch_with_exact_recovery_fault(
                Path(temporary),
                reason="isolated-child-failure",
                evidence_override="e" * 64,
            )
        receipt = outcome["launched"]["pool_receipt"]
        self.assertEqual(len(outcome["resolver_calls"]), 1)
        resolver_evidence = outcome["resolver_calls"][0][
            "recovery_evidence_sha256"
        ]
        self.assertEqual(resolver_evidence, "e" * 64)
        self.assertNotEqual(
            resolver_evidence,
            outcome["action_evidence_sha256"],
        )
        self.assertEqual(receipt["pool_disposition"], "quarantined")
        self.assertTrue(
            any(
                "consumed-recovery-action-binding-mismatch" in reason
                for reason in receipt["reasons"]
            ),
            receipt["reasons"],
        )

    def test_actionless_receipt_relabel_and_reseal_cannot_mint_partial_close(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outcome = self._launch_with_exact_recovery_fault(
                Path(temporary),
                reason="isolated-child-failure",
                provide_recovery=False,
            )
            receipt = outcome["launched"]["pool_receipt"]
            tampered = deepcopy(receipt)
            failed = tampered["child_dispositions"][0]
            peer = tampered["child_dispositions"][1]
            failed["runtime_disposition"] = "failed-contained"
            self.assertIsNone(failed["recovery_projection"])
            peer["runtime_disposition"] = "completed"
            peer["session_disposition"] = "accepted"
            peer["artifact_disposition"] = "accepted"
            peer["implementation_bead_close_authorized"] = True
            peer_control = tampered["child_terminal_receipts"][1][
                "control_receipt"
            ]
            peer_control["terminal_state"] = "completed"
            peer_control["errors"] = []
            peer_control = seal_artifact(peer_control, "receipt_sha256")
            tampered["child_terminal_receipts"][1][
                "control_receipt"
            ] = peer_control
            tampered["child_terminal_receipts"][1][
                "receipt_sha256"
            ] = canonical_sha256(peer_control)
            tampered["pool_disposition"] = "partial"
            tampered["accepting"] = False
            tampered = seal_artifact(tampered, "receipt_sha256")

            errors = validate_pool_receipt(
                tampered,
                contract=outcome["contract"],
                terminal_state=outcome["state"],
                admission_reservation=outcome["reservation"],
                dispatch_receipt=outcome["launched"]["dispatch_receipt"],
                capacity_limits=load_pool_capacity(
                    outcome["fixture"].policy_document
                ),
            )
            self.assertTrue(
                any("recovery" in error for error in errors),
                errors,
            )
            self.assertTrue(
                any("state-runtime-mismatch" in error for error in errors),
                errors,
            )
            self.assertTrue(
                any("state-receipt-sha256-mismatch" in error for error in errors),
                errors,
            )
            with self.assertRaises(NativePoolReportingError):
                build_pool_status_report(
                    outcome["contract"],
                    outcome["state"],
                    tampered,
                    policy_document=outcome["fixture"].policy_document,
                    admission_reservation=outcome["reservation"],
                    dispatch_receipt=outcome["launched"]["dispatch_receipt"],
                )

    def test_missing_authority_all_or_nothing_and_control_loss_drain(self) -> None:
        cases = (
            ("best-effort", "protected"),
            ("all-or-nothing", "protected"),
            ("best-effort", "control-loss"),
        )
        for completion_policy, evidence_mode in cases:
            with (
                self.subTest(
                    completion_policy=completion_policy,
                    evidence_mode=evidence_mode,
                ),
                tempfile.TemporaryDirectory() as temporary,
            ):
                contract, adapters, receipt = self._launch(
                    Path(temporary),
                    size=2,
                    completion_policy=completion_policy,
                    evidence_mode=evidence_mode,
                )
                self.assertEqual(receipt["pool_disposition"], "quarantined")
                runtimes = {
                    item["child_id"]: item["runtime_disposition"]
                    for item in receipt["child_dispositions"]
                }
                self.assertEqual(
                    runtimes[contract["children"][0]["child_id"]],
                    "failed-ambiguous",
                )
                self.assertTrue(
                    all("interrupt" in adapter.calls for adapter in adapters.values())
                )

    def test_throwing_or_serialized_recovery_resolver_never_contains(self) -> None:
        def throwing(**_kwargs):
            raise RuntimeError("resolver failed")

        cases = (
            (throwing, "RuntimeError"),
            (lambda **_kwargs: {"verified": True}, "action-type-invalid"),
        )
        for resolver, expected_reason in cases:
            with (
                self.subTest(expected_reason=expected_reason),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                (root / "authority").mkdir()
                (root / "launch").mkdir()
                _fixture, _reservation, authority_contract, _request = (
                    _admitted_artifacts(root / "authority", size=2)
                )
                store, controller_root = self._bare_authority(
                    root,
                    authority_contract,
                )
                _contract, adapters, receipt = self._launch(
                    root / "launch",
                    size=2,
                    completion_policy="best-effort",
                    evidence_mode="protected",
                    recovery=(store, controller_root, resolver, "f" * 64),
                )
                self.assertEqual(receipt["pool_disposition"], "quarantined")
                self.assertTrue(
                    any(expected_reason in reason for reason in receipt["reasons"]),
                    receipt["reasons"],
                )
                self.assertNotIn(
                    "failed-contained",
                    [
                        item["runtime_disposition"]
                        for item in receipt["child_dispositions"]
                    ],
                )
                self.assertTrue(
                    all("interrupt" in adapter.calls for adapter in adapters.values())
                )


if __name__ == "__main__":
    unittest.main()

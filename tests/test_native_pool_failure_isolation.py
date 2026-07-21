from __future__ import annotations

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
from cwo_core.native_pool_admitted import run_admitted_native_pool  # noqa: E402
from cwo_core.native_pool_contracts import canonical_sha256, zero_usage  # noqa: E402
from cwo_core.native_pool_leases import PoolLeaseRegistry  # noqa: E402
from cwo_core.native_pool_preflight import run_pool_preflight  # noqa: E402
from cwo_core.native_pool_reporting import build_pool_status_report  # noqa: E402
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
        return store, controller_root, action

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

        def read_child_evidence(*, child_id: str, state_file: str) -> dict:
            calls = adapters[child_id].calls
            target = child_id == contract["children"][0]["child_id"]
            triggered = target and calls.count("check") >= 2
            return {
                "state_sha256": canonical_sha256(
                    {"child_id": child_id, "state_file": state_file, "calls": calls}
                ),
                "usage": zero_usage(),
                "protected_fault": triggered and evidence_mode == "protected",
                "control_loss": triggered and evidence_mode == "control-loss",
                "reasons": ["isolated-child-failure"] if triggered else [],
                "session_disposition": "accepted",
                "artifact_disposition": "accepted",
            }

        pool_callbacks["read_child_evidence"] = read_child_evidence
        kwargs = {}
        if recovery is not None:
            store, controller_root, resolver = recovery
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

    def test_verified_containment_yields_exact_partial_receipt_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, reservation, contract, request = _admitted_artifacts(
                root,
                size=3,
                completion_policy="best-effort",
            )
            result = run_pool_preflight(
                request,
                policy_document=fixture.policy_document,
            )
            store, controller_root, action = self._authority(root, contract)
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
                return {
                    "state_sha256": canonical_sha256(
                        {"child_id": child_id, "state_file": state_file, "calls": calls}
                    ),
                    "usage": zero_usage(),
                    "protected_fault": triggered,
                    "control_loss": False,
                    "reasons": ["isolated-child-failure"] if triggered else [],
                    "session_disposition": "accepted",
                    "artifact_disposition": "accepted",
                }

            pool_callbacks["read_child_evidence"] = evidence
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
                    root / "leases.json",
                    owner_alive=lambda _owner: True,
                    now=FakeClock.now_utc,
                ),
                capability_receipt=fixture.pool_capability_receipt,
                policy_document=fixture.policy_document,
                recovery_authority_store=store,
                recovery_controller_root=controller_root,
                recovery_action_resolver=lambda **_kwargs: action,
                state_file=state_path,
            )
            receipt = launched["pool_receipt"]
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
            self.assertIn("interrupt", adapters[failed_id].calls)
            for child in contract["children"][1:]:
                self.assertNotIn("interrupt", adapters[child["child_id"]].calls)
            report = build_pool_status_report(
                contract,
                json.loads(state_path.read_text(encoding="utf-8")),
                receipt,
                policy_document=fixture.policy_document,
                admission_reservation=reservation,
                dispatch_receipt=launched["dispatch_receipt"],
            )
            self.assertEqual(report["completion_policy"], "best-effort")
            self.assertEqual(report["pool_disposition"], "partial")
            self.assertEqual(
                [item["runtime_disposition"] for item in report["children"]],
                ["failed-contained", "completed", "completed"],
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
                    recovery=(store, controller_root, resolver),
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

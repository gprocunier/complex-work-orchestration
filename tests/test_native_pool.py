from __future__ import annotations

import copy
import datetime as dt
import fcntl
import hashlib
import hmac
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_control import build_control_turn_contract  # noqa: E402
from cwo_core.native_pool import (  # noqa: E402
    LegacyNativePoolExecutionRetired,
    NativePoolCoordinator,
    NativePoolError,
    _build_admitted_pool_coordinator,
    run_native_pool,
)
from cwo_core.native_pool_admission import (  # noqa: E402
    AdmissionCandidate,
    PoolAdmissionReservation,
    build_admission_child_binding,
    build_dispatch_context,
    consume_pool_admission,
)
from cwo_core.native_pool_capacity import load_pool_capacity  # noqa: E402
from cwo_core.native_pool_contracts import (  # noqa: E402
    ADMISSION_TOP_BINDING_FIELDS,
    ADMITTED_POOL_CONTRACT_SCHEMA,
    ADMITTED_POOL_VERSION,
    DEFAULT_COMPLETION_POLICY,
    admission_child_render_hashes,
    canonical_sha256,
    seal_artifact,
    validate_pool_contract,
    validate_pool_receipt,
    validate_pool_state,
    write_private_artifact,
    zero_usage,
)
from cwo_core.native_pool_leases import (  # noqa: E402
    PoolLeaseError,
    PoolLeaseRegistry,
    capture_owner_identity,
)
from cwo_core.native_pool_proportionality import pool_proportionality_check  # noqa: E402
from cwo_core.native_stop_scope import (  # noqa: E402
    policy_scope_authority,
    verify_operator_scope_directive,
)
from tests.test_native_pool_admission import _live, _reserve  # noqa: E402
from tests.test_native_pool_contracts import (  # noqa: E402
    child as pool_child,
    control_request,
    pool_contract,
    sha,
)
from tests.test_native_pool_proportionality import _fixture  # noqa: E402


class FakeClock:
    def __init__(self) -> None:
        self.ns = 0
        self.sleeps: list[float] = []

    def monotonic_ns(self) -> int:
        return self.ns

    def advance_ms(self, milliseconds: float) -> None:
        self.ns += int(milliseconds * 1_000_000)

    def sleep(self, *, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.ns += int(seconds * 1_000_000_000)

    @staticmethod
    def now_utc() -> dt.datetime:
        return dt.datetime(2026, 7, 16, 0, 10, tzinfo=dt.timezone.utc)


class FakeAdapter:
    def __init__(
        self,
        clock: FakeClock,
        decisions: list[str],
        *,
        callback_ms: float = 1,
        callback_ms_by_name: dict[str, float] | None = None,
        fail: str | None = None,
        deferred_close: bool = False,
        close_defer_count: int = 0,
    ) -> None:
        self.clock = clock
        self.decisions = list(decisions)
        self.callback_ms = callback_ms
        self.callback_ms_by_name = dict(callback_ms_by_name or {})
        self.fail = fail
        self.deferred_close = deferred_close
        self.close_defer_count = close_defer_count
        self.calls: list[str] = []

    def _call(self, name: str, result=None):
        self.calls.append(name)
        self.clock.advance_ms(self.callback_ms_by_name.get(name, self.callback_ms))
        if self.fail == name:
            raise RuntimeError(f"{name} failed")
        return result

    def check(self, **_kwargs):
        decision = self.decisions.pop(0) if self.decisions else "complete"
        return self._call("check", {"decision": decision})

    def close(self, **_kwargs):
        pending = self.close_defer_count > 0
        if pending:
            self.close_defer_count -= 1
        return self._call(
            "close",
            {
                "ack": "close-pending" if pending else "closed",
                "close_wait_required": pending,
            },
        )

    def callbacks(self) -> dict:
        return {
            "arm": lambda **_kwargs: self._call("arm"),
            "send_input": lambda **_kwargs: self._call(
                "send_input", {"submission_id": f"submission-{id(self)}"}
            ),
            "mark_dispatched": lambda **_kwargs: self._call("mark_dispatched"),
            "check": self.check,
            "interrupt": lambda **_kwargs: self._call("interrupt"),
            "close": self.close,
            "finalize": lambda **_kwargs: self._call(
                "finalize",
                {
                    "ack": _kwargs.get("control_action", "finalized"),
                    "close_wait_required": True,
                }
                if self.deferred_close
                else None,
            ),
            "sleep": lambda **_kwargs: self._call("sleep"),
        }


def _reserve_fixture_contract(contract: dict) -> tuple[dict, PoolAdmissionReservation]:
    """Bind a scheduler fixture to a real one-use reservation with in-memory claims."""
    children = contract["children"]
    cap = len(children)
    readiness, estimates, items, policy = _fixture([600] * cap)
    assessment = pool_proportionality_check(
        readiness, estimates, requested_workers=cap, policy_document=policy,
    )
    bindings = {}
    for child, bead_id in zip(children, sorted(estimates), strict=True):
        bindings[bead_id] = build_admission_child_binding(
            readiness,
            estimates[bead_id],
            bead_id=bead_id,
            child_id=child["child_id"],
            packet_id=child["packet_id"],
            packet_sha256=child["packet_sha256"],
            worktree_identity_sha256=canonical_sha256(child["worktree_identity"]),
        )
    candidate = AdmissionCandidate(readiness, estimates, assessment, bindings)
    reserved, _runner = _reserve(candidate, items, policy_document=policy)
    if not reserved.admitted:
        raise AssertionError(reserved.receipt)
    receipt = reserved.receipt
    for child, claim in zip(children, receipt["claims"], strict=True):
        child.update(bindings[claim["bead_id"]])
        child["claim_sha256"] = claim["claim_sha256"]
        child["hard_budget"] = {**child["hard_budget"], "full_suite_runs": 0, "mutations": 1}
        child.update(admission_child_render_hashes(child))
    contract.update(
        {
            field: receipt[field]
            for field in ADMISSION_TOP_BINDING_FIELDS - {"admission_reservation_sha256"}
        },
        version=ADMITTED_POOL_VERSION,
        schema=ADMITTED_POOL_CONTRACT_SCHEMA,
        completion_policy=DEFAULT_COMPLETION_POLICY,
        admission_reservation_sha256=receipt["reservation_sha256"],
        aggregate_hard_budget={
            field: sum(child["hard_budget"][field] for child in children)
            for field in contract["aggregate_hard_budget"]
        },
    )
    return seal_artifact(contract, "contract_sha256"), reserved


class PoolHarness:
    def __init__(
        self,
        temporary: str,
        *,
        cap: int,
        decisions: list[list[str]] | None = None,
        callback_ms: float = 1,
        callback_ms_by_name: dict[str, float] | None = None,
        fail: tuple[int, str] | None = None,
        deferred_close: bool = False,
        close_defer_count: int = 0,
        dirty_phases: set[str] | None = None,
        usage_by_child: dict[str, dict] | None = None,
        usage_sequence_by_child: dict[str, list[dict]] | None = None,
        dispositions_by_child: dict[str, tuple[str, str]] | None = None,
        protected_fault_reasons_by_child: dict[str, list[str]] | None = None,
        read_only: bool = False,
        read_only_children: set[str] | None = None,
        control_file: Path | None = None,
        policy_document: dict | None = None,
    ) -> None:
        self.clock = FakeClock()
        self.contract, self.capability = pool_contract(cap=cap, read_only=read_only)
        for index, existing_child in enumerate(self.contract["children"]):
            if existing_child["child_id"] in (read_only_children or set()):
                self.contract["children"][index] = pool_child(
                    index,
                    isolation="read-only-shared",
                )
        live_owner = capture_owner_identity()
        self.contract["owner"] = live_owner
        if self.capability is not None:
            self.capability["host_identity"] = live_owner
            self.capability = seal_artifact(self.capability, "receipt_sha256")
            self.contract["capability_receipt_sha256"] = self.capability["receipt_sha256"]
        self.tasks = {f"child-{index}": f"bounded task {index}" for index in range(cap)}
        self.child_contracts: dict[str, dict] = {}
        for index, child in enumerate(self.contract["children"]):
            child_id = child["child_id"]
            control = build_control_turn_contract(
                state_file=child["state_file"],
                agent_id=child["agent_id"],
                control_turn_id=child["control_turn_id"],
                task_sha256=hashlib.sha256(self.tasks[child_id].encode("utf-8")).hexdigest(),
                poll_interval_ms=self.contract["scheduler"]["poll_interval_ms"],
            )
            self.child_contracts[child_id] = control
            child["control_contract_sha256"] = control["contract_sha256"]
        self.contract, self.reservation = _reserve_fixture_contract(self.contract)
        decision_sets = decisions or [["complete"] for _ in range(cap)]
        self.adapters = {
            f"child-{index}": FakeAdapter(
                self.clock,
                decision_sets[index],
                callback_ms=callback_ms,
                callback_ms_by_name=callback_ms_by_name,
                fail=fail[1] if fail is not None and fail[0] == index else None,
                deferred_close=deferred_close,
                close_defer_count=close_defer_count,
            )
            for index in range(cap)
        }
        self.dirty_phases = dirty_phases or set()
        self.usage_by_child = usage_by_child or {}
        self.usage_sequence_by_child = {
            child_id: [copy.deepcopy(usage) for usage in sequence]
            for child_id, sequence in (usage_sequence_by_child or {}).items()
        }
        self.dispositions_by_child = dispositions_by_child or {}
        self.protected_fault_reasons_by_child = (
            protected_fault_reasons_by_child or {}
        )
        self.compare_phases: list[str] = []
        self.registry = PoolLeaseRegistry(
            Path(temporary) / "leases.json",
            owner_alive=lambda _owner: True,
            now=self.clock.now_utc,
        )
        self.root = Path(temporary)
        self.control_file = control_file
        self.policy_document = policy_document
        self.pool_callbacks = {
            "monotonic_ns": self.clock.monotonic_ns,
            "sleep": self.clock.sleep,
            "now_utc": self.clock.now_utc,
            "read_child_evidence": self.read_child_evidence,
            "compare_workspaces": self.compare_workspaces,
        }
        self.start()

    def build_coordinator(self, leases: list[dict], dispatch: dict) -> NativePoolCoordinator:
        return _build_admitted_pool_coordinator(
            self.contract,
            self.child_contracts,
            self.tasks,
            {child_id: adapter.callbacks() for child_id, adapter in self.adapters.items()},
            pool_callbacks=self.pool_callbacks,
            lease_registry=self.registry,
            capability_receipt=self.capability,
            preacquired_leases=leases,
            reservation_receipt=self.reservation.receipt,
            dispatch_receipt=dispatch,
            state_file=self.root / "pool-state.json",
            decision_file=self.root / "pool-decision.json",
            control_file=self.control_file,
            policy_document=self.policy_document,
        )

    def start(self) -> None:
        # The public bridge runs to completion inside its commit. Scheduler
        # tests drive individual steps after the same admission consumer commits.
        limits = load_pool_capacity(self.policy_document)
        self.leases = self.registry.acquire_many(self.contract, list(self.adapters), capacity_limits=limits)
        receipt = self.reservation.receipt
        context = build_dispatch_context(
            receipt,
            pool_contract_sha256=self.contract["contract_sha256"],
            preflight_request_sha256=sha("scheduler-fixture-request"),
            preflight_result_sha256=sha("scheduler-fixture-result"),
            lease_set_sha256=canonical_sha256({"leases": self.leases}),
        )

        def commit(dispatch: dict) -> None:
            self.coordinator = self.build_coordinator(self.leases, dispatch)

        self.dispatch = consume_pool_admission(
            self.reservation.capability,
            receipt,
            context,
            claim_adapter=self.reservation.claim_adapter,
            live_revalidate=_live,
            commit=commit,
            now=self.clock.now_utc(),
        )

    def validate_receipt(self, receipt: dict, *, terminal_state: dict) -> list[str]:
        return validate_pool_receipt(
            receipt,
            contract=self.contract,
            terminal_state=terminal_state,
            admission_reservation=self.reservation.receipt,
            dispatch_receipt=self.dispatch,
        )

    def read_child_evidence(self, *, child_id: str, state_file: str) -> dict:
        sequence = self.usage_sequence_by_child.get(child_id, [])
        usage = (
            copy.deepcopy(sequence.pop(0))
            if sequence
            else copy.deepcopy(self.usage_by_child.get(child_id, zero_usage()))
        )
        session_disposition, artifact_disposition = self.dispositions_by_child.get(
            child_id, ("accepted", "accepted")
        )
        protected_fault_reasons = self.protected_fault_reasons_by_child.get(
            child_id, []
        )
        state_sha256 = sha(
            f"{child_id}:{state_file}:{len(self.adapters[child_id].calls)}"
        )
        return {
            "state_sha256": state_sha256,
            "usage": usage,
            "protected_fault": bool(protected_fault_reasons),
            "control_loss": False,
            "failure_class": (
                "individual-child-failure" if protected_fault_reasons else None
            ),
            "recovery_evidence_sha256": (
                state_sha256 if protected_fault_reasons else None
            ),
            "reasons": list(protected_fault_reasons),
            "session_disposition": session_disposition,
            "artifact_disposition": artifact_disposition,
        }

    def compare_workspaces(self, *, contract: dict, phase: str) -> dict:
        self.compare_phases.append(phase)
        clean = phase not in self.dirty_phases
        evidence = {
            "integration_root_clean": clean,
            "shared_read_only_clean": True,
            "child_worktrees_clean": True,
        }
        return {**evidence, "evidence_sha256": canonical_sha256(evidence)}


def drive_until_lease_states(
    harness: PoolHarness,
    expected_states: list[str],
) -> dict:
    progress: dict = harness.coordinator.progress()
    for _ in range(64):
        if [lease["lifecycle_state"] for lease in harness.registry.snapshot()] == expected_states:
            return progress
        progress = harness.coordinator.step()
        if [lease["lifecycle_state"] for lease in harness.registry.snapshot()] == expected_states:
            return progress
        if progress["wait_required"]:
            harness.clock.sleep(seconds=progress["wait_seconds"])
    raise AssertionError(f"lease states did not reach {expected_states!r}")


def assert_state_lock_released(test: unittest.TestCase, temporary: str) -> None:
    lock_path = Path(temporary) / "pool-state.json.lock"
    with lock_path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            test.fail(f"pool state lock remained held: {error}")
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class NativePoolCoordinatorTests(unittest.TestCase):
    def test_legacy_public_execution_refuses_before_any_effect(self) -> None:
        contract, capability = pool_contract(cap=1)
        contract["owner"] = capture_owner_identity()
        child = contract["children"][0]
        task = "bounded task"
        control = build_control_turn_contract(
            state_file=child["state_file"],
            agent_id=child["agent_id"],
            control_turn_id=child["control_turn_id"],
            task_sha256=hashlib.sha256(task.encode("utf-8")).hexdigest(),
            poll_interval_ms=contract["scheduler"]["poll_interval_ms"],
        )
        child["control_contract_sha256"] = control["contract_sha256"]
        contract = seal_artifact(contract, "contract_sha256")
        self.assertEqual(validate_pool_contract(contract), [])
        for entry in (NativePoolCoordinator, run_native_pool):
            with self.subTest(entry=entry.__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                adapter = FakeAdapter(FakeClock(), ["complete"])
                child_callbacks = {
                    name: mock.Mock(side_effect=callback) for name, callback in adapter.callbacks().items()
                }
                pool_callbacks = {
                    name: mock.Mock(side_effect=AssertionError(f"unexpected {name} callback"))
                    for name in ("monotonic_ns", "now_utc", "sleep", "read_child_evidence", "compare_workspaces")
                }
                registry = PoolLeaseRegistry(root / "leases.json")
                with self.assertRaisesRegex(LegacyNativePoolExecutionRetired, "^legacy-pool-execution-retired$"):
                    entry(
                        contract,
                        {"child-0": control},
                        {"child-0": task},
                        {"child-0": child_callbacks},
                        pool_callbacks=pool_callbacks,
                        lease_registry=registry,
                        capability_receipt=capability,
                        state_file=root / "state.json",
                        decision_file=root / "decision.json",
                        control_file=root / "control.json",
                    )
                self.assertTrue(all(callback.call_count == 0 for callback in pool_callbacks.values()))
                self.assertTrue(all(callback.call_count == 0 for callback in child_callbacks.values()))
                self.assertEqual(list(root.iterdir()), [])

    @staticmethod
    def _add_noncallback_invoke_time(
        harness: PoolHarness,
        *,
        milliseconds: float,
    ) -> list[str]:
        invocations: list[str] = []
        turn = harness.coordinator._turns["child-0"]
        original_step = turn.step

        def timed_step(*args, **kwargs):
            invocations.append("step")
            harness.clock.advance_ms(milliseconds)
            return original_step(*args, **kwargs)

        turn.step = timed_step
        return invocations

    def test_exclusive_timing_buckets_reconcile_and_count_invoke_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=1,
                callback_ms=1,
                decisions=[["continue", "complete"]],
            )
            invocations = self._add_noncallback_invoke_time(
                harness,
                milliseconds=3,
            )
            evidence_calls: list[str] = []
            compare_calls: list[str] = []
            original_evidence = harness.coordinator.pool_callbacks[
                "read_child_evidence"
            ]
            original_compare = harness.coordinator.pool_callbacks[
                "compare_workspaces"
            ]

            def timed_evidence(**kwargs):
                evidence_calls.append("read")
                harness.clock.advance_ms(2)
                return original_evidence(**kwargs)

            def timed_compare(**kwargs):
                compare_calls.append("compare")
                harness.clock.advance_ms(4)
                return original_compare(**kwargs)

            harness.coordinator.pool_callbacks["read_child_evidence"] = (
                timed_evidence
            )
            harness.coordinator.pool_callbacks["compare_workspaces"] = (
                timed_compare
            )

            receipt = harness.coordinator.run()
            timing = receipt["timing"]
            expected_callback_ns = len(harness.adapters["child-0"].calls) * 1_000_000
            expected_invoke_ns = len(invocations) * 3_000_000
            expected_coordinator_ns = (
                len(evidence_calls) * 2_000_000
                + len(compare_calls) * 4_000_000
            )
            expected_wait_ns = round(sum(harness.clock.sleeps) * 1_000_000_000)

            self.assertEqual(timing["accounting_version"], "exclusive-v1")
            self.assertEqual(timing["callback_ns"], expected_callback_ns)
            self.assertEqual(
                timing["noncallback_invoke_ns"],
                expected_invoke_ns,
            )
            self.assertEqual(timing["coordinator_ns"], expected_coordinator_ns)
            self.assertEqual(timing["wait_ns"], expected_wait_ns)
            self.assertEqual(
                sum(
                    timing[field]
                    for field in (
                        "callback_ns",
                        "noncallback_invoke_ns",
                        "coordinator_ns",
                        "wait_ns",
                    )
                ),
                round(receipt["pool_wall_seconds"] * 1_000_000_000),
            )
            terminal_state = harness.coordinator.progress()["state"]
            self.assertEqual(
                terminal_state["poll_overhead_seconds"],
                (expected_invoke_ns + expected_coordinator_ns) / 1_000_000_000,
            )

    def test_manual_and_blocking_runs_account_wait_without_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            blocking = PoolHarness(
                temporary,
                cap=1,
                decisions=[["continue", "complete"]],
            )
            blocking_receipt = blocking.coordinator.run()
            self.assertEqual(
                blocking_receipt["timing"]["wait_ns"],
                round(sum(blocking.clock.sleeps) * 1_000_000_000),
            )

        with tempfile.TemporaryDirectory() as temporary:
            manual = PoolHarness(
                temporary,
                cap=1,
                decisions=[["continue", "complete"]],
            )
            progress = manual.coordinator.step()
            while progress["status"] not in {"closed", "control-failed"}:
                if progress["wait_required"]:
                    manual.clock.sleep(seconds=progress["wait_seconds"])
                progress = manual.coordinator.step()
            manual_receipt = progress["receipt"]
            self.assertEqual(
                manual_receipt["timing"]["wait_ns"],
                round(sum(manual.clock.sleeps) * 1_000_000_000),
            )

    def test_exception_path_accounts_invoke_once_and_freezes_timing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1, fail=(0, "arm"))
            invocations = self._add_noncallback_invoke_time(
                harness,
                milliseconds=3,
            )

            receipt = harness.coordinator.run()

            state = copy.deepcopy(harness.coordinator.progress()["state"])
            self.assertFalse(receipt["accepting"])
            self.assertEqual(
                harness.coordinator._callback_ns,
                len(harness.adapters["child-0"].calls) * 1_000_000,
            )
            self.assertEqual(
                harness.coordinator._noncallback_invoke_ns,
                len(invocations) * 3_000_000,
            )
            self.assertEqual(
                state["poll_overhead_seconds"],
                len(invocations) * 0.003,
            )
            self.assertTrue(harness.coordinator._timing_frozen)

            harness.clock.advance_ms(5000)
            self.assertEqual(harness.coordinator.progress()["state"], state)

    def test_successful_terminal_receipt_timing_is_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            receipt = harness.coordinator.run()
            state = copy.deepcopy(harness.coordinator.progress()["state"])

            harness.clock.advance_ms(5000)

            self.assertEqual(harness.coordinator.run(), receipt)
            self.assertEqual(harness.coordinator.progress()["state"], state)


    def test_active_run_capability_expiry_interrupts_before_next_callback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                decisions=[
                    ["continue", "complete"],
                    ["continue", "complete"],
                ],
            )
            for _ in range(32):
                progress = harness.coordinator.step()
                if all(
                    "mark_dispatched" in adapter.calls
                    for adapter in harness.adapters.values()
                ):
                    break
                if progress["wait_required"]:
                    harness.clock.sleep(seconds=progress["wait_seconds"])
            else:
                self.fail("both children were not dispatched before expiry")

            calls_at_expiry = {
                child_id: list(adapter.calls)
                for child_id, adapter in harness.adapters.items()
            }
            expires_at = dt.datetime.fromisoformat(
                harness.capability["expires_at"].replace("Z", "+00:00")
            )
            harness.coordinator.pool_callbacks["now_utc"] = lambda: expires_at

            progress = harness.coordinator.step()

            self.assertEqual(progress["decision"]["decision"], "interrupt")
            self.assertEqual(
                calls_at_expiry,
                {
                    child_id: list(adapter.calls)
                    for child_id, adapter in harness.adapters.items()
                },
            )
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertEqual(receipt["stop_scope"], "cohort")
            self.assertEqual(
                receipt["first_protected_fault"]["code"],
                "capability-receipt-invalid:capability-receipt-stale",
            )
            post_expiry_calls = {
                child_id: adapter.calls[len(calls_at_expiry[child_id]) :]
                for child_id, adapter in harness.adapters.items()
            }
            self.assertTrue(
                all(
                    calls
                    and set(calls) <= {"interrupt", "finalize", "close"}
                    for calls in post_expiry_calls.values()
                ),
                post_expiry_calls,
            )
            self.assertEqual(
                [item["lifecycle_state"] for item in harness.registry.snapshot()],
                ["released", "released"],
            )

    def test_first_child_protected_fault_reason_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=1,
                protected_fault_reasons_by_child={
                    "child-0": ["unexpected-mutation:targets/child_1.txt"]
                },
            )
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertEqual(
                receipt["first_protected_fault"]["code"],
                "child-protected-fault:unexpected-mutation:targets/child_1.txt",
            )
            self.assertEqual(receipt["stop_scope"], "child")
            self.assertTrue(
                all(
                    set(path) == {"path", "target_id", "conditions"}
                    for path in receipt["authorized_continuation_paths"]
                )
            )


    def test_failed_terminal_control_loss_contains_cohort_before_peer_admission(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                decisions=[["control-lost"], ["continue", "complete"]],
            )
            read_child_evidence = harness.read_child_evidence
            triggering_evidence: list[dict] = []

            def failed_terminal_evidence(
                *, child_id: str, state_file: str
            ) -> dict:
                evidence = read_child_evidence(
                    child_id=child_id,
                    state_file=state_file,
                )
                if (
                    child_id == "child-0"
                    and harness.adapters[child_id].calls[-1] == "check"
                ):
                    evidence.update(
                        {
                            "protected_fault": True,
                            "control_loss": True,
                            "failure_class": "control-security-failure",
                            "recovery_evidence_sha256": evidence["state_sha256"],
                            "reasons": ["trusted-turn-failed"],
                            "session_disposition": "quarantined",
                            "artifact_disposition": "rejected",
                        }
                    )
                    triggering_evidence.append(copy.deepcopy(evidence))
                return evidence

            harness.coordinator.pool_callbacks["read_child_evidence"] = (
                failed_terminal_evidence
            )
            receipt = harness.coordinator.run()
            state = harness.coordinator.progress()["state"]

            self.assertFalse(receipt["accepting"])
            self.assertEqual(receipt["pool_disposition"], "quarantined")
            self.assertEqual(len(triggering_evidence), 1)
            self.assertEqual(
                triggering_evidence[0]["recovery_evidence_sha256"],
                triggering_evidence[0]["state_sha256"],
            )
            self.assertEqual(
                triggering_evidence[0]["failure_class"],
                "control-security-failure",
            )
            self.assertEqual(
                receipt["first_protected_fault"]["code"],
                "child-control-loss",
            )
            self.assertEqual(
                receipt["reasons"],
                ["trusted-turn-failed", "child-control-loss"],
            )
            self.assertEqual(state["status"], "control-failed")
            self.assertEqual(state["control_loss_scope"], "pool")
            self.assertEqual(
                receipt["terminal_state_sha256"],
                state["state_sha256"],
            )
            self.assertEqual(receipt["admission_order"], ["child-0"])
            self.assertEqual(receipt["poll_order"], ["child-0"])
            self.assertIn("check", harness.adapters["child-0"].calls)
            self.assertIn("interrupt", harness.adapters["child-0"].calls)
            self.assertEqual(harness.adapters["child-1"].calls, [])
            self.assertEqual(
                [
                    {key: disposition[key] for key in (
                        "child_id", "runtime_disposition", "session_disposition", "artifact_disposition",
                    )}
                    for disposition in receipt["child_dispositions"]
                ],
                [
                    {
                        "child_id": "child-0",
                        "runtime_disposition": "failed-ambiguous",
                        "session_disposition": "quarantined",
                        "artifact_disposition": "rejected",
                    },
                    {
                        "child_id": "child-1",
                        "runtime_disposition": "interrupted",
                        "session_disposition": "quarantined",
                        "artifact_disposition": "rejected",
                    },
                ],
            )
            self.assertEqual(
                [item["lifecycle_state"] for item in receipt["lease_evidence"]],
                ["release-pending", "release-pending"],
            )
            self.assertEqual(
                validate_pool_state(state, contract=harness.contract),
                [],
            )
            self.assertEqual(
                harness.validate_receipt(receipt, terminal_state=state),
                [],
            )

    def test_cap_one_runs_to_accepting_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1, decisions=[["continue", "complete"]])
            receipt = harness.coordinator.run()
            self.assertTrue(receipt["accepting"])
            self.assertEqual(receipt["admission_order"], ["child-0"])
            self.assertEqual(receipt["terminal_order"], ["child-0"])
            self.assertEqual(
                harness.validate_receipt(
                    receipt,
                    terminal_state=harness.coordinator.progress()["state"],
                ),
                [],
            )
            self.assertEqual(
                harness.adapters["child-0"].calls,
                [
                    "arm",
                    "send_input",
                    "mark_dispatched",
                    "check",
                    "check",
                    "finalize",
                    "close",
                ],
            )
            self.assertTrue(harness.clock.sleeps)
            self.assertEqual(harness.registry.snapshot()[0]["lifecycle_state"], "released")

    def test_cap_two_rotates_polls_and_accepts_bounded_cohort(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                decisions=[["continue", "complete"], ["continue", "complete"]],
            )
            receipt = harness.coordinator.run()
            self.assertTrue(receipt["accepting"])
            self.assertEqual(receipt["admission_order"], ["child-0", "child-1"])
            self.assertEqual(receipt["poll_order"], ["child-0", "child-1", "child-0", "child-1"])
            self.assertLessEqual(receipt["timing"]["max_callback_latency_ms"], 100)
            self.assertLessEqual(receipt["timing"]["max_poll_gap_ms"], 2500)
            self.assertEqual(
                [lease["lifecycle_state"] for lease in harness.registry.snapshot()],
                ["released", "released"],
            )

    def test_cap_two_accepts_callbacks_exactly_at_certified_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                callback_ms=100,
                decisions=[["complete"], ["complete"]],
            )
            receipt = harness.coordinator.run()
            self.assertTrue(receipt["accepting"])
            self.assertIsNone(receipt["first_protected_fault"])

    def test_slack_pressure_warns_without_changing_certification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                callback_ms_by_name={"check": 190},
            )
            warning = None
            for _ in range(32):
                progress = harness.coordinator.step()
                decision = progress["decision"]
                if decision is not None and decision["decision"] == "warn":
                    warning = decision
                    break
                if progress["wait_required"]:
                    harness.clock.sleep(seconds=progress["wait_seconds"])
            self.assertIsNotNone(warning)
            self.assertEqual(warning["observed_callback_latency_ms"], 190.0)
            self.assertEqual(warning["reasons"], [])

            receipt = harness.coordinator.run()
            self.assertTrue(receipt["accepting"])
            self.assertIsNone(receipt["first_protected_fault"])

    def test_send_input_nominal_and_hard_boundaries_are_distinct(self) -> None:
        cases = (
            (250, None, True),
            (250.001, "warn", True),
            (275, "warn", True),
            (275.001, "interrupt", False),
        )
        for callback_ms, expected_decision, expected_accepting in cases:
            with self.subTest(callback_ms=callback_ms), tempfile.TemporaryDirectory() as temporary:
                harness = PoolHarness(
                    temporary,
                    cap=2,
                    callback_ms_by_name={"send_input": callback_ms},
                )
                observed_decision = None
                for _ in range(32):
                    progress = harness.coordinator.step()
                    decision = progress["decision"]
                    if decision is not None and decision["selected_child_id"] == "child-0":
                        if decision["decision"] in {"warn", "interrupt"}:
                            observed_decision = decision["decision"]
                            break
                    if progress["wait_required"]:
                        harness.clock.sleep(seconds=progress["wait_seconds"])
                if expected_decision is None:
                    self.assertIsNone(observed_decision)
                else:
                    self.assertEqual(observed_decision, expected_decision)
                receipt = harness.coordinator.run()
                self.assertEqual(receipt["accepting"], expected_accepting)
                if expected_accepting:
                    self.assertIsNone(receipt["first_protected_fault"])
                else:
                    self.assertEqual(
                        receipt["first_protected_fault"]["code"],
                        "callback-overrun:send_input",
                    )

    def test_step_invokes_at_most_one_adapter_callback_and_never_sleeps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=2)
            for _ in range(12):
                before_calls = sum(len(adapter.calls) for adapter in harness.adapters.values())
                before_sleeps = len(harness.clock.sleeps)
                progress = harness.coordinator.step()
                after_calls = sum(len(adapter.calls) for adapter in harness.adapters.values())
                self.assertLessEqual(after_calls - before_calls, 1)
                self.assertEqual(len(harness.clock.sleeps), before_sleeps)
                if progress["status"] in {"closed", "control-failed"}:
                    break
            harness.coordinator.run()

    def test_initial_mutation_fails_before_any_child_callback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1, dirty_phases={"create", "close"})
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertEqual(receipt["admission_order"], [])
            self.assertIn("initial-workspace-comparison-failed", receipt["reasons"])
            self.assertEqual(harness.adapters["child-0"].calls, [])
            self.assertEqual(
                [lease["lifecycle_state"] for lease in receipt["lease_evidence"]],
                ["released"],
            )

    def test_read_only_fast_path_retains_only_boundary_comparisons(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                read_only=True,
                decisions=[["continue", "complete"], ["continue", "complete"]],
            )

            receipt = harness.coordinator.run()

            self.assertTrue(receipt["accepting"])
            self.assertEqual(harness.compare_phases, ["create", "close"])
            self.assertEqual(
                harness.coordinator._read_only_fast_path_children,
                frozenset({"child-0", "child-1"}),
            )

    def test_mixed_topology_skips_only_validated_read_only_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                read_only_children={"child-0"},
                decisions=[["continue", "complete"], ["continue", "complete"]],
            )

            receipt = harness.coordinator.run()

            self.assertTrue(receipt["accepting"])
            self.assertFalse(
                any(
                    phase.startswith("after-child-0-")
                    for phase in harness.compare_phases
                )
            )
            self.assertTrue(
                any(
                    phase.startswith("after-child-1-")
                    for phase in harness.compare_phases
                )
            )

    def test_mixed_topology_mutation_disables_later_callback_skipping(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            detected_phase = "after-child-1-check"
            harness = PoolHarness(
                temporary,
                cap=2,
                read_only_children={"child-0"},
                decisions=[["continue", "complete"], ["continue", "complete"]],
                dirty_phases={detected_phase},
            )

            receipt = harness.coordinator.run()

            self.assertFalse(receipt["accepting"])
            detection_index = harness.compare_phases.index(detected_phase)
            self.assertFalse(
                any(
                    phase.startswith("after-child-0-")
                    for phase in harness.compare_phases[:detection_index]
                )
            )
            self.assertTrue(
                any(
                    phase.startswith("after-child-0-")
                    for phase in harness.compare_phases[detection_index + 1 :]
                )
            )
            self.assertEqual(
                harness.coordinator._read_only_fast_path_children,
                frozenset(),
            )
            self.assertEqual(
                harness.coordinator._invalidated_read_only_fast_path_children,
                frozenset({"child-0"}),
            )
            self.assertFalse(
                harness.coordinator._deferred_read_only_workspace_check
            )
            dispositions = {
                item["child_id"]: item for item in receipt["child_dispositions"]
            }
            self.assertEqual(
                dispositions["child-0"]["session_disposition"],
                "quarantined",
            )

    def test_read_only_control_failure_runs_deferred_terminal_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=1,
                read_only=True,
                fail=(0, "arm"),
                dirty_phases={"close"},
            )

            receipt = harness.coordinator.run()

            self.assertFalse(receipt["accepting"])
            self.assertEqual(harness.compare_phases, ["create", "close"])
            self.assertIn(
                "terminal-workspace-comparison-failed",
                receipt["reasons"],
            )
            self.assertEqual(
                harness.coordinator._read_only_fast_path_children,
                frozenset(),
            )
            self.assertFalse(
                harness.coordinator._deferred_read_only_workspace_check
            )


    def test_callback_failure_marks_lease_release_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1, fail=(0, "check"))
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertEqual(receipt["pool_disposition"], "quarantined")
            self.assertEqual(receipt["lease_evidence"][0]["lifecycle_state"], "release-pending")
            self.assertEqual(harness.registry.snapshot()[0]["lifecycle_state"], "release-pending")
            self.assertEqual(receipt["terminal_order"], ["child-0"])
            self.assertEqual(receipt["admission_order"], [])
            self.assertEqual(validate_pool_state(harness.coordinator.progress()["state"], contract=harness.contract), [])

    def test_first_poll_hold_failure_becomes_typed_controlled_fault(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=1,
                decisions=[["continue", "complete"]],
            )
            with mock.patch.object(
                harness.registry,
                "hold",
                side_effect=PoolLeaseError(
                    "lease-registry-unreadable:password=must-not-appear"
                ),
            ):
                receipt = harness.coordinator.run()

            self.assertFalse(receipt["accepting"])
            self.assertEqual(
                harness.registry.snapshot()[0]["lifecycle_state"],
                "release-pending",
            )
            reason = next(
                reason
                for reason in receipt["reasons"]
                if reason.startswith("lease-hold-failed:")
            )
            self.assertTrue(
                reason.startswith(
                    "lease-hold-failed:child=child-0:lease=lease-0:"
                    "target=held:error=lease-registry-unreadable:evidence="
                )
            )
            self.assertNotIn("password", reason)
            self.assertNotIn("must-not-appear", reason)
            self.assertEqual(
                harness.coordinator.progress()["state"]["status"],
                "control-failed",
            )
            assert_state_lock_released(self, temporary)

    def test_release_pending_failure_does_not_skip_unaffected_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                decisions=[["continue", "complete"], ["continue", "complete"]],
            )
            drive_until_lease_states(harness, ["held", "held"])
            harness.adapters["child-0"].fail = "check"
            real_mark_release_pending = harness.registry.mark_release_pending

            def injected_mark_release_pending(
                lease_id: str,
                *,
                terminal_evidence_sha256: str,
                reason: str,
            ) -> dict:
                if lease_id == "lease-0":
                    raise PoolLeaseError(
                        "lease-transition-invalid:credential=must-not-appear"
                    )
                return real_mark_release_pending(
                    lease_id,
                    terminal_evidence_sha256=terminal_evidence_sha256,
                    reason=reason,
                )

            with mock.patch.object(
                harness.registry,
                "mark_release_pending",
                side_effect=injected_mark_release_pending,
            ):
                receipt = harness.coordinator.run()

            self.assertFalse(receipt["accepting"])
            self.assertEqual(
                [lease["lifecycle_state"] for lease in harness.registry.snapshot()],
                ["held", "release-pending"],
            )
            reason = next(
                reason
                for reason in receipt["reasons"]
                if reason.startswith("lease-release-pending-failed:")
            )
            self.assertTrue(
                reason.startswith(
                    "lease-release-pending-failed:child=child-0:lease=lease-0:"
                    "target=release-pending:error=lease-transition-invalid:evidence="
                )
            )
            self.assertNotIn("credential", reason)
            self.assertNotIn("must-not-appear", reason)
            assert_state_lock_released(self, temporary)

    def test_release_failure_contains_pool_and_releases_unaffected_peer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=2)
            real_release = harness.registry.release

            def injected_release(
                lease_id: str,
                *,
                terminal_state: dict,
                reason: str,
            ) -> dict:
                if lease_id == "lease-0":
                    raise PoolLeaseError(
                        "lease-transition-invalid:token=must-not-appear"
                    )
                return real_release(
                    lease_id,
                    terminal_state=terminal_state,
                    reason=reason,
                )

            with mock.patch.object(
                harness.registry,
                "release",
                side_effect=injected_release,
            ):
                receipt = harness.coordinator.run()

            self.assertFalse(receipt["accepting"])
            self.assertEqual(
                [lease["lifecycle_state"] for lease in harness.registry.snapshot()],
                ["release-pending", "released"],
            )
            reason = next(
                reason
                for reason in receipt["reasons"]
                if reason.startswith("lease-release-failed:")
            )
            self.assertTrue(
                reason.startswith(
                    "lease-release-failed:child=child-0:lease=lease-0:"
                    "target=released:error=lease-transition-invalid:evidence="
                )
            )
            self.assertNotIn("token", reason)
            self.assertNotIn("must-not-appear", reason)
            self.assertEqual(
                harness.coordinator.progress()["state"]["status"],
                "control-failed",
            )
            assert_state_lock_released(self, temporary)

    def test_unhandled_step_error_persists_control_failure_and_releases_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            original_error = RuntimeError("step failure\nwith control text")
            with mock.patch.object(harness.coordinator, "step", side_effect=original_error):
                with self.assertRaises(RuntimeError) as raised:
                    harness.coordinator.run()

            self.assertIs(raised.exception, original_error)
            self.assertEqual(harness.adapters["child-0"].calls, [])
            self.assertEqual(
                [lease["lifecycle_state"] for lease in harness.registry.snapshot()],
                ["release-pending"],
            )
            state = json.loads((Path(temporary) / "pool-state.json").read_text(encoding="utf-8"))
            self.assertEqual(validate_pool_state(state, contract=harness.contract), [])
            self.assertEqual(state["status"], "control-failed")
            self.assertIn(
                "coordinator-crash:RuntimeError:step failure with control text",
                state["reasons"],
            )
            self.assertIn(
                "coordinator-crash-affected-children:child-0",
                state["reasons"],
            )
            self.assertEqual(state["stop_scope"], "execution-path")
            self.assertIsNone(harness.coordinator._state_lock_handle)
            assert_state_lock_released(self, temporary)

    def test_keyboard_interrupt_after_lease_hold_uses_crash_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=1,
                decisions=[["continue", "complete"]],
            )
            progress = drive_until_lease_states(harness, ["held"])
            self.assertTrue(progress["wait_required"])
            original_error = KeyboardInterrupt("operator interrupt")
            harness.coordinator.pool_callbacks["sleep"] = mock.Mock(
                side_effect=original_error
            )

            with self.assertRaises(KeyboardInterrupt) as raised:
                harness.coordinator.run()

            self.assertIs(raised.exception, original_error)
            self.assertEqual(
                harness.registry.snapshot()[0]["lifecycle_state"],
                "release-pending",
            )
            state = json.loads((Path(temporary) / "pool-state.json").read_text(encoding="utf-8"))
            self.assertEqual(validate_pool_state(state, contract=harness.contract), [])
            self.assertIn(
                "coordinator-crash:KeyboardInterrupt:operator interrupt",
                state["reasons"],
            )
            self.assertTrue(
                any(
                    reason.startswith(
                        "lease-release-failed:child=child-0:lease=lease-0:"
                        "target=released:error=lease-release-requires-completed-or-closed-pool:"
                        "evidence="
                    )
                    for reason in state["reasons"]
                )
            )
            assert_state_lock_released(self, temporary)

    def test_crash_cleanup_retries_state_persistence_without_masking_root_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            original_error = RuntimeError("root failure")
            real_persist = harness.coordinator._persist_state
            attempts = 0

            def flaky_persist() -> None:
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise OSError("state write\nfailed")
                real_persist()

            with (
                mock.patch.object(harness.coordinator, "step", side_effect=original_error),
                mock.patch.object(
                    harness.coordinator,
                    "_persist_state",
                    side_effect=flaky_persist,
                ),
            ):
                with self.assertRaises(RuntimeError) as raised:
                    harness.coordinator.run()

            self.assertIs(raised.exception, original_error)
            self.assertEqual(attempts, 2)
            state = json.loads((Path(temporary) / "pool-state.json").read_text(encoding="utf-8"))
            self.assertEqual(validate_pool_state(state, contract=harness.contract), [])
            self.assertIn(
                "coordinator-crash-cleanup-error:persist-state:OSError:state write failed",
                state["reasons"],
            )
            assert_state_lock_released(self, temporary)

    def test_crash_cleanup_records_unlock_error_and_still_closes_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            original_error = RuntimeError("root failure")
            real_flock = fcntl.flock
            state_lock_fd = harness.coordinator._state_lock_handle.fileno()
            unlock_failed = False

            def flaky_flock(file_descriptor: int, operation: int) -> None:
                nonlocal unlock_failed
                if file_descriptor == state_lock_fd and operation == fcntl.LOCK_UN and not unlock_failed:
                    unlock_failed = True
                    raise OSError("unlock failed")
                real_flock(file_descriptor, operation)

            with (
                mock.patch.object(harness.coordinator, "step", side_effect=original_error),
                mock.patch("cwo_core.native_pool.fcntl.flock", side_effect=flaky_flock),
            ):
                with self.assertRaises(RuntimeError) as raised:
                    harness.coordinator.run()

            self.assertIs(raised.exception, original_error)
            self.assertTrue(unlock_failed)
            state = json.loads((Path(temporary) / "pool-state.json").read_text(encoding="utf-8"))
            self.assertEqual(validate_pool_state(state, contract=harness.contract), [])
            self.assertIn(
                "coordinator-crash-cleanup-error:release-state-lock:OSError:unlock failed",
                state["reasons"],
            )
            self.assertIsNone(harness.coordinator._state_lock_handle)
            assert_state_lock_released(self, temporary)

    def test_crash_cleanup_continues_after_one_release_error_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                decisions=[["continue", "complete"], ["continue", "complete"]],
            )
            drive_until_lease_states(harness, ["held", "held"])
            original_error = RuntimeError("coordinator boundary failed")

            def injected_release(
                lease_id: str,
                *,
                terminal_state: dict,
                reason: str,
            ) -> dict:
                if lease_id == "lease-0":
                    raise PoolLeaseError("injected release failure")
                return harness.registry._transition(
                    lease_id,
                    lifecycle_state="released",
                    terminal_evidence_sha256=terminal_state["state_sha256"],
                    release_reason=reason,
                )

            with (
                mock.patch.object(harness.coordinator, "step", side_effect=original_error),
                mock.patch.object(
                    harness.registry,
                    "release",
                    side_effect=injected_release,
                ),
            ):
                with self.assertRaises(RuntimeError) as raised:
                    harness.coordinator.run()

            self.assertIs(raised.exception, original_error)
            self.assertEqual(
                [lease["lifecycle_state"] for lease in harness.registry.snapshot()],
                ["release-pending", "released"],
            )
            state_before = copy.deepcopy(harness.coordinator._state)
            registry_before = harness.registry.snapshot()
            self.assertTrue(
                any(
                    reason.startswith(
                        "lease-release-failed:child=child-0:lease=lease-0:"
                        "target=released:error=unclassified:evidence="
                    )
                    for reason in state_before["reasons"]
                )
            )
            self.assertFalse(
                any(
                    reason.startswith("lease-release-failed:child=child-1:")
                    for reason in state_before["reasons"]
                )
            )

            harness.coordinator._cleanup_on_crash(original_error)
            self.assertEqual(harness.coordinator._state, state_before)
            self.assertEqual(harness.registry.snapshot(), registry_before)
            assert_state_lock_released(self, temporary)

    def test_cap_two_callback_overrun_interrupts_entire_pool(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                callback_ms=101,
            )
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertIn("callback-overrun:arm", receipt["reasons"])
            self.assertEqual(
                receipt["first_protected_fault"],
                {
                    "code": "callback-overrun:arm",
                    "operation": "arm",
                    "observed_callback_latency_ms": 101.0,
                    "certified_callback_max_ms": 100.0,
                    "latched_state_sequence": receipt["first_protected_fault"][
                        "latched_state_sequence"
                    ],
                },
            )
            self.assertEqual(
                receipt["first_protected_fault"],
                harness.coordinator.progress()["state"]["first_protected_fault"],
            )
            self.assertEqual(receipt["pool_disposition"], "quarantined")
            self.assertTrue(all(item["lifecycle_state"] == "released" for item in receipt["lease_evidence"]))

    def test_cap_two_check_overrun_still_interrupts_the_pool(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=2, callback_ms_by_name={"check": 201})
            receipt = harness.coordinator.run()
            fault = receipt["first_protected_fault"]
            self.assertFalse(receipt["accepting"])
            self.assertEqual(receipt["pool_disposition"], "quarantined")
            self.assertEqual(fault["code"], "callback-overrun:check")
            self.assertEqual(fault["observed_callback_latency_ms"], 201.0)
            self.assertEqual(fault["certified_callback_max_ms"], 200.0)
            self.assertTrue(all(item["lifecycle_state"] == "released" for item in receipt["lease_evidence"]))

    def test_child_local_interrupt_does_not_interrupt_accepted_peer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                decisions=[["interrupt"], ["continue", "complete"]],
                dispositions_by_child={"child-0": ("quarantined", "rejected")},
            )
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertEqual(receipt["pool_disposition"], "partial")
            self.assertIn("interrupt", harness.adapters["child-0"].calls)
            self.assertNotIn("interrupt", harness.adapters["child-1"].calls)
            self.assertEqual(receipt["terminal_order"], ["child-0", "child-1"])

    def test_interrupt_wins_completion_observation_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=1,
                decisions=[["complete"]],
                dirty_phases={"after-child-0-check", "close"},
            )
            receipt = harness.coordinator.run()
            calls = harness.adapters["child-0"].calls
            self.assertFalse(receipt["accepting"])
            self.assertIn("interrupt", calls)
            self.assertGreater(calls.index("interrupt"), calls.index("check"))
            self.assertIn("workspace-mutation-attribution-failed", receipt["reasons"])
            observations = harness.coordinator.workspace_observations()
            suspicious = [
                item
                for item in observations
                if item["phase"] == "after-child-0-check"
            ]
            self.assertEqual(len(suspicious), 1)
            self.assertFalse(suspicious[0]["evidence"]["integration_root_clean"])
            observations[0]["phase"] = "tampered-copy"
            self.assertNotEqual(
                harness.coordinator.workspace_observations()[0]["phase"],
                "tampered-copy",
            )


    def test_free_text_interrupt_cannot_authorize_publication_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            harness.coordinator.request_interrupt(
                "STOP 0.98 block publication",
                stop_scope="publication",
            )
            receipt = harness.coordinator.run()
            self.assertEqual(receipt["stop_scope"], "cohort")
            self.assertEqual(receipt["scope_authority"]["authorized_scope"], "cohort")

    def test_public_policy_factory_cannot_broaden_interrupt_api(self) -> None:
        forged_policy = policy_scope_authority(
            "caller-asserted-policy",
            authorized_scope="complete-task",
        )
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            with self.assertRaisesRegex(
                NativePoolError,
                "broad-interrupt-requires-operator-directive",
            ):
                harness.coordinator.request_interrupt(
                    "caller requests complete task stop",
                    stop_scope="complete-task",
                    scope_authority=forged_policy,
                )
            harness.coordinator.request_interrupt("test-cleanup")
            harness.coordinator.run()

    def test_verified_operator_directive_enforces_publication_scope(self) -> None:
        key = b"test-only-pool-operator-key"
        action_sha256 = sha("pool-publication-stop-action")
        directive = {
            "version": 1,
            "directive_id": "pool-operator-stop-1",
            "action_sha256": action_sha256,
            "actor_id": "operator-1",
            "identity_source": "trusted-control-session",
            "authorized_scope": "publication",
            "parent_receipt_sha256": None,
            "issued_at": "2026-07-20T00:00:00Z",
            "nonce": "pool-directive-nonce-1",
        }
        directive["signature"] = hmac.new(
            key,
            json.dumps(
                directive,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        authority = verify_operator_scope_directive(
            directive,
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            expected_action_sha256=action_sha256,
        )
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            harness.coordinator.request_interrupt(
                "verified-operator-publication-stop",
                stop_scope="publication",
                scope_authority=authority,
            )
            receipt = harness.coordinator.run()
            self.assertEqual(receipt["stop_scope"], "publication")
            self.assertEqual(receipt["scope_authority"]["source_type"], "operator-directive")

    def test_cumulative_counter_reset_is_control_failure(self) -> None:
        first = zero_usage()
        first["tool_calls"] = 1
        reset = zero_usage()
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=1,
                usage_sequence_by_child={"child-0": [first, reset]},
            )
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertTrue(any("cumulative-tool-calls-reset" in reason for reason in receipt["reasons"]))
            self.assertEqual(receipt["lease_evidence"][0]["lifecycle_state"], "release-pending")

    def test_pre_submission_time_does_not_count_as_first_poll_lag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            harness.clock.advance_ms(5000)
            receipt = harness.coordinator.run()
            self.assertTrue(receipt["accepting"])
            self.assertNotIn("maximum-poll-gap-exceeded", receipt["reasons"])
            self.assertLess(receipt["timing"]["max_poll_gap_ms"], 2500)

    def test_post_submission_first_poll_delay_is_pool_wide_protected_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            turn = harness.coordinator._turns["child-0"]
            original_step = turn.step

            def delayed_step(*args, **kwargs):
                if turn._phase == "mark-dispatched":
                    harness.clock.advance_ms(2600)
                return original_step(*args, **kwargs)

            turn.step = delayed_step
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertIn("maximum-poll-gap-exceeded", receipt["reasons"])
            self.assertGreater(receipt["timing"]["max_poll_gap_ms"], 2500)

    def test_mutable_startup_compares_workspace_at_first_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            receipt = harness.coordinator.run()
            self.assertTrue(receipt["accepting"])
            self.assertFalse(
                any(
                    phase in {
                        "after-child-0-arm",
                        "after-child-0-send_input",
                        "after-child-0-mark_dispatched",
                    }
                    for phase in harness.compare_phases
                )
            )
            self.assertIn("after-child-0-check", harness.compare_phases)

    def test_mocked_n3_startup_reaches_all_first_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=3,
                decisions=[["continue", "complete"] for _ in range(3)],
            )
            receipt = harness.coordinator.run()
            self.assertTrue(receipt["accepting"])
            self.assertEqual(
                receipt["admission_order"],
                ["child-0", "child-1", "child-2"],
            )
            self.assertNotIn("maximum-poll-gap-exceeded", receipt["reasons"])
            for child_id in ("child-0", "child-1", "child-2"):
                self.assertIn(
                    f"after-{child_id}-check",
                    harness.compare_phases,
                )

    def test_state_file_tamper_is_detected_before_next_adapter_callback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            state_path = Path(temporary) / "pool-state.json"
            harness.coordinator.step()
            before = len(harness.adapters["child-0"].calls)
            state_path.write_text("{}", encoding="utf-8")
            progress = harness.coordinator.step()
            self.assertEqual(len(harness.adapters["child-0"].calls), before)
            self.assertIn("pool-state-watermark-mismatch", progress["state"]["reasons"])
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])

    def test_state_watermark_rejects_contradictory_duplicate_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            state_path = Path(temporary) / "pool-state.json"
            harness.coordinator.step()
            before = list(harness.adapters["child-0"].calls)
            original = state_path.read_text(encoding="utf-8")
            duplicate = original.replace(
                '"state_sequence":',
                '"state_sequence": -1, "state_sequence":',
                1,
            )
            self.assertNotEqual(duplicate, original)
            self.assertEqual(json.loads(duplicate), json.loads(original))
            state_path.write_text(duplicate, encoding="utf-8")

            progress = harness.coordinator.step()

            self.assertIn("pool-state-watermark-unreadable", progress["state"]["reasons"])
            self.assertEqual(harness.adapters["child-0"].calls, before)
            self.assertFalse(harness.coordinator.run()["accepting"])

    def test_state_bound_control_request_interrupts_once_and_terminates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            control_path = Path(temporary) / "pool-control.json"
            harness = PoolHarness(
                temporary,
                cap=1,
                decisions=[["continue", "complete"]],
                control_file=control_path,
            )
            progress = harness.coordinator.step()
            while progress["status"] != "running":
                progress = harness.coordinator.step()
            request = control_request(harness.contract, progress["state"])
            write_private_artifact(control_path, request)
            before = len(harness.adapters["child-0"].calls)
            interrupted = harness.coordinator.step()
            self.assertEqual(len(harness.adapters["child-0"].calls), before)
            self.assertTrue(any(reason.startswith("external-control-request:interrupt-1:") for reason in interrupted["state"]["reasons"]))
            self.assertEqual(interrupted["state"]["stop_scope"], "cohort")
            harness.coordinator.step()
            self.assertEqual(
                sum(reason.startswith("external-control-request:interrupt-1:") for reason in harness.coordinator.progress()["state"]["reasons"]),
                1,
            )
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])

    def test_malformed_control_request_contains_once_instead_of_livelocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            control_path = Path(temporary) / "pool-control.json"
            harness = PoolHarness(temporary, cap=1, control_file=control_path)
            control_path.write_text("{}\n", encoding="utf-8")
            control_path.chmod(0o600)
            first = harness.coordinator.step()
            self.assertTrue(any(reason.startswith("pool-control-request-failed:") for reason in first["state"]["reasons"]))
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])

    def test_world_readable_or_future_control_request_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            control_path = Path(temporary) / "pool-control.json"
            harness = PoolHarness(temporary, cap=1, control_file=control_path)
            request = control_request(harness.contract, harness.coordinator.progress()["state"])
            write_private_artifact(control_path, request)
            control_path.chmod(0o644)
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertTrue(any("permissions-invalid" in reason for reason in receipt["reasons"]))

        with tempfile.TemporaryDirectory() as temporary:
            control_path = Path(temporary) / "pool-control.json"
            harness = PoolHarness(temporary, cap=1, control_file=control_path)
            state = harness.coordinator.progress()["state"]
            request = control_request(harness.contract, state)
            request["observed_state_sequence"] += 1
            request = seal_artifact(request, "request_sha256")
            write_private_artifact(control_path, request)
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertTrue(any("state-sequence-from-future" in reason for reason in receipt["reasons"]))

    def test_interrupt_request_after_completion_observation_wins_before_close(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            control_path = Path(temporary) / "pool-control.json"
            harness = PoolHarness(temporary, cap=1, control_file=control_path)
            progress = harness.coordinator.step()
            while progress["status"] != "completed":
                if progress["wait_required"]:
                    harness.clock.sleep(seconds=progress["wait_seconds"])
                progress = harness.coordinator.step()
            write_private_artifact(control_path, control_request(harness.contract, progress["state"]))
            harness.coordinator.step()
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertTrue(any(reason.startswith("external-control-request:") for reason in receipt["reasons"]))


    def test_terminal_workspace_comparison_precedes_lease_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            progress = harness.coordinator.step()
            while progress["status"] != "completed":
                if progress["wait_required"]:
                    harness.clock.sleep(seconds=progress["wait_seconds"])
                progress = harness.coordinator.step()
            self.assertEqual(harness.registry.snapshot()[0]["lifecycle_state"], "held")
            self.assertNotIn("close", harness.compare_phases)

            progress = harness.coordinator.step()
            self.assertEqual(progress["status"], "completed")
            self.assertIn("close", harness.compare_phases)
            self.assertEqual(harness.registry.snapshot()[0]["lifecycle_state"], "held")

            harness.coordinator.step()
            self.assertEqual(harness.registry.snapshot()[0]["lifecycle_state"], "released")
            harness.coordinator.run()

    def test_deferred_shared_read_only_mutation_quarantines_cohort(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                read_only=True,
                dirty_phases={"close"},
            )
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertEqual(receipt["pool_disposition"], "quarantined")
            self.assertIn("terminal-workspace-comparison-failed", receipt["reasons"])
            self.assertFalse(
                any(phase.startswith("after-") for phase in harness.compare_phases)
            )
            self.assertTrue(harness.adapters["child-0"].calls)
            self.assertTrue(harness.adapters["child-1"].calls)
            dispositions = {item["child_id"]: item for item in receipt["child_dispositions"]}
            self.assertEqual(
                {item["session_disposition"] for item in dispositions.values()},
                {"quarantined"},
            )
            self.assertEqual(
                {item["artifact_disposition"] for item in dispositions.values()},
                {"rejected"},
            )

    def test_capacity_three_runs_and_reduced_policy_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=3,
                decisions=[
                    ["continue", "complete"],
                    ["continue", "complete"],
                    ["continue", "complete"],
                ],
            )
            receipt = harness.coordinator.run()
            self.assertTrue(receipt["accepting"])
            self.assertEqual(
                receipt["admission_order"],
                ["child-0", "child-1", "child-2"],
            )

        with tempfile.TemporaryDirectory() as temporary:
            deferred = PoolHarness(
                temporary,
                cap=3,
                deferred_close=True,
                close_defer_count=2,
            )
            receipt = deferred.coordinator.run()
            self.assertTrue(receipt["accepting"])
            self.assertEqual(receipt["pool_disposition"], "accepted")
            self.assertLess(
                deferred.coordinator.progress()["state"]["state_sequence"],
                64,
            )
            for adapter in deferred.adapters.values():
                self.assertEqual(
                    adapter.calls[-4:],
                    ["finalize", "close", "close", "close"],
                )

        with tempfile.TemporaryDirectory() as temporary:
            reduced_policy = json.loads(
                (ROOT / "policy/native-worker-execution.yaml").read_text(
                    encoding="utf-8"
                )
            )
            reduced_policy["native_supervision_pool"]["capacity"][
                "released_max_active_workers"
            ] = 2
            with self.assertRaisesRegex(
                PoolLeaseError,
                "admitted-capacity-not-released",
            ):
                PoolHarness(temporary, cap=3, policy_document=reduced_policy)

    def test_state_lock_rejects_duplicate_active_coordinator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            with self.assertRaisesRegex(NativePoolError, "pool-state-lock-unavailable"):
                harness.build_coordinator(harness.leases, harness.dispatch)
            harness.coordinator.run()

    def test_aggregate_exhaustion_interrupts_every_admitted_child(self) -> None:
        usage = zero_usage()
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                usage_by_child={"child-0": usage},
            )
            usage["tool_calls"] = harness.contract["aggregate_hard_budget"]["tool_calls"] + 1
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertIn("aggregate-tool-calls-exhausted", receipt["reasons"])
            self.assertIn("aggregate-budget-exhausted", receipt["reasons"])
            self.assertEqual(receipt["final_aggregate_usage"]["tool_calls"], usage["tool_calls"])
            self.assertEqual(receipt["stop_scope"], "cohort")
            self.assertNotEqual(receipt["stop_scope"], "publication")

    def test_post_admission_contract_tampering_cannot_widen_fast_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            replacement = pool_child(0, isolation="read-only-shared")
            harness.contract["children"][0].update(replacement)

            receipt = harness.coordinator.run()

            self.assertTrue(receipt["accepting"])
            self.assertEqual(
                harness.coordinator._read_only_fast_path_children,
                frozenset(),
            )
            self.assertTrue(
                any(
                    phase.startswith("after-child-0-")
                    for phase in harness.compare_phases
                )
            )


    def test_zero_work_completion_contains_cohort_before_peer_admission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                decisions=[["complete"], ["continue", "complete"]],
                dispositions_by_child={
                    "child-0": ("quarantined", "rejected"),
                },
            )
            read_child_evidence = harness.read_child_evidence

            def completion_evidence(*, child_id: str, state_file: str) -> dict:
                if (
                    child_id == "child-0"
                    and harness.adapters[child_id].calls[-1] == "check"
                ):
                    harness.protected_fault_reasons_by_child[child_id] = [
                        "zero-tool-completion",
                        "premature-completion",
                        "required-evidence-missing",
                    ]
                return read_child_evidence(child_id=child_id, state_file=state_file)

            harness.coordinator.pool_callbacks["read_child_evidence"] = (
                completion_evidence
            )
            receipt = harness.coordinator.run()

            self.assertFalse(receipt["accepting"])
            self.assertEqual(receipt["pool_disposition"], "quarantined")
            self.assertEqual(
                receipt["first_protected_fault"]["code"],
                "child-protected-fault:zero-tool-completion",
            )
            self.assertIn("premature-completion", receipt["reasons"])
            self.assertIn("required-evidence-missing", receipt["reasons"])
            self.assertEqual(receipt["admission_order"], ["child-0"])
            self.assertEqual(receipt["terminal_order"], ["child-1", "child-0"])
            self.assertIn("check", harness.adapters["child-0"].calls)
            self.assertIn("interrupt", harness.adapters["child-0"].calls)
            self.assertEqual(harness.adapters["child-1"].calls, [])
            self.assertEqual(
                [item["artifact_disposition"] for item in receipt["child_dispositions"]],
                ["rejected", "rejected"],
            )
            self.assertEqual(
                [item["lifecycle_state"] for item in receipt["lease_evidence"]],
                ["released", "released"],
            )


if __name__ == "__main__":
    unittest.main()

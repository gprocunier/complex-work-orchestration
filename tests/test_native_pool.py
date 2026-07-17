from __future__ import annotations

import copy
import datetime as dt
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_control import build_control_turn_contract  # noqa: E402
from cwo_core.native_pool import NativePoolCoordinator, NativePoolError  # noqa: E402
from cwo_core.native_pool_contracts import (  # noqa: E402
    canonical_sha256,
    seal_artifact,
    validate_pool_receipt,
    validate_pool_state,
    write_private_artifact,
    zero_usage,
)
from cwo_core.native_pool_leases import PoolLeaseRegistry, capture_owner_identity  # noqa: E402
from tests.test_native_pool_contracts import control_request, pool_contract, sha  # noqa: E402


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
        fail: str | None = None,
    ) -> None:
        self.clock = clock
        self.decisions = list(decisions)
        self.callback_ms = callback_ms
        self.fail = fail
        self.calls: list[str] = []

    def _call(self, name: str, result=None):
        self.calls.append(name)
        self.clock.advance_ms(self.callback_ms)
        if self.fail == name:
            raise RuntimeError(f"{name} failed")
        return result

    def check(self, **_kwargs):
        decision = self.decisions.pop(0) if self.decisions else "complete"
        return self._call("check", {"decision": decision})

    def callbacks(self) -> dict:
        return {
            "arm": lambda **_kwargs: self._call("arm"),
            "send_input": lambda **_kwargs: self._call(
                "send_input", {"submission_id": f"submission-{id(self)}"}
            ),
            "mark_dispatched": lambda **_kwargs: self._call("mark_dispatched"),
            "check": self.check,
            "interrupt": lambda **_kwargs: self._call("interrupt"),
            "close": lambda **_kwargs: self._call("close"),
            "finalize": lambda **_kwargs: self._call("finalize"),
            "sleep": lambda **_kwargs: self._call("sleep"),
        }


class PoolHarness:
    def __init__(
        self,
        temporary: str,
        *,
        cap: int,
        decisions: list[list[str]] | None = None,
        callback_ms: float = 1,
        fail: tuple[int, str] | None = None,
        dirty_phases: set[str] | None = None,
        usage_by_child: dict[str, dict] | None = None,
        usage_sequence_by_child: dict[str, list[dict]] | None = None,
        dispositions_by_child: dict[str, tuple[str, str]] | None = None,
        budget_overrides: dict[str, int] | None = None,
        read_only: bool = False,
        control_file: Path | None = None,
    ) -> None:
        self.clock = FakeClock()
        self.contract, self.capability = pool_contract(cap=cap, read_only=read_only)
        live_owner = capture_owner_identity()
        self.contract["owner"] = live_owner
        if budget_overrides:
            self.contract["aggregate_hard_budget"].update(budget_overrides)
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
        self.contract = seal_artifact(self.contract, "contract_sha256")
        decision_sets = decisions or [["complete"] for _ in range(cap)]
        self.adapters = {
            f"child-{index}": FakeAdapter(
                self.clock,
                decision_sets[index],
                callback_ms=callback_ms,
                fail=fail[1] if fail is not None and fail[0] == index else None,
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
        self.compare_phases: list[str] = []
        self.registry = PoolLeaseRegistry(
            Path(temporary) / "leases.json",
            owner_alive=lambda _owner: True,
            now=self.clock.now_utc,
        )
        self.control_file = control_file
        self.coordinator = NativePoolCoordinator(
            self.contract,
            self.child_contracts,
            self.tasks,
            {child_id: adapter.callbacks() for child_id, adapter in self.adapters.items()},
            pool_callbacks={
                "monotonic_ns": self.clock.monotonic_ns,
                "sleep": self.clock.sleep,
                "now_utc": self.clock.now_utc,
                "read_child_evidence": self.read_child_evidence,
                "compare_workspaces": self.compare_workspaces,
            },
            lease_registry=self.registry,
            capability_receipt=self.capability,
            state_file=Path(temporary) / "pool-state.json",
            decision_file=Path(temporary) / "pool-decision.json",
            control_file=control_file,
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
        return {
            "state_sha256": sha(
                f"{child_id}:{state_file}:{len(self.adapters[child_id].calls)}"
            ),
            "usage": usage,
            "protected_fault": False,
            "control_loss": False,
            "reasons": [],
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


class NativePoolCoordinatorTests(unittest.TestCase):
    def test_cap_one_runs_to_accepting_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1, decisions=[["continue", "complete"]])
            receipt = harness.coordinator.run()
            self.assertTrue(receipt["accepting"])
            self.assertEqual(receipt["admission_order"], ["child-0"])
            self.assertEqual(receipt["terminal_order"], ["child-0"])
            self.assertEqual(
                validate_pool_receipt(
                    receipt,
                    contract=harness.contract,
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
            self.assertEqual(receipt["lease_evidence"], [])

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

    def test_cap_two_callback_overrun_interrupts_entire_pool(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                callback_ms=101,
                dirty_phases={"after-child-0-arm", "close"},
            )
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertIn("callback-overrun:arm", receipt["reasons"])
            self.assertIn("workspace-mutation-attribution-failed", receipt["reasons"])
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

    def test_aggregate_exhaustion_interrupts_every_admitted_child(self) -> None:
        usage = zero_usage()
        usage["tool_calls"] = 2
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                usage_by_child={"child-0": usage},
                budget_overrides={"tool_calls": 1},
            )
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertIn("aggregate-tool-calls-exhausted", receipt["reasons"])
            self.assertIn("aggregate-budget-exhausted", receipt["reasons"])
            self.assertEqual(receipt["final_aggregate_usage"]["tool_calls"], 2)

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

    def test_late_first_poll_is_pool_wide_protected_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1, callback_ms=700)
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertIn("maximum-poll-gap-exceeded", receipt["reasons"])
            self.assertGreater(receipt["timing"]["max_poll_gap_ms"], 2500)

    def test_partial_dispatch_lease_collision_has_strict_nonaccepting_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            harness.registry.acquire(harness.contract, "child-0")
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertEqual(receipt["admission_order"], [])
            self.assertEqual(receipt["lease_evidence"], [])
            self.assertEqual(harness.adapters["child-0"].calls, [])
            self.assertTrue(any("lease-id-already-active" in reason for reason in receipt["reasons"]))

    def test_second_child_lease_collision_interrupts_already_active_first_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                decisions=[["continue"], ["complete"]],
            )
            harness.registry.acquire(harness.contract, "child-1")
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertEqual(receipt["admission_order"], ["child-0"])
            self.assertIn("interrupt", harness.adapters["child-0"].calls)
            self.assertEqual(harness.adapters["child-1"].calls, [])
            self.assertEqual([item["lease_id"] for item in receipt["lease_evidence"]], ["lease-0"])

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

    def test_state_lock_rejects_duplicate_active_coordinator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(temporary, cap=1)
            with self.assertRaisesRegex(NativePoolError, "pool-state-lock-unavailable"):
                NativePoolCoordinator(
                    harness.contract,
                    harness.child_contracts,
                    harness.tasks,
                    {
                        child_id: adapter.callbacks()
                        for child_id, adapter in harness.adapters.items()
                    },
                    pool_callbacks={
                        "monotonic_ns": harness.clock.monotonic_ns,
                        "sleep": harness.clock.sleep,
                        "now_utc": harness.clock.now_utc,
                        "read_child_evidence": harness.read_child_evidence,
                        "compare_workspaces": harness.compare_workspaces,
                    },
                    lease_registry=harness.registry,
                    capability_receipt=harness.capability,
                    state_file=Path(temporary) / "pool-state.json",
                )
            harness.coordinator.run()

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

    def test_shared_read_only_mutation_quarantines_both_children(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            harness = PoolHarness(
                temporary,
                cap=2,
                read_only=True,
                dirty_phases={"after-child-0-check", "close"},
            )
            receipt = harness.coordinator.run()
            self.assertFalse(receipt["accepting"])
            self.assertEqual(receipt["pool_disposition"], "quarantined")
            self.assertIn("interrupt", harness.adapters["child-0"].calls)
            self.assertEqual(harness.adapters["child-1"].calls, [])
            dispositions = {item["child_id"]: item for item in receipt["child_dispositions"]}
            self.assertEqual(dispositions["child-1"]["session_disposition"], "quarantined")


if __name__ == "__main__":
    unittest.main()

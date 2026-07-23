from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_pool_contracts import canonical_sha256, zero_usage  # noqa: E402
from cwo_core.native_pool_scheduler import (  # noqa: E402
    AggregateUsageLedger,
    PoolAccountingError,
    PoolSchedulingError,
    exhausted_budget,
    mutation_evidence_sha256,
    peer_deadline_guard,
    select_earliest_deadline,
    sum_cumulative_usage,
    usage_delta,
    wait_seconds,
)
from cwo_core.native_pool_schedulability import (  # noqa: E402
    PoolSchedulabilityError,
    latency_consumes_slack_fraction,
    scheduling_budget_proof,
)


def available_usage(*, tools: int = 0, runtime: int = 0, tokens: int = 0) -> dict:
    return {
        "tool_calls": tools,
        "runtime_seconds": runtime,
        "compactions": 0,
        "full_suite_runs": 0,
        "mutations": 0,
        "tokens": {
            "availability": "available",
            "input": tokens,
            "cached_input": 0,
            "output": 0,
            "reasoning": 0,
            "total": tokens,
            "unavailable_reason": None,
        },
    }


class NativePoolSchedulerTests(unittest.TestCase):
    def test_earliest_deadline_rotates_equal_ties(self) -> None:
        children = [
            {"child_id": "a", "next_deadline_ns": 100},
            {"child_id": "b", "next_deadline_ns": 100},
        ]
        first = select_earliest_deadline(children, cursor=0)
        self.assertEqual((first.child_id, first.next_cursor), ("a", 1))
        second = select_earliest_deadline(children, cursor=first.next_cursor)
        self.assertEqual((second.child_id, second.next_cursor), ("b", 0))

        children[0]["next_deadline_ns"] = 90
        selected = select_earliest_deadline(children, cursor=1)
        self.assertEqual(selected.child_id, "a")

    def test_peer_deadline_guard_preempts_lifecycle_callback(self) -> None:
        children = [
            {"child_id": "a", "next_deadline_ns": None},
            {"child_id": "b", "next_deadline_ns": 1_550_000_000},
        ]
        selected = peer_deadline_guard(
            children,
            cursor=0,
            proposed_child_id="a",
            now_ns=1_000_000_000,
            certified_callback_ms=250,
            certified_peer_check_ms=200,
            certified_scheduler_overhead_ms=100,
        )
        self.assertEqual(selected.child_id, "b")
        children[1]["next_deadline_ns"] = 1_550_000_001
        self.assertIsNone(
            peer_deadline_guard(
                children,
                cursor=0,
                proposed_child_id="a",
                now_ns=1_000_000_000,
                certified_callback_ms=250,
                certified_peer_check_ms=200,
                certified_scheduler_overhead_ms=100,
            )
        )

    def test_peer_deadline_guard_accounts_for_cumulative_peer_service(self) -> None:
        children = [
            {"child_id": "a", "next_deadline_ns": None},
            {"child_id": "b", "next_deadline_ns": 400_000_001},
            {"child_id": "c", "next_deadline_ns": 550_000_000},
        ]
        selected = peer_deadline_guard(
            children,
            cursor=0,
            proposed_child_id="a",
            now_ns=0,
            certified_callback_ms=100,
            certified_peer_check_ms=200,
            certified_scheduler_overhead_ms=100,
        )
        self.assertEqual(selected.child_id, "b")

        children[2]["next_deadline_ns"] = 600_000_001
        self.assertIsNone(
            peer_deadline_guard(
                children,
                cursor=0,
                proposed_child_id="a",
                now_ns=0,
                certified_callback_ms=100,
                certified_peer_check_ms=200,
                certified_scheduler_overhead_ms=100,
            )
        )

    def test_peer_deadline_guard_rejects_invalid_service_inputs(self) -> None:
        children = [
            {"child_id": "a", "next_deadline_ns": None},
            {"child_id": "b", "next_deadline_ns": 1},
        ]
        for value in (True, -1, float("nan"), float("inf")):
            with self.subTest(value=value):
                with self.assertRaises(PoolSchedulingError):
                    peer_deadline_guard(
                        children,
                        cursor=0,
                        proposed_child_id="a",
                        now_ns=0,
                        certified_callback_ms=100,
                        certified_peer_check_ms=value,
                    )

    def test_schedulability_proof_has_exact_current_capacity_arithmetic(self) -> None:
        callbacks = {
            "arm": 100,
            "send_input": 250,
            "mark_dispatched": 100,
            "check": 200,
            "interrupt": 250,
            "close": 250,
            "finalize": 100,
        }
        expected = {
            2: (750, 250, True),
            3: (950, 50, True),
            4: (1150, -150, False),
        }
        for workers, outcome in expected.items():
            with self.subTest(workers=workers):
                proof = scheduling_budget_proof(
                    requested_workers=workers,
                    certified_callback_max_ms=callbacks,
                    certified_scheduler_overhead_ms=100,
                    poll_interval_ms=1000,
                )
                self.assertEqual(
                    (proof.total_demand_ms, proof.slack_ms, proof.accepted),
                    outcome,
                )
                self.assertEqual(proof.as_dict()["inputs"]["requested_workers"], workers)

    def test_schedulability_boundary_and_warning_are_explicit(self) -> None:
        callbacks = {"send_input": 250, "check": 200}
        equality = scheduling_budget_proof(
            requested_workers=2,
            certified_callback_max_ms=callbacks,
            certified_scheduler_overhead_ms=100,
            poll_interval_ms=750,
        )
        self.assertTrue(equality.accepted)
        self.assertEqual(equality.slack_ms, 0)
        rejected = scheduling_budget_proof(
            requested_workers=2,
            certified_callback_max_ms=callbacks,
            certified_scheduler_overhead_ms=100,
            poll_interval_ms=749.999,
        )
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            latency_consumes_slack_fraction(
                scheduling_budget_proof(
                    requested_workers=2,
                    certified_callback_max_ms=callbacks,
                    certified_scheduler_overhead_ms=100,
                    poll_interval_ms=1000,
                ),
                observed_latency_ms=200,
                warning_fraction=0.8,
            )
        )

    def test_schedulability_property_grid_uses_n_without_clamping(self) -> None:
        for lifecycle in (1, 100, 250.5):
            for check in (1, 50, 200):
                for overhead in (0, 100):
                    previous = None
                    for workers in range(1, 7):
                        with self.subTest(
                            lifecycle=lifecycle,
                            check=check,
                            overhead=overhead,
                            workers=workers,
                        ):
                            proof = scheduling_budget_proof(
                                requested_workers=workers,
                                certified_callback_max_ms={
                                    "lifecycle": lifecycle,
                                    "check": check,
                                },
                                certified_scheduler_overhead_ms=overhead,
                                poll_interval_ms=5000,
                            )
                            expected = max(lifecycle, check) + workers * check + overhead
                            self.assertEqual(proof.total_demand_ms, expected)
                            self.assertEqual(proof.slack_ms, 5000 - expected)
                            if previous is not None:
                                self.assertEqual(proof.total_demand_ms - previous, check)
                            previous = proof.total_demand_ms

        invalid_cases = (
            {"requested_workers": True},
            {"requested_workers": 0},
            {"certified_scheduler_overhead_ms": float("nan")},
            {"poll_interval_ms": float("inf")},
        )
        baseline = {
            "requested_workers": 2,
            "certified_callback_max_ms": {"lifecycle": 250, "check": 200},
            "certified_scheduler_overhead_ms": 100,
            "poll_interval_ms": 1000,
        }
        for override in invalid_cases:
            with self.subTest(override=override):
                with self.assertRaises(PoolSchedulabilityError):
                    scheduling_budget_proof(**{**baseline, **override})

    def test_usage_delta_rejects_reset_and_availability_change(self) -> None:
        before = available_usage(tools=3, runtime=4, tokens=10)
        after = available_usage(tools=5, runtime=8, tokens=16)
        delta = usage_delta(before, after)
        self.assertEqual(delta["tool_calls"], 2)
        self.assertEqual(delta["runtime_seconds"], 4)
        self.assertEqual(delta["tokens"]["total"], 6)

        reset = available_usage(tools=2, runtime=8, tokens=16)
        with self.assertRaisesRegex(PoolAccountingError, "cumulative-tool-calls-reset"):
            usage_delta(after, reset)
        unavailable = zero_usage()
        with self.assertRaisesRegex(PoolAccountingError, "token-availability-changed"):
            usage_delta(unavailable, available_usage())

    def test_ledger_adds_each_observation_once_and_reconciles(self) -> None:
        ledger = AggregateUsageLedger(["a", "b"])
        first = ledger.observe(
            child_id="a",
            child_state_sha256=canonical_sha256({"state": 1}),
            decision_sequence=1,
            cumulative_usage={**zero_usage(), "tool_calls": 2, "runtime_seconds": 3},
        )
        self.assertEqual(first.delta["tool_calls"], 2)
        self.assertEqual(first.aggregate["tool_calls"], 2)

        second = ledger.observe(
            child_id="b",
            child_state_sha256=canonical_sha256({"state": 2}),
            decision_sequence=2,
            cumulative_usage={**zero_usage(), "tool_calls": 4, "runtime_seconds": 5},
        )
        self.assertEqual(second.aggregate["tool_calls"], 6)
        with self.assertRaisesRegex(PoolAccountingError, "usage-observation-replay"):
            ledger.observe(
                child_id="b",
                child_state_sha256=canonical_sha256({"state": 2}),
                decision_sequence=2,
                cumulative_usage={**zero_usage(), "tool_calls": 4, "runtime_seconds": 5},
            )
        ledger.reconcile(second.aggregate)
        with self.assertRaisesRegex(PoolAccountingError, "aggregate-reconciliation-failed"):
            ledger.reconcile({**second.aggregate, "tool_calls": 7})

    def test_unavailable_tokens_remain_explicit_when_summed(self) -> None:
        total = sum_cumulative_usage([zero_usage(), zero_usage()])
        self.assertEqual(total["tokens"]["availability"], "unavailable")
        self.assertIsNone(total["tokens"]["total"])
        available = sum_cumulative_usage(
            [available_usage(tokens=4), available_usage(tokens=6)]
        )
        self.assertEqual(available["tokens"]["total"], 10)

    def test_hard_budget_reports_every_exhausted_dimension(self) -> None:
        aggregate = {
            **zero_usage(),
            "tool_calls": 5,
            "runtime_seconds": 8,
            "compactions": 1,
        }
        reasons = exhausted_budget(
            aggregate,
            {
                "tool_calls": 4,
                "runtime_seconds": 7,
                "compactions": 0,
                "full_suite_runs": 0,
                "mutations": 0,
            },
        )
        self.assertEqual(
            reasons,
            [
                "aggregate-tool-calls-exhausted",
                "aggregate-runtime-seconds-exhausted",
                "aggregate-compactions-exhausted",
            ],
        )

    def test_wait_and_mutation_evidence_are_deterministic(self) -> None:
        self.assertEqual(wait_seconds(1_000_000_000, 1_250_000_000), 0.25)
        self.assertEqual(wait_seconds(2_000_000_000, 1_250_000_000), 0.0)
        clean = {
            "integration_root_clean": True,
            "shared_read_only_clean": True,
            "child_worktrees_clean": True,
        }
        evidence = {**clean, "evidence_sha256": canonical_sha256(clean)}
        self.assertEqual(mutation_evidence_sha256(evidence), evidence["evidence_sha256"])
        evidence["integration_root_clean"] = False
        with self.assertRaisesRegex(ValueError, "mutation-evidence-sha256-mismatch"):
            mutation_evidence_sha256(evidence)


if __name__ == "__main__":
    unittest.main()

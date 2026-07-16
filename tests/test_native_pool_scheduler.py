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
    exhausted_budget,
    mutation_evidence_sha256,
    peer_deadline_guard,
    select_earliest_deadline,
    sum_cumulative_usage,
    usage_delta,
    wait_seconds,
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
            {"child_id": "b", "next_deadline_ns": 1_350_000_000},
        ]
        selected = peer_deadline_guard(
            children,
            cursor=0,
            proposed_child_id="a",
            now_ns=1_000_000_000,
            certified_callback_ms=400,
        )
        self.assertEqual(selected.child_id, "b")
        self.assertIsNone(
            peer_deadline_guard(
                children,
                cursor=0,
                proposed_child_id="a",
                now_ns=1_000_000_000,
                certified_callback_ms=300,
            )
        )

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

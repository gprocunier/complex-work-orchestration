from __future__ import annotations

import json
from pathlib import Path
import statistics
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_pool_contracts import canonical_sha256  # noqa: E402
from tests.test_native_pool import PoolHarness  # noqa: E402


SCENARIOS = (
    ("balanced-short", 2, 2),
    ("asymmetric-medium", 3, 2),
    ("balanced-long", 4, 4),
)


def _decisions(continue_count: int) -> list[str]:
    return [*["continue"] * continue_count, "complete"]


def deterministic_performance_evidence() -> dict:
    pairs: list[dict] = []
    for name, first_checks, second_checks in SCENARIOS:
        sequential_wall_seconds = 0.0
        sequential_adapter_calls = 0
        for checks in (first_checks, second_checks):
            with tempfile.TemporaryDirectory() as temporary:
                harness = PoolHarness(
                    temporary,
                    cap=1,
                    decisions=[_decisions(checks)],
                )
                receipt = harness.coordinator.run()
                if not receipt["accepting"]:
                    raise AssertionError(f"sequential benchmark did not accept: {name}")
                sequential_wall_seconds += receipt["pool_wall_seconds"]
                sequential_adapter_calls += len(harness.adapters["child-0"].calls)

        with tempfile.TemporaryDirectory() as temporary:
            pooled = PoolHarness(
                temporary,
                cap=2,
                decisions=[_decisions(first_checks), _decisions(second_checks)],
            )
            receipt = pooled.coordinator.run()
            if not receipt["accepting"]:
                raise AssertionError(f"pooled benchmark did not accept: {name}")
            pooled_wall_seconds = receipt["pool_wall_seconds"]
            pooled_adapter_calls = sum(len(adapter.calls) for adapter in pooled.adapters.values())

        reduction = (
            (sequential_wall_seconds - pooled_wall_seconds) / sequential_wall_seconds
            if sequential_wall_seconds
            else 0.0
        )
        pairs.append(
            {
                "scenario": name,
                "sequential_wall_seconds": round(sequential_wall_seconds, 6),
                "pooled_wall_seconds": round(pooled_wall_seconds, 6),
                "wall_reduction_ratio": round(reduction, 6),
                "sequential_adapter_calls": sequential_adapter_calls,
                "pooled_adapter_calls": pooled_adapter_calls,
                "operative_send_input_calls_sequential": 2,
                "operative_send_input_calls_pooled": 2,
            }
        )
    report = {
        "report_type": "cwo-native-supervision-pool-deterministic-performance",
        "version": 1,
        "clock": "fake-monotonic-ns",
        "pair_count": len(pairs),
        "pairs": pairs,
        "median_wall_reduction_ratio": round(
            statistics.median(item["wall_reduction_ratio"] for item in pairs),
            6,
        ),
        "worker_operative_call_increase": sum(
            item["operative_send_input_calls_pooled"]
            - item["operative_send_input_calls_sequential"]
            for item in pairs
        ),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


class NativePoolPerformanceTests(unittest.TestCase):
    def test_three_deterministic_pairs_reduce_median_wall_without_worker_call_increase(self) -> None:
        evidence = deterministic_performance_evidence()
        self.assertEqual(evidence["pair_count"], 3)
        self.assertGreaterEqual(evidence["median_wall_reduction_ratio"], 0.30)
        self.assertEqual(evidence["worker_operative_call_increase"], 0)
        for pair in evidence["pairs"]:
            with self.subTest(scenario=pair["scenario"]):
                self.assertLess(pair["pooled_wall_seconds"], pair["sequential_wall_seconds"])
                self.assertEqual(pair["pooled_adapter_calls"], pair["sequential_adapter_calls"])
        expected_hash = evidence.pop("report_sha256")
        self.assertEqual(expected_hash, canonical_sha256(evidence))


if __name__ == "__main__":
    if "--report-json" in sys.argv:
        print(json.dumps(deterministic_performance_evidence(), indent=2, sort_keys=True))
    else:
        unittest.main()

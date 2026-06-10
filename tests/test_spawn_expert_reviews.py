from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import classify_work  # noqa: E402
from spawn_expert_reviews import control_review_tasks  # noqa: E402


class SpawnExpertReviewsTests(unittest.TestCase):
    def test_provider_conflict_adds_peer_and_sabotage_control_reviews(self) -> None:
        route = classify_work(
            "Claude Opus contractor return for model provider sabotage review.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security"],
        )
        tasks = control_review_tasks("Expert review", route)
        labels = [set(task["labels"]) for task in tasks]
        self.assertTrue(any("contract-jd-peer-review" in item for item in labels))
        self.assertTrue(any("contract-jd-sabotage-review" in item for item in labels))
        self.assertTrue(all(task["metadata"]["codex_pickup"] == "forbidden" for task in tasks))


if __name__ == "__main__":
    unittest.main()

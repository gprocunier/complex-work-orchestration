from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import classify_work  # noqa: E402
from spawn_expert_reviews import control_review_tasks, review_fields  # noqa: E402


class SpawnExpertReviewsTests(unittest.TestCase):
    def assert_native_fields(self, item: dict[str, object]) -> None:
        self.assertTrue(item.get("skills"))
        self.assertTrue(item.get("acceptance"))
        self.assertTrue(item.get("design"))
        self.assertTrue(item.get("notes"))

    def test_expert_review_fields_include_native_beads_contract(self) -> None:
        route = classify_work(
            "Security and documentation review for public contractor packet behavior.",
            requested_roles=["security", "documentation"],
        )
        expert = route["ranked_experts"][0]
        fields = review_fields(expert, route)
        self.assert_native_fields(fields)
        self.assertIn(expert["job_description_label"], fields["skills"])
        self.assertIn("Review is complete", fields["acceptance"])

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
        for task in tasks:
            self.assert_native_fields(task)


if __name__ == "__main__":
    unittest.main()

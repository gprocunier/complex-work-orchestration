from __future__ import annotations

import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import classify_work  # noqa: E402
from route_work import print_human  # noqa: E402


class RouteWorkTests(unittest.TestCase):
    def test_security_and_web_design_triggers(self) -> None:
        result = classify_work(
            "Security and web design review for contractor packet behavior.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security", "web-design"],
        )
        names = [expert["name"] for expert in result["ranked_experts"]]
        self.assertIn("security", names[:3])
        self.assertIn("web_design", names[:3])

    def test_ranked_experts_have_per_expert_executor_metadata(self) -> None:
        result = classify_work(
            "Security and web design review for contractor packet behavior.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security", "web-design"],
        )
        self.assertEqual(result["recommended_executor"], result["ranked_experts"][0]["recommended_executor"])
        for expert in result["ranked_experts"][:2]:
            self.assertIn("recommended_executor", expert)
            self.assertIn("selected_executor", expert)
            self.assertIn("executor_policy_violations", expert)

    def test_human_output_shows_per_expert_executor_and_controls(self) -> None:
        result = classify_work(
            "Security review redacted packet behavior.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["security"],
        )
        output = StringIO()
        with redirect_stdout(output):
            print_human(result, 2)
        rendered = output.getvalue()
        self.assertIn("External contract allowed:", rendered)
        self.assertIn("Local worker allowed:", rendered)
        self.assertIn("Has external expert contracts:", rendered)
        self.assertIn("External experts:", rendered)
        self.assertIn("Acceptance required experts:", rendered)
        self.assertIn("executor=", rendered)
        self.assertIn("violations=", rendered)


if __name__ == "__main__":
    unittest.main()

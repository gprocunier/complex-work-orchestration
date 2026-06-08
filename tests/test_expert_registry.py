from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import load_expert_profile  # noqa: E402

REQUIRED_SECTIONS = [
    "## Charter",
    "## Mastery calibration",
    "## Core mental models",
    "## Invocation triggers",
    "## Required inputs",
    "## Review method",
    "## Domain-specific checklist",
    "## Evidence standard",
    "## Red flags",
    "## Anti-patterns",
    "## Output contract",
    "## Acceptance criteria",
    "## Escalation triggers",
    "## Unacceptable shallow output",
]


class ExpertRegistryTests(unittest.TestCase):
    def test_registered_personas_have_required_distinguished_engineer_structure(self) -> None:
        registry = json.loads((ROOT / "policy" / "expert-registry.yaml").read_text(encoding="utf-8"))
        for name, expert in registry["experts"].items():
            with self.subTest(name=name):
                profile = load_expert_profile(expert["persona_file"])
                text = profile["content"]
                self.assertIn("Distinguished Engineer", text)
                self.assertIn(f"Use for `{expert['job_description_label']}`.", text)
                for section in REQUIRED_SECTIONS:
                    self.assertIn(section, text)
                self.assertIn("Generic advice without evidence", text)


if __name__ == "__main__":
    unittest.main()

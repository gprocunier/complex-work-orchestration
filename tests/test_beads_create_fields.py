from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestration_lib import create_bead  # noqa: E402


class BeadsCreateFieldsTests(unittest.TestCase):
    def test_create_bead_passes_native_fields_and_normalizes_literal_newlines(self) -> None:
        captured: list[list[str]] = []

        def fake_run_bd(args: list[str]) -> str:
            captured.append(args)
            return "Created issue: example-1\n"

        with patch("orchestration_lib.run_bd", side_effect=fake_run_bd):
            result = create_bead(
                "Example",
                labels=["one", "two"],
                skills=["python", None, "beads"],  # type: ignore[list-item]
                description="Purpose:\\nDo the work.",
                acceptance="Done when:\\n- tests pass",
                design="Approach:\\nKeep it small.",
                notes="Route:\\ninternal-worker",
                metadata={"key": "value"},
            )

        self.assertEqual(result["id"], "example-1")
        args = captured[0]
        self.assertEqual(args[args.index("--skills") + 1], "python, beads")
        self.assertEqual(args[args.index("--description") + 1], "Purpose:\nDo the work.")
        self.assertEqual(args[args.index("--acceptance") + 1], "Done when:\n- tests pass")
        self.assertEqual(args[args.index("--design") + 1], "Approach:\nKeep it small.")
        self.assertEqual(args[args.index("--notes") + 1], "Route:\ninternal-worker")
        self.assertIn("--metadata", args)


if __name__ == "__main__":
    unittest.main()

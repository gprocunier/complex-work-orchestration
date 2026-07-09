from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.beads import create_bead  # noqa: E402


class BeadsCreateFieldsTests(unittest.TestCase):
    def test_create_bead_passes_native_fields_and_normalizes_literal_newlines(self) -> None:
        captured: list[list[str]] = []

        metadata_seen = {}

        def fake_run_bd(args: list[str]) -> str:
            captured.append(args)
            metadata_arg = args[args.index("--metadata") + 1]
            self.assertTrue(metadata_arg.startswith("@"))
            metadata_path = Path(metadata_arg[1:])
            self.assertTrue(metadata_path.exists())
            metadata_seen.update(json.loads(metadata_path.read_text(encoding="utf-8")))
            return "Created issue: example-1\n"

        with patch("cwo_core.beads.run_bd", side_effect=fake_run_bd):
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
        metadata_path = Path(args[args.index("--metadata") + 1][1:])
        self.assertEqual(metadata_seen, {"key": "value"})
        self.assertFalse(metadata_path.exists())

    def test_create_bead_uses_file_backed_large_description_and_design(self) -> None:
        captured: list[list[str]] = []
        large_description = "Purpose:\n" + ("Document the work.\n" * 300)
        large_design = "Design:\n" + ("Use file-backed Beads fields.\n" * 300)
        seen_paths: list[Path] = []

        def fake_run_bd(args: list[str]) -> str:
            captured.append(args)
            description_path = Path(args[args.index("--body-file") + 1])
            design_path = Path(args[args.index("--design-file") + 1])
            metadata_path = Path(args[args.index("--metadata") + 1][1:])
            seen_paths.extend([description_path, design_path, metadata_path])
            self.assertEqual(description_path.read_text(encoding="utf-8"), large_description.strip())
            self.assertEqual(design_path.read_text(encoding="utf-8"), large_design.strip())
            return "Created issue: example-2\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"CWO_TEMP_ROOT": tmpdir, "CWO_SESSION_ID": "beads-test"}, clear=False):
                with patch("cwo_core.beads.run_bd", side_effect=fake_run_bd):
                    result = create_bead(
                        "Large Example",
                        description=large_description,
                        design=large_design,
                        metadata={"route": {"ranked_experts": [{"name": "editor"}]}},
                    )

        self.assertEqual(result["id"], "example-2")
        args = captured[0]
        self.assertIn("--body-file", args)
        self.assertIn("--design-file", args)
        self.assertNotIn("--description", args)
        self.assertNotIn("--design", args)
        self.assertFalse(Path(args[args.index("--body-file") + 1]).exists())
        self.assertFalse(Path(args[args.index("--design-file") + 1]).exists())
        self.assertTrue(seen_paths)
        for path in seen_paths:
            self.assertIn("/cwo-", path.as_posix())
            self.assertIn("/beads/", path.as_posix())


if __name__ == "__main__":
    unittest.main()

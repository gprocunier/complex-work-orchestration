from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class InstallScriptTests(unittest.TestCase):
    def test_copr_guidance_does_not_expand_raw_env_into_copy_paste_command(self) -> None:
        text = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")

        self.assertIn("valid_copr_ref()", text)
        self.assertIn("print_copr_command", text)
        self.assertNotIn("sudo dnf copr enable $BEADS_COPR", text)
        self.assertIn("sudo dnf copr enable '$copr_ref'", text)
        self.assertIn("brew install beads", text)
        self.assertIn("https://raw.githubusercontent.com/gastownhall/beads/main/scripts/install.sh", text)
        self.assertIn("https://gastownhall.github.io/beads/", text)
        self.assertIn("reduced-durability Markdown handoff state", text)


if __name__ == "__main__":
    unittest.main()

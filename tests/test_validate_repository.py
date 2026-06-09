from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_repository import validate_repository  # noqa: E402


class ValidateRepositoryTests(unittest.TestCase):
    def test_repository_control_plane_is_consistent(self) -> None:
        self.assertEqual(validate_repository(), [])


if __name__ == "__main__":
    unittest.main()

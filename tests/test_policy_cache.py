from __future__ import annotations

import sys
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import policy  # noqa: E402


class PolicyCacheTests(unittest.TestCase):
    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def test_load_policy_caches_disk_read_and_returns_defensive_copy(self) -> None:
        policy.clear_policy_cache()
        original_read_text = Path.read_text
        read_count = 0

        def counted_read_text(path: Path, *args: object, **kwargs: object) -> str:
            nonlocal read_count
            if path.name == "routing-policy.yaml":
                read_count += 1
            return original_read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", counted_read_text):
            first = policy.load_policy("routing-policy")
            first["mutated"] = True
            second = policy.load_policy("routing-policy")

        self.assertEqual(read_count, 1)
        self.assertNotIn("mutated", second)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text('{"a": 1, "a": 2}', encoding="utf-8")
            with self.assertRaises(SystemExit) as exc:
                policy.load_json_compatible_yaml(path)
        self.assertIn("duplicate key", str(exc.exception))


if __name__ == "__main__":
    unittest.main()

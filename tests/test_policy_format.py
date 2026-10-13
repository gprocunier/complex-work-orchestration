from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import policy  # noqa: E402


class PolicyFormatTests(unittest.TestCase):
    def _load(self, content: str) -> SystemExit:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text(content, encoding="utf-8")
            with self.assertRaises(SystemExit) as raised:
                policy.load_json_compatible_yaml(path)
            return raised.exception

    def test_comments_and_unquoted_keys_explain_json_subset(self) -> None:
        for content in ('{"a": 1} # comment', "{a: 1}"):
            message = str(self._load(content))
            self.assertIn("strict JSON-compatible YAML subset", message)
            self.assertIn("comments and unquoted keys", message)

    def test_policy_document_must_be_top_level_object(self) -> None:
        message = str(self._load("[]"))
        self.assertIn("top-level object", message)
        self.assertIn("arrays and scalar documents", message)

    def test_repository_policies_are_json_load_compatible(self) -> None:
        for path in sorted((ROOT / "policy").glob("*.yaml")):
            value = policy.load_json_compatible_yaml(path)
            self.assertIsInstance(value, dict, path)


if __name__ == "__main__":
    unittest.main()

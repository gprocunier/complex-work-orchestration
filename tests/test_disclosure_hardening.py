from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.outbound_screen import OutboundRefused, require_clean  # noqa: E402


class RefusalTextTests(unittest.TestCase):
    def test_refusal_text_carries_no_digest_of_the_matched_value(self) -> None:
        # A digest of a short password can be reversed with a word list, so the
        # refusal names the rule and offsets only.
        secret = "hunter2"
        with self.assertRaises(OutboundRefused) as raised:
            require_clean(f"password: {secret}\n", surface="test")
        message = str(raised.exception)
        self.assertIn("offsets", message)
        self.assertNotIn(secret, message)
        self.assertNotIn(hashlib.sha256(secret.encode()).hexdigest()[:16], message)
        self.assertNotIn("value sha256", message)


if __name__ == "__main__":
    unittest.main()

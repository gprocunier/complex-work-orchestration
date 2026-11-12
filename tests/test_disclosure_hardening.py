from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from chatgpt_browser_review import PlaywrightChatGPTRunner  # noqa: E402
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


class BrowserPageSelectionTests(unittest.TestCase):
    def select(self, *urls: str) -> object:
        pages = [SimpleNamespace(url=url) for url in urls]
        context = SimpleNamespace(pages=pages, new_page=lambda: "new-page")
        return PlaywrightChatGPTRunner._select_page(None, context)

    def test_look_alike_hosts_are_not_selected(self) -> None:
        look_alikes = ("https://chatgpt.com.example/", "https://example.invalid/?next=chatgpt.com",
                       "https://chatgpt.com@example.invalid/", "http://chatgpt.com/")
        chosen = self.select(*look_alikes, "https://chatgpt.com/c/1")
        self.assertEqual(chosen.url, "https://chatgpt.com/c/1")

    def test_without_a_chatgpt_page_the_first_page_is_used(self) -> None:
        chosen = self.select("https://example.invalid/?next=chat.openai.com", "https://chatgpt.com.example/")
        self.assertEqual(chosen.url, "https://example.invalid/?next=chat.openai.com")


if __name__ == "__main__":
    unittest.main()

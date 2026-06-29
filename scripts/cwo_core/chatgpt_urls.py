from __future__ import annotations

import re
from urllib.parse import urlparse


CHATGPT_HOSTS = {"chatgpt.com", "www.chatgpt.com", "chat.openai.com"}
CHATGPT_SHARE_URL_RE = re.compile(
    r"https://(?:www\.)?(?:chatgpt\.com|chat\.openai\.com)/(?:s|share)/[^\s\"'<>),\]&]+"
)


def valid_chatgpt_share_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme == "https" and (parsed.hostname or "").lower() in CHATGPT_HOSTS and (
        parsed.path.startswith("/s/") or parsed.path.startswith("/share/")
    )
